#![allow(clippy::arithmetic_side_effects)]

use std::fs::{File, OpenOptions};
use std::path::Path;

#[cfg(not(feature = "shuttle-test"))]
use rand::{thread_rng, Rng};

#[cfg(feature = "shuttle-test")]
use shuttle::rand::{thread_rng, Rng};

use rand::{
    distributions::{Distribution, Uniform},
    rngs::SmallRng,
    SeedableRng,
};
use std::io::Write;
use std::mem::offset_of;
use std::{fmt::Debug, mem, ptr};

use crate::riscv;
use crate::{
    ebpf::{self, FIRST_SCRATCH_REG, FRAME_PTR_REG, INSN_SIZE, SCRATCH_REGS, STACK_PTR_REG},
    elf::Executable,
    error::{EbpfError, ProgramResult},
    memory_management::{
        allocate_pages, free_pages, get_system_page_size, protect_pages, round_to_page_size,
    },
    memory_region::{AccessType, MemoryMapping},
    riscv::*,
    vm::{get_runtime_environment_key, Config, ContextObject, EbpfVm},
};

const MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH: usize = 4096;
const MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION: usize = 32; //riscv中每条指令机器码长度都为32位
const MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT: usize = 13;
const MAX_START_PADDING_LENGTH: usize = 256;

pub struct JitProgram {
    /// OS page size in bytes and the alignment of the sections
    pub page_size: usize,
    /// A `*const u8` pointer into the text_section for each BPF instruction
    pub pc_section: &'static mut [usize],
    /// The RISC-V machinecode
    pub text_section: &'static mut [u8],
}

impl JitProgram {
    fn new(pc: usize, code_size: usize) -> Result<Self, EbpfError> {
        let page_size = get_system_page_size();
        let element_size = std::mem::size_of::<usize>();
        let pc_loc_table_size = round_to_page_size(pc * element_size, page_size); //riscv中是否可以优化成pc*4？
        let over_allocated_code_size = round_to_page_size(code_size, page_size);
        unsafe {
            let raw = allocate_pages(pc_loc_table_size + over_allocated_code_size)?;
            Ok(Self {
                page_size,
                pc_section: std::slice::from_raw_parts_mut(raw.cast::<usize>(), pc),
                text_section: std::slice::from_raw_parts_mut(
                    raw.add(pc_loc_table_size),
                    over_allocated_code_size,
                ),
            })
        }
    }

    fn seal(&mut self, text_section_usage: usize) -> Result<(), EbpfError> {
        if self.page_size == 0 {
            return Ok(());
        }
        let raw = self.pc_section.as_ptr() as *mut u8;
        let element_size = std::mem::size_of::<usize>(); // 获取 usize 的大小（4 或 8）
        let pc_loc_table_size =
            round_to_page_size(self.pc_section.len() * element_size, self.page_size);
        let over_allocated_code_size = round_to_page_size(self.text_section.len(), self.page_size);
        let code_size = round_to_page_size(text_section_usage, self.page_size);
        unsafe {
            // Fill with debugger traps
            std::ptr::write_bytes(
                raw.add(pc_loc_table_size).add(text_section_usage),
                0x13,
                code_size - text_section_usage,
            );
            if over_allocated_code_size > code_size {
                free_pages(
                    raw.add(pc_loc_table_size).add(code_size),
                    over_allocated_code_size - code_size,
                )?;
            }
            self.text_section =
                std::slice::from_raw_parts_mut(raw.add(pc_loc_table_size), text_section_usage);
            protect_pages(
                self.pc_section.as_mut_ptr().cast::<u8>(),
                pc_loc_table_size,
                false,
            )?;
            protect_pages(self.text_section.as_mut_ptr(), code_size, true)?;
        }
        Ok(())
    }

    pub fn invoke<C: ContextObject>(
        &self,
        _config: &Config,
        vm: &mut EbpfVm<C>,
        registers: [u64; 12],
    ) {
        unsafe {
            std::arch::asm!(
                "addi sp, sp, -24",                // 创建栈帧，预留 16 字节空间
                "sd s1, 0(sp)",                    // 保存 s0 到栈
                "sd s0, 8(sp)",                    // 保存 s1 到栈

                "sd sp, 0(t5)",


                "mv s1, a0",
                "ld a0, 0(a7)",           // 加载第 1 个参数到 a0
                "ld a1, 8(a7)",           // 加载第 2 个参数到 a2
                "ld a2, 16(a7)",          // 加载第 3 个参数到 a1
                "ld a3, 24(a7)",          // 加载第 4 个参数到 t0
                "ld a4, 32(a7)",          // 加载第 5 个参数到 a4
                "ld a5, 40(a7)",          // 加载第 6 个参数到 a5

                // 设置被调用者保存寄存器
                "ld s2, 48(a7)",          // 加载 s2
                "ld s3, 56(a7)",          // 加载 s3
                "ld s4, 64(a7)",          // 加载 s4
                "ld s5, 72(a7)",          // 加载 s5
                "ld s0, 80(a7)",          // 加载 s1
                "ld a7, 88(a7)",          // 加载 a7
                // 跳转到目标地址并调用
                "auipc t2, 0",
                "addi t2, t2, 10",
                "sd t2, 16(sp)",
                "jalr ra, a6",       // 调用目标函数

                // 恢复被调用者保存寄存器
                "ld s1, 0(sp)",
                "ld s0, 8(sp)",
                "addi sp, sp, 24",                 // 恢复栈帧

                inlateout("t5") &mut vm.host_stack_pointer => _,
                inlateout("s10") std::ptr::addr_of_mut!(*vm).cast::<u64>().offset(get_runtime_environment_key() as isize) => _,//a3
                inlateout("a0") (vm.previous_instruction_meter as i64).wrapping_add(registers[11] as i64) => _,//a0
                inlateout("a6") self.pc_section[registers[11] as usize] => _,
                inlateout("a7") &registers => _,
                lateout("a2") _, lateout("a1") _, lateout("a4") _,
                lateout("a5") _, lateout("s2") _, lateout("s3") _, lateout("s4") _, lateout("s5") _,
            );
        }
    }

    pub fn machine_code_length(&self) -> usize {
        self.text_section.len()
    }

    pub fn mem_size(&self) -> usize {
        let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        pc_loc_table_size + code_size
    }
}

impl Drop for JitProgram {
    fn drop(&mut self) {
        let pc_loc_table_size = round_to_page_size(self.pc_section.len() * 8, self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        if pc_loc_table_size + code_size > 0 {
            unsafe {
                let _ = free_pages(
                    self.pc_section.as_ptr() as *mut u8,
                    pc_loc_table_size + code_size,
                );
            }
        }
    }
}

impl Debug for JitProgram {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("JitProgram {:?}", self as *const _))
    }
}

impl PartialEq for JitProgram {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self as *const _, other as *const _)
    }
}

// Used to define subroutines and then call them
// See JitCompiler::set_anchor() and JitCompiler::relative_to_anchor()
const ANCHOR_TRACE: usize = 0;
const ANCHOR_THROW_EXCEEDED_MAX_INSTRUCTIONS: usize = 1;
const ANCHOR_EPILOGUE: usize = 2;
const ANCHOR_THROW_EXCEPTION_UNCHECKED: usize = 3;
const ANCHOR_EXIT: usize = 4;
const ANCHOR_THROW_EXCEPTION: usize = 5;
const ANCHOR_CALL_DEPTH_EXCEEDED: usize = 6;
const ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT: usize = 7;
const ANCHOR_DIV_BY_ZERO: usize = 8;
const ANCHOR_DIV_OVERFLOW: usize = 9;
const ANCHOR_CALL_UNSUPPORTED_INSTRUCTION: usize = 10;
const ANCHOR_EXTERNAL_FUNCTION_CALL: usize = 11;
const ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE: usize = 12;
const ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_REG: usize = 13;
const ANCHOR_TRANSLATE_MEMORY_ADDRESS: usize = 21;
const ANCHOR_COUNT: usize = 30; // Update me when adding or removing anchors

const REGISTER_MAP: [u8; 11] = [
    CALLER_SAVED_REGISTERS[4], //a0
    ARGUMENT_REGISTERS[1],     //a1
    ARGUMENT_REGISTERS[2],     //a2
    ARGUMENT_REGISTERS[3],     //a3
    ARGUMENT_REGISTERS[4],     //a4
    ARGUMENT_REGISTERS[5],     //a5
    CALLEE_SAVED_REGISTERS[2], //s2
    CALLEE_SAVED_REGISTERS[3], //s3
    CALLEE_SAVED_REGISTERS[4], //s4
    CALLEE_SAVED_REGISTERS[5], //s5
    CALLEE_SAVED_REGISTERS[0], //S0
];

/// S10: Used together with slot_in_vm()
const REGISTER_PTR_TO_VM: u8 = S10;
/// S1: Program counter limit
const REGISTER_INSTRUCTION_METER: u8 = CALLEE_SAVED_REGISTERS[1]; //S1
/// A6: Other scratch register
const REGISTER_OTHER_SCRATCH: u8 = CALLER_SAVED_REGISTERS[7];
/// A7: Scratch register
const REGISTER_SCRATCH: u8 = CALLER_SAVED_REGISTERS[8];

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OperandSize {
    S0 = 0,
    S8 = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, i32, bool),
    RegisterPlusConstant32(u8, i32, bool),
    RegisterPlusConstant64(u8, i64, bool),
    Constant64(i64, bool),
}

struct Argument {
    index: usize,
    value: Value,
}

#[derive(Debug)]
struct Jump {
    location: *const u8,
    target_pc: usize,
}

/// Indices of slots inside RuntimeEnvironment
enum RuntimeEnvironmentSlot {
    HostStackPointer = 0,
    CallDepth = 1,
    StackPointer = 2,
    ContextObjectPointer = 3,
    PreviousInstructionMeter = 4,
    DueInsnCount = 5,
    StopwatchNumerator = 6,
    StopwatchDenominator = 7,
    Registers = 8,
    ProgramResult = 20,
    MemoryMapping = 28,
}

pub struct JitCompiler<'a, C: ContextObject> {
    result: JitProgram,
    text_section_jumps: Vec<Jump>,
    anchors: [*const u8; ANCHOR_COUNT],
    offset_in_text_section: usize,
    executable: &'a Executable<C>,
    program: &'a [u8],
    program_vm_addr: u64,
    config: &'a Config,
    pc: usize,
    last_instruction_meter_validation_pc: usize,
    next_noop_insertion: u32,
    noop_range: Uniform<u32>,
    runtime_environment_key: i32,
    diversification_rng: SmallRng,
    stopwatch_is_active: bool,
}

#[rustfmt::skip]
impl<'a, C: ContextObject> JitCompiler<'a, C> {
    /// Constructs a new compiler and allocates memory for the compilation output
    pub fn new(executable: &'a Executable<C>)->Result<Self,EbpfError>{
        let config = executable.get_config();
        let (program_vm_addr, program) = executable.get_text_bytes();

        // Scan through program to find actual number of instructions
        let mut pc = 0;
        if executable.get_sbpf_version().enable_lddw() {
            while (pc + 1) * ebpf::INSN_SIZE <= program.len() {
                let insn = ebpf::get_insn_unchecked(program, pc);
                pc += match insn.opc {
                    ebpf::LD_DW_IMM => 2,
                    _ => 1,
                };
            }
        } else {
            pc = program.len() / ebpf::INSN_SIZE;
        }

        let mut code_length_estimate = MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH + MAX_START_PADDING_LENGTH + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION * pc;
        if config.noop_instruction_rate != 0 {
            code_length_estimate += code_length_estimate / config.noop_instruction_rate as usize;
        }
        if config.instruction_meter_checkpoint_distance != 0 {
            code_length_estimate += pc / config.instruction_meter_checkpoint_distance * MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT;
        }
        // Relative jump destinations limit the maximum output size
        debug_assert!(code_length_estimate < (i32::MAX as usize));

        let runtime_environment_key = get_runtime_environment_key();
        // let runtime_environment_key:i32 = 0;
        let mut diversification_rng = SmallRng::from_rng(rand::thread_rng()).map_err(|_| EbpfError::JitNotCompiled)?;
        
        Ok(Self {
            result: JitProgram::new(pc, code_length_estimate)?,
            text_section_jumps: vec![],
            anchors: [std::ptr::null(); ANCHOR_COUNT],
            offset_in_text_section: 0,
            executable,
            program_vm_addr,
            program,
            config,
            pc: 0,
            last_instruction_meter_validation_pc: 0,
            next_noop_insertion: if config.noop_instruction_rate == 0 { u32::MAX } else { diversification_rng.gen_range(0..config.noop_instruction_rate * 2) },
            noop_range: Uniform::new_inclusive(0, config.noop_instruction_rate * 2),
            runtime_environment_key,
            diversification_rng,
            stopwatch_is_active: false,
        })
    }

    /// Compiles the given executable, consuming the compiler
    pub fn compile(mut self) -> Result<JitProgram, EbpfError> {
        let text_section_base = self.result.text_section.as_ptr();

        self.emit_subroutines();

        while self.pc * ebpf::INSN_SIZE < self.program.len(){
            if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
                return Err(EbpfError::ExhaustedTextSegment(self.pc));
            }
            let mut insn = ebpf::get_insn_unchecked(self.program, self.pc);//获取当前eBPF指令
            println!("这是insn的结构：{:?}、",insn);
            self.result.pc_section[self.pc] = unsafe { text_section_base.add(self.offset_in_text_section) } as usize;

            // Regular instruction meter checkpoints to prevent long linear runs from exceeding their budget
            if self.last_instruction_meter_validation_pc + self.config.instruction_meter_checkpoint_distance <= self.pc {
                self.emit_validate_instruction_count(true, Some(self.pc));
            }
            //TODO
            if self.config.enable_instruction_tracing {
                println!("指令追踪开启：");
                self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
                self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_TRACE, 0), RA));
                self.emit_ins(RISCVInstruction::mov(OperandSize::S64, ZERO, REGISTER_SCRATCH));
            }

            //eg: mov r1 1
            let dst = if insn.dst == STACK_PTR_REG as u8 { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };//确定目标寄存器 r1
            let src = REGISTER_MAP[insn.src as usize];//确定源寄存器或立即数 1
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;//计算目标程序计数器

            match insn.opc{
                ebpf::ADD64_IMM if insn.dst == STACK_PTR_REG as u8 && self.executable.get_sbpf_version().dynamic_stack_frames() =>{
                    let stack_ptr_access = self.slot_in_vm(RuntimeEnvironmentSlot::StackPointer) as i64;
                    self.load(OperandSize::S64, REGISTER_PTR_TO_VM, stack_ptr_access, T5);
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.emit_ins(RISCVInstruction::add(OperandSize::S64, T5, T1, T5));
                    self.store(OperandSize::S64, REGISTER_PTR_TO_VM, T5, stack_ptr_access);
                }

                ebpf::LD_DW_IMM if self.executable.get_sbpf_version().enable_lddw() => {
                    self.emit_validate_and_profile_instruction_count(false,true, Some(self.pc + 2));
                    self.pc += 1;
                    self.result.pc_section[self.pc] = self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
                    ebpf::augment_lddw_unchecked(self.program, &mut insn);
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(OperandSize::S64, dst, insn.imm);
                    } else {
                        self.load_immediate(OperandSize::S64, dst, insn.imm);
                    }
                }

                // BPF_LDX class
                ebpf::LD_B_REG   => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 1, None);
                },
                ebpf::LD_H_REG   => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 2, None);
                },
                ebpf::LD_W_REG   => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 4, None);
                },
                ebpf::LD_DW_REG  => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 8, None);
                },

                // BPF_ST class
                ebpf::ST_B_IMM   => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_H_IMM   => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_W_IMM   => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_DW_IMM  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Constant64(insn.imm, true)));
                },

                // BPF_STX class
                ebpf::ST_B_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Register(src)));
                },
                ebpf::ST_H_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Register(src)));
                },
                ebpf::ST_W_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Register(src)));
                },
                ebpf::ST_DW_REG  => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Register(src)));
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    self.emit_sanitized_add(OperandSize::S32, dst, insn.imm);
                }
                ebpf::ADD32_REG  => {
                    self.emit_ins(RISCVInstruction::addw(OperandSize::S32, src, dst, dst));
                }
                ebpf::SUB32_IMM  =>{
                    if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                        self.emit_ins(RISCVInstruction::subw(OperandSize::S32, ZERO, dst, dst));
                        if insn.imm != 0{
                            self.emit_sanitized_add(OperandSize::S32, dst, insn.imm);
                        }
                    } else {
                        self.emit_sanitized_sub(OperandSize::S32, dst, insn.imm);
                    }
                }
                ebpf::SUB32_REG  => {
                    self.emit_ins(RISCVInstruction::subw(OperandSize::S32, dst, src, dst));
                }
                ebpf::MUL32_IMM | ebpf::LMUL32_IMM => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.emit_ins(RISCVInstruction::mulw(OperandSize::S32, dst, T1, dst));
                }
                ebpf::MUL32_REG | ebpf::LMUL32_REG => {
                    self.emit_ins(RISCVInstruction::mulw(OperandSize::S32, dst, src, dst));
                }
                ebpf::DIV32_IMM | ebpf::UDIV32_IMM => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, false, T1, dst);
                    self.emit_ins(RISCVInstruction::divuw(OperandSize::S32, dst, T1, dst));
                }
                ebpf::DIV32_REG | ebpf::UDIV32_REG => {
                    self.div_err_handle(OperandSize::S32, false, src, dst);
                    self.emit_ins(RISCVInstruction::divuw(OperandSize::S32, dst, src, dst));
                }
                ebpf::SDIV32_IMM => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, true, T1, dst);
                    self.emit_ins(RISCVInstruction::divw(OperandSize::S32, dst, T1, dst));
                }
                ebpf::SDIV32_REG => {
                    self.div_err_handle(OperandSize::S32, true, src, dst);
                    self.emit_ins(RISCVInstruction::divw(OperandSize::S32, dst, src, dst));
                }
                ebpf::MOD32_IMM if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, T1, dst));
                }
                ebpf::MOD32_REG if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, false, src, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, src, dst));
                }
                ebpf::UREM32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, T1, dst));
                }
                ebpf::UREM32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, false, src, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, src, dst));
                }
                ebpf::UREM64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::UREM64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, false, src, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, src, dst));
                }
                ebpf::SREM32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, true, T1, dst);
                    self.emit_ins(RISCVInstruction::remw(OperandSize::S32, dst, T1, dst));
                }
                ebpf::SREM32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, true, src, dst);
                    self.emit_ins(RISCVInstruction::remw(OperandSize::S32, dst, src, dst));
                }
                ebpf::SREM64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, true, T1, dst);
                    self.emit_ins(RISCVInstruction::rem(OperandSize::S64, dst, T1, dst));
                }
                ebpf::SREM64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, true, src, dst);
                    self.emit_ins(RISCVInstruction::rem(OperandSize::S64, dst, src, dst));
                }
                ebpf::OR32_IMM   => {
                    self.emit_sanitized_or(OperandSize::S32, dst, insn.imm);
                    //清零高32位
                    self.clear_high_32bits(dst);}
                ebpf::OR32_REG   => {
                    self.emit_ins(RISCVInstruction::or(OperandSize::S32, dst, src, dst));
                    //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::AND32_IMM  => {
                    self.emit_sanitized_and(OperandSize::S32, dst, insn.imm);
                    //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::AND32_REG  => {
                    self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, src, dst));
                    //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::LSH32_IMM  => {
                    self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, dst, insn.imm, dst));
                    // //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::LSH32_REG  => {
                    self.emit_ins(RISCVInstruction::sllw(OperandSize::S32, dst, src, dst));
                    // //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::RSH32_IMM  => {
                    self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, insn.imm, dst));
                    // //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::RSH32_REG  => {
                    self.emit_ins(RISCVInstruction::srlw(OperandSize::S32, dst, src, dst));
                    // //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::NEG32     if self.executable.get_sbpf_version().enable_neg() => {
                    self.emit_ins(RISCVInstruction::sub(OperandSize::S32, ZERO, dst, dst));
                    //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::XOR32_IMM  => {
                    self.emit_sanitized_xor(OperandSize::S32, dst, insn.imm);
                    //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::XOR32_REG  => {
                    self.emit_ins(RISCVInstruction::xor(OperandSize::S32, dst, src, dst));
                    //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::MOV32_IMM  => {
                    if self.should_sanitize_constant(insn.imm) {//检查立即数是否需要进行安全处理，防止可能的安全漏洞 
                        self.emit_sanitized_load_immediate(OperandSize::S32, dst, insn.imm);
                    } else {
                        self.load_immediate(OperandSize::S32, dst, insn.imm);
                    }
                    //清零高32位
                    self.clear_high_32bits(dst);
                }
                ebpf::MOV32_REG  => {
                    self.emit_ins(RISCVInstruction::mov(OperandSize::S32, src, dst));
                    //清零高32位
                    self.clear_high_32bits(dst);
                }//将一个寄存器中的值移动到另一个寄存器
                ebpf::ARSH32_IMM => {
                    self.emit_ins(RISCVInstruction::sraiw(OperandSize::S32, dst, insn.imm, dst));
                    self.clear_high_32bits(dst);
                }
                ebpf::ARSH32_REG => {
                    self.emit_ins(RISCVInstruction::sraw(OperandSize::S32, dst, src, dst));
                    self.clear_high_32bits(dst);
                }
                ebpf::LE if self.executable.get_sbpf_version().enable_le() => {
                    match insn.imm {
                        16 => {
                            self.load_immediate(OperandSize::S64, T1, 0xffff);
                            self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, T1, dst)); // Mask to 16 bit
                        }
                        32 => {
                            self.load_immediate(OperandSize::S64, T1, 0xffffffff);
                            self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, T1, dst)); // Mask to 32 bit
                        }
                        64 => {}
                        _ => {
                            return Err(EbpfError::InvalidInstruction);
                        }
                    }
                },
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, dst, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 8, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T1, 8, T1));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T1, T2, dst));
                            // self.load_immediate(OperandSize::S64, T1, 0xffff);
                            // self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, T1, dst)); // Mask to 16 bit
                        }
                        32 => {
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, dst, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 8, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 16, T3));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T3, 0xff, T3));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 24, T4));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T4, 0xff, T4));
                            
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T1, 24, T1));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T2, 16, T2));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T3, 8, T3));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T1, T2, dst));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, dst, T3, dst));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, dst, T4, dst));
                            // self.load_immediate(OperandSize::S64, T1, 0xffffffff);
                            // self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, T1, dst)); // Mask to 16 bit
                        }
                        64 => {
                            //low32bits
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, dst, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S64, dst, 8, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S64, dst, 16, T3));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T3, 0xff, T3));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S64, dst, 24, T4));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T4, 0xff, T4));
                            
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S64, T1, 24, T1));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S64, T2, 16, T2));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S64, T3, 8, T3));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T1, T2, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T3, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T4, T5));
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64,T5,32,T5));
                            // self.clear_high_32bits(T5);
                            //high32bits
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 32, T1));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T1, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 40, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 48, T3));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T3, 0xff, T3));
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 56, T4));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T4, 0xff, T4));
                        
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64, T1, 24, T1));
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64, T2, 16, T2));
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64, T3, 8, T3));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T1, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T2, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T3, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T4, dst));
                        }
                        _ => {
                            return Err(EbpfError::InvalidInstruction);
                        }
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => self.emit_sanitized_add(OperandSize::S64, dst, insn.imm),
                ebpf::ADD64_REG  => self.emit_ins(RISCVInstruction::add(OperandSize::S64, src, dst, dst)),
                ebpf::SUB64_IMM  =>{
                    if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                        self.emit_ins(RISCVInstruction::sub(OperandSize::S64, ZERO, dst, dst));
                        if insn.imm != 0{
                            self.emit_sanitized_add(OperandSize::S64, dst, insn.imm);
                        }
                    } else {
                        self.emit_sanitized_sub(OperandSize::S64, dst, insn.imm);
                    }
                }
                ebpf::SUB64_REG  => {
                    self.emit_ins(RISCVInstruction::sub(OperandSize::S64, dst, src, dst));
                }
                ebpf::MUL64_IMM | ebpf::LMUL64_IMM => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.emit_ins(RISCVInstruction::mul(OperandSize::S64, dst, T1, dst));
                }
                ebpf::DIV64_IMM | ebpf::UDIV64_IMM => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, false, T1, dst);
                    self.emit_ins(RISCVInstruction::divu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::MOD64_IMM => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::MUL64_REG | ebpf::LMUL64_REG => {
                    self.emit_ins(RISCVInstruction::mul(OperandSize::S64, dst, src, dst));
                }
                ebpf::DIV64_REG | ebpf::UDIV64_REG => {
                    self.div_err_handle(OperandSize::S64, false, src, dst);
                    self.emit_ins(RISCVInstruction::divu(OperandSize::S64, dst, src, dst));
                }
                ebpf::MOD64_REG  => {
                    self.div_err_handle(OperandSize::S64, false, src, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, src, dst));
                }
                ebpf::UHMUL64_IMM => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.emit_ins(RISCVInstruction::mulhu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::UHMUL64_REG => {
                    self.emit_ins(RISCVInstruction::mulhu(OperandSize::S64, dst, src, dst));
                }
                ebpf::SHMUL64_IMM => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.emit_ins(RISCVInstruction::mulh(OperandSize::S64, dst, T1, dst));
                }
                ebpf::SHMUL64_REG => {
                    self.emit_ins(RISCVInstruction::mulh(OperandSize::S64, dst, src, dst));
                }
                ebpf::SDIV64_IMM => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, true, T1, dst);
                    self.emit_ins(RISCVInstruction::div(OperandSize::S64, dst, T1, dst));
                }
                ebpf::SDIV64_REG => {
                    self.div_err_handle(OperandSize::S64, true, src, dst);
                    self.emit_ins(RISCVInstruction::div(OperandSize::S64, dst, src, dst));
                }
                ebpf::OR64_IMM   => self.emit_sanitized_or(OperandSize::S64, dst, insn.imm),
                ebpf::OR64_REG   => self.emit_ins(RISCVInstruction::or(OperandSize::S64, dst, src, dst)),
                ebpf::AND64_IMM  => self.emit_sanitized_and(OperandSize::S64, dst, insn.imm),
                ebpf::AND64_REG  => self.emit_ins(RISCVInstruction::and(OperandSize::S64, dst, src, dst)),
                ebpf::LSH64_IMM  => self.emit_ins(RISCVInstruction::slli(OperandSize::S64, dst, insn.imm, dst)),
                ebpf::LSH64_REG  => self.emit_ins(RISCVInstruction::sll(OperandSize::S64, dst, src, dst)),
                ebpf::RSH64_IMM  => self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, insn.imm, dst)),
                ebpf::RSH64_REG  => self.emit_ins(RISCVInstruction::srl(OperandSize::S64, dst, src, dst)),
                ebpf::NEG64     if self.executable.get_sbpf_version().enable_neg() => self.emit_ins(RISCVInstruction::sub(OperandSize::S64, ZERO, dst, dst)),
                ebpf::XOR64_IMM  => self.emit_sanitized_xor(OperandSize::S64, dst, insn.imm),
                ebpf::XOR64_REG  => self.emit_ins(RISCVInstruction::xor(OperandSize::S64, dst, src, dst)),
                ebpf::MOV64_IMM  => {
                    if self.should_sanitize_constant(insn.imm) {//检查立即数是否需要进行安全处理，防止可能的安全漏洞 
                        self.emit_sanitized_load_immediate(OperandSize::S64, dst, insn.imm);
                    } else {println!("here11");
                        self.load_immediate(OperandSize::S64, dst, insn.imm);
                    }
                }
                ebpf::MOV64_REG  => {println!("here18");self.emit_ins(RISCVInstruction::mov(OperandSize::S64, src, dst));println!("here19");}//将一个寄存器中的值移动到另一个寄存器
                ebpf::ARSH64_IMM => self.emit_ins(RISCVInstruction::srai(OperandSize::S64, dst, insn.imm, dst)),
                ebpf::ARSH64_REG => self.emit_ins(RISCVInstruction::sra(OperandSize::S64, dst, src, dst)),
                ebpf::HOR64_IMM if !self.executable.get_sbpf_version().enable_lddw() => {
                    self.emit_sanitized_or(OperandSize::S64, dst, (insn.imm as u64).wrapping_shl(32) as i64);
                }

                // BPF_JMP class
                ebpf::JA         => {
                    self.emit_validate_and_profile_instruction_count(false,true, Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::jal(jump_offset as i64, ZERO));
                },
                // Jump if Equal
                ebpf::JEQ_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S64,T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JEQ_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if Greater Than
                ebpf::JGT_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JGT_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if Greater or Equal
                ebpf::JGE_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64,dst, T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JGE_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64,dst, src,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if less Than
                ebpf::JLT_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, dst,T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JLT_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, dst, src, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if less or Equal
                ebpf::JLE_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JLE_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if Bitwise AND is Non-Zero
                ebpf::JSET_IMM   => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    self.emit_ins(RISCVInstruction::and(OperandSize::S64, T1, dst, T1));
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, ZERO, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSET_REG   => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    self.emit_ins(RISCVInstruction::and(OperandSize::S64, src, dst, T1));
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, ZERO, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                // Jump if Not Equal
                ebpf::JNE_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JNE_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                
                //Jump if Greater Than Signed
                ebpf::JSGT_IMM   => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSGT_REG   => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if Greater or Equal Signed
                ebpf::JSGE_IMM   => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64,dst, T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSGE_REG   => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64,dst, src,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if less Than
                ebpf::JSLT_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, dst,T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSLT_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, dst, src, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if less or Equal Signed
                ebpf::JSLE_IMM    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSLE_REG    => {
                    self.emit_validate_and_profile_instruction_count(false, true,Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::CALL_IMM   => {
                    // For JIT, external functions MUST be registered at compile time.
                    let mut resolved = false;
                    let (external, internal) = if self.executable.get_sbpf_version().static_syscalls() {
                        (insn.src == 0, insn.src != 0)
                    } else {
                        (true, true)
                    };

                    if external {
                        if let Some((_function_name, function)) = self.executable.get_loader().get_function_registry().lookup_by_key(insn.imm as u32) {
                            self.emit_validate_and_profile_instruction_count(true, false, Some(0));
                            self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, function as usize as i64);
                            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                            self.store(OperandSize::S64, SP, RA, 0);
                            self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EXTERNAL_FUNCTION_CALL, 0), RA));
                            self.load(OperandSize::S64, SP, 0, RA);
                            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));

                            self.emit_undo_profile_instruction_count(0);
                            resolved = true;
                        }
                    }

                    if internal {
                        if let Some((_function_name, target_pc)) = self.executable.get_function_registry().lookup_by_key(insn.imm as u32) {
                            self.emit_internal_call(Value::Constant64(target_pc as i64, true));
                            resolved = true;
                        }
                    }

                    if !resolved {
                        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
                        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION, 0), ZERO));
                    }
                },
                ebpf::CALL_REG  => {
                    let target_pc = if self.executable.get_sbpf_version().callx_uses_src_reg() {
                        src
                    } else {
                        REGISTER_MAP[insn.imm as usize]
                    };
                    self.emit_internal_call(Value::Register(target_pc));
                },

                ebpf::EXIT      =>{println!("here6");
                    let call_depth_access=self.slot_in_vm(RuntimeEnvironmentSlot::CallDepth) as i64;
                    self.load(OperandSize::S64, REGISTER_PTR_TO_VM, call_depth_access, REGISTER_MAP[FRAME_PTR_REG]);
                
                    // If CallDepth == 0, we've reached the exit instruction of the entry point
                    if self.config.enable_instruction_meter {
                        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
                    }
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], ZERO, self.relative_to_anchor(ANCHOR_EXIT, 0)));
                    // we're done

                    // else decrement and update CallDepth
                    self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], -1, REGISTER_MAP[FRAME_PTR_REG]));
                    self.store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_MAP[FRAME_PTR_REG], call_depth_access);
                    
                    //TODO
                    if !self.executable.get_sbpf_version().dynamic_stack_frames() {
                        let stack_pointer_access=self.slot_in_vm(RuntimeEnvironmentSlot::StackPointer) as i64;
                        let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
                        self.load_immediate(OperandSize::S64, T1, stack_frame_size);
                        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, stack_pointer_access, T5);
                        self.emit_ins(RISCVInstruction::sub(OperandSize::S64, T5, T1, T5));
                        self.store(OperandSize::S64, REGISTER_PTR_TO_VM, T5, stack_pointer_access);
                    }
                    
                    // and return
                    self.emit_validate_and_profile_instruction_count(false, false, Some(0));
                    self.emit_ins(RISCVInstruction::return_near());
                }
                _ => return Err(EbpfError::UnsupportedInstruction),
            }
            self.pc += 1;
        }
        // Bumper in case there was no final exit 处理程序结束，防止最后没有exit
        if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION > self.result.text_section.len() {
            return Err(EbpfError::ExhaustedTextSegment(self.pc));
        }   
        self.emit_validate_and_profile_instruction_count(false,true, Some(self.pc + 2));
        self.emit_set_exception_kind(EbpfError::ExecutionOverrun);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        self.resolve_jumps();
        self.result.seal(self.offset_in_text_section)?;
        Ok(self.result)
    }

    #[inline]
    fn emit_validate_and_profile_instruction_count(&mut self, exclusive: bool, user_provided: bool, target_pc: Option<usize>) {
        if self.config.enable_instruction_meter {
            self.emit_validate_instruction_count(exclusive, Some(self.pc));
            self.emit_profile_instruction_count(user_provided,target_pc);
        }
    }

    #[inline(always)]
    pub fn emit_ins(&mut self,instruction: RISCVInstruction) {
        // 发射一条 RISC-V 指令
        self.write_binary(instruction.emit());
    }

    fn write_binary(&mut self,instruction: u32) {
        // 文件路径
        let file_path = "mov_test.bin";

        // 判断文件是否存在
        let mut file = if Path::new(file_path).exists() {
            // 文件存在，打开文件并追加内容
            OpenOptions::new()
                .append(true) // 追加模式
                .open(file_path)
                .expect("Failed to open existing file")
        } else {
            // 文件不存在，创建新文件
            File::create(file_path).expect("Failed to create file")
        };

        // 写入指令（小端字节序）
        file.write_all(&instruction.to_le_bytes())
            .expect("Failed to write to file");

        // println!("{:?}",&instruction.to_le_bytes());
        // println!();
        self.emit(instruction);
    }

    /// 判断偏移量并执行load指令
    pub fn load(&mut self,size: OperandSize,source1: u8,offset:i64,destination: u8){
        if offset >= -2048 && offset <= 2047 {
            // 偏移量在 12 位范围内，使用 ld
            self.emit_ins(RISCVInstruction::load(size, source1, offset, destination));
        } else {
            self.load_immediate(size, T1, offset);
            self.emit_ins(RISCVInstruction::add(size, source1, T1, T1));
            self.emit_ins(RISCVInstruction::load(size, T1, 0, destination));
        }
    }

    /// 判断偏移量并执行store指令
    pub fn store(&mut self,size: OperandSize,source1: u8, source2: u8,offset:i64){
        if offset >= -2048 && offset <= 2047 {
            // 偏移量在 12 位范围内，使用 ld
            self.emit_ins(RISCVInstruction::store(size, source1, source2, offset));
        } else {
            self.load_immediate(size, T1, offset);
            self.emit_ins(RISCVInstruction::add(size, source1, T1, T1));
            self.emit_ins(RISCVInstruction::store(size, T1, source2, 0));
        }
    }

    /// 寄存器跳转并链接，若rd为ZERO，仅做寄存器跳转
    // pub fn jalr(&mut self,size: OperandSize,source1: u8,offset:i64,destination: u8){
    //     if offset >= -2048 && offset <= 2047 {
    //         // 偏移量在 12 位范围内，使用 jalr
    //         self.emit_ins(RISCVInstruction::jalr(source1, offset, destination));
    //     } else {
    //         self.load_immediate(size, T1, offset);
    //         self.emit_ins(RISCVInstruction::add(size, source1, T1, T1));
    //         self.emit_ins(RISCVInstruction::jalr(T1, 0, destination));
    //     }
    // }

    ///清零高32位
    pub fn clear_high_32bits(&mut self,destination: u8) {
        self.emit_ins(RISCVInstruction::slli(OperandSize::S64, destination, 32, destination));
        self.emit_ins(RISCVInstruction::srli(OperandSize::S64, destination, 32, destination));
    }

    /// 将立即数分解为高 20 位和低 12 位，支持有符号扩展并生成相应的 RISC-V 指令
    fn load_immediate_with_lui_and_addi(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if immediate >= -2048 && immediate <= 2047 {
            // 立即数在 12 位范围内，使用 ADDI
            self.emit_ins(RISCVInstruction::addi(size, 0, immediate, destination));
        } else {
            // 处理立即数超过 12 位的情况
            let upper_imm = immediate >> 12; // 高 20 位
            let lower_imm = immediate & 0xFFF; // 低 12 位
            let sign_ext = if lower_imm & 0x800 != 0 { 1 } else { 0 };

            // Step 1: 加载高 20 位
            self.emit_ins(RISCVInstruction::lui(
                size,
                upper_imm + sign_ext, // 加上符号扩展
                destination,
            ));

            // Step 2: 使用 ADDI 添加低 12 位
            if lower_imm != 0 {
                self.emit_ins(RISCVInstruction::addi(
                    size,
                    destination,
                    lower_imm,
                    destination,
                ));
            }
        }
    }

    /// Load immediate (LI rd, imm)
    #[inline]
    pub fn load_immediate(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if immediate >= i32::MIN as i64 && immediate <= i32::MAX as i64 {
            // 大小在32位之间的情况
            self.load_immediate_with_lui_and_addi(size, destination, immediate);
        } else if size == OperandSize::S64 {
            // RV64 的情况
            let upper_imm = immediate >> 32; // 高 32 位
            let lower_imm = immediate & 0xFFFFFFFF; // 低 32 位

            // Step 1: 处理高32位
            self.load_immediate_with_lui_and_addi(size, destination, upper_imm);

            // Step 2: 使用 SLLI 将寄存器左移 32 位   logical left shift
            self.emit_ins(RISCVInstruction::slli(size, destination, 32, destination));

            // Step 3: 处理低 32 位立即数到临时寄存器并使用 OR 合并
            // 使用 T0 作为临时寄存器
            self.load_immediate_with_lui_and_addi(size, T0, lower_imm);

            // 低32位无符号扩展
            self.clear_high_32bits(T0);

            // 使用 OR 指令合并高位和低位
            self.emit_ins(RISCVInstruction::or(size, destination, T0, destination));
        }
    }

    #[inline]
    pub fn rotate_right(&mut self,size: OperandSize, source1: u8, shamt: i64, destination: u8) {
        self.emit_ins(RISCVInstruction::mov(size, source1, T2));
        self.emit_ins(RISCVInstruction::mov(size, source1, T3));
        self.emit_ins(RISCVInstruction::slli(size, T2, shamt, T2));
        self.emit_ins(RISCVInstruction::srli(size, T3, shamt, T3));
        self.emit_ins(RISCVInstruction::or(size, T2, T3, destination));
    }

    #[inline]
    pub fn should_sanitize_constant(&mut self,value: i64) -> bool {
        if !self.config.sanitize_user_provided_values {
            return false;
        }

        match value as u64 {
            0xFFFF | 0xFFFFFF | 0xFFFFFFFF | 0xFFFFFFFFFF | 0xFFFFFFFFFFFF | 0xFFFFFFFFFFFFFF
            | 0xFFFFFFFFFFFFFFFF => false,
            v if v <= 0xFF => false,
            v if !v <= 0xFF => false, //没问题
            _ => true,
        }
    }

    #[inline]
    fn slot_in_vm(&self, slot: RuntimeEnvironmentSlot) -> i32 {
        8 * (slot as i32 - self.runtime_environment_key)
    }

    #[inline]
    pub(crate) fn emit<T: std::fmt::Debug>(&mut self, data: T) {
        // println!("{:x?}",data);
        // 使用 OpenOptions 创建或打开文件以进行追加
        // let mut file = match OpenOptions::new()
        //     .write(true)          // 允许写入
        //     .create(true)        // 如果文件不存在，则创建
        //     .append(true)        // 追加内容
        //     .open("output.txt")  // 打开文件
        // {
        //     Ok(file) => file,
        //     Err(e) => {
        //         eprintln!("Failed to open or create file: {}", e);
        //         return; // 返回以避免继续执行
        //     }
        // };

        // // 格式化输出内容
        // let output = format!("{:x?}", data);

        // // 将输出写入文件，并处理可能的错误
        // if let Err(e) = writeln!(file, "{}", output) {
        //     eprintln!("Failed to write to file: {}", e);
        // }

        unsafe {
            let ptr = self.result.text_section.as_ptr().add(self.offset_in_text_section);
            #[allow(clippy::cast_ptr_alignment)]
            // ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            ptr::write_unaligned(ptr as *mut T, data as T);
            // println!("ptr:{:x?}",*ptr);
        }

        // println!("offset_in_text_section:{:?}",self.offset_in_text_section);
        self.offset_in_text_section += mem::size_of::<T>();
    }

    #[inline]
    pub fn emit_sanitized_load_immediate(&mut self,size: OperandSize, destination: u8, value: i64) {
        match size {
            OperandSize::S32 => {
                let key = SmallRng::from_entropy().gen::<i32>() as i64;
                self.load_immediate(
                    size,
                    destination,
                    (value as i32).wrapping_sub(key as i32) as i64,
                );
                self.load_immediate(size, T1, key);
                self.emit_ins(RISCVInstruction::add(size, destination, T1, destination));
            }
            OperandSize::S64 if value >= i32::MIN as i64 && value <= i32::MAX as i64 => {
                let key = SmallRng::from_entropy().gen::<i32>() as i64;
                self.load_immediate(size, destination, value.wrapping_sub(key));
                self.load_immediate(size, T1, key);
                self.emit_ins(RISCVInstruction::add(size, destination, T1, destination));
            }
            OperandSize::S64 if value as u64 & u32::MAX as u64 == 0 => {
                let key = SmallRng::from_entropy().gen::<i32>() as i64;
                self.load_immediate(size, destination, value.rotate_right(32).wrapping_sub(key));
                self.load_immediate(size, T1, key);
                self.emit_ins(RISCVInstruction::add(size, destination, T1, destination)); // wrapping_add(key)
                self.emit_ins(RISCVInstruction::slli(size, destination, 32, destination));
                // shift_left(32)
            }
            OperandSize::S64 => {
                let key = SmallRng::from_entropy().gen::<i64>();
                let lower_key = key as i32 as i64;
                let upper_key = (key >> 32) as i32 as i64;
                self.load_immediate(
                    size,
                    destination,
                    value
                        .wrapping_sub(lower_key)
                        .rotate_right(32)
                        .wrapping_sub(upper_key),
                );
                self.load_immediate(size, T1, upper_key); // wrapping_add(upper_key)
                self.emit_ins(RISCVInstruction::add(size, destination, T1, destination));
                self.rotate_right(size, destination, 32, destination);
                self.load_immediate(size, T1, lower_key); // wrapping_add(lower_key)
                self.emit_ins(RISCVInstruction::add(size, destination, T1, destination));
            }
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }
    }

    #[inline]
    pub fn emit_sanitized_add(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(size, T4, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::addw(size, T4, destination, destination));
            } else {
                self.emit_ins(RISCVInstruction::add(size, T4, destination, destination));
            }
        } else {
            self.load_immediate(size, T1, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::addw(size, T1, destination, destination));
            } else {
                self.emit_ins(RISCVInstruction::add(size, T1, destination, destination));
            }
        }
    }

    #[inline]
    pub fn emit_sanitized_sub(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(size, T4, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::subw(size, destination, T4, destination));
            } else {
                self.emit_ins(RISCVInstruction::sub(size, destination, T4, destination));
            }
        } else {
            self.load_immediate(size, T1, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::subw(size, destination, T1, destination));
            } else {
                self.emit_ins(RISCVInstruction::sub(size, destination, T1, destination));
            }
        }
    }

    #[inline]
    pub fn emit_sanitized_or(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::or(size, destination, T4, destination));
        } else if immediate >= -2048 && immediate <= 2047 {
            // 立即数在 12 位范围内，直接使用 ORI
            self.emit_ins(RISCVInstruction::ori(
                size,
                destination,
                immediate,
                destination,
            ));
        } else {
            self.load_immediate(size, T1, immediate);
            self.emit_ins(RISCVInstruction::or(size, destination, T1, destination));
        }
    }

    #[inline]
    pub fn emit_sanitized_xor(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::xor(size, destination, T4, destination));
        } else if immediate >= -2048 && immediate <= 2047 {
            // 立即数在 12 位范围内，直接使用 XORI
            self.emit_ins(RISCVInstruction::xori(
                size,
                destination,
                immediate,
                destination,
            ));
        } else {
            self.load_immediate(size, T1, immediate);
            self.emit_ins(RISCVInstruction::xor(size, destination, T1, destination));
        }
    }

    #[inline]
    pub fn emit_sanitized_and(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::and(size, destination, T4, destination));
        } else if immediate >= -2048 && immediate <= 2047 {
            // 立即数在 12 位范围内，直接使用 ANDI
            self.emit_ins(RISCVInstruction::andi(
                size,
                destination,
                immediate,
                destination,
            ));
        } else {
            self.load_immediate(size, T1, immediate);
            self.emit_ins(RISCVInstruction::and(size, destination, T1, destination));
        }
    }   

    #[inline]
    fn emit_validate_instruction_count(&mut self, exclusive: bool, pc: Option<usize>) {
        if !self.config.enable_instruction_meter {
            return;
        }
        // Update `MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT` if you change the code generation here
        if let Some(pc) = pc {
            self.last_instruction_meter_validation_pc = pc;
            self.emit_ins(RISCVInstruction::mov(OperandSize::S64, ZERO, T5));
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, pc as i64 + 1, T5));
            println!("heeeee");
            self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, T5,REGISTER_INSTRUCTION_METER,  self.relative_to_anchor(ANCHOR_THROW_EXCEEDED_MAX_INSTRUCTIONS, 0)));
        } else {
            println!("hhhhheeee");
            //无符号r11 <= rbx
            self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, REGISTER_SCRATCH,REGISTER_INSTRUCTION_METER,  self.relative_to_anchor(ANCHOR_THROW_EXCEEDED_MAX_INSTRUCTIONS, 0)));
        }
    }

    #[inline]
    fn emit_profile_instruction_count(&mut self, user_provided: bool, target_pc: Option<usize>) {
        match target_pc {
            Some(target_pc) => {
                let immediate = target_pc as i64 - self.pc as i64 - 1;
                if user_provided {
                    self.emit_sanitized_add(OperandSize::S64, REGISTER_INSTRUCTION_METER, immediate);
                } else {
                    self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_INSTRUCTION_METER, immediate, REGISTER_INSTRUCTION_METER));
                }
            },
            None => {
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_INSTRUCTION_METER, -(self.pc as i64 + 1), REGISTER_INSTRUCTION_METER));
                self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_SCRATCH, REGISTER_INSTRUCTION_METER, REGISTER_INSTRUCTION_METER));
            }
        }
    }

    #[inline]
    fn div_err_handle(&mut self, size: OperandSize, signed: bool, src: u8, dst: u8){
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, src, T6));
        if size == OperandSize::S32 {
            self.clear_high_32bits(T6);
        }

        // Prevent division by zero
        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);// Save pc
        self.emit_ins(RISCVInstruction::beq(OperandSize::S64, T6, ZERO, self.relative_to_anchor(ANCHOR_DIV_BY_ZERO, 0)));

        // Signed division overflows with MIN / -1.
        // If we have an immediate and it's not -1, we can skip the following check.
        if signed  == true {
            self.load_immediate(size, T4, if let OperandSize::S64 = size { i64::MIN } else { i32::MIN as u32 as i64 });
            self.emit_ins(RISCVInstruction::sltu(OperandSize::S64, dst, T4, T4));
            self.emit_ins(RISCVInstruction::sltiu(OperandSize::S64, T4, 1, T4));

            // The exception case is: dst == MIN && src == -1
            // Via De Morgan's law becomes: !(dst != MIN || src != -1)
            // Also, we know that src != 0 in here, so we can use it to set REGISTER_SCRATCH to something not zero
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T6, 1, T5));
            self.emit_ins(RISCVInstruction::sltiu(OperandSize::S64, T5, 1, T5));

            // MIN / -1, raise EbpfError::DivideOverflow
            self.emit_ins(RISCVInstruction::and(OperandSize::S64, T5, T4, T5));
            self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
            println!("ANCHOR_DIV_OVERFLOW!!!!");
            self.emit_ins(RISCVInstruction::bne(OperandSize::S64, T5, ZERO, self.relative_to_anchor(ANCHOR_DIV_OVERFLOW, 0)));
        }
    }

    fn emit_set_exception_kind(&mut self, err: EbpfError) {
        let err_kind = unsafe { *std::ptr::addr_of!(err).cast::<u64>() };
        let err_discriminant = ProgramResult::Err(err).discriminant();
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, REGISTER_OTHER_SCRATCH));
        // result.discriminant = err_discriminant;
        self.load_immediate(OperandSize::S64, T1, err_discriminant as i64);
        self.store(OperandSize::S64, REGISTER_OTHER_SCRATCH, T1, 0);
        // err.kind = err_kind;
        self.load_immediate(OperandSize::S64, T1, err_kind as i64);
        self.store(OperandSize::S64, REGISTER_OTHER_SCRATCH, T1, std::mem::size_of::<u64>() as i64);
    }

    // fn emit_result_is_err(&mut self, destination: u8) {
    //     let ok = ProgramResult::Ok(0);
    //     let ok_discriminant = ok.discriminant();
    //     self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64, T5);
    //     self.emit_ins(RISCVInstruction::mov(OperandSize::S64, T5, destination));
    //     self.load_immediate(OperandSize::S64, T1, ok_discriminant as i64);
    // }

    #[inline]
    fn emit_address_translation(&mut self, dst: Option<u8>, vm_addr: Value, len: u64, value: Option<Value>) {
        debug_assert_ne!(dst.is_some(), value.is_some());

        match vm_addr {
            Value::RegisterPlusConstant64(reg, constant, user_provided) => {
                if user_provided && self.should_sanitize_constant(constant) {
                    self.emit_sanitized_load_immediate(OperandSize::S64, REGISTER_SCRATCH, constant);
                } else {
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, constant);
                }
                self.emit_ins(RISCVInstruction::add(OperandSize::S64, reg, REGISTER_SCRATCH, REGISTER_SCRATCH));
            },
            Value::Constant64(constant, user_provided) => {
                if user_provided && self.should_sanitize_constant(constant) {
                    self.emit_sanitized_load_immediate(OperandSize::S64, REGISTER_SCRATCH, constant);
                } else {
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, constant);
                }
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            },
        }
        
        match value {
            Some(Value::Register(reg)) => {
                self.emit_ins(RISCVInstruction::mov(OperandSize::S64, reg, REGISTER_OTHER_SCRATCH));
            }
            Some(Value::Constant64(constant, user_provided)) => {
                if user_provided && self.should_sanitize_constant(constant) {
                    self.emit_sanitized_load_immediate(OperandSize::S64, REGISTER_OTHER_SCRATCH, constant);
                } else {
                    self.load_immediate(OperandSize::S64, REGISTER_OTHER_SCRATCH, constant);
                }
            }
            _ => {}
        }
        
        if self.config.enable_address_translation {
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            self.store(OperandSize::S64, SP, RA, 0);
            let access_type = if value.is_none() { AccessType::Load } else { AccessType::Store };
            let anchor = ANCHOR_TRANSLATE_MEMORY_ADDRESS + len.trailing_zeros() as usize + 4 * (access_type as usize);
            self.load_immediate(OperandSize::S64, T1, self.pc as i64);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            self.store(OperandSize::S64, SP, T1, 0);
            
            self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(anchor, 0), RA));
            self.load(OperandSize::S64, SP, 0, RA);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            if let Some(dst) = dst {
                self.emit_ins(RISCVInstruction::mov(OperandSize::S64, REGISTER_SCRATCH, dst));
            }
        } else if let Some(dst) = dst {
            match len {
                1 => self.load(OperandSize::S8, REGISTER_SCRATCH,0, dst),
                2 => self.load(OperandSize::S16, REGISTER_SCRATCH, 0,dst),
                4 => self.load(OperandSize::S32, REGISTER_SCRATCH, 0,dst),
                8 => self.load(OperandSize::S64, REGISTER_SCRATCH, 0,dst),
                _ => unreachable!(),
            }
        } else {
            match len {
                1 => self.store(OperandSize::S8, REGISTER_OTHER_SCRATCH, REGISTER_SCRATCH, 0),
                2 => self.store(OperandSize::S16, REGISTER_OTHER_SCRATCH, REGISTER_SCRATCH, 0),
                4 => self.store(OperandSize::S32, REGISTER_OTHER_SCRATCH, REGISTER_SCRATCH, 0),
                8 => self.store(OperandSize::S64, REGISTER_OTHER_SCRATCH, REGISTER_SCRATCH, 0),
                _ => unreachable!(),
            }
        }
    }

    fn emit_subroutines(&mut self){
        //  TODO    
        // Routine for instruction tracing
        if self.config.enable_instruction_tracing {
            self.set_anchor(ANCHOR_TRACE);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            self.emit_ins(RISCVInstruction::store(OperandSize::S64, SP, REGISTER_SCRATCH, 0));
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, REGISTER_MAP.len() as i64 * (-8), SP));
            let mut current_offset = 0;
            for reg in REGISTER_MAP.iter().rev() {
                self.store(OperandSize::S64, SP, *reg, current_offset);
                current_offset+=8;
            }
            self.emit_ins(RISCVInstruction::mov(OperandSize::S64, SP, REGISTER_MAP[0]));
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8 * 3, SP));
            self.emit_rust_call(Value::Constant64(C::trace as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
                Argument { index: 0, value: Value::RegisterIndirect(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ContextObjectPointer), false) },
            ], None);
            // Pop stack and return
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8 * 3, SP)); // RSP += 8 * 3;
            self.load(OperandSize::S64, SP, 0, REGISTER_MAP[0]);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8 * (REGISTER_MAP.len() - 1) as i64, SP));
            self.load(OperandSize::S64, SP, 0, REGISTER_SCRATCH);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            self.emit_ins(RISCVInstruction::return_near());
        }

        // Epilogue
        self.set_anchor(ANCHOR_EPILOGUE);
        if self.config.enable_instruction_meter {
            // REGISTER_INSTRUCTION_METER -= 1;
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_INSTRUCTION_METER, -1, REGISTER_INSTRUCTION_METER));
            // REGISTER_INSTRUCTION_METER -= pc;
            self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_INSTRUCTION_METER, REGISTER_SCRATCH, REGISTER_INSTRUCTION_METER));
            // REGISTER_INSTRUCTION_METER -= *PreviousInstructionMeter;
            self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::PreviousInstructionMeter) as i64, T5);
            self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_INSTRUCTION_METER, T5, REGISTER_INSTRUCTION_METER));
            // REGISTER_INSTRUCTION_METER = -REGISTER_INSTRUCTION_METER;
            self.emit_ins(RISCVInstruction::sub(OperandSize::S64, ZERO, REGISTER_INSTRUCTION_METER, REGISTER_INSTRUCTION_METER));
            // *DueInsnCount = REGISTER_INSTRUCTION_METER;
            self.store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_INSTRUCTION_METER, self.slot_in_vm(RuntimeEnvironmentSlot::DueInsnCount) as i64);
        }

        // Restore stack pointer in case we did not exit gracefully
        
        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::HostStackPointer) as i64, SP);
        self.load(OperandSize::S64, SP,16, RA);
        self.emit_ins(RISCVInstruction::return_near());
        
        // Handler for EbpfError::ExceededMaxInstructions
        self.set_anchor(ANCHOR_THROW_EXCEEDED_MAX_INSTRUCTIONS);
        self.emit_set_exception_kind(EbpfError::ExceededMaxInstructions);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, REGISTER_INSTRUCTION_METER, REGISTER_SCRATCH)); // REGISTER_SCRATCH = REGISTER_INSTRUCTION_METER;
        // Fall through

        // Epilogue for errors
        self.set_anchor(ANCHOR_THROW_EXCEPTION_UNCHECKED);
        self.store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_SCRATCH, (self.slot_in_vm(RuntimeEnvironmentSlot::Registers) + 11 * std::mem::size_of::<u64>() as i32) as i64); // registers[11] = pc;
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EPILOGUE, 0), ZERO));

        // Quit gracefully
        self.set_anchor(ANCHOR_EXIT);
        self.emit_validate_instruction_count(false, None);
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, REGISTER_OTHER_SCRATCH));
        self.store(OperandSize::S64, REGISTER_OTHER_SCRATCH, REGISTER_MAP[0], std::mem::size_of::<u64>() as i64);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, ZERO,  REGISTER_MAP[0]));
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EPILOGUE, 0), ZERO));
    
        // Handler for exceptions which report their pc
        self.set_anchor(ANCHOR_THROW_EXCEPTION);
        // Validate that we did not reach the instruction meter limit before the exception occured
        self.emit_validate_instruction_count(false, None);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION_UNCHECKED, 0), ZERO));

        // Handler for EbpfError::CallDepthExceeded
        self.set_anchor(ANCHOR_CALL_DEPTH_EXCEEDED);
        self.emit_set_exception_kind(EbpfError::CallDepthExceeded);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));
        
        // Handler for EbpfError::CallOutsideTextSegment
        self.set_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT);
        self.emit_set_exception_kind(EbpfError::CallOutsideTextSegment);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        // Handler for EbpfError::DivideByZero
        self.set_anchor(ANCHOR_DIV_BY_ZERO);
        self.emit_set_exception_kind(EbpfError::DivideByZero);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        // Handler for EbpfError::DivideOverflow
        self.set_anchor(ANCHOR_DIV_OVERFLOW);
        self.emit_set_exception_kind(EbpfError::DivideOverflow);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        // Handler for EbpfError::UnsupportedInstruction
        self.set_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION);
        //TODO if self.config.enable_instruction_tracing 
        self.emit_set_exception_kind(EbpfError::UnsupportedInstruction);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        //Routine for external functions
        self.set_anchor(ANCHOR_EXTERNAL_FUNCTION_CALL);
        self.load_immediate(OperandSize::S64, T1, -1);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, T1, 0);// Used as PC value in error case, acts as stack padding otherwise
        if self.config.enable_instruction_meter {
            self.store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_INSTRUCTION_METER,  self.slot_in_vm(RuntimeEnvironmentSlot::DueInsnCount) as i64); // *DueInsnCount = REGISTER_INSTRUCTION_METER;
        }
        self.emit_rust_call(Value::Register(REGISTER_SCRATCH), &[
            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
            Argument { index: 0, value: Value::Register(REGISTER_PTR_TO_VM) },
        ], None);
        if self.config.enable_instruction_meter {
            self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::PreviousInstructionMeter) as i64, REGISTER_INSTRUCTION_METER); // REGISTER_INSTRUCTION_METER = *PreviousInstructionMeter;
        }

        //Test if result indicates that an error occured
        // self.emit_result_is_err(REGISTER_SCRATCH);
        let ok = ProgramResult::Ok(0);
        let ok_discriminant = ok.discriminant();
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, T5));
        // self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64, T5);
        
        self.load_immediate(OperandSize::S64, T1, ok_discriminant as i64);
        self.load(OperandSize::S64, SP, 0, REGISTER_SCRATCH);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
        self.load(OperandSize::S64, T5, 0, T4);
        self.emit_ins(RISCVInstruction::bne(OperandSize::S32, T1, T4, self.relative_to_anchor(ANCHOR_EPILOGUE, 0)));
        // Store Ok value in result register
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, REGISTER_SCRATCH));
        // self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64, REGISTER_SCRATCH);
        self.load(OperandSize::S64, REGISTER_SCRATCH, 8, REGISTER_MAP[0]);
        self.emit_ins(RISCVInstruction::return_near());

        // Routine for prologue of emit_internal_call()
        self.set_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8 * (SCRATCH_REGS + 1) as i64, SP));
        self.store(OperandSize::S64, SP, REGISTER_SCRATCH,  0); // Save original REGISTER_SCRATCH
        self.load(OperandSize::S64, SP, 8 * (SCRATCH_REGS + 1) as i64, REGISTER_SCRATCH); // Load return address
        for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
            self.store(OperandSize::S64, SP, *reg,  8 * (SCRATCH_REGS - i + 1) as i64); // Push SCRATCH_REG
        }
        // Push the caller's frame pointer. The code to restore it is emitted at the end of emit_internal_call().
        self.store(OperandSize::S64, SP, REGISTER_MAP[FRAME_PTR_REG],  8);

        // Push return address and restore original REGISTER_SCRATCH
        self.load(OperandSize::S64, SP, 0, T5);
        self.store(OperandSize::S64, SP, REGISTER_SCRATCH, 0);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, T5, REGISTER_SCRATCH));

        // Increase CallDepth
        let call_depth_access = self.slot_in_vm(RuntimeEnvironmentSlot::CallDepth) as i64;
        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, call_depth_access, T5);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, 1, T5));
        self.store(OperandSize::S64, REGISTER_PTR_TO_VM, T5, call_depth_access);
        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, call_depth_access, REGISTER_MAP[FRAME_PTR_REG]);
        // If CallDepth == self.config.max_call_depth, stop and return CallDepthExceeded
        self.load_immediate(OperandSize::S64, T1, self.config.max_call_depth as i64);
        self.emit_ins(RISCVInstruction::beq(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], T1, self.relative_to_anchor(ANCHOR_CALL_DEPTH_EXCEEDED, 0)));

        // Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
        let stack_pointer_access = self.slot_in_vm(RuntimeEnvironmentSlot::StackPointer) as i64;
        if !self.executable.get_sbpf_version().dynamic_stack_frames() {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
            self.load_immediate(OperandSize::S32, T1, stack_frame_size);
            self.store(OperandSize::S64, REGISTER_PTR_TO_VM, T1, stack_pointer_access);
        }
        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, stack_pointer_access, REGISTER_MAP[FRAME_PTR_REG]); // reg[ebpf::FRAME_PTR_REG] = env.stack_pointer;
        self.emit_ins(RISCVInstruction::return_near());

        // Routine for emit_internal_call(Value::Register())
        self.set_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_REG);
        // Calculate offset relative to instruction_addresses
        self.load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], self.program_vm_addr as i64);
        self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0]));// RAX -= self.program_vm_addr;
        // Force alignment of RAX
        self.load_immediate(OperandSize::S64, T5, !(INSN_SIZE as i64 - 1));
        self.emit_ins(RISCVInstruction::and(OperandSize::S64, REGISTER_MAP[0], T5, REGISTER_MAP[0]));// RAX &= !(INSN_SIZE - 1);
        // Bound check
        // if(RAX >= number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        let number_of_instructions = self.result.pc_section.len();
        self.load_immediate(OperandSize::S64, T1, (number_of_instructions * INSN_SIZE) as i64);
        self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, REGISTER_MAP[0], T1, self.relative_to_anchor(ANCHOR_CALL_OUTSIDE_TEXT_SEGMENT, 0)));
        // Calculate the target_pc (dst / INSN_SIZE) to update REGISTER_INSTRUCTION_METER
        // and as target pc for potential ANCHOR_CALL_UNSUPPORTED_INSTRUCTION
        let shift_amount = INSN_SIZE.trailing_zeros();
        debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, REGISTER_MAP[0], REGISTER_SCRATCH));
        self.emit_ins(RISCVInstruction::srli(OperandSize::S64, REGISTER_SCRATCH, shift_amount as i64, REGISTER_SCRATCH));
        
        // Load host target_address from self.result.pc_section
        debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
        println!("here pc_section:{:?}", self.result.pc_section);
        println!("here pc_section:{:?}", self.result.pc_section.as_ptr());
        println!("here pc_section:{:?}", self.result.pc_section.as_ptr() as i64);
        let result_pc_section = self.result.pc_section.as_ptr() as i64;
        self.load_immediate(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], result_pc_section);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_MAP[0], REGISTER_MAP[FRAME_PTR_REG], REGISTER_MAP[0])); // RAX += self.result.pc_section;
        self.load(OperandSize::S64, REGISTER_MAP[0], 0,REGISTER_MAP[0]); // RAX = self.result.pc_section[RAX / 8];
        // Load the frame pointer again since we've clobbered REGISTER_MAP[FRAME_PTR_REG]
        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, stack_pointer_access, REGISTER_MAP[FRAME_PTR_REG]);
        self.emit_ins(RISCVInstruction::return_near());

        // Translates a vm memory address to a host memory address
        // 内存地址翻译子程序
        for (access_type, len) in &[
            (AccessType::Load, 1i32),
            (AccessType::Load, 2i32),
            (AccessType::Load, 4i32),
            (AccessType::Load, 8i32),
            (AccessType::Store, 1i32),
            (AccessType::Store, 2i32),
            (AccessType::Store, 4i32),
            (AccessType::Store, 8i32),
        ] {
            let target_offset = len.trailing_zeros() as usize + 4 * (*access_type as usize);
            self.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + target_offset);
            // call MemoryMapping::(load|store) storing the result in RuntimeEnvironmentSlot::ProgramResult
            if *access_type == AccessType::Load {
                let load = match len {
                    1 => MemoryMapping::load::<u8> as *const u8 as i64,
                    2 => MemoryMapping::load::<u16> as *const u8 as i64,
                    4 => MemoryMapping::load::<u32> as *const u8 as i64,
                    8 => MemoryMapping::load::<u64> as *const u8 as i64,
                    _ => unreachable!()
                };
                self.emit_rust_call(Value::Constant64(load, false), &[
                    Argument { index: 2, value: Value::Register(REGISTER_SCRATCH) }, // Specify first as the src register could be overwritten by other arguments
                    Argument { index: 3, value: Value::Constant64(0, false) }, // self.pc is set later
                    Argument { index: 1, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::MemoryMapping), false) },
                    Argument { index: 0, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult), false) },
                ], None);
            } else {
                let store = match len {
                    1 => MemoryMapping::store::<u8> as *const u8 as i64,
                    2 => MemoryMapping::store::<u16> as *const u8 as i64,
                    4 => MemoryMapping::store::<u32> as *const u8 as i64,
                    8 => MemoryMapping::store::<u64> as *const u8 as i64,
                    _ => unreachable!()
                };
                self.emit_rust_call(Value::Constant64(store, false), &[
                    Argument { index: 3, value: Value::Register(REGISTER_SCRATCH) }, // Specify first as the src register could be overwritten by other arguments
                    Argument { index: 2, value: Value::Register(REGISTER_OTHER_SCRATCH) },
                    Argument { index: 4, value: Value::Constant64(0, false) }, // self.pc is set later
                    Argument { index: 1, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::MemoryMapping), false) },
                    Argument { index: 0, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult), false) },
                ], None);
            }

            // Throw error if the result indicates one
            // self.emit_result_is_err(REGISTER_SCRATCH);
            let ok = ProgramResult::Ok(0);
            let ok_discriminant = ok.discriminant();
            self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, T5));
            // self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64, T5);
            
            self.load_immediate(OperandSize::S64, T1, ok_discriminant as i64);
            self.load(OperandSize::S64, SP, 0, REGISTER_SCRATCH);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            self.load(OperandSize::S64, T5, 0, T4);
            self.emit_ins(RISCVInstruction::bne(OperandSize::S32, T1, T4, self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0)));

            // unwrap() the result into REGISTER_SCRATCH
            self.load(OperandSize::S64, REGISTER_PTR_TO_VM, (self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) + std::mem::size_of::<u64>() as i32) as i64,REGISTER_SCRATCH);

            self.emit_ins(RISCVInstruction::return_near());
        }
    }

    fn set_anchor(&mut self, anchor: usize) {
        self.anchors[anchor] = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
    }

    

    // instruction_length = 4字节
    #[inline]
    fn relative_to_anchor(&self, anchor: usize, instruction_length: usize) -> i64 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = self.anchors[anchor];
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_end) } as i64) // Relative jump
    }

    #[inline]
    fn relative_to_target_pc(&mut self, target_pc: usize, instruction_length: usize) -> i32 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = if self.result.pc_section[target_pc] != 0 {
            // Backward jump
            println!("back!");
            self.result.pc_section[target_pc] as *const u8
        } else {
            println!("Forward!");
            // Forward jump, needs relocation
            self.text_section_jumps.push(Jump { location: unsafe { instruction_end.sub(0) }, target_pc });
            return 0;
        };
        println!("relative_to_target_pc destination:{:?}",destination);
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_end) } as i32) // Relative jump
    }

    #[inline]
    fn emit_undo_profile_instruction_count(&mut self, target_pc: usize) {
        if self.config.enable_instruction_meter {
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_INSTRUCTION_METER, self.pc as i64 + 1 - target_pc as i64, REGISTER_INSTRUCTION_METER));
            // instruction_meter += (self.pc + 1) - target_pc;
        }
    }

    fn emit_rust_call(&mut self, target: Value, arguments: &[Argument], result_reg: Option<u8>){
        let mut saved_registers = CALLER_SAVED_REGISTERS.to_vec();
        if let Some(reg) = result_reg {
            if let Some(dst) = saved_registers.iter().position(|x| *x == reg) {
                saved_registers.remove(dst);
            }
        }

        // Save registers on stack
        let saved_registers_len = saved_registers.len();
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8 * saved_registers_len as i64, SP));
        let mut current_offset = 0;
        for reg in saved_registers.iter() {
            self.store(OperandSize::S64, SP, *reg, current_offset);
            current_offset += 8;
        }

        // Align RSP to 16 bytes
        // if current_offset % 16 != 0 {
        //     self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        // }
        // self.emit_ins(RISCVInstruction::mov(OperandSize::S64, SP, T5));
        
        // self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -16, SP));
        // self.store(OperandSize::S64, T5, SP, 0);
        // self.load(OperandSize::S64, SP, 0, T5);
        // self.store(OperandSize::S64, SP, T5, 8);
        // self.emit_ins(RISCVInstruction::andi(OperandSize::S64, SP, -16, SP));
        // self.emit_ins(X86Instruction::push(RSP, None));
        // self.emit_ins(X86Instruction::push(RSP, Some(X86IndirectAccess::OffsetIndexShift(0, RSP, 0))));
        // self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 4, RSP, -16, None)); //RSP &= -16

        let stack_arguments = arguments.len().saturating_sub(ARGUMENT_REGISTERS.len()) as i64;
        if stack_arguments % 2 != 0 {
            // If we're going to pass an odd number of stack args we need to pad
            // to preserve alignment
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            // self.emit_ins(X86Instruction::alu(OperandSize::S64, 0x81, 5, RSP, 8, None));
        }

        // Pass arguments
        for argument in arguments {
            let is_stack_argument = argument.index >= ARGUMENT_REGISTERS.len();
            let dst = if is_stack_argument {
                u8::MAX // Never used
            } else {
                ARGUMENT_REGISTERS[argument.index]
            };
            match argument.value {
                Value::Register(reg) => {
                    if is_stack_argument {
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, 0);
                    } else if reg != dst {
                        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, reg, dst));
                    }
                },
                Value::RegisterIndirect(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, offset as i64);
                    } else {
                        self.load(OperandSize::S64, reg, offset as i64,dst);
                    }
                },
                Value::RegisterPlusConstant32(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, 0);
                        self.load(OperandSize::S64, SP, 0, T5);
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, 1, T5));
                        self.store(OperandSize::S64, SP, T5, 0);
                    } else {
                        self.load_immediate(OperandSize::S64, T1, offset as i64);
                        self.emit_ins(RISCVInstruction::add(OperandSize::S64, reg, T1, dst));
                    }
                },
                Value::RegisterPlusConstant64(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, 0);
                        self.load(OperandSize::S64, SP, 0, T5);
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, 1, T5));
                        self.store(OperandSize::S64, SP, T5, 0);
                    } else {
                        self.load_immediate(OperandSize::S64, T1, offset as i64);
                        self.emit_ins(RISCVInstruction::add(OperandSize::S64, reg, T1, dst));
                    }
                },
                Value::Constant64(value, user_provided) => {
                    debug_assert!(!user_provided && !is_stack_argument);
                    self.load_immediate(OperandSize::S64, dst, value);
                },
            }
        }
        match target {
            Value::Register(reg) => {
                // self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                // self.store(OperandSize::S64, SP, RA, 0);
                self.emit_ins(RISCVInstruction::jalr(reg, 0, RA));
                // self.load(OperandSize::S64, SP, 0, RA);
                // self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            },
            Value::Constant64(value, user_provided) => {
                debug_assert!(!user_provided);
                // self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                // self.store(OperandSize::S64, SP, RA, 0);
                self.load_immediate(OperandSize::S64, T1, value);
                self.emit_ins(RISCVInstruction::jalr(T1, 0, RA));
                // self.load(OperandSize::S64, SP, 0, RA);
                // self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }

        // Save returned value in result register
        if let Some(reg) = result_reg {
            self.emit_ins(RISCVInstruction::mov(OperandSize::S64, reg, A0));
        }

        // Restore registers from stack
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, if stack_arguments % 2 != 0 { stack_arguments + 1 } else { stack_arguments } * 8, SP));
        // self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 16, SP));
        // self.load(OperandSize::S64, SP, 8,SP );//???这有什么作用？

        let mut current_offset = 0;
        for reg in saved_registers.iter() {
            self.load(OperandSize::S64, SP, current_offset, *reg);
            current_offset += 8;
        }
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8 * saved_registers_len as i64, SP));
    }

    #[inline]
    fn call_immediate(&mut self, offset:i64){
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, RA, 0);
        self.emit_ins(RISCVInstruction::jal(offset, RA));
        self.load(OperandSize::S64, SP, 0, RA);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
    }
    
    #[inline]
    fn call_reg(&mut self, dst: u8){
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, RA, 0);
        self.emit_ins(RISCVInstruction::jalr(dst, 0,RA));
        self.load(OperandSize::S64, SP, 0, RA);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
    }

    #[inline]
    fn emit_internal_call(&mut self, dst: Value) {
        // Store PC in case the bounds check fails
        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, RA, 0);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE, 0), RA));
        self.load(OperandSize::S64, SP, 0, RA);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));

        // self.call_immediate(self.relative_to_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE, 0));
        
        match dst {
            Value::Register(reg) => {
                // Move vm target_address into RAX
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                self.store(OperandSize::S64, SP, REGISTER_MAP[0], 0);
                if reg != REGISTER_MAP[0] {
                    self.emit_ins(RISCVInstruction::mov(OperandSize::S64, reg, REGISTER_MAP[0]));
                }

                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                self.store(OperandSize::S64, SP, RA, 0);
                self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_REG, 0), RA));
                self.load(OperandSize::S64, SP, 0, RA);
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));

                // self.call_immediate(self.relative_to_anchor(ANCHOR_ANCHOR_INTERNAL_FUNCTION_CALL_REG, 0));

                self.emit_validate_and_profile_instruction_count(false, false, None);
                self.emit_ins(RISCVInstruction::mov(OperandSize::S64, REGISTER_MAP[0], REGISTER_OTHER_SCRATCH));
                self.load(OperandSize::S64, SP, 0, REGISTER_MAP[0]);// Restore RAX
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
    
                self.call_reg(REGISTER_OTHER_SCRATCH); // callq *REGISTER_OTHER_SCRATCH
            },
            Value::Constant64(target_pc, user_provided) => {
                debug_assert!(user_provided);
                self.emit_validate_and_profile_instruction_count(false, user_provided, Some(target_pc as usize));
                if user_provided && self.should_sanitize_constant(target_pc) {
                    self.emit_sanitized_load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc);
                } else {
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc);
                }
                
                
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                self.store(OperandSize::S64, SP, RA, 0);
                let jump_offset = self.relative_to_target_pc(target_pc as usize, 0) as i64;
                self.emit_ins(RISCVInstruction::jal(jump_offset, RA));
                self.load(OperandSize::S64, SP, 0, RA);
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
                // self.call_immediate(jump_offset);
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }

        self.emit_undo_profile_instruction_count(0);

        // Restore the previous frame pointer
        self.load(OperandSize::S64, SP, 0, REGISTER_MAP[FRAME_PTR_REG]);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
        let mut current_offset = 0;
        for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
            self.load(OperandSize::S64, SP, current_offset, *reg);
            current_offset += 8;
        }
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, current_offset, SP));
    }

    fn resolve_jumps(&mut self) {
        // Relocate forward jumps
        for jump in &self.text_section_jumps {
            let destination = self.result.pc_section[jump.target_pc] as *const u8;
            println!("jump.location:{:?}",jump.location);
            println!("des:{:?}",destination);
            // println!("destination.offset_from(jump.location):{:?}",destination.offset_from(jump.location));
            let offset_value = 
                unsafe { destination.offset_from(jump.location) } as i32 ;// Relative jump
                // - mem::size_of::<i32>() as i32; // Jump from end of instruction
            println!("offset_value:{:?}",offset_value);
            let address: *const u32 = jump.location as *const u32;  // 这里是你的示例地址
    
            unsafe {
                // 从指定的地址读取4个字节的指令
                let original_instruction = *address;
                
                // 输出机器码，保持8位十六进制格式，和gdb一致
                println!("original_instruction at address 0x7ffff7fd17d0: 0x{:08x}", original_instruction);
                let op = original_instruction & 0x7f;
                if op != 0x6f as u32 {
                    // B 型指令（Branch）
                    let imm_11 = (offset_value & 0x800) >> 4; // 提取立即数第 12 位，移动到 bit[7]
                    let imm_4_1 = (offset_value & 0x1E) << 7; // 提取立即数 bit[1:4]，移动到 bit[8:11]
                    let imm_10_5 = (offset_value & 0x7E0) << 20; // 提取立即数 bit[5:10]，移动到 bit[25:30]
                    let imm_12 = (offset_value & 0x1000) << 19; // 提取立即数 bit[12]，移动到 bit[31]
                    let rs2_rs1_funct3 = (original_instruction & 0x1FFF000) as i32;
                    let opcode = (original_instruction & 0x7F) as i32;
                    let instruction = imm_12 | imm_10_5 | rs2_rs1_funct3 | imm_4_1 | imm_11 | opcode;
                    unsafe { ptr::write_unaligned(jump.location as *mut i32, instruction); }
                } else {
                    // J 型指令 (Jump)
                    let imm_19_12 = offset_value & 0xFF000; // 提取立即数 bit[12:19]
                    let imm_11 = (offset_value & 0x800) << 9; // 提取立即数 bit[11]
                    let imm_10_1 = (offset_value & 0x7FE) << 20; // 提取立即数 bit[1:10]
                    let imm_20 = (offset_value & 0x100000) << 11; // 提取立即数 bit[20]
                    let rd = (original_instruction & 0xF80) as i32;
                    let opcode = 0x6f & 0x7F;
                    let instruction= imm_20 | imm_10_1 | imm_11 | imm_19_12 | rd | opcode;
                    unsafe { ptr::write_unaligned(jump.location as *mut i32, instruction); }
                }
            }         
        }
        // There is no `VerifierError::JumpToMiddleOfLDDW` for `call imm` so patch it here
        let call_unsupported_instruction = self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION] as usize;
        if self.executable.get_sbpf_version().static_syscalls() {
            let mut prev_pc = 0;
            for current_pc in self.executable.get_function_registry().keys() {
                if current_pc as usize >= self.result.pc_section.len() {
                    break;
                }
                for pc in prev_pc..current_pc as usize {
                    self.result.pc_section[pc] = call_unsupported_instruction;
                }
                prev_pc = current_pc as usize + 1;
            }
            for pc in prev_pc..self.result.pc_section.len() {
                self.result.pc_section[pc] = call_unsupported_instruction;
            }
        }
    }
}
