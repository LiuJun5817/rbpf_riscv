#![allow(clippy::arithmetic_side_effects)]

use std::fs::{File, OpenOptions};
use std::path::Path;

use rand::{rngs::SmallRng, Rng, SeedableRng};
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
    // memory_region::{AccessType, MemoryMapping},
    riscv::*,
    // vm::ContextObject,
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
    pc_section: &'static mut [usize],
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

    // pub fn invoke<C: ContextObject>(
    //     &self,
    //     _config: &Config,
    //     vm: &mut EbpfVm<C>,
    //     registers: [u64; 12],
    // ) {
    //     unsafe {
    //         std::arch::asm!(
    //             // 保存寄存器
    //             "sw ra, 0(sp)",
    //             "sw t0, 4(sp)",
    //             "sw t1, 8(sp)",
    //             "sw t2, 12(sp)",
    //             "sw t3, 16(sp)",
    //             "sw t4, 20(sp)",
    //             "sw t5, 24(sp)",
    //             "sw t6, 28(sp)",

    //             // 修改栈指针
    //             "mv sp, {host_stack_pointer}",

    //             // 将寄存器值加载到对应寄存器中
    //             "lw a0, 0(a1)",       // r11 + 0x00 -> a0
    //             "lw a1, 4(a1)",       // r11 + 0x08 -> a1
    //             "lw a2, 8(a1)",       // r11 + 0x10 -> a2
    //             "lw a3, 12(a1)",      // r11 + 0x18 -> a3
    //             "lw a4, 16(a1)",      // r11 + 0x20 -> a4
    //             "lw a5, 20(a1)",      // r11 + 0x28 -> a5
    //             "lw a6, 24(a1)",      // r11 + 0x30 -> a6
    //             "lw a7, 28(a1)",      // r11 + 0x38 -> a7

    //             // 跳转到函数
    //             "jalr {pc_section}",

    //             // 恢复栈和寄存器
    //             "lw ra, 0(sp)",
    //             "lw t0, 4(sp)",
    //             "lw t1, 8(sp)",
    //             "lw t2, 12(sp)",
    //             "lw t3, 16(sp)",
    //             "lw t4, 20(sp)",
    //             "lw t5, 24(sp)",
    //             "lw t6, 28(sp)",
    //             host_stack_pointer = in(reg) &mut vm.host_stack_pointer,
    //             inlateout("a1") &registers => _,
    //             lateout("a0") _,
    //         );
    //     }
    // }
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
    CALLER_SAVED_REGISTERS[0], //RA
    ARGUMENT_REGISTERS[1],     //a1
    ARGUMENT_REGISTERS[2],     //a2
    ARGUMENT_REGISTERS[3],     //a3
    ARGUMENT_REGISTERS[4],     //a4
    ARGUMENT_REGISTERS[5],     //a5
    CALLEE_SAVED_REGISTERS[2], //s2
    CALLEE_SAVED_REGISTERS[3], //s3
    CALLEE_SAVED_REGISTERS[4], //s4
    CALLEE_SAVED_REGISTERS[5], //s5
    CALLEE_SAVED_REGISTERS[0], //s0
];

/// A0: Used together with slot_in_vm()
const REGISTER_PTR_TO_VM: u8 = ARGUMENT_REGISTERS[0];
/// S1: Program counter limit
const REGISTER_INSTRUCTION_METER: u8 = CALLEE_SAVED_REGISTERS[1];
/// T5: Other scratch register
const REGISTER_OTHER_SCRATCH: u8 = CALLER_SAVED_REGISTERS[14];
/// T6: Scratch register
const REGISTER_SCRATCH: u8 = CALLER_SAVED_REGISTERS[15];

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OperandSize {
    S0 = 0,
    S8 = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
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
            self.result.pc_section[self.pc] = unsafe { text_section_base.add(self.offset_in_text_section) } as usize;
            //eg: mov r1 1
            let dst = if insn.dst == STACK_PTR_REG as u8 { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };//确定目标寄存器 r1
            let src = REGISTER_MAP[insn.src as usize];//确定源寄存器或立即数 1
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;//计算目标程序计数器

            match insn.opc{
                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    self.emit_sanitized_add(OperandSize::S32, dst, insn.imm);
                }
                ebpf::ADD32_REG  => {
                    self.emit_ins(RISCVInstruction::add(OperandSize::S32, src, dst, dst));
                }
                ebpf::SUB32_IMM  =>{
                    if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                        self.emit_ins(RISCVInstruction::sub(OperandSize::S32, ZERO, dst, dst));
                        if insn.imm != 0{
                            self.emit_sanitized_add(OperandSize::S32, dst, insn.imm);
                        }
                    } else {
                        self.emit_sanitized_sub(OperandSize::S32, dst, insn.imm);
                    }
                }
                ebpf::SUB32_REG  => {
                    self.emit_ins(RISCVInstruction::sub(OperandSize::S32, dst, src, dst));
                }
                // TODO ebpf::MUL32_IMM | ebpf::DIV32_IMM | ebpf::MOD32_IMM
                ebpf::OR32_IMM   => self.emit_sanitized_or(OperandSize::S32, dst, insn.imm),
                ebpf::OR32_REG   => self.emit_ins(RISCVInstruction::or(OperandSize::S32, dst, src, dst)),
                ebpf::AND32_IMM  => self.emit_sanitized_and(OperandSize::S32, dst, insn.imm),
                ebpf::AND32_REG  => self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, src, dst)),
                ebpf::LSH32_IMM  => self.emit_ins(RISCVInstruction::slli(OperandSize::S32, dst, insn.imm, dst)),
                ebpf::LSH32_REG  => self.emit_ins(RISCVInstruction::sll(OperandSize::S32, dst, src, dst)),
                ebpf::RSH32_IMM  => self.emit_ins(RISCVInstruction::srli(OperandSize::S32, dst, insn.imm, dst)),
                ebpf::RSH32_REG  => self.emit_ins(RISCVInstruction::srl(OperandSize::S32, dst, src, dst)),
                ebpf::NEG32     if self.executable.get_sbpf_version().enable_neg() => self.emit_ins(RISCVInstruction::sub(OperandSize::S32, ZERO, dst, dst)),
                ebpf::XOR32_IMM  => self.emit_sanitized_xor(OperandSize::S32, dst, insn.imm),
                ebpf::XOR32_REG  => self.emit_ins(RISCVInstruction::xor(OperandSize::S32, dst, src, dst)),
                ebpf::MOV32_IMM  => {
                    if self.should_sanitize_constant(insn.imm) {//检查立即数是否需要进行安全处理，防止可能的安全漏洞 
                        self.emit_sanitized_load_immediate(OperandSize::S32, dst, insn.imm);
                    } else {println!("here10");
                        self.load_immediate(OperandSize::S32, dst, insn.imm);
                    }
                }
                ebpf::MOV32_REG  => {println!("here8");self.emit_ins(RISCVInstruction::mov(OperandSize::S32, src, dst));println!("here9");}//将一个寄存器中的值移动到另一个寄存器
                ebpf::ARSH32_IMM => self.emit_ins(RISCVInstruction::srai(OperandSize::S32, dst, insn.imm, dst)),
                ebpf::ARSH32_REG => self.emit_ins(RISCVInstruction::sra(OperandSize::S32, dst, src, dst)),
                //TODO ebpf::LE
                //TODO ebpf::BE

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
                // TODO ebpf::MUL64_IMM | ebpf::DIV64_IMM | ebpf::MOD64_IMM

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
                //TODO ebpf::HOR64_IMM


                ebpf::EXIT      =>{println!("here6");
                    let call_depth_access=self.slot_in_vm(RuntimeEnvironmentSlot::CallDepth) as i64;
                    self.emit_ins(RISCVInstruction::load(OperandSize::S64, REGISTER_PTR_TO_VM, call_depth_access, REGISTER_MAP[FRAME_PTR_REG]));
                
                    // If CallDepth == 0, we've reached the exit instruction of the entry point
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S32, REGISTER_MAP[FRAME_PTR_REG], ZERO, self.relative_to_anchor(ANCHOR_EXIT, 4)));
                    // if self.config.enable_instruction_meter {
                    //     self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
                    // }
                    // we're done

                    // else decrement and update CallDepth
                    self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], -1, REGISTER_MAP[FRAME_PTR_REG]));
                    self.emit_ins(RISCVInstruction::store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_MAP[FRAME_PTR_REG], call_depth_access));
                
                    if !self.executable.get_sbpf_version().dynamic_stack_frames() {
                        let stack_pointer_access=self.slot_in_vm(RuntimeEnvironmentSlot::StackPointer) as i64;
                        let stack_frame_size = self.config.stack_frame_size as i64 * if self.config.enable_stack_frame_gaps { 2 } else { 1 };
                        self.load_immediate(OperandSize::S64, T1, stack_frame_size);
                        self.emit_ins(RISCVInstruction::load(OperandSize::S64, REGISTER_PTR_TO_VM, stack_pointer_access, REGISTER_PTR_TO_VM));
                        self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_PTR_TO_VM, T1, REGISTER_PTR_TO_VM));
                    }
                    
                    // and return
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
        // self.emit_set_exception_kind(EbpfError::ExecutionOverrun);//输出了三句x86指令
        // self.emit_ins(X86Instruction::jump_immediate(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 5)));
        // self.resolve_jumps();//处理跳转和生成最终结果
        self.result.seal(self.offset_in_text_section)?;
        Ok(self.result)
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
            self.emit_ins(RISCVInstruction::add(size, T4, destination, destination));
        } else {
            self.load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::add(size, T4, destination, destination));
        }
    }

    #[inline]
    pub fn emit_sanitized_sub(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::sub(size, destination, T4, destination));
        } else {
            self.load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::sub(size, destination, T4, destination));
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
            self.load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::or(size, destination, T4, destination));
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
            self.load_immediate(size, T4, immediate);
            self.emit_ins(RISCVInstruction::xor(size, destination, T4, destination));
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
            self.load_immediate(size, T5, immediate);
            self.emit_ins(RISCVInstruction::and(size, destination, T5, destination));
        }
    }   

    #[inline]
    fn emit_validate_instruction_count(&mut self, exclusive: bool, pc: Option<usize>) {
        if !self.config.enable_instruction_meter {
            return;
        }
    }

    fn emit_subroutines(&mut self){
        // Epilogue
        self.set_anchor(ANCHOR_EPILOGUE);
        // Restore stack pointer in case we did not exit gracefully
        self.emit_ins(RISCVInstruction::load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::HostStackPointer) as i64, SP));
        self.emit_ins(RISCVInstruction::return_near());
        
        // Quit gracefully
        self.set_anchor(ANCHOR_EXIT);
        // self.emit_validate_instruction_count(false, None);
        self.emit_ins(RISCVInstruction::load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64, REGISTER_OTHER_SCRATCH));
        self.emit_ins(RISCVInstruction::store(OperandSize::S64, REGISTER_MAP[0], REGISTER_OTHER_SCRATCH, std::mem::size_of::<u64>() as i64));
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_MAP[0], 0, REGISTER_MAP[0]));
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EPILOGUE, 4), ZERO));
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

}
