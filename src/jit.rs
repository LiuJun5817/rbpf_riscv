#![allow(clippy::arithmetic_side_effects)]

use std::fs::{File, OpenOptions};
use std::path::Path;

use rand::{rngs::SmallRng, Rng, SeedableRng};
use std::io::Write;
use std::mem::offset_of;
use std::{fmt::Debug, mem, ptr};

use crate::{
    ebpf::{self, FIRST_SCRATCH_REG, FRAME_PTR_REG, INSN_SIZE, SCRATCH_REGS},
    elf::Executable,
    error::{EbpfError, ProgramResult},
    memory_management::{
        allocate_pages, free_pages, get_system_page_size, protect_pages, round_to_page_size,
    },
    // memory_region::{AccessType, MemoryMapping},
    riscv::*,
    // vm::ContextObject,
    vm::{Config, ContextObject},
};

const MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH: usize = 4096;
const MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION: usize = 110;
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
    CALLER_SAVED_REGISTERS[0], //a0
    ARGUMENT_REGISTERS[1],     //a1
    ARGUMENT_REGISTERS[2],     //a2
    ARGUMENT_REGISTERS[3],     //a3
    ARGUMENT_REGISTERS[4],     //a4
    ARGUMENT_REGISTERS[5],     //a5
    CALLEE_SAVED_REGISTERS[0], //s0
    CALLEE_SAVED_REGISTERS[1], //s1
    CALLEE_SAVED_REGISTERS[2], //s2
    CALLEE_SAVED_REGISTERS[3], //s3
    RA,                        //ra
];

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
    /// Compiles the given executable, consuming the compiler
    pub fn compile(mut self) -> Result<JitProgram, EbpfError> {
        let text_section_base = self.result.text_section.as_ptr();
        while self.pc * ebpf::INSN_SIZE < self.program.len(){
            let mut insn = ebpf::get_insn_unchecked(self.program, self.pc);//获取当前eBPF指令
            //eg: mov r1 1
            let dst = if insn.dst == SP { u8::MAX } else { REGISTER_MAP[insn.dst as usize] };//确定目标寄存器 r1
            let src = REGISTER_MAP[insn.src as usize];//确定源寄存器或立即数 1
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;//计算目标程序计数器

            match insn.opc{
                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    self.emit_sanitized_add(OperandSize::S32, dst, insn.imm);
                },
                ebpf::ADD32_REG  => {
                    
                },
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
    self.emit_ins(RISCVInstruction::mov(size, source1, T3));
    self.emit_ins(RISCVInstruction::mov(size, source1, T4));
    self.emit_ins(RISCVInstruction::slli(size, T3, shamt, T3));
    self.emit_ins(RISCVInstruction::srli(size, T4, shamt, T4));
    self.emit_ins(RISCVInstruction::or(size, T3, T4, destination));
}

#[inline]
pub fn should_sanitize_constant(&mut self,value: i64) -> bool {
    // if !self.config.sanitize_user_provided_values {
    //     return false;
    // }

    match value as u64 {
        0xFFFF | 0xFFFFFF | 0xFFFFFFFF | 0xFFFFFFFFFF | 0xFFFFFFFFFFFF | 0xFFFFFFFFFFFFFF
        | 0xFFFFFFFFFFFFFFFF => false,
        v if v <= 0xFF => false,
        v if !v <= 0xFF => false, //没问题
        _ => true,
    }
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
            self.load_immediate(size, T2, lower_key); // wrapping_add(lower_key)
            self.emit_ins(RISCVInstruction::add(size, destination, T2, destination));
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
        self.emit_sanitized_load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::add(size, T5, destination, destination));
    } else {
        self.load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::add(size, T5, destination, destination));
    }
}

#[inline]
pub fn emit_sanitized_sub(&mut self,size: OperandSize, destination: u8, immediate: i64) {
    if self.should_sanitize_constant(immediate) {
        self.emit_sanitized_load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::sub(size, destination, T5, destination));
    } else {
        self.load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::sub(size, destination, T5, destination));
    }
}

#[inline]
pub fn emit_sanitized_or(&mut self,size: OperandSize, destination: u8, immediate: i64) {
    if self.should_sanitize_constant(immediate) {
        self.emit_sanitized_load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::or(size, destination, T5, destination));
    } else if immediate >= -2048 && immediate <= 2047 {
        // 立即数在 12 位范围内，直接使用 ORI
        self.emit_ins(RISCVInstruction::ori(
            size,
            destination,
            immediate,
            destination,
        ));
    } else {
        self.load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::or(size, destination, T5, destination));
    }
}

#[inline]
pub fn emit_sanitized_xor(&mut self,size: OperandSize, destination: u8, immediate: i64) {
    if self.should_sanitize_constant(immediate) {
        self.emit_sanitized_load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::xor(size, destination, T5, destination));
    } else if immediate >= -2048 && immediate <= 2047 {
        // 立即数在 12 位范围内，直接使用 XORI
        self.emit_ins(RISCVInstruction::xori(
            size,
            destination,
            immediate,
            destination,
        ));
    } else {
        self.load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::xor(size, destination, T5, destination));
    }
}

#[inline]
pub fn emit_sanitized_and(&mut self,size: OperandSize, destination: u8, immediate: i64) {
    if self.should_sanitize_constant(immediate) {
        self.emit_sanitized_load_immediate(size, T5, immediate);
        self.emit_ins(RISCVInstruction::and(size, destination, T5, destination));
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

}
