#![allow(clippy::arithmetic_side_effects)]

use std::fs::{File, OpenOptions};
use std::path::Path;

use rand::{rngs::SmallRng, Rng, SeedableRng};
use std::io::Write;
use std::mem::offset_of;
use std::{fmt::Debug, mem, ptr};

use crate::{
    // ebpf::{self, FIRST_SCRATCH_REG, FRAME_PTR_REG, INSN_SIZE, SCRATCH_REGS, STACK_PTR_REG},
    // elf::Executable,
    // error::{EbpfError, ProgramResult},
    // memory_management::{
    //     allocate_pages, free_pages, get_system_page_size, protect_pages, round_to_page_size,
    // },
    // memory_region::{AccessType, MemoryMapping},
    riscv::*,
    //vm::{get_runtime_environment_key, Config, ContextObject, EbpfVm},
};

pub struct JitProgram {
    /// OS page size in bytes and the alignment of the sections
    pub page_size: usize,
    /// A `*const u8` pointer into the text_section for each BPF instruction
    pc_section: &'static mut [usize],
    /// The RISC-V machinecode
    pub text_section: &'static mut [u8],
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OperandSize {
    S0 = 0,
    S8 = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

// pub struct JitCompiler<'a, C: ContextObject> {
//     result: JitProgram,
//     text_section_jumps: Vec<Jump>,
//     anchors: [*const u8; ANCHOR_COUNT],
//     offset_in_text_section: usize,
//     executable: &'a Executable<C>,
//     program: &'a [u8],
//     program_vm_addr: u64,
//     config: &'a Config,
//     pc: usize,
//     last_instruction_meter_validation_pc: usize,
//     next_noop_insertion: u32,
//     runtime_environment_key: i32,
//     diversification_rng: SmallRng,
//     stopwatch_is_active: bool,
// }

// #[rustfmt::skip]
// impl<'a, C: ContextObject> JitCompiler<'a, C> {
//     /// Compiles the given executable, consuming the compiler
//     pub fn compile(mut self) -> Result<JitProgram, EbpfError> {
//         let text_section_base = self.result.text_section.as_ptr();
//         // Randomized padding at the start before random intervals begin 在程序在开始处插入一定数量的无操作指令（NOOP）可能有助于防止静态分析或逆向工程？
//         if self.config.noop_instruction_rate != 0 {
//             for _ in 0..self.diversification_rng.gen_range(0..MAX_START_PADDING_LENGTH) {
//                 // X86Instruction::noop().emit(self)?;
//                 self.emit::<u8>(0x90);
//             }
//         }
//     }
// }

#[inline(always)]
pub fn emit_ins(instruction: RISCVInstruction) {
    // 发射一条 RISC-V 指令
    write_binary(instruction.emit());
}

fn write_binary(instruction: u32) {
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
fn load_immediate_with_lui_and_addi(size: OperandSize, destination: u8, immediate: i64) {
    if immediate >= -2048 && immediate <= 2047 {
        // 立即数在 12 位范围内，使用 ADDI
        emit_ins(RISCVInstruction::addi(size, 0, immediate, destination));
    } else {
        // 处理立即数超过 12 位的情况
        let upper_imm = immediate >> 12; // 高 20 位
        let lower_imm = immediate & 0xFFF; // 低 12 位
        let sign_ext = if lower_imm & 0x800 != 0 { 1 } else { 0 };

        // Step 1: 加载高 20 位
        emit_ins(RISCVInstruction::lui(
            size,
            upper_imm + sign_ext, // 加上符号扩展
            destination,
        ));

        // Step 2: 使用 ADDI 添加低 12 位
        if lower_imm != 0 {
            emit_ins(RISCVInstruction::addi(
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
pub fn load_immediate(size: OperandSize, destination: u8, immediate: i64) {
    if immediate >= i32::MIN as i64 && immediate <= i32::MAX as i64 {
        // 大小在32位之间的情况
        load_immediate_with_lui_and_addi(size, destination, immediate);
    } else if size == OperandSize::S64 {
        // RV64 的情况
        let upper_imm = immediate >> 32; // 高 32 位
        let lower_imm = immediate & 0xFFFFFFFF; // 低 32 位

        // Step 1: 处理高32位
        load_immediate_with_lui_and_addi(size, destination, upper_imm);

        // Step 2: 使用 SLLI 将寄存器左移 32 位   logical left shift
        emit_ins(RISCVInstruction::slli(size, destination, 32, destination));

        // Step 3: 处理低 32 位立即数到临时寄存器并使用 OR 合并
        // 使用 T0 作为临时寄存器
        load_immediate_with_lui_and_addi(size, T0, lower_imm);

        // 使用 OR 指令合并高位和低位
        emit_ins(RISCVInstruction::or(size, destination, T0, destination));
    }
}

#[inline]
pub fn rotate_right(size: OperandSize, source1: u8, shamt: i64, destination: u8) {
    emit_ins(RISCVInstruction::mov(size, source1, T3));
    emit_ins(RISCVInstruction::mov(size, source1, T4));
    emit_ins(RISCVInstruction::slli(size, T3, shamt, T3));
    emit_ins(RISCVInstruction::srli(size, T4, shamt, T4));
    emit_ins(RISCVInstruction::or(size, T3, T4, destination));
}

#[inline]
pub fn should_sanitize_constant(value: i64) -> bool {
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
pub fn emit_sanitized_load_immediate(size: OperandSize, destination: u8, value: i64) {
    match size {
        OperandSize::S32 => {
            let key = SmallRng::from_entropy().gen::<i32>() as i64;
            load_immediate(
                size,
                destination,
                (value as i32).wrapping_sub(key as i32) as i64,
            );
            load_immediate(size, T1, key);
            emit_ins(RISCVInstruction::add(size, destination, T1, destination));
        }
        OperandSize::S64 if value >= i32::MIN as i64 && value <= i32::MAX as i64 => {
            let key = SmallRng::from_entropy().gen::<i32>() as i64;
            load_immediate(size, destination, value.wrapping_sub(key));
            load_immediate(size, T1, key);
            emit_ins(RISCVInstruction::add(size, destination, T1, destination));
        }
        OperandSize::S64 if value as u64 & u32::MAX as u64 == 0 => {
            let key = SmallRng::from_entropy().gen::<i32>() as i64;
            load_immediate(size, destination, value.rotate_right(32).wrapping_sub(key));
            load_immediate(size, T1, key);
            emit_ins(RISCVInstruction::add(size, destination, T1, destination)); // wrapping_add(key)
            emit_ins(RISCVInstruction::slli(size, destination, 32, destination));
            // shift_left(32)
        }
        OperandSize::S64 => {
            let key = SmallRng::from_entropy().gen::<i64>();
            let lower_key = key as i32 as i64;
            let upper_key = (key >> 32) as i32 as i64;
            load_immediate(
                size,
                destination,
                value
                    .wrapping_sub(lower_key)
                    .rotate_right(32)
                    .wrapping_sub(upper_key),
            );
            load_immediate(size, T1, upper_key); // wrapping_add(upper_key)
            emit_ins(RISCVInstruction::add(size, destination, T1, destination));
            rotate_right(size, destination, 32, destination);
            load_immediate(size, T2, lower_key); // wrapping_add(lower_key)
            emit_ins(RISCVInstruction::add(size, destination, T2, destination));
        }
        _ => {
            #[cfg(debug_assertions)]
            unreachable!();
        }
    }
}
