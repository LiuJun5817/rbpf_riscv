use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

mod riscv;
use crate::riscv::*;

#[inline(always)]
fn emit_ins(instruction: RISCVInstruction) {
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
fn load_immediate_with_lui_and_addi(size: OperandSize, immediate: i64, destination: u8) {
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
fn load_immediate(size: OperandSize, immediate: i64, destination: u8) {
    if size == OperandSize::S32 {
        // RV32 的情况
        load_immediate_with_lui_and_addi(size, immediate, destination);
    } else if size == OperandSize::S64 {
        if immediate >= i32::MIN as i64 && immediate <= i32::MAX as i64 {
            load_immediate_with_lui_and_addi(size, immediate, destination);
        } else {
            // RV64 的情况
            let upper_imm = immediate >> 32; // 高 32 位
            let lower_imm = immediate & 0xFFFFFFFF; // 低 32 位

            // Step 1: 处理高32位
            load_immediate_with_lui_and_addi(size, upper_imm, destination);

            // Step 2: 使用 SLLI 将寄存器左移 32 位   logical left shift
            emit_ins(RISCVInstruction::slli(size, destination, 32, destination));

            // Step 3: 处理低 32 位立即数到临时寄存器并使用 OR 合并
            let temp_register = 1; // 使用 x1 (ra) 作为临时寄存器
            load_immediate_with_lui_and_addi(size, lower_imm, temp_register);

            // 使用 OR 指令合并高位和低位
            emit_ins(RISCVInstruction::or(
                size,
                destination,
                temp_register,
                destination,
            ));
        }
    }
}

#[inline]
fn should_sanitize_constant(value: i64) -> bool {
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

fn main() {
    //emit_ins(RISCVInstruction::addi(OperandSize::S64, 5, 100, 6));
    load_immediate(OperandSize::S64, 0x2345ffff, 8);
}
