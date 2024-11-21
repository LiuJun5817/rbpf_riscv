mod jit;
mod riscv;
use crate::{jit::*, riscv::*};

fn main() {
    //emit_ins(RISCVInstruction::addi(OperandSize::S64, 5, 100, 6));
    // load_immediate(OperandSize::S64, 8, 0x12345ffff);
    // if should_sanitize_constant(0x33345) {
    //     //检查立即数是否需要进行安全处理，防止可能的安全漏洞   怎么处理的
    //     println!("here");
    //     emit_sanitized_load_immediate(OperandSize::S32, 8, 0x33345);
    // } else {
    //     load_immediate(OperandSize::S32, 8, 0x33345);
    // }
    // load_immediate(OperandSize::S32, 8, 0x33345);
    // emit_sanitized_load_immediate(OperandSize::S64, S0, 0x12345ffff);

    // emit_ins(RISCVInstruction::noop());
    load_immediate(OperandSize::S32, S0, -8);
    load_immediate(OperandSize::S32, S1, 3);
    // emit_ins(RISCVInstruction::sub(OperandSize::S32, S0, S1, S2));
    // emit_ins(RISCVInstruction::sll(OperandSize::S32, S0, S1, S3));
    // emit_ins(RISCVInstruction::srl(OperandSize::S32, S0, S1, S4));
    emit_ins(RISCVInstruction::sra(OperandSize::S32, S0, S1, S5));
    emit_ins(RISCVInstruction::srai(OperandSize::S32, S0, 3, S6));
    emit_ins(RISCVInstruction::ori(OperandSize::S32, S0, 0x111, S7));
    emit_ins(RISCVInstruction::xor(OperandSize::S32, S0, S1, S8));
    emit_ins(RISCVInstruction::xori(OperandSize::S32, S0, 0x111, S9));
    emit_ins(RISCVInstruction::and(OperandSize::S32, S0, S1, S10));
    emit_ins(RISCVInstruction::andi(OperandSize::S32, S0, 0x1111, S11));
}
