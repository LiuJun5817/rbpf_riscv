mod jit;
mod riscv;
use crate::{jit::*, riscv::*};

fn main() {
    //emit_ins(RISCVInstruction::addi(OperandSize::S64, 5, 100, 6));
    // load_immediate(OperandSize::S64, 8, 0x12345ffff);
    if should_sanitize_constant(0x12345) {
        //检查立即数是否需要进行安全处理，防止可能的安全漏洞   怎么处理的
        emit_sanitized_load_immediate(OperandSize::S32, 8, 0x12345);
    } else {
        load_immediate(OperandSize::S32, 8, 0x12345);
    }
}
