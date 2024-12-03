mod aligned_memory;
mod asm_parser;
mod assembler;
mod ebpf;
mod elf;
mod elf_parser;
mod elf_parser_glue;
mod error;
mod jit;
mod memory_management;
mod memory_region;
mod program;
mod riscv;
mod static_analysis;
mod verifier;
mod vm;
extern crate byteorder;
extern crate libc;
use crate::{
    assembler::assemble,
    error::{EbpfError, ProgramResult},
    program::{BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion},
    vm::{Config, ContextObject, TestContextObject},
};
use std::{fs::File, io::Read, sync::Arc};

trait ErrCheckedArithmetic: Sized {
    fn err_checked_add(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    fn err_checked_sub(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    fn err_checked_mul(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    #[allow(dead_code)]
    fn err_checked_div(self, other: Self) -> Result<Self, ArithmeticOverflow>;
}
struct ArithmeticOverflow;

macro_rules! impl_err_checked_arithmetic {
    ($($ty:ty),*) => {
        $(
            impl ErrCheckedArithmetic for $ty {
                fn err_checked_add(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_add(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_sub(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_sub(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_mul(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_mul(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_div(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_div(other).ok_or(ArithmeticOverflow)
                }
            }
        )*
    }
}
impl_err_checked_arithmetic!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);

macro_rules! test_interpreter_and_jit {
    ($executable:expr, $mem:tt, $context_object:expr, $expected_result:expr $(,)?) => {
        let expected_instruction_count = $context_object.get_remaining();
        #[allow(unused_mut)]
        let mut context_object = $context_object;
        #[allow(unused_mut)]
        let compilation_result = $executable.jit_compile();
        println!("{:?}", compilation_result);
    };
}

macro_rules! test_interpreter_and_jit_asm {
    ($source:tt, $config:expr, $mem:tt, ($($location:expr => $syscall_function:expr),* $(,)?), $context_object:expr, $expected_result:expr $(,)?) => {
        #[allow(unused_mut)]
        {
            let mut config = $config;
            config.enable_instruction_tracing = true;
            let mut function_registry = FunctionRegistry::<BuiltinFunction<TestContextObject>>::default();
            $(test_interpreter_and_jit!(register, function_registry, $location => $syscall_function);)*
            let loader = Arc::new(BuiltinProgram::new_loader(config, function_registry));
            let mut executable = assemble($source, loader).unwrap();
            println!("{:?}",executable);
            test_interpreter_and_jit!(executable, $mem, $context_object, $expected_result);
        }
    };
    ($source:tt, $mem:tt, ($($location:expr => $syscall_function:expr),* $(,)?), $context_object:expr, $expected_result:expr $(,)?) => {
        #[allow(unused_mut)]
        {
            test_interpreter_and_jit_asm!($source, Config::default(), $mem, ($($location => $syscall_function),*), $context_object, $expected_result);
        }
    };
}

fn main() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r1, 1
        mov32 r0, r1 
        exit", //这是要测试的汇编代码，表示将 1 移动到寄存器 r1，然后将 r1 的值移动到 r0，最后退出。
        [],                        //这是一个空数组，表示没有额外的内存配置
        (),                        //这是一个空元组，表示没有需要注册的系统调用。
        TestContextObject::new(3), //这里创建了一个新的 TestContextObject，用于跟踪执行状态或上下文信息，3 是传递给构造函数的参数
        ProgramResult::Ok(0x1),    //这是预期的程序执行结果，表示期望最终返回 0x1
    );
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
    // load_immediate(OperandSize::S32, S0, 100);
    // load_immediate(OperandSize::S32, S1, 3);
    // emit_ins(RISCVInstruction::sub(OperandSize::S32, S0, S1, S2));
    // emit_ins(RISCVInstruction::sll(OperandSize::S32, S0, S1, S3));
    // emit_ins(RISCVInstruction::srl(OperandSize::S32, S0, S1, S4));
    // emit_ins(RISCVInstruction::sra(OperandSize::S32, S0, S1, S5));
    // emit_ins(RISCVInstruction::srai(OperandSize::S32, S0, 3, S6));
    // emit_ins(RISCVInstruction::ori(OperandSize::S32, S0, 0x111, S7));
    // emit_ins(RISCVInstruction::xor(OperandSize::S32, S0, S1, S8));
    // emit_ins(RISCVInstruction::xori(OperandSize::S32, S0, 0x111, S9));
    // emit_ins(RISCVInstruction::and(OperandSize::S32, S0, S1, S10));
    // emit_ins(RISCVInstruction::andi(OperandSize::S32, S0, 0x1111, S11));
}
