mod aligned_memory;
mod asm_parser;
mod assembler;
mod disassembler;
mod ebpf;
mod elf;
mod elf_parser;
mod elf_parser_glue;
mod error;
mod interpreter;
mod jit;
mod memory_management;
mod memory_region;
mod program;
mod riscv;
mod static_analysis;
mod syscalls;
mod test_utils;
mod verifier;
mod vm;
extern crate byteorder;
extern crate libc;
use crate::{
    assembler::assemble,
    elf::Executable,
    error::{EbpfError, ProgramResult},
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::Analysis,
    verifier::RequisiteVerifier,
    vm::{Config, ContextObject, TestContextObject},
};
use std::{fs::File, io::Read, sync::Arc};

const INSTRUCTION_METER_BUDGET: u64 = 1024;

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
        let expected_result = format!("{:?}", $expected_result);
        if !expected_result.contains("ExceededMaxInstructions") {
            context_object.remaining = INSTRUCTION_METER_BUDGET;
        }
        $executable.verify::<RequisiteVerifier>().unwrap();
        let (instruction_count_interpreter, interpreter_final_pc, _tracer_interpreter) = {
            let mut mem = $mem;
            let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
            let mut context_object = context_object.clone();
            create_vm!(
                vm,
                &$executable,
                &mut context_object,
                stack,
                heap,
                vec![mem_region],
                None
            );
            let (instruction_count_interpreter, result) = vm.execute_program(&$executable, true);
            println!(
                "instruction_count_interpreter output:{:?}",
                instruction_count_interpreter
            );
            println!("interpreter output:{:?}", result);
            println!("expected_result:{:?}", expected_result);
            assert_eq!(
                format!("{:?}", result),
                expected_result,
                "Unexpected result for Interpreter"
            );
            (
                instruction_count_interpreter,
                vm.registers[11],
                vm.context_object_pointer.clone(),
            )
        };

        #[allow(unused_mut)]
        let compilation_result = $executable.jit_compile();
        println!("{:?}", compilation_result);
        let mut mem = $mem;
        let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
        create_vm!(
            vm,
            &$executable,
            &mut context_object,
            stack,
            heap,
            vec![mem_region],
            None
        );
        match compilation_result {
            Err(err) => assert_eq!(
                format!("{:?}", err),
                expected_result,
                "Unexpected result for JIT compilation"
            ),
            Ok(()) => {
                let (instruction_count_jit, result) = vm.execute_program(&$executable, false);
                println!("instruction_count_jit output:{:?}", instruction_count_jit);
                println!("jit output:{:?}", result);
                println!("expected_result:{:?}", expected_result);
                let tracer_jit = &vm.context_object_pointer;
                // println!("{:?}",&tracer_jit as *const _);
                if !TestContextObject::compare_trace_log(&_tracer_interpreter, tracer_jit) {
                    let analysis = Analysis::from_executable(&$executable).unwrap();
                    let stdout = std::io::stdout();
                    analysis
                        .disassemble_trace_log(&mut stdout.lock(), &_tracer_interpreter.trace_log)
                        .unwrap();
                    analysis
                        .disassemble_trace_log(&mut stdout.lock(), &tracer_jit.trace_log)
                        .unwrap();
                    panic!();
                }
                println!("now");
                assert_eq!(
                    format!("{:?}", result),
                    expected_result,
                    "Unexpected result for JIT"
                );

                assert_eq!(
                    instruction_count_interpreter, instruction_count_jit,
                    "Interpreter and JIT instruction meter diverged",
                );
                println!("hello1");
                assert_eq!(
                    interpreter_final_pc, vm.registers[11],
                    "Interpreter and JIT instruction final PC diverged",
                );
                println!("hello2");
            }
        }
        // if $executable.get_config().enable_instruction_meter {
        //     assert_eq!(
        //         instruction_count_interpreter, expected_instruction_count,
        //         "Instruction meter did not consume expected amount"
        //     );
        // }
    };
}

macro_rules! test_interpreter_and_jit_asm {
    ($source:tt, $config:expr, $mem:tt, ($($location:expr => $syscall_function:expr),* $(,)?), $context_object:expr, $expected_result:expr $(,)?) => {
        #[allow(unused_mut)]
        {
            let mut config = $config;
            config.enable_instruction_tracing = false;//改成了 false
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
//#[test]
fn test_mov() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r1, 1
        mov32 r0, r1
        exit",
        [],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0x1),
    );
}

//#[test]
fn test_mov32_imm_large() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, -1
        exit",
        [],
        (),
        TestContextObject::new(2),
        ProgramResult::Ok(0xffffffff),
    );
}

//#[test]
fn test_mov_large() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r1, -1
        mov32 r0, r1
        exit",
        [],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0xffffffff),
    );
}

//#[test]
fn test_bounce() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 1
        mov r6, r0
        mov r7, r6
        mov r8, r7
        mov r9, r8
        mov r0, r9
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

//#[test]
fn test_add32() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 2
        add32 r0, 1
        add32 r0, r1
        exit",
        [],
        (),
        TestContextObject::new(5),
        ProgramResult::Ok(0x3),
    );
}

// #[test]
fn test_alu32_arithmetic() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 1
        mov32 r2, 2
        mov32 r3, 3
        mov32 r4, 4
        mov32 r5, 5
        mov32 r6, 6
        mov32 r7, 7
        mov32 r8, 8
        mov32 r9, 9
        sub32 r0, 13
        sub32 r0, r1
        add32 r0, 23
        add32 r0, r7
        lmul32 r0, 7
        lmul32 r0, r3
        udiv32 r0, 2
        udiv32 r0, r4
        exit",
        [],
        (),
        TestContextObject::new(19),
        ProgramResult::Ok(110),
    );
}

// #[test]
fn test_alu64_arithmetic() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        mov r6, 6
        mov r7, 7
        mov r8, 8
        mov r9, 9
        sub r0, 13
        sub r0, r1
        add r0, 23
        add r0, r7
        lmul r0, 7
        lmul r0, r3
        udiv r0, 2
        udiv r0, r4
        exit",
        [],
        (),
        TestContextObject::new(19),
        ProgramResult::Ok(110),
    );
}

// #[test]
fn test_lmul128() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        mov r2, 30
        mov r3, 0
        mov r4, 20
        mov r5, 0
        lmul64 r3, r4
        lmul64 r5, r2
        add64 r5, r3
        mov64 r0, r2
        rsh64 r0, 0x20
        mov64 r3, r4
        rsh64 r3, 0x20
        mov64 r6, r3
        lmul64 r6, r0
        add64 r5, r6
        lsh64 r4, 0x20
        rsh64 r4, 0x20
        mov64 r6, r4
        lmul64 r6, r0
        lsh64 r2, 0x20
        rsh64 r2, 0x20
        lmul64 r4, r2
        mov64 r0, r4
        rsh64 r0, 0x20
        add64 r0, r6
        mov64 r6, r0
        rsh64 r6, 0x20
        add64 r5, r6
        lmul64 r3, r2
        lsh64 r0, 0x20
        rsh64 r0, 0x20
        add64 r0, r3
        mov64 r2, r0
        rsh64 r2, 0x20
        add64 r5, r2
        stxdw [r1+0x8], r5
        lsh64 r0, 0x20
        lsh64 r4, 0x20
        rsh64 r4, 0x20
        or64 r0, r4
        stxdw [r1+0x0], r0
        exit",
        [0; 16],
        (),
        TestContextObject::new(42),
        ProgramResult::Ok(600),
    );
}

//#[test]
fn test_alu32_logic() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 1
        mov32 r2, 2
        mov32 r3, 3
        mov32 r4, 4
        mov32 r5, 5
        mov32 r6, 6
        mov32 r7, 7
        mov32 r8, 8
        or32 r0, r5
        or32 r0, 0xa0
        and32 r0, 0xa3
        mov32 r9, 0x91
        and32 r0, r9
        lsh32 r0, 22
        lsh32 r0, r8
        rsh32 r0, 19
        rsh32 r0, r7
        xor32 r0, 0x03
        xor32 r0, r2
        exit",
        [],
        (),
        TestContextObject::new(21),
        ProgramResult::Ok(0x11),
    );
}

// #[test]
fn test_alu64_logic() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        mov r6, 6
        mov r7, 7
        mov r8, 8
        or r0, r5
        or r0, 0xa0
        and r0, 0xa3
        mov r9, 0x91
        and r0, r9
        lsh r0, 32
        lsh r0, 22
        lsh r0, r8
        rsh r0, 32
        rsh r0, 19
        rsh r0, r7
        xor r0, 0x03
        xor r0, r2
        exit",
        [],
        (),
        TestContextObject::new(23),
        ProgramResult::Ok(0x11),
    );
}

// #[test]
fn test_arsh32_high_shift() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 8
        mov32 r1, 0x00000001
        hor64 r1, 0x00000001
        arsh32 r0, r1
        exit",
        [],
        (),
        TestContextObject::new(5),
        ProgramResult::Ok(0x4),
    );
}

// #[test]
fn test_arsh32_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0xf8
        lsh32 r0, 28
        arsh32 r0, 16
        exit",
        [],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0xffff8000),
    );
}

// #[test]
fn test_arsh32_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0xf8
        mov32 r1, 16
        lsh32 r0, 28
        arsh32 r0, r1
        exit",
        [],
        (),
        TestContextObject::new(5),
        ProgramResult::Ok(0xffff8000),
    );
}

// #[test]
fn test_arsh64() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 1
        lsh r0, 63
        arsh r0, 55
        mov32 r1, 5
        arsh r0, r1
        exit",
        [],
        (),
        TestContextObject::new(6),
        ProgramResult::Ok(0xfffffffffffffff8),
    );
}

// #[test]
fn test_lsh64_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x1
        mov r7, 4
        lsh r0, r7
        exit",
        [],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0x10),
    );
}

// #[test]
fn test_rhs32_imm() {
    test_interpreter_and_jit_asm!(
        "
        xor r0, r0
        add r0, -1
        rsh32 r0, 8
        exit",
        [],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0x00ffffff),
    );
}

// #[test]
fn test_rsh64_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0x10
        mov r7, 4
        rsh r0, r7
        exit",
        [],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
// fn test_be16() {
//     test_interpreter_and_jit_asm!(
//         "
//         ldxh r0, [r1]
//         be16 r0
//         exit",
//         [0x11, 0x22],
//         (),
//         TestContextObject::new(3),
//         ProgramResult::Ok(0x1122),
//     );
// }

// #[test]
// fn test_be16_high() {
//     test_interpreter_and_jit_asm!(
//         "
//         ldxdw r0, [r1]
//         be16 r0
//         exit",
//         [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
//         (),
//         TestContextObject::new(3),
//         ProgramResult::Ok(0x1122),
//     );
// }

// #[test]
// fn test_be32() {
//     test_interpreter_and_jit_asm!(
//         "
//         ldxw r0, [r1]
//         be32 r0
//         exit",
//         [0x11, 0x22, 0x33, 0x44],
//         (),
//         TestContextObject::new(3),
//         ProgramResult::Ok(0x11223344),
//     );
// }

// #[test]
// fn test_be32_high() {
//     test_interpreter_and_jit_asm!(
//         "
//         ldxdw r0, [r1]
//         be32 r0
//         exit",
//         [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
//         (),
//         TestContextObject::new(3),
//         ProgramResult::Ok(0x11223344),
//     );
// }

// #[test]
// fn test_be64() {
//     test_interpreter_and_jit_asm!(
//         "
//         ldxdw r0, [r1]
//         be64 r0
//         exit",
//         [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
//         (),
//         TestContextObject::new(3),
//         ProgramResult::Ok(0x1122334455667788),
//     );
// }

fn test_err_divide_by_zero() {
    let mut prog = [0; 24];
    prog[0] = ebpf::MOV32_IMM;
    prog[16] = ebpf::EXIT;
    let loader = Arc::new(BuiltinProgram::new_mock());
    for opc in [
        ebpf::UDIV32_REG,
        ebpf::UDIV64_REG,
        ebpf::UREM32_REG,
        ebpf::UREM64_REG,
        ebpf::SDIV32_REG,
        ebpf::SDIV64_REG,
        ebpf::SREM32_REG,
        ebpf::SREM64_REG,
    ] {
        prog[8] = opc;
        #[allow(unused_mut)]
        let mut executable = Executable::<TestContextObject>::from_text_bytes(
            &prog,
            loader.clone(),
            SBPFVersion::V2,
            FunctionRegistry::default(),
        )
        .unwrap();
        test_interpreter_and_jit!(
            executable,
            [],
            TestContextObject::new(2),
            ProgramResult::Err(EbpfError::DivideByZero),
        );
    }
}

// BPF_LD : Loads

// #[test]
fn test_hor64() {
    test_interpreter_and_jit_asm!(
        "
        hor64 r0, 0x10203040
        hor64 r0, 0x01020304
        exit",
        [],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0x1122334400000000),
    );
}

// #[test]
fn test_ldxb() {
    test_interpreter_and_jit_asm!(
        "
        ldxb r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0x11, 0xcc, 0xdd],
        (),
        TestContextObject::new(2),
        ProgramResult::Ok(0x11),
    );
}

// #[test]
fn test_ldxh() {
    test_interpreter_and_jit_asm!(
        "
        ldxh r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd],
        (),
        TestContextObject::new(2),
        ProgramResult::Ok(0x2211),
    );
}

// #[test]
fn test_ldxw() {
    test_interpreter_and_jit_asm!(
        "
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(2),
        ProgramResult::Ok(0x44332211),
    );
}

// #[test]
fn test_ldxh_same_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        sth [r0], 0x1234
        ldxh r0, [r0]
        exit",
        [0xff, 0xff],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0x1234),
    );
}

// #[test]
fn test_lldxdw() {
    test_interpreter_and_jit_asm!(
        "
        ldxdw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, //
            0x77, 0x88, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(2),
        ProgramResult::Ok(0x8877665544332211),
    );
}

// #[test]
fn test_ldxb_all() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        ldxb r9, [r0+0]
        lsh r9, 0
        ldxb r8, [r0+1]
        lsh r8, 4
        ldxb r7, [r0+2]
        lsh r7, 8
        ldxb r6, [r0+3]
        lsh r6, 12
        ldxb r5, [r0+4]
        lsh r5, 16
        ldxb r4, [r0+5]
        lsh r4, 20
        ldxb r3, [r0+6]
        lsh r3, 24
        ldxb r2, [r0+7]
        lsh r2, 28
        ldxb r1, [r0+8]
        lsh r1, 32
        ldxb r0, [r0+9]
        lsh r0, 36
        or r0, r1
        or r0, r2
        or r0, r3
        or r0, r4
        or r0, r5
        or r0, r6
        or r0, r7
        or r0, r8
        or r0, r9
        exit",
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
            0x08, 0x09, //
        ],
        (),
        TestContextObject::new(31),
        ProgramResult::Ok(0x9876543210),
    );
}

// #[test]
fn test_stb() {
    test_interpreter_and_jit_asm!(
        "
        stb [r1+2], 0x11
        ldxb r0, [r1+2]
        exit",
        [0xaa, 0xbb, 0xff, 0xcc, 0xdd],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0x11),
    );
}

// #[test]
fn test_sth() {
    test_interpreter_and_jit_asm!(
        "
        sth [r1+2], 0x2211
        ldxh r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0x2211),
    );
}

// #[test]
fn test_stw() {
    test_interpreter_and_jit_asm!(
        "
        stw [r1+2], 0x44332211
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0x44332211),
    );
}

// #[test]
fn test_stdw() {
    test_interpreter_and_jit_asm!(
        "
        stdw [r1+2], 0x44332211
        ldxdw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0x44332211),
    );
}

// #[test]
fn test_stxb() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r2, 0x11
        stxb [r1+2], r2
        ldxb r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0x11),
    );
}

// #[test]
fn test_stxh() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r2, 0x2211
        stxh [r1+2], r2
        ldxh r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0x2211),
    );
}

// #[test]
fn test_stxw() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r2, 0x44332211
        stxw [r1+2], r2
        ldxw r0, [r1+2]
        exit",
        [
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd, //
        ],
        (),
        TestContextObject::new(4),
        ProgramResult::Ok(0x44332211),
    );
}

// #[test]
fn test_stxb_chain() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, r1
        ldxb r9, [r0+0]
        stxb [r0+1], r9
        ldxb r8, [r0+1]
        stxb [r0+2], r8
        ldxb r7, [r0+2]
        stxb [r0+3], r7
        ldxb r6, [r0+3]
        stxb [r0+4], r6
        ldxb r5, [r0+4]
        stxb [r0+5], r5
        ldxb r4, [r0+5]
        stxb [r0+6], r4
        ldxb r3, [r0+6]
        stxb [r0+7], r3
        ldxb r2, [r0+7]
        stxb [r0+8], r2
        ldxb r1, [r0+8]
        stxb [r0+9], r1
        ldxb r0, [r0+9]
        exit",
        [
            0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, //
        ],
        (),
        TestContextObject::new(21),
        ProgramResult::Ok(0x2a),
    );
}

fn test_exit_without_value() {
    test_interpreter_and_jit_asm!(
        "
        exit",
        [],
        (),
        TestContextObject::new(1),
        ProgramResult::Ok(0x0),
    );
}

// #[test]
fn test_exit() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        exit",
        [],
        (),
        TestContextObject::new(2),
        ProgramResult::Ok(0x0),
    );
}

// #[test]
fn test_early_exit() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 3
        exit
        mov r0, 4
        exit",
        [],
        (),
        TestContextObject::new(2),
        ProgramResult::Ok(0x3),
    );
}

fn test_ja() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 1
        ja +1
        mov r0, 2
        exit",
        [],
        (),
        TestContextObject::new(3),
        ProgramResult::Ok(0x1),
    );
}

fn test_jeq_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        jeq r1, 0xb, +4
        mov32 r0, 1
        mov32 r1, 0xb
        jeq r1, 0xb, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jeq_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        mov32 r2, 0xb
        jeq r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0xb
        jeq r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(8),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jge_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        jge r1, 0xb, +4
        mov32 r0, 1
        mov32 r1, 0xc
        jge r1, 0xb, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jge_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xa
        mov32 r2, 0xb
        jge r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0xb
        jge r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(8),
        ProgramResult::Ok(0x1),
    );
}

fn test_jle_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 5
        jle r1, 4, +1
        jle r1, 6, +1
        exit
        jle r1, 5, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jle_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 5
        mov r2, 4
        mov r3, 6
        jle r1, r2, +2
        jle r1, r1, +1
        exit
        jle r1, r3, +1
        exit
        mov r0, 1
        exit",
        [],
        (),
        TestContextObject::new(9),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jgt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 5
        jgt r1, 6, +2
        jgt r1, 5, +1
        jgt r1, 4, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jgt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 5
        mov r2, 6
        mov r3, 4
        jgt r1, r2, +2
        jgt r1, r1, +1
        jgt r1, r3, +1
        exit
        mov r0, 1
        exit",
        [],
        (),
        TestContextObject::new(9),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jlt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 5
        jlt r1, 4, +2
        jlt r1, 5, +1
        jlt r1, 6, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jlt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov r0, 0
        mov r1, 5
        mov r2, 4
        mov r3, 6
        jlt r1, r2, +2
        jlt r1, r1, +1
        jlt r1, r3, +1
        exit
        mov r0, 1
        exit",
        [],
        (),
        TestContextObject::new(9),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jne_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xb
        jne r1, 0xb, +4
        mov32 r0, 1
        mov32 r1, 0xa
        jne r1, 0xb, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jne_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0xb
        mov32 r2, 0xb
        jne r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0xa
        jne r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(8),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jset_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0x7
        jset r1, 0x8, +4
        mov32 r0, 1
        mov32 r1, 0x9
        jset r1, 0x8, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jset_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov32 r1, 0x7
        mov32 r2, 0x8
        jset r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0x9
        jset r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(8),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jsge_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jsge r1, -1, +5
        jsge r1, 0, +4
        mov32 r0, 1
        mov r1, -1
        jsge r1, -1, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(8),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jsge_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        mov r2, -1
        mov32 r3, 0
        jsge r1, r2, +5
        jsge r1, r3, +4
        mov32 r0, 1
        mov r1, r2
        jsge r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(10),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jsle_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jsle r1, -3, +1
        jsle r1, -1, +1
        exit
        mov32 r0, 1
        jsle r1, -2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jsle_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -1
        mov r2, -2
        mov32 r3, 0
        jsle r1, r2, +1
        jsle r1, r3, +1
        exit
        mov32 r0, 1
        mov r1, r2
        jsle r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(10),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jsgt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jsgt r1, -1, +4
        mov32 r0, 1
        mov32 r1, 0
        jsgt r1, -1, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jsgt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        mov r2, -1
        jsgt r1, r2, +4
        mov32 r0, 1
        mov32 r1, 0
        jsgt r1, r2, +1
        mov32 r0, 2
        exit",
        [],
        (),
        TestContextObject::new(8),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jslt_imm() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        jslt r1, -3, +2
        jslt r1, -2, +1
        jslt r1, -1, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        TestContextObject::new(7),
        ProgramResult::Ok(0x1),
    );
}

// #[test]
fn test_jslt_reg() {
    test_interpreter_and_jit_asm!(
        "
        mov32 r0, 0
        mov r1, -2
        mov r2, -3
        mov r3, -1
        jslt r1, r1, +2
        jslt r1, r2, +1
        jslt r1, r3, +1
        exit
        mov32 r0, 1
        exit",
        [],
        (),
        TestContextObject::new(9),
        ProgramResult::Ok(0x1),
    );
}

fn test_syscall_parameter_on_stack() {
    test_interpreter_and_jit_asm!(
        "
        mov64 r1, r10
        add64 r1, -0x100
        mov64 r2, 0x1
        syscall bpf_syscall_string
        mov64 r0, 0x0
        exit",
        [],
        (
            "bpf_syscall_string" => syscalls::SyscallString::vm,
        ),
        TestContextObject::new(6),
        ProgramResult::Ok(0),
    );
}

fn main() {
    // test_mov();
    // test_mov32_imm_large();
    // test_mov_large();
    // test_bounce();
    // test_add32();
    // test_alu32_arithmetic();
    // test_alu64_arithmetic();
    // test_lmul128();
    // test_alu32_logic();
    // test_alu64_logic();
    // test_arsh32_high_shift();
    // test_arsh32_imm();
    // test_arsh32_reg();
    // test_arsh64();
    // test_lsh64_reg();
    // test_rhs32_imm();
    // test_rsh64_reg();
    // test_hor64();
    // test_ldxb();
    // test_ldxh();
    // test_ldxw();
    // test_ldxh_same_reg();
    // test_lldxdw();
    // test_ldxb_all();
    // test_stb();
    // test_sth();
    // test_stw();
    // test_stdw();
    // test_stxb();
    // test_stxh();
    // test_stxw();
    // test_stxb_chain();
    // test_exit_without_value();
    // test_exit();
    // test_early_exit();
    // test_ja();
    // test_jeq_imm();
    // test_jeq_reg();
    // test_jge_imm();
    // test_jge_reg();
    // test_jle_imm();
    // test_jle_reg();
    // test_jgt_imm();
    // test_jgt_reg();
    // test_jlt_imm();
    // test_jlt_reg();
    // test_jne_imm();
    // test_jne_reg();
    // test_jset_imm();
    // test_jset_reg();
    // test_jsge_imm();
    // test_jsge_reg();
    // test_jsle_imm();
    // test_jsle_reg();
    // test_jsgt_imm();
    // test_jsgt_reg();
    // test_jslt_imm();
    // test_jslt_reg();
}
