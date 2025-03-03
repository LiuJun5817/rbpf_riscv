use crate::jit::OperandSize;

macro_rules! exclude_operand_sizes {
    ($size:expr, $($to_exclude:path)|+ $(,)?) => {
        debug_assert!(match $size {
            $($to_exclude)|+ => false,
            _ => true,
        });
    }
}

// RISC-V 64 寄存器定义
//参数/返回值寄存器
pub const A0: u8 = 10; // A0 = x10
pub const A1: u8 = 11; // A1 = x11
pub const A2: u8 = 12;
pub const A3: u8 = 13;
pub const A4: u8 = 14;
pub const A5: u8 = 15;
pub const A6: u8 = 16;
pub const A7: u8 = 17;

//临时寄存器
pub const T0: u8 = 5;
pub const T1: u8 = 6;
pub const T2: u8 = 7;
pub const T3: u8 = 28;
pub const T4: u8 = 29;
pub const T5: u8 = 30;
pub const T6: u8 = 31;

//保存寄存器
pub const S0: u8 = 8;
pub const S1: u8 = 9;
pub const S2: u8 = 18;
pub const S3: u8 = 19;
pub const S4: u8 = 20;
pub const S5: u8 = 21;
pub const S6: u8 = 22;
pub const S7: u8 = 23;
pub const S8: u8 = 24;
pub const S9: u8 = 25;
pub const S10: u8 = 26;
pub const S11: u8 = 27;

pub const ZERO: u8 = 0; //zero 寄存器（值始终为0）
pub const RA: u8 = 1; // Return Address (Link Register)
pub const SP: u8 = 2; // 栈指针 相当于x86_64中的RSP寄存器
pub const GP: u8 = 3; //全局指针
pub const TP: u8 = 4; //线程指针


pub const ARGUMENT_REGISTERS: [u8; 6] = [A0, A1, A2, A3, A4, A5];

// why this order?
pub const CALLER_SAVED_REGISTERS: [u8; 9] = [RA, A3, A2, A1, A0, A4, A5, A6, A7]; // a0 to a7 are caller saved

pub const CALLEE_SAVED_REGISTERS: [u8; 6] = [S0, S1, S2, S3, S4, S5]; // s0 to s11 are callee saved

#[derive(Debug, Clone, Copy)]
pub enum RISCVInstructionType {
    //31 - 0
    R, //Register  寄存器到寄存器操作 funct7 rs2 rs1 funct3 rd opcode
    I, //Immediate 立即数操作、加载指令、环境调用 imm[11:0] rs1 funct3 rd opcode
    S, //Store 存储指令 imm[11:5] rs2 rs1 funct3 imm[4:0] opcode
    B, //Branch 条件跳转指令 imm[12|10:5] rs2 rs1 funct3 imm[4:1|11] opcode
    U, //Upper 大立即数加载指令 imm[31:12] rd opcode
    J, //Jump 无条件跳转指令 imm[20|10:1|11|19:12] rd opcode
}

#[derive(Debug, Clone, Copy)]
pub struct RISCVInstruction {
    inst_type: RISCVInstructionType, // 指令类型（R/I/S/B/U/J）
    opcode: u8,                      // 操作码
    rd: Option<u8>,                  // 目的寄存器 (R/I/U/J 型指令使用)
    funct3: Option<u8>,              // 功能码3（R/I/S/B 型指令使用）
    rs1: Option<u8>,                 // 第一个源寄存器
    rs2: Option<u8>,                 // 第二个源寄存器（R/S/B 型指令使用）
    funct7: Option<u8>,              // 功能码7（R 型指令使用）
    immediate: Option<i64>,          // 立即数（I/S/B/U/J 型指令使用）
    size: OperandSize,               // 操作数大小
}

impl RISCVInstruction {
    pub const DEFAULT: RISCVInstruction = RISCVInstruction {
        inst_type: RISCVInstructionType::R,
        opcode: 0,
        rd: None,
        funct3: None,
        rs1: None,
        rs2: None,
        funct7: None,
        immediate: None,
        size: OperandSize::S0,
    };

    #[inline]
    pub fn emit(&self) -> u32 {
        match self.inst_type {
            RISCVInstructionType::R => {
                // R 型指令 (Register)
                let rs1 = ((self.rs1.unwrap() & 0x1F) as i64) << 15;
                let rs2 = ((self.rs2.unwrap() & 0x1F) as i64) << 20;
                let funct3 = ((self.funct3.unwrap() & 0x07) as i64) << 12;
                let funct7 = ((self.funct7.unwrap() & 0x7F) as i64) << 25;
                let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                let opcode = (self.opcode & 0x7F) as i64;
                (funct7 | rs2 | rs1 | funct3 | rd | opcode)
                    .try_into()
                    .unwrap()
            }
            RISCVInstructionType::I => {
                // 计算 I 型指令格式
                if self.funct3.is_none() {
                    let imm = (self.immediate.unwrap() & 0xFFF) << 20;
                    let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                    let opcode = (self.opcode & 0x7F) as i64;
                    (imm | rd | opcode).try_into().unwrap()
                } else if self.funct7.is_none() {
                    let imm = (self.immediate.unwrap() & 0xFFF) << 20;
                    let rs1 = ((self.rs1.unwrap() & 0x1F) as i64) << 15;
                    let funct3 = ((self.funct3.unwrap() & 0x07) as i64) << 12;
                    let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                    let opcode = (self.opcode & 0x7F) as i64;
                    (imm | rs1 | funct3 | rd | opcode).try_into().unwrap()
                } else {
                    let imm = (self.immediate.unwrap() & 0xFFF) << 20;
                    let rs1 = ((self.rs1.unwrap() & 0x1F) as i64) << 15;
                    let funct3 = ((self.funct3.unwrap() & 0x07) as i64) << 12;
                    let funct7 = ((self.funct7.unwrap() & 0x7F) as i64) << 25;
                    let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                    let opcode = (self.opcode & 0x7F) as i64;
                    (funct7 | imm | rs1 | funct3 | rd | opcode)
                        .try_into()
                        .unwrap()
                }
            }
            RISCVInstructionType::S => {
                // 计算 S 型指令格式
                let imm_4_0 = (self.immediate.unwrap() & 0x1F) << 7; // 低 5 位
                let imm_11_5 = (self.immediate.unwrap() & 0xFE0) << 20; // 高 7 位
                let rs1 = ((self.rs1.unwrap() & 0x1F) as i64) << 15;
                let rs2 = ((self.rs2.unwrap() & 0x1F) as i64) << 20;
                let funct3 = ((self.funct3.unwrap() & 0x07) as i64) << 12;
                let opcode = (self.opcode & 0x7F) as i64;
                (imm_11_5 | rs2 | rs1 | funct3 | imm_4_0 | opcode)
                    .try_into()
                    .unwrap()
            }
            RISCVInstructionType::B => {
                // B 型指令（Branch）
                let imm_11 = (self.immediate.unwrap() & 0x800) >> 4; // 提取立即数第 12 位，移动到 bit[7]
                let imm_4_1 = (self.immediate.unwrap() & 0x1E) << 7; // 提取立即数 bit[1:4]，移动到 bit[8:11]
                let imm_10_5 = (self.immediate.unwrap() & 0x7E0) << 20; // 提取立即数 bit[5:10]，移动到 bit[25:30]
                let imm_12 = (self.immediate.unwrap() & 0x1000) << 19; // 提取立即数 bit[12]，移动到 bit[31]
                let rs1 = ((self.rs1.unwrap() & 0x1F) as i64) << 15;
                let rs2 = ((self.rs2.unwrap() & 0x1F) as i64) << 20;
                let funct3 = ((self.funct3.unwrap() & 0x07) as i64) << 12;
                let opcode = (self.opcode & 0x7F) as i64;
                (imm_12 | imm_10_5 | rs2 | rs1 | funct3 | imm_4_1 | imm_11 | opcode)
                    .try_into()
                    .unwrap()
            }
            RISCVInstructionType::U => {
                // U 型指令 (Upper Immediate)
                let imm = (self.immediate.unwrap() & 0xFFFFF) << 12; // 20 位高位立即数
                let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                let opcode = (self.opcode & 0x7F) as i64;
                (imm | rd | opcode).try_into().unwrap()
            }
            RISCVInstructionType::J => {
                // J 型指令 (Jump)
                let imm_19_12 = (self.immediate.unwrap() & 0xFF000); // 提取立即数 bit[12:19]
                let imm_11 = (self.immediate.unwrap() & 0x800) << 9; // 提取立即数 bit[11]
                let imm_10_1 = (self.immediate.unwrap() & 0x7FE) << 20; // 提取立即数 bit[1:10]
                let imm_20 = (self.immediate.unwrap() & 0x100000) << 11; // 提取立即数 bit[20]
                let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                let opcode = (self.opcode & 0x7F) as i64;
                (imm_20 | imm_10_1 | imm_11 | imm_19_12 | rd | opcode)
                    .try_into()
                    .unwrap()
            }
            _ => {
                panic!("暂不支持的指令类型");
            }
        }
    }

    /// No operation (NOP) for RISC-V
    #[inline]
    pub const fn noop() -> Self {
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13, // 操作码为 0x13 对应于 ADDI 指令
            rd: Some(0),  // 操作数 1 (x0)
            funct3: Some(0),
            rs1: Some(0),           // 操作数 2 (x0)
            immediate: Some(0),     // 立即数为 0
            size: OperandSize::S32, // 对应于 32 位操作数大小
            ..Self::DEFAULT
        }
    }

    /// Move source to destination (ADDI rd, rs1, 0)
    #[inline]
    pub const fn mov(size: OperandSize, source: u8, destination: u8) -> Self {
        // 在 RISC-V 中，MOV 操作通常使用 ADDI 指令，立即数为 0
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I, // I 型指令
            opcode: 0x13,                       // ADDI 指令的操作码
            rd: Some(destination),              // 目的寄存器
            funct3: Some(0),                    // ADDI 指令的 funct3 为 0
            rs1: Some(source),                  // 源寄存器
            immediate: Some(0),                 // 立即数为 0
            size,                               // 操作数大小
            ..Self::DEFAULT
        }
    }

    /// Load Upper Immediate (LUI rd, imm)
    #[inline]
    pub const fn lui(size: OperandSize, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::U,
            opcode: 0x37,
            rd: Some(destination),
            immediate: Some(immediate),
            size,
            ..Self::DEFAULT
        }
    }

    ///Add rs1 and rs2 to destination (ADD rd, rs1, rs2)
    #[inline]
    pub const fn add(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(0),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0),
            immediate: None,
            size,
        }
    }

    ///Addw rs1 and rs2 to destination (ADDW rd, rs1, rs2)
    #[inline]
    pub const fn addw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0),
            immediate: None,
            size,
        }
    }

    ///Add imm and rs1 to destination (ADDI rd, rs1, imm)
    #[inline]
    pub const fn addi(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13,
            rd: Some(destination),
            funct3: Some(0),
            rs1: Some(source1),
            immediate: Some(immediate),
            size,
            ..Self::DEFAULT
        }
    }

    ///sub rs1 and rs2 to destination (sub rd, rs1, rs2)  rd = rs1 - rs2
    #[inline]
    pub const fn sub(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(0),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x20),
            immediate: None,
            size,
        }
    }

    ///subw rs1 and rs2 to destination (subw rd, rs1, rs2)  rd = rs1 - rs2
    #[inline]
    pub const fn subw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x20),
            immediate: None,
            size,
        }
    }

    /// Multiply the lower 32 bits of rs1 and rs2, sign-extend the result to 64 bits, and write to rd (MULW rd, rs1, rs2)
    #[inline]
    pub const fn mulw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(
            size,
            OperandSize::S0 | OperandSize::S8 | OperandSize::S16 | OperandSize::S64
        );
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B, // Base opcode for RV64M extension instructions
            rd: Some(destination),
            funct3: Some(0), // funct3 = 0 for MULW
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1), // funct7 = 0x01 for MULW
            immediate: None,
            size,
        }
    }

    /// Multiply rs1 and rs2 to destination (MUL rd, rs1, rs2)
    #[inline]
    pub const fn mul(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(0x0), // funct3 for MUL operation
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x01), // funct7 for MUL operation
            immediate: None,
            size,
        }
    }

    /// Multiply rs1 and rs2 (unsigned) and store high 64 bits in destination (MULHU rd, rs1, rs2)
    #[inline]
    pub const fn mulhu(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for arithmetic operations
            rd: Some(destination),
            funct3: Some(0x3), // funct3 for MULHU
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1), // funct7 for MULHU (unsigned multiplication)
            immediate: None,
            size,
        }
    }

    /// Multiply rs1 (signed) and rs2 (unsigned) and store high 64 bits in destination (MULHSU rd, rs1, rs2)
    #[inline]
    pub const fn mulhsu(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for arithmetic operations
            rd: Some(destination),
            funct3: Some(0x2), // funct3 for MULHSU
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1), // funct7 for MULHSU
            immediate: None,
            size,
        }
    }

    /// Multiply rs1 and rs2, and store the high 64 bits of the result in rd (MULH rd, rs1, rs2)
    #[inline]
    pub const fn mulh(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for ALU instructions
            rd: Some(destination),
            funct3: Some(0x1), // funct3 for MULH
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1), // funct7 for MULH
            immediate: None,
            size,
        }
    }

    /// Divide unsigned rs1 by rs2 and store the result in destination (DIVUW rd, rs1, rs2)
    #[inline]
    pub const fn divuw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0x5),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1),
            immediate: None,
            size,
        }
    }

    /// Divide signed rs1 by rs2 and store the result in destination (DIVW rd, rs1, rs2)
    #[inline]
    pub const fn divw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0x4),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1),
            immediate: None,
            size,
        }
    }

    /// Divide rs1 by rs2 (unsigned) and store the result in rd (DIVU rd, rs1, rs2)
    #[inline]
    pub const fn divu(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(0x5),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1),
            immediate: None,
            size,
        }
    }

    /// Divide rs1 by rs2 (signed) and store the result in rd (DIV rd, rs1, rs2)
    #[inline]
    pub const fn div(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(0x4),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1),
            immediate: None,
            size,
        }
    }

    /// `remuw rd, rs1, rs2` computes `rd = rs1 % rs2` for unsigned integers.
    #[inline]
    pub const fn remuw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0x7),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1),
            immediate: None,
            size,
        }
    }

    /// Remainder of unsigned division rs1 by rs2 (REMU rd, rs1, rs2)
    #[inline]
    pub const fn remu(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(0x7), // funct3 value for REMU
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1), // funct7 value for REMU
            immediate: None,
            size,
        }
    }

    /// Remainder of signed division rs1 by rs2 (REM rd, rs1, rs2)
    #[inline]
    pub const fn rem(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(0x6),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1),
            immediate: None,
            size,
        }
    }

    /// Remainder of 32 bits signed division rs1 by rs2 (REMW rd, rs1, rs2)
    #[inline]
    pub const fn remw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0x6),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x1),
            immediate: None,
            size,
        }
    }

    /// SLL (Shift Left Logical rd, rs1, rs2) 按位逻辑左移操作
    #[inline]
    pub const fn sll(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for shift operations
            rd: Some(destination),
            funct3: Some(0x1), // funct3 for SLL (Shift Left Logical)
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x0), // funct7 for SLL
            immediate: None,
            size,
        }
    }

    /// SLLw (Shift Left Logical rd, rs1, rs2) 按位逻辑左移低32位操作
    #[inline]
    pub const fn sllw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0x1),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x0),
            immediate: None,
            size,
        }
    }

    ///logical left shift (SLLI rd, rs1, imm)
    #[inline]
    pub const fn slli(size: OperandSize, source1: u8, shift: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13,
            rd: Some(destination),
            funct3: Some(1),
            rs1: Some(source1),
            rs2: None,
            funct7: Some(0),
            immediate: Some(shift),
            size,
        }
    }

    ///logical left shift (SLLIW rd, rs1, imm)
    #[inline]
    pub const fn slliw(size: OperandSize, source1: u8, shift: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x1B,
            rd: Some(destination),
            funct3: Some(1),
            rs1: Some(source1),
            rs2: None,
            funct7: Some(0),
            immediate: Some(shift),
            size,
        }
    }

    /// SRL (Shift Right Logical rd, rs1, rs2) 按位逻辑右移操作
    #[inline]
    pub const fn srl(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for shift operations
            rd: Some(destination),
            funct3: Some(0x5), // funct3 for SRL (Shift Right Logical)
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x0), // funct7 for SRL
            immediate: None,
            size,
        }
    }

    /// SRLW (Shift Right Logical rd, rs1, rs2) 按位逻辑右移低32位操作
    #[inline]
    pub const fn srlw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0x5),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x0),
            immediate: None,
            size,
        }
    }

    ///logical right shift (SRLI rd, rs1, imm)
    #[inline]
    pub const fn srli(size: OperandSize, source1: u8, shift: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13,
            rd: Some(destination),
            funct3: Some(5),
            rs1: Some(source1),
            rs2: None,
            funct7: Some(0),
            immediate: Some(shift),
            size,
        }
    }

    ///logical right low 32 bits shift (SRLIW rd, rs1, imm)
    #[inline]
    pub const fn srliw(size: OperandSize, source1: u8, shift: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x1B,
            rd: Some(destination),
            funct3: Some(5),
            rs1: Some(source1),
            rs2: None,
            funct7: Some(0),
            immediate: Some(shift),
            size,
        }
    }

    /// SRA (Shift Right Arithmetic rd, rs1, rs2) 按位算术右移操作
    #[inline]
    pub const fn sra(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for shift operations
            rd: Some(destination),
            funct3: Some(0x5), // funct3 for SRA (Shift Right Arithmetic)
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x20), // funct7 for SRA
            immediate: None,
            size,
        }
    }

    /// SRAW (Shift Right Arithmetic rd, rs1, rs2) 按位算术右移低32位操作
    #[inline]
    pub const fn sraw(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x3B,
            rd: Some(destination),
            funct3: Some(0x5),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x20),
            immediate: None,
            size,
        }
    }

    /// SRAI (Shift Right Arithmetic Immediate rd, rs1, imm) 算术右移立即数操作
    #[inline]
    pub const fn srai(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13, // I-type opcode for immediate shift operations
            rd: Some(destination),
            funct3: Some(0x5), // funct3 for SRAI (Shift Right Arithmetic Immediate)
            rs1: Some(source1),
            rs2: None,
            funct7: Some(0x20), // funct7 for SRAI
            immediate: Some(immediate),
            size,
        }
    }

    /// SRAIW (Shift Right Arithmetic Immediate rd, rs1, imm) 算术右移低32位立即数操作
    #[inline]
    pub const fn sraiw(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x1B,
            rd: Some(destination),
            funct3: Some(0x5),
            rs1: Some(source1),
            rs2: None,
            funct7: Some(0x20),
            immediate: Some(immediate),
            size,
        }
    }

    /// OR (OR rd, rs1, rs2) 按位 or 操作
    #[inline]
    pub const fn or(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(6),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0),
            immediate: None,
            size,
        }
    }

    /// ORI (ORI rd, rs1, imm) 按位 or 立即数操作
    #[inline]
    pub const fn ori(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13, // I-type opcode for ORI
            rd: Some(destination),
            funct3: Some(0x6), // funct3 for ORI
            rs1: Some(source1),
            immediate: Some(immediate),
            size,
            ..Self::DEFAULT
        }
    }

    /// XOR (XOR rd, rs1, rs2) 按位异或操作
    #[inline]
    pub const fn xor(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for XOR
            rd: Some(destination),
            funct3: Some(0x4), // funct3 for XOR
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x0), // funct7 for XOR
            immediate: None,
            size,
        }
    }

    /// XORI (XORI rd, rs1, imm) 按位异或立即数操作
    #[inline]
    pub const fn xori(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13, // I-type opcode for XORI
            rd: Some(destination),
            funct3: Some(0x4), // funct3 for XORI
            rs1: Some(source1),
            immediate: Some(immediate),
            size,
            ..Self::DEFAULT
        }
    }

    /// AND (AND rd, rs1, rs2) 按位与操作
    #[inline]
    pub const fn and(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33, // R-type opcode for AND
            rd: Some(destination),
            funct3: Some(0x7), // funct3 for AND
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0x0), // funct7 for AND
            immediate: None,
            size,
        }
    }

    /// ANDI (ANDI rd, rs1, imm) 按位与立即数操作
    #[inline]
    pub const fn andi(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13, // I-type opcode for ANDI
            rd: Some(destination),
            funct3: Some(0x7), // funct3 for ANDI
            rs1: Some(source1),
            immediate: Some(immediate),
            size,
            ..Self::DEFAULT
        }
    }

    /// Load destination from [source + offset] 内存->寄存器
    //LB rd,rs1,imm rs1存内存地址，imm代表偏移量，将内存地址（rs1+imm）的1字节值存到rd寄存器中
    #[inline]
    pub const fn load(size: OperandSize, source1: u8, offset: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x03,
            rd: Some(destination),
            funct3: match size {
                OperandSize::S8 => Some(0),  //(Load Byte)
                OperandSize::S16 => Some(1), //(Load Halfword) 一个半字（2字节）
                OperandSize::S32 => Some(2), //(Load Word) 一个字（4字节）
                OperandSize::S64 => Some(3), //(Load DoubleWord) 两个字（8字节）
                _ => Some(2),
            },
            rs1: Some(source1),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// Store source in [destination + offset] 寄存器->内存
    // SB rs2, imm(rs1) rs1存内存地址，imm代表偏移量，将寄存器rs2中的1字节值存到内存地址（rs1+imm）中
    #[inline]
    pub const fn store(size: OperandSize, source1: u8, source2: u8, offset: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0);
        Self {
            inst_type: RISCVInstructionType::S,
            opcode: 0x23,
            funct3: match size {
                OperandSize::S8 => Some(0),  //(Store Byte)
                OperandSize::S16 => Some(1), //(Store Halfword) 一个半字（2字节）
                OperandSize::S32 => Some(2), //(Store Word) 一个字（4字节）
                OperandSize::S64 => Some(3), //(Store DoubleWord) 两个字（8字节）
                _ => Some(2),
            },
            rs1: Some(source1),
            rs2: Some(source2),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// BEQ rs1,rs2,offset if (rs1 == rs2) pc += sext(offset)
    #[inline]
    pub const fn beq(size: OperandSize, source1: u8, source2: u8, offset: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::B,
            opcode: 0x63,
            funct3: Some(0),
            rs1: Some(source1),
            rs2: Some(source2),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// BNE rs1,rs2,offset if (rs1 != rs2) pc += sext(offset)
    #[inline]
    pub const fn bne(size: OperandSize, source1: u8, source2: u8, offset: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::B,
            opcode: 0x63,
            funct3: Some(1),
            rs1: Some(source1),
            rs2: Some(source2),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// BLT rs1,rs2,offset if (rs1 < rs2) pc += sext(offset)
    #[inline]
    pub const fn blt(size: OperandSize, source1: u8, source2: u8, offset: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::B,
            opcode: 0x63,
            funct3: Some(4),
            rs1: Some(source1),
            rs2: Some(source2),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// BLTU rs1,rs2,offset if (rs1 < rs2) pc += sext(offset)
    #[inline]
    pub const fn bltu(size: OperandSize, source1: u8, source2: u8, offset: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::B,
            opcode: 0x63,
            funct3: Some(6),
            rs1: Some(source1),
            rs2: Some(source2),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// BGE rs1,rs2,offset if (rs1 >= rs2) pc += sext(offset)
    #[inline]
    pub const fn bge(size: OperandSize, source1: u8, source2: u8, offset: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::B,
            opcode: 0x63,
            funct3: Some(5),
            rs1: Some(source1),
            rs2: Some(source2),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// BGEU rs1,rs2,offset if (rs1 >= rs2) pc += sext(offset)
    #[inline]
    pub const fn bgeu(size: OperandSize, source1: u8, source2: u8, offset: i64) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::B,
            opcode: 0x63,
            funct3: Some(7),
            rs1: Some(source1),
            rs2: Some(source2),
            immediate: Some(offset),
            size,
            ..Self::DEFAULT
        }
    }

    /// Add imm and rs1 to destination (ADDIW rd, rs1, imm) 只保留低 32 位
    #[inline]
    pub const fn addiw(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        // 仅在 RV64 中支持 ADDIW 指令，因此排除非 64 位大小
        exclude_operand_sizes!(
            size,
            OperandSize::S0 | OperandSize::S8 | OperandSize::S16 | OperandSize::S32
        );
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x1B,
            rd: Some(destination),
            funct3: Some(0),
            rs1: Some(source1),
            immediate: Some(immediate),
            size,
            ..Self::DEFAULT
        }
    }

    /// Jump to the address in rs1 + imm and link to rd (typically ra)
    #[inline]
    pub const fn jalr(source1: u8, immediate: i64, destination: u8) -> Self {
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x67,
            rd: Some(destination),
            funct3: Some(0),
            rs1: Some(source1),
            immediate: Some(immediate),
            size: OperandSize::S64,
            ..Self::DEFAULT
        }
    }

    /// JAl rd,offset   Jump to the address offset and link to rd
    #[inline]
    pub const fn jal(offset: i64, destination: u8) -> Self {
        Self {
            inst_type: RISCVInstructionType::J,
            opcode: 0x6f,
            rd: Some(destination),
            immediate: Some(offset),
            size: OperandSize::S64,
            ..Self::DEFAULT
        }
    }

    ///Sltu rd, rs1, rs2 无符号比较rs1和rs2，rd = (rs1 < rs2) ? 1 : 0
    #[inline]
    pub const fn sltu(size: OperandSize, source1: u8, source2: u8, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::R,
            opcode: 0x33,
            rd: Some(destination),
            funct3: Some(3),
            rs1: Some(source1),
            rs2: Some(source2),
            funct7: Some(0),
            immediate: None,
            size,
        }
    }

    ///Sltiu rd, rs1, imm 无符号比较rs1和imm，rd = (rs1 < imm) ? 1 : 0
    #[inline]
    pub const fn sltiu(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13,
            rd: Some(destination),
            funct3: Some(3),
            rs1: Some(source1),
            immediate: Some(immediate),
            size,
            ..Self::DEFAULT
        }
    }

    /// return from the subroutine
    #[inline]
    pub const fn return_near() -> Self {
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x67,
            rd: Some(ZERO),
            funct3: Some(0),
            rs1: Some(RA),
            immediate: Some(0),
            size: OperandSize::S64,
            ..Self::DEFAULT
        }
    }
}
