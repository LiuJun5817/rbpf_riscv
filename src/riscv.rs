use std::fs::File;
use std::io::Write;

//nop mov add这三条指令在riscv里对应的样子

macro_rules! exclude_operand_sizes {
    ($size:expr, $($to_exclude:path)|+ $(,)?) => {
        debug_assert!(match $size {
            $($to_exclude)|+ => false,
            _ => true,
        });
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OperandSize {
    S0 = 0,   // 无操作数
    S8 = 8,   // 8位
    S16 = 16, // 16位
    S32 = 32, // 32位
    S64 = 64, // 64位
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

    /// No operation (NOP) for RISC-V
    #[inline]
    pub const fn noop() -> Self {
        Self {
            opcode: 0x13,           // 操作码为 0x13 对应于 ADDI 指令
            rd: Some(0),            // 操作数 1 (x0)
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

    ///Add imm and rs1 to destination (ADD rd, rs1, imm)
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

    ///logical left shift (SLLI rd, rs1, imm)
    #[inline]
    pub const fn slli(size: OperandSize, source1: u8, immediate: i64, destination: u8) -> Self {
        exclude_operand_sizes!(size, OperandSize::S0 | OperandSize::S8 | OperandSize::S16);
        Self {
            inst_type: RISCVInstructionType::I,
            opcode: 0x13,
            rd: Some(destination),
            funct3: Some(1),
            rs1: Some(source1),
            rs2: None,
            funct7: Some(0),
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

    pub fn emit(&self) -> u32 {
        match self.inst_type {
            RISCVInstructionType::I => {
                // 计算 I 型指令格式
                let imm = (self.immediate.unwrap() & 0xFFF) << 20;
                let rs1 = ((self.rs1.unwrap() & 0x1F) as i64) << 15;
                let funct3 = ((self.funct3.unwrap() & 0x07) as i64) << 12;
                let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                let opcode = (self.opcode & 0x7F) as i64;

                (imm | rs1 | funct3 | rd | opcode).try_into().unwrap()
            }
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
            RISCVInstructionType::U => {
                // U 型指令 (Upper Immediate)
                let imm = (self.immediate.unwrap() & 0xFFFFF) << 12; // 20 位高位立即数
                let rd = ((self.rd.unwrap() & 0x1F) as i64) << 7;
                let opcode = (self.opcode & 0x7F) as i64;

                (imm | rd | opcode).try_into().unwrap()
            }
            _ => {
                panic!("暂不支持的指令类型");
            }
        }
    }
}
