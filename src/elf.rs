use crate::{
    aligned_memory::{is_memory_aligned, AlignedMemory},
    ebpf::{self, EF_SBPF_V2, HOST_ALIGN, INSN_SIZE},
    error::EbpfError,
    memory_region::MemoryRegion,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    vm::{Config, ContextObject},
};

use crate::jit::{JitCompiler, JitProgram};
use byteorder::{ByteOrder, LittleEndian};
use std::{collections::BTreeMap, fmt::Debug, mem, ops::Range, str, sync::Arc};

/// Error definitions
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ElfError {
    /// Failed to parse ELF file
    #[error("Failed to parse ELF file: {0}")]
    FailedToParse(String),
    /// Entrypoint out of bounds
    #[error("Entrypoint out of bounds")]
    EntrypointOutOfBounds,
    /// Invaid entrypoint
    #[error("Invaid entrypoint")]
    InvalidEntrypoint,
    /// Failed to get section
    #[error("Failed to get section {0}")]
    FailedToGetSection(String),
    /// Unresolved symbol
    #[error("Unresolved symbol ({0}) at instruction #{1:?} (ELF file offset {2:#x})")]
    UnresolvedSymbol(String, usize, usize),
    /// Section not found
    #[error("Section not found: {0}")]
    SectionNotFound(String),
    /// Relative jump out of bounds
    #[error("Relative jump out of bounds at instruction #{0}")]
    RelativeJumpOutOfBounds(usize),
    /// Symbol hash collision
    #[error("Symbol hash collision {0:#x}")]
    SymbolHashCollision(u32),
    /// Incompatible ELF: wrong endianess
    #[error("Incompatible ELF: wrong endianess")]
    WrongEndianess,
    /// Incompatible ELF: wrong ABI
    #[error("Incompatible ELF: wrong ABI")]
    WrongAbi,
    /// Incompatible ELF: wrong mchine
    #[error("Incompatible ELF: wrong machine")]
    WrongMachine,
    /// Incompatible ELF: wrong class
    #[error("Incompatible ELF: wrong class")]
    WrongClass,
    /// Not one text section
    #[error("Multiple or no text sections, consider removing llc option: -function-sections")]
    NotOneTextSection,
    /// Read-write data not supported
    #[error("Found writable section ({0}) in ELF, read-write data not supported")]
    WritableSectionNotSupported(String),
    /// Relocation failed, no loadable section contains virtual address
    #[error("Relocation failed, no loadable section contains virtual address {0:#x}")]
    AddressOutsideLoadableSection(u64),
    /// Relocation failed, invalid referenced virtual address
    #[error("Relocation failed, invalid referenced virtual address {0:#x}")]
    InvalidVirtualAddress(u64),
    /// Relocation failed, unknown type
    #[error("Relocation failed, unknown type {0:?}")]
    UnknownRelocation(u32),
    /// Failed to read relocation info
    #[error("Failed to read relocation info")]
    FailedToReadRelocationInfo,
    /// Incompatible ELF: wrong type
    #[error("Incompatible ELF: wrong type")]
    WrongType,
    /// Unknown symbol
    #[error("Unknown symbol with index {0}")]
    UnknownSymbol(usize),
    /// Offset or value is out of bounds
    #[error("Offset or value is out of bounds")]
    ValueOutOfBounds,
    /// Detected sbpf_version required by the executable which are not enabled
    #[error("Detected sbpf_version required by the executable which are not enabled")]
    UnsupportedSBPFVersion,
    /// Invalid program header
    #[error("Invalid ELF program header")]
    InvalidProgramHeader,
}

#[derive(Debug, PartialEq)]
struct SectionInfo {
    name: String,
    vaddr: u64,
    offset_range: Range<usize>,
}
impl SectionInfo {
    fn mem_size(&self) -> usize {
        mem::size_of::<Self>().saturating_add(self.name.capacity())
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Section {
    /// Owned section data.
    ///
    /// The first field is the offset of the section from MM_PROGRAM_START. The
    /// second field is the actual section data.
    Owned(usize, Vec<u8>),
    /// Borrowed section data.
    ///
    /// The first field is the offset of the section from MM_PROGRAM_START. The
    /// second field an be used to index the input ELF buffer to retrieve the
    /// section data.
    Borrowed(usize, Range<usize>),
}

/// Elf loader/relocator
#[derive(Debug, PartialEq)]
pub struct Executable<C: ContextObject> {
    /// Loaded and executable elf
    elf_bytes: AlignedMemory<{ HOST_ALIGN }>,
    /// Required SBPF capabilities
    sbpf_version: SBPFVersion,
    /// Read-only section
    ro_section: Section,
    /// Text section info
    text_section_info: SectionInfo,
    /// Address of the entry point
    entry_pc: usize,
    /// Call resolution map (hash, pc, name)
    function_registry: FunctionRegistry<usize>,
    /// Loader built-in program
    loader: Arc<BuiltinProgram<C>>,
    /// Compiled program and argument
    //#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "riscv64"))]
    compiled_program: Option<JitProgram>,
}

impl<C: ContextObject> Executable<C> {
    /// Get the configuration settings
    pub fn get_config(&self) -> &Config {
        self.loader.get_config()
    }

    /// Get the executable sbpf_version
    pub fn get_sbpf_version(&self) -> &SBPFVersion {
        &self.sbpf_version
    }

    /// Get the .text section virtual address and bytes
    pub fn get_text_bytes(&self) -> (u64, &[u8]) {
        let (ro_offset, ro_section) = match &self.ro_section {
            Section::Owned(offset, data) => (*offset, data.as_slice()),
            Section::Borrowed(offset, byte_range) => {
                (*offset, &self.elf_bytes.as_slice()[byte_range.clone()])
            }
        };

        let offset = self
            .text_section_info
            .vaddr
            .saturating_sub(ebpf::MM_PROGRAM_START)
            .saturating_sub(ro_offset as u64) as usize;
        (
            self.text_section_info.vaddr,
            &ro_section[offset..offset.saturating_add(self.text_section_info.offset_range.len())],
        )
    }

    pub fn jit_compile(&mut self) -> Result<(), crate::error::EbpfError> {
        let jit = JitCompiler::<C>::new(self)?;
        self.compiled_program = Some(jit.compile()?);
        Ok(())
    }
}
