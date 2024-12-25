use crate::{
    aligned_memory::{is_memory_aligned, AlignedMemory},
    ebpf::{self, EF_SBPF_V2, HOST_ALIGN, INSN_SIZE},
    elf_parser::{
        consts::{
            ELFCLASS64, ELFDATA2LSB, ELFOSABI_NONE, EM_BPF, EM_SBPF, ET_DYN, R_RISCV_32,
            R_RISCV_64, R_RISCV_NONE, R_RISCV_RELATIVE,
        },
        types::Elf64Word,
    },
    elf_parser_glue::{
        ElfParser, ElfProgramHeader, ElfRelocation, ElfSectionHeader, ElfSymbol, GoblinParser,
        NewParser,
    },
    error::EbpfError,
    memory_region::MemoryRegion,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::Verifier,
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

// For more information on the BPF instruction set:
// https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+

// From least significant to most significant bit:
//   8 bit opcode
//   4 bit destination register (dst)
//   4 bit source register (src)
//   16 bit offset
//   32 bit immediate (imm)

/// Byte offset of the immediate field in the instruction
const BYTE_OFFSET_IMMEDIATE: usize = 4;
/// Byte length of the immediate field
const BYTE_LENGTH_IMMEDIATE: usize = 4;

/// BPF relocation types.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
enum BpfRelocationType {
    /// No relocation, placeholder
    R_Bpf_None = 0,
    /// R_BPF_64_64 relocation type is used for ld_imm64 instruction.
    /// The actual to-be-relocated data (0 or section offset) is
    /// stored at r_offset + 4 and the read/write data bitsize is 32
    /// (4 bytes). The relocation can be resolved with the symbol
    /// value plus implicit addend.
    R_Bpf_64_64 = 1,
    /// 64 bit relocation of a ldxdw instruction.  The ldxdw
    /// instruction occupies two instruction slots. The 64-bit address
    /// to load from is split into the 32-bit imm field of each
    /// slot. The first slot's pre-relocation imm field contains the
    /// virtual address (typically same as the file offset) of the
    /// location to load. Relocation involves calculating the
    /// post-load 64-bit physical address referenced by the imm field
    /// and writing that physical address back into the imm fields of
    /// the ldxdw instruction.
    R_Bpf_64_Relative = 8,
    /// Relocation of a call instruction.  The existing imm field
    /// contains either an offset of the instruction to jump to (think
    /// local function call) or a special value of "-1".  If -1 the
    /// symbol must be looked up in the symbol table.  The relocation
    /// entry contains the symbol number to call.  In order to support
    /// both local jumps and calling external symbols a 32-bit hash is
    /// computed and stored in the the call instruction's 32-bit imm
    /// field.  The hash is used later to look up the 64-bit address
    /// to jump to.  In the case of a local jump the hash is
    /// calculated using the current program counter and in the case
    /// of a symbol the hash is calculated using the name of the
    /// symbol.
    R_Bpf_64_32 = 10,
}
impl BpfRelocationType {
    fn from_RISCV_relocation_type(from: u32) -> Option<BpfRelocationType> {
        match from {
            R_RISCV_NONE => Some(BpfRelocationType::R_Bpf_None),
            R_RISCV_64 => Some(BpfRelocationType::R_Bpf_64_64),
            R_RISCV_RELATIVE => Some(BpfRelocationType::R_Bpf_64_Relative),
            R_RISCV_32 => Some(BpfRelocationType::R_Bpf_64_32),
            _ => None,
        }
    }
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

    /// Get a memory region that can be used to access the merged readonly section
    pub fn get_ro_region(&self) -> MemoryRegion {
        get_ro_region(&self.ro_section, self.elf_bytes.as_slice())
    }

    /// Get the entry point offset into the text section
    pub fn get_entrypoint_instruction_offset(&self) -> usize {
        self.entry_pc
    }

    /// Get the loader built-in program
    pub fn get_loader(&self) -> &Arc<BuiltinProgram<C>> {
        &self.loader
    }

    /// Get the JIT compiled program
    pub fn get_compiled_program(&self) -> Option<&JitProgram> {
        self.compiled_program.as_ref()
    }

    /// Verify the executable
    pub fn verify<V: Verifier>(&self) -> Result<(), EbpfError> {
        <V as Verifier>::verify(
            self.get_text_bytes().1,
            self.get_config(),
            self.get_sbpf_version(),
            self.get_function_registry(),
        )?;
        Ok(())
    }

    pub fn jit_compile(&mut self) -> Result<(), crate::error::EbpfError> {
        let jit = JitCompiler::<C>::new(self)?;
        self.compiled_program = Some(jit.compile()?);
        // println!("hello9");
        // println!(
        //     "{:?}",
        //     self.compiled_program
        //         .as_ref()
        //         .unwrap()
        //         .text_section
        //         .as_ptr()
        // );
        // println!("{:?}", self.compiled_program.as_ref().unwrap().text_section);
        // let instructions_dec = &*self.compiled_program.as_ref().unwrap().text_section; // 十进制表示

        // // 以十六进制输出
        // println!("机器指令的十六进制表示：");
        // for instr in instructions_dec {
        //     print!("{:02x} ", instr); // 每个指令以十六进制格式打印
        // }
        Ok(())
    }

    /// Get the function registry
    pub fn get_function_registry(&self) -> &FunctionRegistry<usize> {
        &self.function_registry
    }

    /// Create from raw text section bytes (list of instructions)
    pub fn new_from_text_bytes(
        text_bytes: &[u8],
        loader: Arc<BuiltinProgram<C>>,
        sbpf_version: SBPFVersion,
        mut function_registry: FunctionRegistry<usize>,
    ) -> Result<Self, ElfError> {
        let elf_bytes = AlignedMemory::from_slice(text_bytes);
        let config = loader.get_config();
        let enable_symbol_and_section_labels = config.enable_symbol_and_section_labels;
        let entry_pc = if let Some((_name, pc)) = function_registry.lookup_by_name(b"entrypoint") {
            pc
        } else {
            function_registry.register_function_hashed_legacy(
                &loader,
                !sbpf_version.static_syscalls(),
                *b"entrypoint",
                0,
            )?;
            0
        };
        Ok(Self {
            elf_bytes,
            sbpf_version,
            ro_section: Section::Borrowed(0, 0..text_bytes.len()),
            text_section_info: SectionInfo {
                name: if enable_symbol_and_section_labels {
                    ".text".to_string()
                } else {
                    String::default()
                },
                vaddr: ebpf::MM_PROGRAM_START,
                offset_range: 0..text_bytes.len(),
            },
            entry_pc,
            function_registry,
            loader,
            // #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
            compiled_program: None,
        })
    }

    /// Fully loads an ELF, including validation and relocation
    pub fn load(bytes: &[u8], loader: Arc<BuiltinProgram<C>>) -> Result<Self, ElfError> {
        if loader.get_config().new_elf_parser {
            // The new parser creates references from the input byte slice, so
            // it must be properly aligned. We assume that HOST_ALIGN is a
            // multiple of the ELF "natural" alignment. See test_load_unaligned.
            let aligned;
            let bytes = if is_memory_aligned(bytes.as_ptr() as usize, HOST_ALIGN) {
                bytes
            } else {
                aligned = AlignedMemory::<{ HOST_ALIGN }>::from_slice(bytes);
                aligned.as_slice()
            };
            Self::load_with_parser(&NewParser::parse(bytes)?, bytes, loader)
        } else {
            Self::load_with_parser(&GoblinParser::parse(bytes)?, bytes, loader)
        }
    }

    fn load_with_parser<'a, P: ElfParser<'a>>(
        elf: &'a P,
        bytes: &[u8],
        loader: Arc<BuiltinProgram<C>>,
    ) -> Result<Self, ElfError> {
        let mut elf_bytes = AlignedMemory::from_slice(bytes);
        let config = loader.get_config();
        let header = elf.header();
        let sbpf_version = if header.e_flags == EF_SBPF_V2 {
            SBPFVersion::V2
        } else {
            SBPFVersion::V1
        };

        Self::validate(config, elf, elf_bytes.as_slice())?;

        // calculate the text section info
        let text_section = elf.section(b".text")?;
        let text_section_info = SectionInfo {
            name: if config.enable_symbol_and_section_labels {
                elf.section_name(text_section.sh_name())
                    .and_then(|name| std::str::from_utf8(name).ok())
                    .unwrap_or(".text")
                    .to_string()
            } else {
                String::default()
            },
            vaddr: if sbpf_version.enable_elf_vaddr()
                && text_section.sh_addr() >= ebpf::MM_PROGRAM_START
            {
                text_section.sh_addr()
            } else {
                text_section
                    .sh_addr()
                    .saturating_add(ebpf::MM_PROGRAM_START)
            },
            offset_range: text_section.file_range().unwrap_or_default(),
        };
        let vaddr_end = if sbpf_version.reject_rodata_stack_overlap() {
            text_section_info
                .vaddr
                .saturating_add(text_section.sh_size())
        } else {
            text_section_info.vaddr
        };
        if (config.reject_broken_elfs
            && !sbpf_version.enable_elf_vaddr()
            && text_section.sh_addr() != text_section.sh_offset())
            || vaddr_end > ebpf::MM_STACK_START
        {
            return Err(ElfError::ValueOutOfBounds);
        }

        // relocate symbols
        let mut function_registry = FunctionRegistry::default();
        Self::relocate(
            &mut function_registry,
            &loader,
            elf,
            elf_bytes.as_slice_mut(),
        )?;

        // calculate entrypoint offset into the text section
        let offset = header.e_entry.saturating_sub(text_section.sh_addr());
        if offset.checked_rem(ebpf::INSN_SIZE as u64) != Some(0) {
            return Err(ElfError::InvalidEntrypoint);
        }
        let entry_pc = if let Some(entry_pc) = (offset as usize).checked_div(ebpf::INSN_SIZE) {
            if !sbpf_version.static_syscalls() {
                function_registry.unregister_function(ebpf::hash_symbol_name(b"entrypoint"));
            }
            function_registry.register_function_hashed_legacy(
                &loader,
                !sbpf_version.static_syscalls(),
                *b"entrypoint",
                entry_pc,
            )?;
            entry_pc
        } else {
            return Err(ElfError::InvalidEntrypoint);
        };

        let ro_section = Self::parse_ro_sections(
            config,
            &sbpf_version,
            elf.section_headers()
                .map(|s| (elf.section_name(s.sh_name()), s)),
            elf_bytes.as_slice(),
        )?;

        Ok(Self {
            elf_bytes,
            sbpf_version,
            ro_section,
            text_section_info,
            entry_pc,
            function_registry,
            loader,
            // #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
            compiled_program: None,
        })
    }

    pub(crate) fn parse_ro_sections<
        'a,
        T: ElfSectionHeader + 'a,
        S: IntoIterator<Item = (Option<&'a [u8]>, &'a T)>,
    >(
        config: &Config,
        sbpf_version: &SBPFVersion,
        sections: S,
        elf_bytes: &[u8],
    ) -> Result<Section, ElfError> {
        // the lowest section address
        let mut lowest_addr = usize::MAX;
        // the highest section address
        let mut highest_addr = 0;
        // the aggregated section length, not including gaps between sections
        let mut ro_fill_length = 0usize;
        let mut invalid_offsets = false;
        // when sbpf_version.enable_elf_vaddr()=true, we allow section_addr != sh_offset
        // if section_addr - sh_offset is constant across all sections. That is,
        // we allow sections to be translated by a fixed virtual offset.
        let mut addr_file_offset = None;

        // keep track of where ro sections are so we can tell whether they're
        // contiguous
        let mut first_ro_section = 0;
        let mut last_ro_section = 0;
        let mut n_ro_sections = 0usize;

        let mut ro_slices = vec![];
        for (i, (name, section_header)) in sections.into_iter().enumerate() {
            match name {
                Some(name)
                    if name == b".text"
                        || name == b".rodata"
                        || name == b".data.rel.ro"
                        || name == b".eh_frame" => {}
                _ => continue,
            }

            if n_ro_sections == 0 {
                first_ro_section = i;
            }
            last_ro_section = i;
            n_ro_sections = n_ro_sections.saturating_add(1);

            let section_addr = section_header.sh_addr();

            // sh_offset handling:
            //
            // If sbpf_version.enable_elf_vaddr()=true, we allow section_addr >
            // sh_offset, if section_addr - sh_offset is constant across all
            // sections. That is, we allow the linker to align rodata to a
            // positive base address (MM_PROGRAM_START) as long as the mapping
            // to sh_offset(s) stays linear.
            //
            // If sbpf_version.enable_elf_vaddr()=false, section_addr must match
            // sh_offset for backwards compatibility
            if !invalid_offsets {
                if sbpf_version.enable_elf_vaddr() {
                    // This is enforced in validate()
                    debug_assert!(config.optimize_rodata);
                    if section_addr < section_header.sh_offset() {
                        invalid_offsets = true;
                    } else {
                        let offset = section_addr.saturating_sub(section_header.sh_offset());
                        if *addr_file_offset.get_or_insert(offset) != offset {
                            // The sections are not all translated by the same
                            // constant. We won't be able to borrow, but unless
                            // config.reject_broken_elf=true, we're still going
                            // to accept this file for backwards compatibility.
                            invalid_offsets = true;
                        }
                    }
                } else if section_addr != section_header.sh_offset() {
                    invalid_offsets = true;
                }
            }

            let mut vaddr_end =
                if sbpf_version.enable_elf_vaddr() && section_addr >= ebpf::MM_PROGRAM_START {
                    section_addr
                } else {
                    section_addr.saturating_add(ebpf::MM_PROGRAM_START)
                };
            if sbpf_version.reject_rodata_stack_overlap() {
                vaddr_end = vaddr_end.saturating_add(section_header.sh_size());
            }
            if (config.reject_broken_elfs && invalid_offsets) || vaddr_end > ebpf::MM_STACK_START {
                return Err(ElfError::ValueOutOfBounds);
            }

            let section_data = elf_bytes
                .get(section_header.file_range().unwrap_or_default())
                .ok_or(ElfError::ValueOutOfBounds)?;

            let section_addr = section_addr as usize;
            lowest_addr = lowest_addr.min(section_addr);
            highest_addr = highest_addr.max(section_addr.saturating_add(section_data.len()));
            ro_fill_length = ro_fill_length.saturating_add(section_data.len());

            ro_slices.push((section_addr, section_data));
        }

        if config.reject_broken_elfs && lowest_addr.saturating_add(ro_fill_length) > highest_addr {
            return Err(ElfError::ValueOutOfBounds);
        }

        let can_borrow = !invalid_offsets
            && last_ro_section
                .saturating_add(1)
                .saturating_sub(first_ro_section)
                == n_ro_sections;
        if sbpf_version.enable_elf_vaddr() && !can_borrow {
            return Err(ElfError::ValueOutOfBounds);
        }
        let ro_section = if config.optimize_rodata && can_borrow {
            // Read only sections are grouped together with no intermixed non-ro
            // sections. We can borrow.

            // When sbpf_version.enable_elf_vaddr()=true, section addresses and their
            // corresponding buffer offsets can be translated by a constant
            // amount. Subtract the constant to get buffer positions.
            let buf_offset_start =
                lowest_addr.saturating_sub(addr_file_offset.unwrap_or(0) as usize);
            let buf_offset_end =
                highest_addr.saturating_sub(addr_file_offset.unwrap_or(0) as usize);

            let addr_offset = if lowest_addr >= ebpf::MM_PROGRAM_START as usize {
                // The first field of Section::Borrowed is an offset from
                // ebpf::MM_PROGRAM_START so if the linker has already put the
                // sections within ebpf::MM_PROGRAM_START, we need to subtract
                // it now.
                lowest_addr.saturating_sub(ebpf::MM_PROGRAM_START as usize)
            } else {
                if sbpf_version.enable_elf_vaddr() {
                    return Err(ElfError::ValueOutOfBounds);
                }
                lowest_addr
            };

            Section::Borrowed(addr_offset, buf_offset_start..buf_offset_end)
        } else {
            // Read only and other non-ro sections are mixed. Zero the non-ro
            // sections and and copy the ro ones at their intended offsets.

            if config.optimize_rodata {
                // The rodata region starts at MM_PROGRAM_START + offset,
                // [MM_PROGRAM_START, MM_PROGRAM_START + offset) is not
                // mappable. We only need to allocate highest_addr - lowest_addr
                // bytes.
                highest_addr = highest_addr.saturating_sub(lowest_addr);
            } else {
                // For backwards compatibility, the whole [MM_PROGRAM_START,
                // MM_PROGRAM_START + highest_addr) range is mappable. We need
                // to allocate the whole address range.
                lowest_addr = 0;
            };

            let buf_len = highest_addr;
            if buf_len > elf_bytes.len() {
                return Err(ElfError::ValueOutOfBounds);
            }

            let mut ro_section = vec![0; buf_len];
            for (section_addr, slice) in ro_slices.iter() {
                let buf_offset_start = section_addr.saturating_sub(lowest_addr);
                ro_section[buf_offset_start..buf_offset_start.saturating_add(slice.len())]
                    .copy_from_slice(slice);
            }

            let addr_offset = if lowest_addr >= ebpf::MM_PROGRAM_START as usize {
                lowest_addr.saturating_sub(ebpf::MM_PROGRAM_START as usize)
            } else {
                lowest_addr
            };
            Section::Owned(addr_offset, ro_section)
        };

        Ok(ro_section)
    }

    /// Validates the ELF
    pub fn validate<'a, P: ElfParser<'a>>(
        config: &Config,
        elf: &'a P,
        elf_bytes: &[u8],
    ) -> Result<(), ElfError> {
        let header = elf.header();
        if header.e_ident.ei_class != ELFCLASS64 {
            return Err(ElfError::WrongClass);
        }
        if header.e_ident.ei_data != ELFDATA2LSB {
            return Err(ElfError::WrongEndianess);
        }
        if header.e_ident.ei_osabi != ELFOSABI_NONE {
            return Err(ElfError::WrongAbi);
        }
        if header.e_machine != EM_BPF && (!config.new_elf_parser || header.e_machine != EM_SBPF) {
            return Err(ElfError::WrongMachine);
        }
        if header.e_type != ET_DYN {
            return Err(ElfError::WrongType);
        }

        let sbpf_version = if header.e_flags == EF_SBPF_V2 {
            if !config.enable_sbpf_v2 {
                return Err(ElfError::UnsupportedSBPFVersion);
            }
            SBPFVersion::V2
        } else {
            if !config.enable_sbpf_v1 {
                return Err(ElfError::UnsupportedSBPFVersion);
            }
            SBPFVersion::V1
        };

        if sbpf_version.enable_elf_vaddr() {
            if !config.optimize_rodata {
                // When optimize_rodata=false, we allocate a vector and copy all
                // rodata sections into it. In that case we can't allow virtual
                // addresses or we'd potentially have to do huge allocations.
                return Err(ElfError::UnsupportedSBPFVersion);
            }

            // This is needed to avoid an overflow error in header.vm_range() as
            // used by relocate(). See https://github.com/m4b/goblin/pull/306.
            //
            // Once we bump to a version of goblin that includes the fix, this
            // check can be removed, and relocate() will still return
            // ValueOutOfBounds on malformed program headers.
            if elf
                .program_headers()
                .any(|header| header.p_vaddr().checked_add(header.p_memsz()).is_none())
            {
                return Err(ElfError::InvalidProgramHeader);
            }

            // The toolchain currently emits up to 4 program headers. 10 is a
            // future proof nice round number.
            //
            // program_headers() returns an ExactSizeIterator so count doesn't
            // actually iterate again.
            if elf.program_headers().count() >= 10 {
                return Err(ElfError::InvalidProgramHeader);
            }
        }

        let num_text_sections = elf
            .section_headers()
            .fold(0, |count: usize, section_header| {
                if let Some(this_name) = elf.section_name(section_header.sh_name()) {
                    if this_name == b".text" {
                        return count.saturating_add(1);
                    }
                }
                count
            });
        if 1 != num_text_sections {
            return Err(ElfError::NotOneTextSection);
        }

        for section_header in elf.section_headers() {
            if let Some(name) = elf.section_name(section_header.sh_name()) {
                if name.starts_with(b".bss")
                    || (section_header.is_writable()
                        && (name.starts_with(b".data") && !name.starts_with(b".data.rel")))
                {
                    return Err(ElfError::WritableSectionNotSupported(
                        String::from_utf8_lossy(name).to_string(),
                    ));
                }
            }
        }

        for section_header in elf.section_headers() {
            let start = section_header.sh_offset() as usize;
            let end = section_header
                .sh_offset()
                .checked_add(section_header.sh_size())
                .ok_or(ElfError::ValueOutOfBounds)? as usize;
            let _ = elf_bytes
                .get(start..end)
                .ok_or(ElfError::ValueOutOfBounds)?;
        }
        let text_section = elf.section(b".text")?;
        if !text_section.vm_range().contains(&header.e_entry) {
            return Err(ElfError::EntrypointOutOfBounds);
        }

        Ok(())
    }

    /// Relocates the ELF in-place
    fn relocate<'a, P: ElfParser<'a>>(
        function_registry: &mut FunctionRegistry<usize>,
        loader: &BuiltinProgram<C>,
        elf: &'a P,
        elf_bytes: &mut [u8],
    ) -> Result<(), ElfError> {
        let mut syscall_cache = BTreeMap::new();
        let text_section = elf.section(b".text")?;
        let sbpf_version = if elf.header().e_flags == EF_SBPF_V2 {
            SBPFVersion::V2
        } else {
            SBPFVersion::V1
        };

        // Fixup all program counter relative call instructions
        let config = loader.get_config();
        let text_bytes = elf_bytes
            .get_mut(text_section.file_range().unwrap_or_default())
            .ok_or(ElfError::ValueOutOfBounds)?;
        let instruction_count = text_bytes
            .len()
            .checked_div(ebpf::INSN_SIZE)
            .ok_or(ElfError::ValueOutOfBounds)?;
        for i in 0..instruction_count {
            let insn = ebpf::get_insn(text_bytes, i);
            if insn.opc == ebpf::CALL_IMM
                && insn.imm != -1
                && !(sbpf_version.static_syscalls() && insn.src == 0)
            {
                let target_pc = (i as isize)
                    .saturating_add(1)
                    .saturating_add(insn.imm as isize);
                if target_pc < 0 || target_pc >= instruction_count as isize {
                    return Err(ElfError::RelativeJumpOutOfBounds(i));
                }
                let name = if config.enable_symbol_and_section_labels {
                    format!("function_{target_pc}")
                } else {
                    String::default()
                };
                let key = function_registry.register_function_hashed_legacy(
                    loader,
                    !sbpf_version.static_syscalls(),
                    name.as_bytes(),
                    target_pc as usize,
                )?;
                let offset = i.saturating_mul(ebpf::INSN_SIZE).saturating_add(4);
                let checked_slice = text_bytes
                    .get_mut(offset..offset.saturating_add(4))
                    .ok_or(ElfError::ValueOutOfBounds)?;
                LittleEndian::write_u32(checked_slice, key);
            }
        }

        let mut program_header: Option<&<P as ElfParser<'a>>::ProgramHeader> = None;

        // Fixup all the relocations in the relocation section if exists
        for relocation in elf.dynamic_relocations() {
            let mut r_offset = relocation.r_offset() as usize;

            // When sbpf_version.enable_elf_vaddr()=true, we allow section.sh_addr !=
            // section.sh_offset so we need to bring r_offset to the correct
            // byte offset.
            if sbpf_version.enable_elf_vaddr() {
                match program_header {
                    Some(header) if header.vm_range().contains(&(r_offset as u64)) => {}
                    _ => {
                        program_header = elf
                            .program_headers()
                            .find(|header| header.vm_range().contains(&(r_offset as u64)))
                    }
                }
                let header = program_header.as_ref().ok_or(ElfError::ValueOutOfBounds)?;
                r_offset = r_offset
                    .saturating_sub(header.p_vaddr() as usize)
                    .saturating_add(header.p_offset() as usize);
            }

            match BpfRelocationType::from_RISCV_relocation_type(relocation.r_type()) {
                Some(BpfRelocationType::R_Bpf_64_64) => {
                    // Offset of the immediate field
                    let imm_offset = if text_section
                        .file_range()
                        .unwrap_or_default()
                        .contains(&r_offset)
                        || sbpf_version == SBPFVersion::V1
                    {
                        r_offset.saturating_add(BYTE_OFFSET_IMMEDIATE)
                    } else {
                        r_offset
                    };

                    // Read the instruction's immediate field which contains virtual
                    // address to convert to physical
                    let checked_slice = elf_bytes
                        .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    let refd_addr = LittleEndian::read_u32(checked_slice) as u64;

                    let symbol = elf
                        .dynamic_symbol(relocation.r_sym())
                        .ok_or_else(|| ElfError::UnknownSymbol(relocation.r_sym() as usize))?;

                    // The relocated address is relative to the address of the
                    // symbol at index `r_sym`
                    let mut addr = symbol.st_value().saturating_add(refd_addr);

                    // The "physical address" from the VM's perspective is rooted
                    // at `MM_PROGRAM_START`. If the linker hasn't already put
                    // the symbol within `MM_PROGRAM_START`, we need to do so
                    // now.
                    if addr < ebpf::MM_PROGRAM_START {
                        addr = ebpf::MM_PROGRAM_START.saturating_add(addr);
                    }

                    if text_section
                        .file_range()
                        .unwrap_or_default()
                        .contains(&r_offset)
                        || sbpf_version == SBPFVersion::V1
                    {
                        let imm_low_offset = imm_offset;
                        let imm_high_offset = imm_low_offset.saturating_add(INSN_SIZE);

                        // Write the low side of the relocate address
                        let imm_slice = elf_bytes
                            .get_mut(
                                imm_low_offset
                                    ..imm_low_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(imm_slice, (addr & 0xFFFFFFFF) as u32);

                        // Write the high side of the relocate address
                        let imm_slice = elf_bytes
                            .get_mut(
                                imm_high_offset
                                    ..imm_high_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(
                            imm_slice,
                            addr.checked_shr(32).unwrap_or_default() as u32,
                        );
                    } else {
                        let imm_slice = elf_bytes
                            .get_mut(imm_offset..imm_offset.saturating_add(8))
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u64(imm_slice, addr);
                    }
                }
                Some(BpfRelocationType::R_Bpf_64_Relative) => {
                    // Relocation between different sections, where the target
                    // memory is not associated to a symbol (eg some compiler
                    // generated rodata that doesn't have an explicit symbol).

                    // Offset of the immediate field
                    let imm_offset = r_offset.saturating_add(BYTE_OFFSET_IMMEDIATE);

                    if text_section
                        .file_range()
                        .unwrap_or_default()
                        .contains(&r_offset)
                    {
                        // We're relocating a lddw instruction, which spans two
                        // instruction slots. The address to be relocated is
                        // split in two halves in the two imms of the
                        // instruction slots.
                        let imm_low_offset = imm_offset;
                        let imm_high_offset = r_offset
                            .saturating_add(INSN_SIZE)
                            .saturating_add(BYTE_OFFSET_IMMEDIATE);

                        // Read the low side of the address
                        let imm_slice = elf_bytes
                            .get(
                                imm_low_offset
                                    ..imm_low_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        let va_low = LittleEndian::read_u32(imm_slice) as u64;

                        // Read the high side of the address
                        let imm_slice = elf_bytes
                            .get(
                                imm_high_offset
                                    ..imm_high_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        let va_high = LittleEndian::read_u32(imm_slice) as u64;

                        // Put the address back together
                        let mut refd_addr = va_high.checked_shl(32).unwrap_or_default() | va_low;

                        if refd_addr == 0 {
                            return Err(ElfError::InvalidVirtualAddress(refd_addr));
                        }

                        if refd_addr < ebpf::MM_PROGRAM_START {
                            // The linker hasn't already placed rodata within
                            // MM_PROGRAM_START, so we do so now
                            refd_addr = ebpf::MM_PROGRAM_START.saturating_add(refd_addr);
                        }

                        // Write back the low half
                        let imm_slice = elf_bytes
                            .get_mut(
                                imm_low_offset
                                    ..imm_low_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(imm_slice, (refd_addr & 0xFFFFFFFF) as u32);

                        // Write back the high half
                        let imm_slice = elf_bytes
                            .get_mut(
                                imm_high_offset
                                    ..imm_high_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(
                            imm_slice,
                            refd_addr.checked_shr(32).unwrap_or_default() as u32,
                        );
                    } else {
                        let refd_addr = if sbpf_version != SBPFVersion::V1 {
                            // We're relocating an address inside a data section (eg .rodata). The
                            // address is encoded as a simple u64.

                            let addr_slice = elf_bytes
                                .get(r_offset..r_offset.saturating_add(mem::size_of::<u64>()))
                                .ok_or(ElfError::ValueOutOfBounds)?;
                            let mut refd_addr = LittleEndian::read_u64(addr_slice);
                            if refd_addr < ebpf::MM_PROGRAM_START {
                                // Not within MM_PROGRAM_START, do it now
                                refd_addr = ebpf::MM_PROGRAM_START.saturating_add(refd_addr);
                            }
                            refd_addr
                        } else {
                            // There used to be a bug in toolchains before
                            // https://github.com/solana-labs/llvm-project/pull/35 where for 64 bit
                            // relocations we were encoding only the low 32 bits, shifted 32 bits to
                            // the left. Our relocation code used to be compatible with that, so we
                            // need to keep supporting this case for backwards compatibility.
                            let addr_slice = elf_bytes
                                .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                                .ok_or(ElfError::ValueOutOfBounds)?;
                            let refd_addr = LittleEndian::read_u32(addr_slice) as u64;
                            ebpf::MM_PROGRAM_START.saturating_add(refd_addr)
                        };

                        let addr_slice = elf_bytes
                            .get_mut(r_offset..r_offset.saturating_add(mem::size_of::<u64>()))
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u64(addr_slice, refd_addr);
                    }
                }
                Some(BpfRelocationType::R_Bpf_64_32) => {
                    // The .text section has an unresolved call to symbol instruction
                    // Hash the symbol name and stick it into the call instruction's imm
                    // field.  Later that hash will be used to look up the function location.

                    // Offset of the immediate field
                    let imm_offset = r_offset.saturating_add(BYTE_OFFSET_IMMEDIATE);

                    let symbol = elf
                        .dynamic_symbol(relocation.r_sym())
                        .ok_or_else(|| ElfError::UnknownSymbol(relocation.r_sym() as usize))?;

                    let name = elf
                        .dynamic_symbol_name(symbol.st_name() as Elf64Word)
                        .ok_or_else(|| ElfError::UnknownSymbol(symbol.st_name() as usize))?;

                    // If the symbol is defined, this is a bpf-to-bpf call
                    let key = if symbol.is_function() && symbol.st_value() != 0 {
                        if !text_section.vm_range().contains(&symbol.st_value()) {
                            return Err(ElfError::ValueOutOfBounds);
                        }
                        let target_pc = (symbol.st_value().saturating_sub(text_section.sh_addr())
                            as usize)
                            .checked_div(ebpf::INSN_SIZE)
                            .unwrap_or_default();
                        function_registry.register_function_hashed_legacy(
                            loader,
                            !sbpf_version.static_syscalls(),
                            name,
                            target_pc,
                        )?
                    } else {
                        // Else it's a syscall
                        let hash = *syscall_cache
                            .entry(symbol.st_name())
                            .or_insert_with(|| ebpf::hash_symbol_name(name));
                        if config.reject_broken_elfs
                            && loader.get_function_registry().lookup_by_key(hash).is_none()
                        {
                            return Err(ElfError::UnresolvedSymbol(
                                String::from_utf8_lossy(name).to_string(),
                                r_offset.checked_div(ebpf::INSN_SIZE).unwrap_or(0),
                                r_offset,
                            ));
                        }
                        hash
                    };

                    let checked_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    LittleEndian::write_u32(checked_slice, key);
                }
                _ => return Err(ElfError::UnknownRelocation(relocation.r_type())),
            }
        }

        if config.enable_symbol_and_section_labels {
            // Register all known function names from the symbol table
            for symbol in elf.symbols() {
                if symbol.st_info() & 0xEF != 0x02 {
                    continue;
                }
                if !text_section.vm_range().contains(&symbol.st_value()) {
                    return Err(ElfError::ValueOutOfBounds);
                }
                let target_pc = (symbol.st_value().saturating_sub(text_section.sh_addr()) as usize)
                    .checked_div(ebpf::INSN_SIZE)
                    .unwrap_or_default();
                let name = elf
                    .symbol_name(symbol.st_name() as Elf64Word)
                    .ok_or_else(|| ElfError::UnknownSymbol(symbol.st_name() as usize))?;
                function_registry.register_function_hashed_legacy(
                    loader,
                    !sbpf_version.static_syscalls(),
                    name,
                    target_pc,
                )?;
            }
        }

        Ok(())
    }
}

pub(crate) fn get_ro_region(ro_section: &Section, elf: &[u8]) -> MemoryRegion {
    let (offset, ro_data) = match ro_section {
        Section::Owned(offset, data) => (*offset, data.as_slice()),
        Section::Borrowed(offset, byte_range) => (*offset, &elf[byte_range.clone()]),
    };

    // If offset > 0, the region will start at MM_PROGRAM_START + the offset of
    // the first read only byte. [MM_PROGRAM_START, MM_PROGRAM_START + offset)
    // will be unmappable, see MemoryRegion::vm_to_host.
    MemoryRegion::new_readonly(
        ro_data,
        ebpf::MM_PROGRAM_START.saturating_add(offset as u64),
    )
}
