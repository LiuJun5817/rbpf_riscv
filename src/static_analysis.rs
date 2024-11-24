/// Register state recorded after executing one instruction
///
/// The last register is the program counter (aka pc).
pub type TraceLogEntry = [u64; 12];
