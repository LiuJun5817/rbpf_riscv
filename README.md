# Solana RISC-V JIT Compiler

## Overview

The project aims to develop a Just-In-Time (JIT) compiler for the Solana blockchain that targets the RISC-V architecture. The goal is to optimize Solana's smart contract execution engine (using eBPF) by leveraging RISC-V’s open-source nature and powerful processing capabilities. This project will improve Solana's performance on RISC-V-based hardware, especially in scenarios requiring high computational efficiency, low-latency processing, and more hardware flexibility. 

## Install
```shell
# 1. install Rust + vscode + rust-analyzer
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

rustc --version
# e.g. expected: rustc 1.85.0

# 2.change target to rv64
rustup target add riscv64imac-unknown-none-elf

# 3. remember to change this github repo to `solana_rbpf`
# Now. your rust-analyzer should be OK
```

## License 

TRust2 is open source and distributed under the [MIT license](LICENSE.md).