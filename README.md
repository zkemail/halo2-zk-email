# halo2-zk-email

**Email verification circuit in halo2.**

## Disclaimer
DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development not audited. It has known and unknown bugs and security flaws.

## Features
`halo2-zk-email` provides a library and a command-line interface for an email verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).

## Requirement
- rustc 1.68.0-nightly (0468a00ae 2022-12-17)
- cargo 1.68.0-nightly (cc0a32087 2022-12-14)
- solc 0.8.19+commit.7dd6d404
- anvil 0.1.0 (0d3bd04 2022-11-20T00:11:22.107775Z)

Install solc (Mac instructions):
```bash
brew tap ethereum/ethereum
brew install solidity
```

## Installation and Build
You can install and build our library with the following commands.
```bash
git clone https://github.com/zkemail/halo2-zk-email.git
cd halo2-zk-email
cargo build --release
```

## Usage
You can open the API specification by executing `cargo doc --open`.

## Test
You can run the tests by executing `cargo test --release`.

## Description
To generate a proof and verify it on EVM, do:
```bash
cargo build --release
cargo run --release -- gen-params --k 18
cargo run --release -- gen-keys
cargo run --release -- gen-evm-verifier
cargo run --release -- evm-prove
cargo run --release -- evm-verify
```

To generate regex files for a new decomposed regex definition. do:
```bash
cargo run --release -- gen-regex-files --decomposed-regex-config-path new_regex_file.json --regex-files-prefix new_regex
```