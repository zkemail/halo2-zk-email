# halo2-zk-email

Email verification circuit in halo2. Still in early alpha stages. Documentation coming soon.

## Description

Generate regexes by calling the CLI in zk-regex with a specific string, and copying over the halo2_regex_lookup_js.txt file. The first line is total states, second line is accept states.

test_regexes/regex_bh.txt is the body hash regex.

Install solc (Mac instructions):
```bash
brew tap ethereum/ethereum
brew install solidity
```

Then build:
```bash
cargo build
cargo test
```

To generate a sample circuit and it's non aggregated EVM verifier, do:
```bash
cargo build --release
cargo run --release -- gen-param --k 19
cargo run --release -- gen-app-key
cargo run --release -- gen-evm-verifier
cargo run --release -- evm-verify-app
```


To test just DNS get of a domain, run `cargo run --bin parse_email -- --nocapture`.