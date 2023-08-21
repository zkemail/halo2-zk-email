use ethers::prelude::*;
use std::process::Command;
fn main() {
    Command::new("solc")
        .args(["./src/eth/EmailVerifier.sol", "-o", "./src/eth/out", "--abi", "--overwrite"])
        .output()
        .expect("failed to compile EmailVerifier.sol");
    Abigen::new("EmailVerifierContract", "./src/eth/out/EmailVerifier.abi")
        .unwrap()
        .generate()
        .unwrap()
        .write_to_file("./src/eth/email_verifier_contract.rs")
        .unwrap();
}
