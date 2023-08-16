// use crate::snark_verifier_sdk::*;
use crate::utils::{get_email_circuit_public_hash_input, get_email_substrs, read_default_circuit_config_params};
use crate::vrm::DecomposedRegexConfig;
use crate::EMAIL_VERIFY_CONFIG_ENV;
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use ethereum_types::Address;
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::thread_rng;
use regex_simple::Regex;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::loader::evm::{compile_yul, EvmLoader, ExecutorBuilder};
use snark_verifier::loader::LoadedScalar;
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier::verifier::PlonkVerifier;
use snark_verifier_sdk::evm::{encode_calldata, evm_verify, gen_evm_proof_shplonk};
use snark_verifier_sdk::halo2::aggregation::PublicAggregationCircuit;
use snark_verifier_sdk::halo2::{gen_proof_shplonk, gen_snark_shplonk};
use snark_verifier_sdk::Plonk;
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use std::env::set_var;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub fn gen_evm_verifier_yul<C>(params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, num_instance: Vec<usize>) -> String
where
    C: CircuitExt<Fr>,
{
    type PCS = Kzg<Bn256, Bdfg21>;
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()).with_accumulator_indices(C::accumulator_indices()),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::<PCS>::read_proof(&svk, &protocol, &instances, &mut transcript);
    Plonk::<PCS>::verify(&svk, &dk, &protocol, &instances, &proof);

    loader.yul_code()
}

// original: https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L326-L602
pub fn gen_evm_verifier_sols(input_file: PathBuf, max_line_size_per_file: usize, output_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(input_file.clone())?;
    let reader = BufReader::new(file);

    let mut transcript_addrs: Vec<u32> = Vec::new();
    let mut modified_lines: Vec<String> = Vec::new();

    // convert calldataload 0x0 to 0x40 to read from pubInputs, and the rest
    // from proof
    let calldata_pattern = Regex::new(r"^.*(calldataload\((0x[a-f0-9]+)\)).*$")?;
    let mstore_pattern = Regex::new(r"^\s*(mstore\(0x([0-9a-fA-F]+)+),.+\)")?;
    let mstore8_pattern = Regex::new(r"^\s*(mstore8\((\d+)+),.+\)")?;
    let mstoren_pattern = Regex::new(r"^\s*(mstore\((\d+)+),.+\)")?;
    let mload_pattern = Regex::new(r"(mload\((0x[0-9a-fA-F]+))\)")?;
    let keccak_pattern = Regex::new(r"(keccak256\((0x[0-9a-fA-F]+))")?;
    let modexp_pattern = Regex::new(r"(staticcall\(gas\(\), 0x5, (0x[0-9a-fA-F]+), 0xc0, (0x[0-9a-fA-F]+), 0x20)")?;
    let ecmul_pattern = Regex::new(r"(staticcall\(gas\(\), 0x7, (0x[0-9a-fA-F]+), 0x60, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecadd_pattern = Regex::new(r"(staticcall\(gas\(\), 0x6, (0x[0-9a-fA-F]+), 0x80, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecpairing_pattern = Regex::new(r"(staticcall\(gas\(\), 0x8, (0x[0-9a-fA-F]+), 0x180, (0x[0-9a-fA-F]+), 0x20)")?;
    let bool_pattern = Regex::new(r":bool")?;

    // Count the number of pub inputs
    let mut start = None;
    let mut end = None;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().starts_with("mstore(0x20") && start.is_none() {
            start = Some(i as u32);
        }

        if line.trim().starts_with("mstore(0x0") {
            end = Some(i as u32);
            break;
        }
    }

    let num_pubinputs = if let Some(s) = start { end.unwrap() - s } else { 0 };

    let mut max_pubinputs_addr = 0;
    if num_pubinputs > 0 {
        max_pubinputs_addr = num_pubinputs * 32 - 32;
    }
    // println!("max_pubinputs_addr {}", max_pubinputs_addr);

    let file = File::open(input_file)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let mut line = line?;
        let m = bool_pattern.captures(&line);
        if m.is_some() {
            line = line.replace(":bool", "");
        }

        let m = calldata_pattern.captures(&line);
        if let Some(m) = m {
            let calldata_and_addr = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;

            if addr_as_num <= max_pubinputs_addr {
                let pub_addr = format!("{:#x}", addr_as_num + 32);
                // println!("pub_addr {}", pub_addr);
                line = line.replace(calldata_and_addr, &format!("sload(add(pubInputs, {}))", pub_addr));
            } else {
                let proof_addr = format!("{:#x}", addr_as_num - max_pubinputs_addr);
                // println!("proof_addr {}", proof_addr);
                line = line.replace(calldata_and_addr, &format!("sload(add(proof, {}))", proof_addr));
            }
        }

        let m = mstore8_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            // [TODO] Check mstore8 -> sstore is OK.
            line = line.replace(mstore, &format!("sstore(add(transcript, {})", transcript_addr));
        }

        let m = mstoren_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mstore, &format!("sstore(add(transcript, {})", transcript_addr));
        }

        let m = modexp_pattern.captures(&line);
        if let Some(m) = m {
            let modexp = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num = u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num = u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            line = line.replace(
                modexp,
                &format!("staticcall(gas(), 0x5, add(transcript, {}), 0xc0, add(transcript, {}), 0x20", transcript_addr, result_addr),
            );
        }

        let m = ecmul_pattern.captures(&line);
        if let Some(m) = m {
            let ecmul = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num = u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num = u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecmul,
                &format!("staticcall(gas(), 0x7, add(transcript, {}), 0x60, add(transcript, {}), 0x40", transcript_addr, result_addr),
            );
        }

        let m = ecadd_pattern.captures(&line);
        if let Some(m) = m {
            let ecadd = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num = u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num = u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecadd,
                &format!("staticcall(gas(), 0x6, add(transcript, {}), 0x80, add(transcript, {}), 0x40", transcript_addr, result_addr),
            );
        }

        let m = ecpairing_pattern.captures(&line);
        if let Some(m) = m {
            let ecpairing = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num = u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num = u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecpairing,
                &format!("staticcall(gas(), 0x8, add(transcript, {}), 0x180, add(transcript, {}), 0x20", transcript_addr, result_addr),
            );
        }

        let m = mstore_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mstore, &format!("sstore(add(transcript, {})", transcript_addr));
        }

        let m = keccak_pattern.captures(&line);
        if let Some(m) = m {
            let keccak = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(keccak, &format!("keccak256(add(transcript, {})", transcript_addr));
        }

        // mload can show up multiple times per line
        loop {
            let m = mload_pattern.captures(&line);
            if m.is_none() {
                break;
            }
            let mload = m.as_ref().unwrap().get(1).unwrap().as_str();
            let addr = m.as_ref().unwrap().get(2).unwrap().as_str();

            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mload, &format!("sload(add(transcript, {})", transcript_addr));
        }

        modified_lines.push(line);
    }

    // get the max transcript addr
    let max_transcript_addr = transcript_addrs.iter().max().unwrap() / 32;
    {
        let mut storage_file = File::create(output_dir.join("VerifierStorage.sol"))?;
        let mut template = include_str!("./VerifierStorageBase.sol").to_string();
        template = template.replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
        storage_file.write_all(template.as_bytes())?;
    }
    let mut func_idx = 0;
    let mut lines = String::new();
    // let mut write = BufWriter::new(File::create(output_dir.join(format!("VerifierFunc{}.sol", func_idx)))?);
    for (idx, line) in modified_lines[16..modified_lines.len() - 7].iter().enumerate() {
        if lines.len() > max_line_size_per_file {
            let mut template = include_str!("./VerifierFuncBase.sol").to_string();
            template = template.replace("<%ID%>", &format!("{}", func_idx));
            template = template.replace("<%ASSEMBLY%>", &lines);
            let mut func_file = File::create(output_dir.join(format!("VerifierFunc{}.sol", func_idx)))?;
            func_file.write_all(template.as_bytes())?;
            lines = String::new();
            func_idx += 1;
        }
        lines += &format!("{}\n", line);
    }
    if lines.len() > 0 {
        let mut template = include_str!("./VerifierFuncBase.sol").to_string();
        template = template.replace("<%ID%>", &format!("{}", func_idx));
        template = template.replace("<%ASSEMBLY%>", &lines);
        let mut func_file = File::create(output_dir.join(format!("VerifierFunc{}.sol", func_idx)))?;
        func_file.write_all(template.as_bytes())?;
    }

    // let mut contract = format!(
    //     "// SPDX-License-Identifier: MIT
    // pragma solidity ^0.8.17;

    // contract Verifier {{
    //     function verify(
    //         uint256[] memory pubInputs,
    //         bytes memory proof
    //     ) public view returns (bool) {{
    //         bool success = true;
    //         bytes32[{}] memory transcript;
    //         assembly {{
    //     ",
    //     max_transcript_addr
    // )
    // .trim()
    // .to_string();

    // using a boxed Write trait object here to show it works for any Struct impl'ing Write
    // you may also use a std::fs::File here
    // let mut write: Box<&mut dyn std::fmt::Write> = Box::new(&mut contract);

    // for line in modified_lines[16..modified_lines.len() - 7].iter() {
    //     write!(write, "{}", line).unwrap();
    // }
    // writeln!(write, "}} return success; }} }}")?;
    Ok(())
}
