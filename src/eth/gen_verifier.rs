// use crate::snark_verifier_sdk::*;
use crate::config_params::default_config_params;
use crate::eth::DeployParamsJson;
use crate::*;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use regex_simple::Regex;
use snark_verifier::loader::evm::{compile_yul, EvmLoader, ExecutorBuilder};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier::verifier::PlonkVerifier;
use snark_verifier_sdk::Plonk;
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::rc::Rc;

pub fn gen_sol_verifiers(params: &ParamsKZG<Bn256>, vks: &[VerifyingKey<G1Affine>], max_line_size_per_file: usize, sols_dir: &PathBuf) {
    let store_sols = |sols: Vec<String>, dir_name: &str, max_transcript_addr: u32| {
        let dir = sols_dir.join(dir_name);
        fs::create_dir_all(&dir).unwrap();
        for (idx, sol) in sols.iter().enumerate() {
            let mut file = File::create(dir.join(format!("VerifierFunc{}.sol", idx))).unwrap();
            file.write_all(sol.as_bytes()).unwrap();
        }
        let deploy_params = DeployParamsJson {
            max_transcript_addr,
            num_func_contracts: sols.len(),
        };
        let mut json_file = File::create(dir.join("deploy_params.json")).unwrap();
        json_file.write_all(serde_json::to_string_pretty(&deploy_params).unwrap().as_bytes()).unwrap();
    };
    let config_params = default_config_params();
    let mut vk_idx = 0;
    let sha2_header_yul = gen_evm_verifier_yul::<Sha256HeaderCircuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
    let (sha2_header_sols, sha2_header_max) = gen_evm_verifier_sols_from_yul(&sha2_header_yul, max_line_size_per_file).unwrap();
    vk_idx += 1;
    store_sols(sha2_header_sols, "sha2_header", sha2_header_max);
    let sign_verify_yul = gen_evm_verifier_yul::<SignVerifyCircuit<Fr>>(params, &vks[vk_idx], vec![3usize]);
    let (sign_verify_sols, sign_verify_max) = gen_evm_verifier_sols_from_yul(&sign_verify_yul, max_line_size_per_file).unwrap();
    vk_idx += 1;
    store_sols(sign_verify_sols, "sign_verify", sign_verify_max);
    let regex_header_yul = gen_evm_verifier_yul::<RegexHeaderCircuit<Fr>>(params, &vks[vk_idx], vec![3usize]);
    let (regex_header_sols, regex_header_max) = gen_evm_verifier_sols_from_yul(&regex_header_yul, max_line_size_per_file).unwrap();
    vk_idx += 1;
    store_sols(regex_header_sols, "regex_header", regex_header_max);
    if config_params.header_config.as_ref().unwrap().expose_substrs.unwrap_or(false) {
        let sha2_header_masked_chars_yul = gen_evm_verifier_yul::<Sha256HeaderMaskedCharsCircuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
        let (sha2_header_masked_chars_sols, sha2_header_masked_chars_max) = gen_evm_verifier_sols_from_yul(&sha2_header_masked_chars_yul, max_line_size_per_file).unwrap();
        vk_idx += 1;
        store_sols(sha2_header_masked_chars_sols, "sha2_header_masked_chars", sha2_header_masked_chars_max);
        let sha2_header_substr_ids_yul = gen_evm_verifier_yul::<Sha256HeaderSubstrIdsCircuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
        let (sha2_header_substr_ids_sols, sha2_header_substr_ids_max) = gen_evm_verifier_sols_from_yul(&sha2_header_substr_ids_yul, max_line_size_per_file).unwrap();
        vk_idx += 1;
        store_sols(sha2_header_substr_ids_sols, "sha2_header_substr_ids", sha2_header_substr_ids_max);
    }
    if let Some(body_configs) = config_params.body_config.as_ref() {
        let regex_bodyhash_yul = gen_evm_verifier_yul::<RegexBodyHashCircuit<Fr>>(params, &vks[vk_idx], vec![3usize]);
        let (regex_bodyhash_sols, regex_bodyhash_max) = gen_evm_verifier_sols_from_yul(&regex_bodyhash_yul, max_line_size_per_file).unwrap();
        vk_idx += 1;
        store_sols(regex_bodyhash_sols, "regex_bodyhash", regex_bodyhash_max);
        let chars_shift_bodyhash_yul = gen_evm_verifier_yul::<CharsShiftBodyHashCircuit<Fr>>(params, &vks[vk_idx], vec![3usize]);
        let (chars_shift_bodyhash_sols, chars_shift_bodyhash_max) = gen_evm_verifier_sols_from_yul(&chars_shift_bodyhash_yul, max_line_size_per_file).unwrap();
        vk_idx += 1;
        store_sols(chars_shift_bodyhash_sols, "chars_shift_bodyhash", chars_shift_bodyhash_max);
        let sha2_body_yul = gen_evm_verifier_yul::<Sha256BodyCircuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
        let (sha2_body_sols, sha2_body_max) = gen_evm_verifier_sols_from_yul(&sha2_body_yul, max_line_size_per_file).unwrap();
        vk_idx += 1;
        store_sols(sha2_body_sols, "sha2_body", sha2_body_max);
        let base64_yul = gen_evm_verifier_yul::<Base64Circuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
        let (base64_sols, base64_max) = gen_evm_verifier_sols_from_yul(&base64_yul, max_line_size_per_file).unwrap();
        vk_idx += 1;
        store_sols(base64_sols, "base64", base64_max);
        let regex_body_yul = gen_evm_verifier_yul::<RegexBodyCircuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
        let (regex_body_sols, regex_body_max) = gen_evm_verifier_sols_from_yul(&regex_body_yul, max_line_size_per_file).unwrap();
        vk_idx += 1;
        store_sols(regex_body_sols, "regex_body", regex_body_max);
        if body_configs.expose_substrs.unwrap_or(false) {
            let sha2_body_masked_chars_yul = gen_evm_verifier_yul::<Sha256BodyMaskedCharsCircuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
            let (sha2_body_masked_chars_sols, sha2_body_masked_chars_max) = gen_evm_verifier_sols_from_yul(&sha2_body_masked_chars_yul, max_line_size_per_file).unwrap();
            vk_idx += 1;
            store_sols(sha2_body_masked_chars_sols, "sha2_body_masked_chars", sha2_body_masked_chars_max);
            let sha2_body_substr_ids_yul = gen_evm_verifier_yul::<Sha256BodySubstrIdsCircuit<Fr>>(params, &vks[vk_idx], vec![2usize]);
            let (sha2_body_substr_ids_sols, sha2_body_substr_ids_max) = gen_evm_verifier_sols_from_yul(&sha2_body_substr_ids_yul, max_line_size_per_file).unwrap();
            store_sols(sha2_body_substr_ids_sols, "sha2_body_substr_ids", sha2_body_substr_ids_max);
        }
    }
    let email_verifier_sol = include_str!("./EmailVerifier.sol");
    fs::write(sols_dir.join("EmailVerifier.sol"), email_verifier_sol).unwrap();
    let verifier_base_sol = include_str!("./VerifierBase.sol");
    fs::write(sols_dir.join("VerifierBase.sol"), verifier_base_sol).unwrap();
    let verifier_func_abst_sol = include_str!("./VerifierFuncAbst.sol");
    fs::write(sols_dir.join("VerifierFuncAbst.sol"), verifier_func_abst_sol).unwrap();
}

fn gen_evm_verifier_yul<C>(params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, num_instance: Vec<usize>) -> String
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
fn gen_evm_verifier_sols_from_yul(yul: &str, max_line_size_per_file: usize) -> Result<(Vec<String>, u32), Box<dyn std::error::Error>> {
    // let file = File::open(input_file.clone())?;
    let reader = BufReader::new(yul.as_bytes());

    let mut transcript_addrs: Vec<u32> = Vec::new();

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

    // let file = File::open(input_file)?;
    let reader = BufReader::new(yul.as_bytes());
    let mut modified_lines: Vec<String> = Vec::new();

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
                line = line.replace(calldata_and_addr, &format!("mload(add(pubInputs, {}))", pub_addr));
            } else {
                let proof_addr = format!("{:#x}", addr_as_num - max_pubinputs_addr);
                // println!("proof_addr {}", proof_addr);
                line = line.replace(calldata_and_addr, &format!("mload(add(proof, {}))", proof_addr));
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
            line = line.replace(mstore, &format!("mstore8(add(transcript, {})", transcript_addr));
        }

        let m = mstoren_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(mstore, &format!("mstore(add(transcript, {})", transcript_addr));
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
            line = line.replace(mstore, &format!("mstore(add(transcript, {})", transcript_addr));
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
            line = line.replace(mload, &format!("mload(add(transcript, {})", transcript_addr));
        }

        modified_lines.push(line);
    }
    // modified_lines.push("}}".to_string());
    let mut outputs = vec![];
    // get the max transcript addr
    let max_transcript_addr = transcript_addrs.iter().max().unwrap() / 32;
    // {
    //     // let mut storage_file = File::create(output_dir.join("VerifierBase.sol"))?;
    //     let mut template = include_str!("./VerifierBase.sol").to_string();
    //     // template = template.replace("<%name%>", &format!("{}", max_transcript_addr));
    //     template = template.replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
    //     outputs.push(template);
    //     // storage_file.write_all(template.as_bytes())?;
    // }

    let mut blocks = vec![];
    let mut is_nest = false;
    let mut cur_block = String::new();
    for line in modified_lines[16..modified_lines.len() - 7].iter() {
        if line.trim() == "{" {
            debug_assert!(!is_nest, "depth >= 2 is not supported");
            is_nest = true;
            cur_block += line;
        } else if line.trim() == "}" {
            debug_assert!(is_nest, "there is no opening brace");
            is_nest = false;
            cur_block += line;
            blocks.push(cur_block);
            cur_block = String::new();
        } else {
            if is_nest {
                cur_block += line;
            } else {
                blocks.push(line.to_string());
            }
        }
    }

    let mut codes = String::new();
    // let mut write = BufWriter::new(File::create(output_dir.join(format!("VerifierFunc{}.sol", func_idx)))?);
    let mut func_idx = 0;
    let declares = r"
            let f_p
            := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            let
                f_q
            := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            function validate_ec_point(x, y) -> valid {
                {
                    let x_lt_p := lt(
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let y_lt_p := lt(
                        y,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    valid := and(x_lt_p, y_lt_p)
                }
                {
                    let x_is_zero := eq(x, 0)
                    let y_is_zero := eq(y, 0)
                    let x_or_y_is_zero := or(x_is_zero, y_is_zero)
                    let x_and_y_is_not_zero := not(x_or_y_is_zero)
                    valid := and(x_and_y_is_not_zero, valid)
                }
                {
                    let y_square := mulmod(
                        y,
                        y,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_square := mulmod(
                        x,
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_cube := mulmod(
                        x_square,
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_cube_plus_3 := addmod(
                        x_cube,
                        3,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let y_square_eq_x_cube_plus_3 := eq(x_cube_plus_3, y_square)
                    valid := and(y_square_eq_x_cube_plus_3, valid)
                }
            }
    ";
    for block in blocks.iter() {
        let new_block = format!("{}\n", block);
        if codes.len() + new_block.len() > max_line_size_per_file {
            let mut template = include_str!("./VerifierFunc.sol").to_string();
            template = template.replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
            template = template.replace("<%ID%>", &format!("{}", func_idx));
            template = template.replace("<%ASSEMBLY%>", &codes);
            // let mut func_file = File::create(output_dir.join(format!("VerifierFunc{}.sol", func_idx)))?;
            // func_file.write_all(template.as_bytes())?;
            outputs.push(template);
            codes = declares.to_string();
            func_idx += 1;
        }
        codes += &new_block;
    }
    if codes.len() > 0 {
        let mut template = include_str!("./VerifierFunc.sol").to_string();
        template = template.replace("<%max_transcript_addr%>", &format!("{}", max_transcript_addr));
        template = template.replace("<%ID%>", &format!("{}", func_idx));
        template = template.replace("<%ASSEMBLY%>", &codes);
        outputs.push(template);
        // let mut func_file = File::create(output_dir.join(format!("VerifierFunc{}.sol", func_idx)))?;
        // func_file.write_all(template.as_bytes())?;
    }
    // let template = include_str!("./EmailVerifier.sol").to_string();
    // let mut func_file = File::create(output_dir.join("EmailVerifier.sol"))?;
    // func_file.write_all(template.as_bytes())?;

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
    Ok((outputs, max_transcript_addr))
}
