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

/// The number of limbs of the accumulator in the aggregation circuit.
pub const NUM_ACC_INSTANCES: usize = 4 * LIMBS;
/// The name of env variable for the path to the configuration json of the aggregation circuit.
pub const VERIFY_CONFIG_KEY: &'static str = "VERIFY_CONFIG";

/// Generate SRS parameters.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `k` - the SRS size.
pub fn gen_params(params_path: &str, k: u32) -> Result<(), Error> {
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    let f = File::create(params_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

/// Reduce the size of the given SRS parameters.
///
/// # Arguments
/// * `original_params_path` - a file path of the original SRS parameters.
/// * `new_params_path` - a file path of the new SRS parameters.
/// * `k` - the reduced SRS size.
pub fn downsize_params(original_params_path: &str, new_params_path: &str, k: u32) -> Result<(), Error> {
    let f = File::open(Path::new(original_params_path)).unwrap();
    let mut reader = BufReader::new(f);
    let mut params = ParamsKZG::<Bn256>::read(&mut reader).unwrap();
    params.downsize(k);
    let f = File::create(new_params_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

/// Generate proving and verifying keys for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `pk_path` - a file path of the output proving key.
/// * `vk_path` - a file path of the output verifying key.
/// * `circuit` - an email verification circuit.
pub fn gen_app_key<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, vk_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);

    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = read_default_circuit_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = gen_pk::<C>(&params, &circuit, None);
    println!("app pk generated");
    {
        let f = File::create(pk_path).unwrap();
        let mut writer = BufWriter::new(f);
        pk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
        writer.flush().unwrap();
    }

    let vk = pk.get_vk();
    {
        let f = File::create(vk_path).unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
        writer.flush().unwrap();
    }
    Ok(())
}

/// Generate proving and verifying keys for the aggregation circuit.
///
/// # Arguments
/// * `app_params_path` - a file path of the SRS parameters for the email verification circuit.
/// * `agg_params_path` - a file path of the SRS parameters for the aggregation circuit.
/// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
/// * `app_pk_path` - a file path of the proving key for the email verification circuit.
/// * `agg_pk_path` - a file path of the output proving key for the aggregation circuit.
/// * `agg_vk_path` - a file path of the output verifying key for the aggregation circuit.
/// * `app_circuit` - an email verification circuit.
pub fn gen_agg_key<C: CircuitExt<Fr>>(
    app_params_path: &str,
    agg_params_path: &str,
    app_circuit_config_path: &str,
    agg_circuit_config_path: &str,
    app_pk_path: &str,
    agg_pk_path: &str,
    agg_vk_path: &str,
    app_circuit: C,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
    set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
    let agg_params = {
        let f = File::open(Path::new(agg_params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_params = {
        let f = File::open(Path::new(app_params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_pk = {
        let f = File::open(Path::new(app_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let snark = gen_snark_shplonk(&app_params, &app_pk, app_circuit, &mut OsRng, None::<&str>);
    println!("snark generated");
    let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
    let agg_pk = gen_pk::<PublicAggregationCircuit>(&agg_params, &agg_circuit, None);
    println!("agg pk generated");
    {
        let f = File::create(agg_pk_path).unwrap();
        let mut writer = BufWriter::new(f);
        agg_pk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
        writer.flush().unwrap();
    }

    let vk = agg_pk.get_vk();
    {
        let f = File::create(agg_vk_path).unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
        writer.flush().unwrap();
    }
    Ok(())
}

/// Generate a proof for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `pk_path` - a file path of the proving key.
/// * `proof_path` - a file path of the output proof.
/// * `circuit` - an email verification circuit.
pub fn prove_app<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, proof_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = read_default_circuit_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    // let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let instances = circuit.instances();
    let proof = gen_proof_shplonk(&params, &pk, circuit, instances, &mut OsRng, None);
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    Ok(())
}

/// Generate a proof for the email verification circuit verifiable on EVM.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `pk_path` - a file path of the proving key.
/// * `proof_path` - a file path of the output proof.
/// * `circuit` - an email verification circuit.
pub fn evm_prove_app<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, proof_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = read_default_circuit_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    // let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances, &mut OsRng);
    {
        let proof_hex = hex::encode(&proof);
        let mut file = File::create(proof_path)?;
        write!(file, "0x{}", proof_hex).unwrap();
        file.flush().unwrap();
    };
    Ok(())
}

/// Generate proving and verifying keys of the aggregation circuit verifiable on EVM..
///
/// # Arguments
/// * `app_params_path` - a file path of the SRS parameters for the email verification circuit.
/// * `agg_params_path` - a file path of the SRS parameters for the aggregation circuit.
/// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
/// * `app_pk_path` - a file path of the proving key for the email verification circuit.
/// * `agg_pk_path` - a file path of the proving key for the aggregation circuit.
/// * `acc_path` - a file path of the output accumulator for the aggregation circuit.
/// * `proof_path` - a file path of the output proof for the aggregation circuit.
/// * `app_circuit` - an email verification circuit.
pub fn evm_prove_agg<C: CircuitExt<Fr>>(
    app_params_path: &str,
    agg_params_path: &str,
    app_circuit_config_path: &str,
    agg_circuit_config_path: &str,
    app_pk_path: &str,
    agg_pk_path: &str,
    acc_path: &str,
    proof_path: &str,
    app_circuit: C,
    // public_input_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
    set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
    let agg_params = {
        let f = File::open(Path::new(agg_params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_params = {
        let f = File::open(Path::new(app_params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    // let (app_circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let app_pk = {
        let f = File::open(Path::new(app_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let snark = gen_snark_shplonk(&app_params, &app_pk, app_circuit, &mut OsRng, None::<&str>);
    println!("snark generated");
    let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
    let agg_pk = {
        let f = File::open(Path::new(agg_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let instances = agg_circuit.instances();
    println!("instances {:?}", instances[0]);

    let acc = encode_calldata(&[instances[0][0..NUM_ACC_INSTANCES].to_vec()], &[]);
    {
        let acc_hex = hex::encode(&acc);
        let mut file = File::create(acc_path)?;
        write!(file, "0x{}", acc_hex).unwrap();
        file.flush().unwrap();
    };
    let proof = gen_evm_proof_shplonk(&agg_params, &agg_pk, agg_circuit, instances, &mut OsRng);
    println!("proof generated");
    {
        let proof_hex = hex::encode(&proof);
        let mut file = File::create(proof_path)?;
        write!(file, "0x{}", proof_hex).unwrap();
        file.flush().unwrap();
    };
    Ok(())
}

/// Generate yul and Solidity code of the verifier contract for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `vk_path` - a file path of the verifying key.
/// * `bytecode_path` - a file path of the output yul bytecode.
/// * `solidity_path` - a file path of the output Solidity code.
pub fn gen_evm_verifier<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, vk_path: &str, bytecode_path: &str, solidity_path: &str) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = read_default_circuit_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let num_instance = vec![1];
    let verifier_yul = gen_evm_verifier_yul::<C>(&params, &vk, num_instance);
    {
        let bytecode = compile_yul(&verifier_yul);
        let f = File::create(bytecode_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&bytecode).unwrap();
        writer.flush().unwrap();
    }
    {
        let mut f = File::create(solidity_path).unwrap();
        let _ = f.write(verifier_yul.as_bytes());
        let output = fix_verifier_sol(Path::new(solidity_path).to_path_buf()).unwrap();

        let mut f = File::create(solidity_path)?;
        let _ = f.write(output.as_bytes());
    };
    Ok(())
}

/// Generate yul and Solidity code of the verifier contract for the aggregation circuit.
///
/// # Arguments
/// * `agg_params_path` - a file path of the SRS parameters for the aggregation circuit.
/// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
/// * `agg_vk_path` - a file path of the verifying key for the aggregation circuit.
/// * `bytecode_path` - a file path of the output yul bytecode.
/// * `solidity_path` - a file path of the output Solidity code.
pub fn gen_agg_evm_verifier(
    agg_params_path: &str,
    app_circuit_config_path: &str,
    agg_circuit_config_path: &str,
    vk_path: &str,
    bytecode_path: &str,
    solidity_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
    set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
    let params = {
        let f = File::open(Path::new(agg_params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let num_instance = vec![1 + NUM_ACC_INSTANCES];
    let verifier_yul = gen_evm_verifier_yul::<PublicAggregationCircuit>(&params, &vk, num_instance);
    {
        let bytecode = compile_yul(&verifier_yul);
        let f = File::create(bytecode_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&bytecode).unwrap();
        writer.flush().unwrap();
    }
    {
        let mut f = File::create(solidity_path).unwrap();
        let _ = f.write(verifier_yul.as_bytes());
        let output = fix_verifier_sol(Path::new(solidity_path).to_path_buf()).unwrap();

        let mut f = File::create(solidity_path)?;
        let _ = f.write(output.as_bytes());
    };
    Ok(())
}

/// Verify an given evm-proof and instances with the yul bytecode of the verifier contract for the email verification circuit.
///
/// # Arguments
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `bytecode_path` - a file path of the yul bytecode.
/// * `proof_path` - a file path of the proof for the email verification circuit.
/// * `instances` - instances (public inputs) for the email verification circuit.
///
/// # Note
/// The contract size limitation is disabled in this function.
/// Therefore, your verifier contract may violate that limitation even if it passes the verification here.
pub fn evm_verify_app(circuit_config_path: &str, bytecode_path: &str, proof_path: &str, instances: Vec<Fr>) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let deployment_code = {
        let f = File::open(bytecode_path).unwrap();
        let mut reader = BufReader::new(f);
        let mut code = vec![];
        reader.read_to_end(&mut code).unwrap();
        code
    };
    let proof = {
        let hex = fs::read_to_string(proof_path).unwrap();
        hex::decode(&hex[2..]).unwrap()
    };
    println!("instances {:?}", instances);
    evm_verify(deployment_code, false, vec![instances], proof);
    Ok(())
}

/// Verify an given evm-proof and instances with the yul bytecode of the verifier contract for the aggregation circuit.
///
/// # Arguments
/// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
/// * `bytecode_path` - a file path of the yul bytecode.
/// * `proof_path` - a file path of the proof for the aggregation circuit.
/// * `instances` - instances (public inputs) for the email verification circuit and the aggregation circuit. (It must include the accumulator of the aggregation circuit.)
///
/// # Note
/// The contract size limitation is disabled in this function.
/// Therefore, your verifier contract may violate that limitation even if it passes the verification here.
pub fn evm_verify_agg(app_circuit_config_path: &str, agg_circuit_config_path: &str, bytecode_path: &str, proof_path: &str, instances: Vec<Fr>) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
    set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
    let deployment_code = {
        let f = File::open(bytecode_path).unwrap();
        let mut reader = BufReader::new(f);
        let mut code = vec![];
        reader.read_to_end(&mut code).unwrap();
        code
    };
    let proof = {
        let hex = fs::read_to_string(proof_path).unwrap();
        hex::decode(&hex[2..]).unwrap()
    };
    println!("instances {:?}", instances);
    evm_verify(deployment_code, false, vec![instances], proof);
    Ok(())
}

/// Generate regex-definition text files from the given decomposed regex json file.
///
/// # Arguments
/// * `decomposed_regex_config_path` - a file path pf the decomposed regex json.
/// * `regex_dir_path` - a directory path in which the output text files are stored.
/// * `regex_files_prefix` - a prefix used for the output text files.
pub fn gen_regex_files(decomposed_regex_config_path: &str, regex_dir_path: &str, regex_files_prefix: &str) -> Result<(), Error> {
    let decomposed_regex_config = serde_json::from_reader::<File, DecomposedRegexConfig>(File::open(decomposed_regex_config_path).unwrap()).unwrap();
    let regex_dir_path = PathBuf::new().join(regex_dir_path);
    let allstr_file_path = regex_dir_path.join(format!("{}_allstr.txt", regex_files_prefix));
    let mut num_public_parts = 0usize;
    for part in decomposed_regex_config.parts.iter() {
        if part.is_public {
            num_public_parts += 1;
        }
    }
    let substr_file_pathes = (0..num_public_parts)
        .map(|idx| regex_dir_path.join(format!("{}_substr_{}.txt", regex_files_prefix, idx)))
        .collect_vec();
    decomposed_regex_config
        .gen_regex_files(&allstr_file_path, &substr_file_pathes)
        .expect("fail to generate regex files");
    Ok(())
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
fn fix_verifier_sol(input_file: PathBuf) -> Result<String, Box<dyn std::error::Error>> {
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

    // get the max transcript addr
    let max_transcript_addr = transcript_addrs.iter().max().unwrap() / 32;
    let mut contract = format!(
        "// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.17;

    contract Verifier {{
        function verify(
            uint256[] memory pubInputs,
            bytes memory proof
        ) public view returns (bool) {{
            bool success = true;
            bytes32[{}] memory transcript;
            assembly {{
        ",
        max_transcript_addr
    )
    .trim()
    .to_string();

    // using a boxed Write trait object here to show it works for any Struct impl'ing Write
    // you may also use a std::fs::File here
    let mut write: Box<&mut dyn std::fmt::Write> = Box::new(&mut contract);

    for line in modified_lines[16..modified_lines.len() - 7].iter() {
        write!(write, "{}", line).unwrap();
    }
    writeln!(write, "}} return success; }} }}")?;
    Ok(contract)
}

#[cfg(test)]
mod test {
    use crate::{DefaultEmailVerifyCircuit, DefaultEmailVerifyPublicInput};

    use super::*;
    use cfdkim::{canonicalize_signed_email, resolve_public_key};
    use halo2_base::halo2_proofs::{
        circuit::Value,
        halo2curves::bn256::{Fr, G1},
    };
    use halo2_rsa::RSAPubE;
    use num_bigint::BigUint;
    use rsa::PublicKeyParts;
    use std::{fs::File, io::Read, path::Path};
    use temp_env;

    #[ignore]
    #[tokio::test]
    async fn test_helper_app_circuit() {
        gen_regex_files("./test_data/bodyhash_defs.json", "./test_data", "body_hash").unwrap();
        gen_regex_files("./test_data/from_defs.json", "./test_data", "from").unwrap();
        gen_regex_files("./test_data/to_defs.json", "./test_data", "to").unwrap();
        gen_regex_files("./test_data/subject_defs.json", "./test_data", "subject").unwrap();
        gen_regex_files("./test_data/test_ex1_email_body_defs.json", "./test_data", "test_ex1_email_body").unwrap();
        let email_path = "./test_data/test_email1.eml";
        let email_bytes = {
            let mut f = File::open(email_path).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };
        println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
        let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
        let headerhash = Sha256::digest(&canonicalized_header).to_vec();
        let public_key_n = {
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            match resolve_public_key(&logger, &email_bytes).await.unwrap() {
                cfdkim::DkimPublicKey::Rsa(_pk) => BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap(),
                _ => {
                    panic!("Only RSA keys are supported.");
                }
            }
        };
        let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
        let public_key = RSAPublicKey::<Fr>::new(Value::known(public_key_n.clone()), e);
        let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
        let header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
        let body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
        let circuit_config_path = "./configs/app_bench.config";
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some(circuit_config_path), move || {
            let config_params = read_default_circuit_config_params();
            let header_config = config_params.header_config.expect("header_config is required");
            let body_config = config_params.body_config.expect("body_config is required");
            let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes, body_config.substr_regexes);
            let circuit = DefaultEmailVerifyCircuit {
                header_bytes: canonicalized_header.clone(),
                body_bytes: canonicalized_body.clone(),
                public_key: public_key.clone(),
                signature: signature.clone(),
            };
            let public_input = DefaultEmailVerifyPublicInput::new(headerhash.clone(), public_key_n.clone(), header_substrs, body_substrs);
            let public_input_path = "./build/public_input.json";
            public_input.write_file(&public_input_path);
            let params_path = "./build/test.params";
            gen_params(params_path, config_params.degree).unwrap();
            let pk_path = "./build/test.pk";
            let vk_path = "./build/test.vk";
            gen_app_key(params_path, circuit_config_path, pk_path, vk_path, circuit.clone()).unwrap();
            let proof_path = "./build/test.proof";
            prove_app(params_path, circuit_config_path, pk_path, proof_path, circuit.clone()).unwrap();
            let evm_proof_path = "./build/test_evm.hex";
            evm_prove_app(params_path, circuit_config_path, pk_path, evm_proof_path, circuit.clone()).unwrap();
            let bytecode_path = "./build/test_verifier.bin";
            let solidity_path = "./build/testVerifier.sol";
            gen_evm_verifier::<DefaultEmailVerifyCircuit<Fr>>(params_path, circuit_config_path, vk_path, bytecode_path, solidity_path).unwrap();
            let instances = DefaultEmailVerifyCircuit::<Fr>::get_instances_from_default_public_input(&public_input_path);
            evm_verify_app(circuit_config_path, bytecode_path, evm_proof_path, instances).unwrap();
        });
    }

    #[ignore]
    #[tokio::test]
    async fn test_helper_agg_circuit() {
        gen_regex_files("./test_data/bodyhash_defs.json", "./test_data", "body_hash").unwrap();
        gen_regex_files("./test_data/from_defs.json", "./test_data", "from").unwrap();
        gen_regex_files("./test_data/to_defs.json", "./test_data", "to").unwrap();
        gen_regex_files("./test_data/subject_defs.json", "./test_data", "subject").unwrap();
        gen_regex_files("./test_data/test_ex1_email_body_defs.json", "./test_data", "test_ex1_email_body").unwrap();
        let email_path = "./test_data/test_email1.eml";
        let email_bytes = {
            let mut f = File::open(email_path).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };
        println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
        let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
        let headerhash = Sha256::digest(&canonicalized_header).to_vec();
        let public_key_n = {
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            match resolve_public_key(&logger, &email_bytes).await.unwrap() {
                cfdkim::DkimPublicKey::Rsa(_pk) => BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap(),
                _ => {
                    panic!("Only RSA keys are supported.");
                }
            }
        };
        let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
        let public_key = RSAPublicKey::<Fr>::new(Value::known(public_key_n.clone()), e);
        let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
        let header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
        let body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
        let app_config_path = "./configs/app_recursion_bench.config";
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some(app_config_path), move || {
            let app_config_params = read_default_circuit_config_params();
            let header_config = app_config_params.header_config.expect("header_config is required");
            let body_config = app_config_params.body_config.expect("body_config is required");
            let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes, body_config.substr_regexes);
            let circuit = DefaultEmailVerifyCircuit {
                header_bytes: canonicalized_header.clone(),
                body_bytes: canonicalized_body.clone(),
                public_key: public_key.clone(),
                signature: signature.clone(),
            };
            let public_input = DefaultEmailVerifyPublicInput::new(headerhash.clone(), public_key_n.clone(), header_substrs, body_substrs);
            let public_input_path = "./build/public_input.json";
            public_input.write_file(&public_input_path);
            let app_params_path = "./build/test_app.params";
            let agg_params_path = "./build/test_agg.params";
            gen_params(agg_params_path, 22).unwrap();
            downsize_params(agg_params_path, app_params_path, app_config_params.degree).unwrap();
            let app_pk_path = "./build/test_app.pk";
            let app_vk_path = "./build/test_app.vk";
            gen_app_key(app_params_path, app_config_path, app_pk_path, app_vk_path, circuit.clone()).unwrap();
            let agg_pk_path = "./build/test_agg.pk";
            let agg_vk_path = "./build/test_agg.vk";
            let agg_config_path = "./configs/agg_bench.config";
            gen_agg_key(
                app_params_path,
                agg_params_path,
                app_config_path,
                agg_config_path,
                app_pk_path,
                agg_pk_path,
                agg_vk_path,
                circuit.clone(),
            )
            .unwrap();
            let app_proof_path = "./build/test_agg.proof";
            prove_app(app_params_path, app_config_path, app_pk_path, app_proof_path, circuit.clone()).unwrap();
            let agg_evm_proof_path = "./build/test_agg_evm.hex";
            let agg_acc_path = "./build/test_agg_acc.hex";
            evm_prove_agg(
                app_params_path,
                agg_params_path,
                app_config_path,
                agg_config_path,
                app_pk_path,
                agg_pk_path,
                agg_acc_path,
                agg_evm_proof_path,
                circuit.clone(),
            )
            .unwrap();
            let bytecode_path = "./build/test_verifier.bin";
            let solidity_path = "./build/testVerifier.sol";
            gen_agg_evm_verifier(agg_params_path, app_config_path, agg_config_path, agg_vk_path, bytecode_path, solidity_path).unwrap();
            let instances = {
                let acc = {
                    let hex = fs::read_to_string(agg_acc_path).unwrap();
                    hex::decode(&hex[2..])
                        .unwrap()
                        .chunks(32)
                        .map(|bytes| {
                            let mut bytes = bytes.to_vec();
                            bytes.reverse();
                            Fr::from_bytes(bytes[..].try_into().unwrap()).unwrap()
                        })
                        .collect_vec()
                };
                assert_eq!(acc.len(), NUM_ACC_INSTANCES);
                let public_fr = DefaultEmailVerifyCircuit::<Fr>::get_instances_from_default_public_input(public_input_path);
                vec![acc, public_fr].concat()
            };
            evm_verify_agg(app_config_path, agg_config_path, bytecode_path, agg_evm_proof_path, instances).unwrap();
        });
    }
}
