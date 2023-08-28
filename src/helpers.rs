use crate::eth::deploy_and_call_verifiers;
// use crate::snark_verifier_sdk::*;
use crate::eth::gen_verifier::gen_sol_verifiers;
use crate::{default_config_params, DefaultEmailVerifyPublicInput};
// use crate::eth::{gen_evm_verifier_sols, gen_evm_verifier_yul};
use crate::utils::get_email_substrs;
use crate::vrm::DecomposedRegexConfig;
use crate::EMAIL_VERIFY_CONFIG_ENV;
use ark_std::{end_timer, start_timer};
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use ethereum_types::Address;
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{verify_proof, Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_base::halo2_proofs::poly::VerificationStrategy;
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
use snark_verifier_sdk::evm::gen_evm_proof_shplonk;
// use snark_verifier_sdk::evm::{encode_calldata, gen_evm_proof_shplonk};
use snark_verifier_sdk::halo2::aggregation::PublicAggregationCircuit;
use snark_verifier_sdk::halo2::{gen_proof_shplonk, gen_snark_shplonk, PoseidonTranscript};
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use snark_verifier_sdk::{NativeLoader, Plonk};
use std::env::set_var;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

// /// The number of limbs of the accumulator in the aggregation circuit.
// pub const NUM_ACC_INSTANCES: usize = 4 * LIMBS;
// /// The name of env variable for the path to the configuration json of the aggregation circuit.
// pub const VERIFY_CONFIG_KEY: &'static str = "VERIFY_CONFIG";

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
pub fn gen_keys<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, vk_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);

    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = default_config_params();
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

// /// Generate proving and verifying keys for the aggregation circuit.
// ///
// /// # Arguments
// /// * `app_params_path` - a file path of the SRS parameters for the email verification circuit.
// /// * `agg_params_path` - a file path of the SRS parameters for the aggregation circuit.
// /// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
// /// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
// /// * `app_pk_path` - a file path of the proving key for the email verification circuit.
// /// * `agg_pk_path` - a file path of the output proving key for the aggregation circuit.
// /// * `agg_vk_path` - a file path of the output verifying key for the aggregation circuit.
// /// * `app_circuit` - an email verification circuit.
// pub fn gen_agg_key<C: CircuitExt<Fr>>(
//     app_params_path: &str,
//     agg_params_path: &str,
//     app_circuit_config_path: &str,
//     agg_circuit_config_path: &str,
//     app_pk_path: &str,
//     agg_pk_path: &str,
//     agg_vk_path: &str,
//     app_circuit: C,
// ) -> Result<(), Error> {
//     set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
//     set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
//     let agg_params = {
//         let f = File::open(Path::new(agg_params_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     let app_params = {
//         let f = File::open(Path::new(app_params_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     let app_pk = {
//         let f = File::open(Path::new(app_pk_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
//     };
//     let snark = gen_snark_shplonk(&app_params, &app_pk, app_circuit, &mut OsRng, None::<&str>);
//     println!("snark generated");
//     let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
//     let agg_pk = gen_pk::<PublicAggregationCircuit>(&agg_params, &agg_circuit, None);
//     println!("agg pk generated");
//     {
//         let f = File::create(agg_pk_path).unwrap();
//         let mut writer = BufWriter::new(f);
//         agg_pk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
//         writer.flush().unwrap();
//     }

//     let vk = agg_pk.get_vk();
//     {
//         let f = File::create(agg_vk_path).unwrap();
//         let mut writer = BufWriter::new(f);
//         vk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
//         writer.flush().unwrap();
//     }
//     Ok(())
// }

/// Generate a proof for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `pk_path` - a file path of the proving key.
/// * `proof_path` - a file path of the output proof.
/// * `circuit` - an email verification circuit.
pub fn prove<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, proof_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = default_config_params();
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

/// Verify a proof for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `vk_path` - a file path of the verifying key.
/// * `proof_path` - a file path of the proof.
/// * `public_input_path` - a file path of the public input.
/// # Return values
/// Return `true` if the proof is valid, otherwise `false`.
pub fn verify<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, vk_path: &str, proof_path: &str, public_input_path: &str) -> Result<bool, Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(Path::new(vk_path)).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let proof = {
        let mut f = File::open(&proof_path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    let public_input = serde_json::from_reader::<_, DefaultEmailVerifyPublicInput>(File::open(public_input_path).unwrap()).unwrap();
    let instances = public_input.instances::<Fr>();
    let result = {
        let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::new(&proof);
        VerificationStrategy::<_, VerifierSHPLONK<Bn256>>::finalize(verify_proof::<_, VerifierSHPLONK<Bn256>, _, _, _>(
            params.verifier_params(),
            &vk,
            AccumulatorStrategy::new(params.verifier_params()),
            &[&[instances.as_slice()]],
            &mut transcript_read,
        )?)
    };
    Ok(result)
}

/// Generate a proof for the email verification circuit verifiable on EVM.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `pk_path` - a file path of the proving key.
/// * `proof_path` - a file path of the output proof.
/// * `circuit` - an email verification circuit.
pub fn evm_prove<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, proof_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = default_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    // let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let timer = start_timer!(|| "generate evm proof");
    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances, &mut OsRng);
    end_timer!(timer);
    {
        // let proof_hex = hex::encode(&proof);
        // let mut file = File::create(proof_path)?;
        // write!(file, "0x{}", proof_hex).unwrap();
        // file.flush().unwrap();
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    Ok(())
}

// /// Generate proving and verifying keys of the aggregation circuit verifiable on EVM..
// ///
// /// # Arguments
// /// * `app_params_path` - a file path of the SRS parameters for the email verification circuit.
// /// * `agg_params_path` - a file path of the SRS parameters for the aggregation circuit.
// /// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
// /// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
// /// * `app_pk_path` - a file path of the proving key for the email verification circuit.
// /// * `agg_pk_path` - a file path of the proving key for the aggregation circuit.
// /// * `acc_path` - a file path of the output accumulator for the aggregation circuit.
// /// * `proof_path` - a file path of the output proof for the aggregation circuit.
// /// * `app_circuit` - an email verification circuit.
// pub fn evm_prove_agg<C: CircuitExt<Fr>>(
//     app_params_path: &str,
//     agg_params_path: &str,
//     app_circuit_config_path: &str,
//     agg_circuit_config_path: &str,
//     app_pk_path: &str,
//     agg_pk_path: &str,
//     acc_path: &str,
//     proof_path: &str,
//     app_circuit: C,
//     // public_input_path: &str,
// ) -> Result<(), Error> {
//     set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
//     set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
//     let agg_params = {
//         let f = File::open(Path::new(agg_params_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     let app_params = {
//         let f = File::open(Path::new(app_params_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     // let (app_circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
//     let app_pk = {
//         let f = File::open(Path::new(app_pk_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
//     };
//     let snark = gen_snark_shplonk(&app_params, &app_pk, app_circuit, &mut OsRng, None::<&str>);
//     println!("snark generated");
//     let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
//     let agg_pk = {
//         let f = File::open(Path::new(agg_pk_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ProvingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
//     };
//     let instances = agg_circuit.instances();
//     println!("instances {:?}", instances[0]);

//     let acc = encode_calldata(&[instances[0][0..NUM_ACC_INSTANCES].to_vec()], &[]);
//     {
//         let acc_hex = hex::encode(&acc);
//         let mut file = File::create(acc_path)?;
//         write!(file, "0x{}", acc_hex).unwrap();
//         file.flush().unwrap();
//     };
//     let proof = gen_evm_proof_shplonk(&agg_params, &agg_pk, agg_circuit, instances, &mut OsRng);
//     println!("proof generated");
//     {
//         let proof_hex = hex::encode(&proof);
//         let mut file = File::create(proof_path)?;
//         write!(file, "0x{}", proof_hex).unwrap();
//         file.flush().unwrap();
//     };
//     Ok(())
// }

/// Generate yul and Solidity code of the verifier contract for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `vk_path` - a file path of the verifying key.
/// * `sols_path` - a directory path of the output Solidity codes.
/// * `max_line_size_per_file` - the maximum bytes size of each output Solidity code.
pub fn gen_evm_verifier<C: CircuitExt<Fr>>(
    params_path: &str,
    circuit_config_path: &str,
    vk_path: &str,
    sols_dir: &str,
    max_line_size_per_file: Option<usize>,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = default_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let max_line_size_per_file = max_line_size_per_file.unwrap_or(100 * 1000);
    if PathBuf::new().join(sols_dir).exists() {
        fs::remove_dir_all(sols_dir).unwrap();
    }
    gen_sol_verifiers(&params, &vk, max_line_size_per_file, &PathBuf::new().join(sols_dir));
    Ok(())
}

// /// Generate yul and Solidity code of the verifier contract for the aggregation circuit.
// ///
// /// # Arguments
// /// * `agg_params_path` - a file path of the SRS parameters for the aggregation circuit.
// /// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
// /// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
// /// * `agg_vk_path` - a file path of the verifying key for the aggregation circuit.
// /// * `bytecode_path` - a file path of the output yul bytecode.
// /// * `solidity_path` - a file path of the output Solidity code.
// pub fn gen_agg_evm_verifier(
//     agg_params_path: &str,
//     app_circuit_config_path: &str,
//     agg_circuit_config_path: &str,
//     vk_path: &str,
//     bytecode_path: &str,
//     solidity_path: &str,
// ) -> Result<(), Error> {
//     set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
//     set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
//     let params = {
//         let f = File::open(Path::new(agg_params_path)).unwrap();
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     let vk = {
//         let f = File::open(vk_path).unwrap();
//         let mut reader = BufReader::new(f);
//         VerifyingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
//     };
//     let num_instance = vec![1 + NUM_ACC_INSTANCES];
//     let verifier_yul = gen_evm_verifier_yul::<PublicAggregationCircuit>(&params, &vk, num_instance);
//     {
//         let bytecode = compile_yul(&verifier_yul);
//         let f = File::create(bytecode_path).unwrap();
//         let mut writer = BufWriter::new(f);
//         writer.write_all(&bytecode).unwrap();
//         writer.flush().unwrap();
//     }
//     {
//         // let mut f = File::create(solidity_path).unwrap();
//         // let _ = f.write(verifier_yul.as_bytes());
//         // let output = fix_verifier_sol(Path::new(solidity_path).to_path_buf()).unwrap();

//         // let mut f = File::create(solidity_path)?;
//         // let _ = f.write(output.as_bytes());
//         let mut f = File::create(solidity_path).unwrap();
//         let _ = f.write(verifier_yul.as_bytes());
//         fs::create_dir(solidity_path).expect("failed to create solidity_path dir");
//         let yul_file_path = PathBuf::new().join(solidity_path).join("verifier.yul");
//         let mut yul_file = File::create(&yul_file_path).unwrap();
//         yul_file.write(verifier_yul.as_bytes())?;
//         gen_evm_verifier_sols(yul_file_path, 100, PathBuf::new().join(solidity_path)).unwrap();
//     };
//     Ok(())
// }

/// Verify an given evm-proof and instances with the yul bytecode of the verifier contract for the email verification circuit.
///
/// # Arguments
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `sols_dir` - a directory path of
/// * `proof_path` - a file path of the proof for the email verification circuit.
/// * `instances` - instances (public inputs) for the email verification circuit.
///
/// # Note
/// The contract size limitation is disabled in this function.
/// Therefore, your verifier contract may violate that limitation even if it passes the verification here.
pub async fn evm_verify(circuit_config_path: &str, sols_dir: &str, proof_path: &str, public_input_path: &str) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let proof = {
        let mut f = File::open(&proof_path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    println!("proof {}", hex::encode(&proof));
    let public_input = serde_json::from_reader(File::open(public_input_path).unwrap()).unwrap();
    println!("public_input {:?}", public_input);
    deploy_and_call_verifiers(&PathBuf::new().join(sols_dir), None, &proof, &public_input).await;
    Ok(())
}

// /// Verify an given evm-proof and instances with the yul bytecode of the verifier contract for the aggregation circuit.
// ///
// /// # Arguments
// /// * `app_circuit_config_path` - a file path of the configuration of the email verification circuit.
// /// * `agg_circuit_config_path` - a file path of the configuration of the aggregation circuit.
// /// * `bytecode_path` - a file path of the yul bytecode.
// /// * `proof_path` - a file path of the proof for the aggregation circuit.
// /// * `instances` - instances (public inputs) for the email verification circuit and the aggregation circuit. (It must include the accumulator of the aggregation circuit.)
// ///
// /// # Note
// /// The contract size limitation is disabled in this function.
// /// Therefore, your verifier contract may violate that limitation even if it passes the verification here.
// pub fn evm_verify_agg(app_circuit_config_path: &str, agg_circuit_config_path: &str, bytecode_path: &str, proof_path: &str, instances: Vec<Fr>) -> Result<(), Error> {
//     set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
//     set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
//     let deployment_code = {
//         let f = File::open(bytecode_path).unwrap();
//         let mut reader = BufReader::new(f);
//         let mut code = vec![];
//         reader.read_to_end(&mut code).unwrap();
//         code
//     };
//     let proof = {
//         let hex = fs::read_to_string(proof_path).unwrap();
//         hex::decode(&hex[2..]).unwrap()
//     };
//     println!("instances {:?}", instances);
//     evm_verify(deployment_code, false, vec![instances], proof);
//     Ok(())
// }

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
        let public_key_n = {
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            match resolve_public_key(&logger, &email_bytes).await.unwrap() {
                cfdkim::DkimPublicKey::Rsa(_pk) => BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap(),
                _ => {
                    panic!("Only RSA keys are supported.");
                }
            }
        };
        // let header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
        // let body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
        let circuit_config_path = "./configs/app_bench.config";
        let public_input_path = "./build/public_input.json";
        let params_path = "./build/test.params";
        let pk_path = "./build/test.pk";
        let vk_path = "./build/test.vk";
        let proof_path = "./build/test.proof";
        let evm_proof_path = "./build/test_evm.proof";
        let sols_dir = "./build/test_sols";
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some(circuit_config_path), move || {
            let config_params = default_config_params();
            // let (header_: &crate::BodyConfigParamssubstrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes.clone(), body_config.substr_regexes.clone());
            let circuit = DefaultEmailVerifyCircuit::new(email_bytes.clone(), public_key_n.clone());
            let public_input = circuit.gen_default_public_input();
            public_input.write_file(&public_input_path);
            gen_params(params_path, config_params.degree).unwrap();
            gen_keys(params_path, circuit_config_path, pk_path, vk_path, circuit.clone()).unwrap();
            prove(params_path, circuit_config_path, pk_path, proof_path, circuit.clone()).unwrap();
            let result = verify::<DefaultEmailVerifyCircuit<Fr>>(params_path, circuit_config_path, vk_path, proof_path, public_input_path).unwrap();
            assert!(result);
            evm_prove(params_path, circuit_config_path, pk_path, evm_proof_path, circuit.clone()).unwrap();
            gen_evm_verifier::<DefaultEmailVerifyCircuit<Fr>>(params_path, circuit_config_path, vk_path, sols_dir, None).unwrap();
        });
        evm_verify(circuit_config_path, sols_dir, evm_proof_path, public_input_path).await.unwrap();
    }

    // #[ignore]
    // #[tokio::test]
    // async fn test_helper_agg_circuit() {
    //     gen_regex_files("./test_data/bodyhash_defs.json", "./test_data", "body_hash").unwrap();
    //     gen_regex_files("./test_data/from_defs.json", "./test_data", "from").unwrap();
    //     gen_regex_files("./test_data/to_defs.json", "./test_data", "to").unwrap();
    //     gen_regex_files("./test_data/subject_defs.json", "./test_data", "subject").unwrap();
    //     gen_regex_files("./test_data/test_ex1_email_body_defs.json", "./test_data", "test_ex1_email_body").unwrap();
    //     let email_path = "./test_data/test_email1.eml";
    //     let email_bytes = {
    //         let mut f = File::open(email_path).unwrap();
    //         let mut buf = Vec::new();
    //         f.read_to_end(&mut buf).unwrap();
    //         buf
    //     };
    //     println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
    //     let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
    //     let headerhash = Sha256::digest(&canonicalized_header).to_vec();
    //     let public_key_n = {
    //         let logger = slog::Logger::root(slog::Discard, slog::o!());
    //         match resolve_public_key(&logger, &email_bytes).await.unwrap() {
    //             cfdkim::DkimPublicKey::Rsa(_pk) => BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap(),
    //             _ => {
    //                 panic!("Only RSA keys are supported.");
    //             }
    //         }
    //     };
    //     let header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
    //     let body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
    //     let app_config_path = "./configs/app_recursion_bench.config";
    //     temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some(app_config_path), move || {
    //         let app_config_params = read_default_circuit_config_params();
    //         let header_config = app_config_params.header_config.expect("header_config is required");
    //         let body_config = app_config_params.body_config.expect("body_config is required");
    //         let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes, body_config.substr_regexes);
    //         let circuit = DefaultEmailVerifyCircuit::new(email_bytes.clone(), public_key_n.clone());
    //         let public_input = DefaultEmailVerifyPublicInput::new(headerhash.clone(), public_key_n.clone(), header_substrs, body_substrs);
    //         let public_input_path = "./build/public_input.json";
    //         public_input.write_file(&public_input_path);
    //         let app_params_path = "./build/test_app.params";
    //         let agg_params_path = "./build/test_agg.params";
    //         gen_params(agg_params_path, 22).unwrap();
    //         downsize_params(agg_params_path, app_params_path, app_config_params.degree).unwrap();
    //         let app_pk_path = "./build/test_app.pk";
    //         let app_vk_path = "./build/test_app.vk";
    //         gen_app_key(app_params_path, app_config_path, app_pk_path, app_vk_path, circuit.clone()).unwrap();
    //         let agg_pk_path = "./build/test_agg.pk";
    //         let agg_vk_path = "./build/test_agg.vk";
    //         let agg_config_path = "./configs/agg_bench.config";
    //         gen_agg_key(
    //             app_params_path,
    //             agg_params_path,
    //             app_config_path,
    //             agg_config_path,
    //             app_pk_path,
    //             agg_pk_path,
    //             agg_vk_path,
    //             circuit.clone(),
    //         )
    //         .unwrap();
    //         let app_proof_path = "./build/test_agg.proof";
    //         prove_app(app_params_path, app_config_path, app_pk_path, app_proof_path, circuit.clone()).unwrap();
    //         let agg_evm_proof_path = "./build/test_agg_evm.hex";
    //         let agg_acc_path = "./build/test_agg_acc.hex";
    //         evm_prove_agg(
    //             app_params_path,
    //             agg_params_path,
    //             app_config_path,
    //             agg_config_path,
    //             app_pk_path,
    //             agg_pk_path,
    //             agg_acc_path,
    //             agg_evm_proof_path,
    //             circuit.clone(),
    //         )
    //         .unwrap();
    //         let bytecode_path = "./build/test_verifier.bin";
    //         let solidity_path = "./build/testVerifier.sol";
    //         gen_agg_evm_verifier(agg_params_path, app_config_path, agg_config_path, agg_vk_path, bytecode_path, solidity_path).unwrap();
    //         let instances = {
    //             let acc = {
    //                 let hex = fs::read_to_string(agg_acc_path).unwrap();
    //                 hex::decode(&hex[2..])
    //                     .unwrap()
    //                     .chunks(32)
    //                     .map(|bytes| {
    //                         let mut bytes = bytes.to_vec();
    //                         bytes.reverse();
    //                         Fr::from_bytes(bytes[..].try_into().unwrap()).unwrap()
    //                     })
    //                     .collect_vec()
    //             };
    //             assert_eq!(acc.len(), NUM_ACC_INSTANCES);
    //             let public_fr = DefaultEmailVerifyCircuit::<Fr>::get_instances_from_default_public_input(public_input_path);
    //             vec![acc, public_fr].concat()
    //         };
    //         evm_verify_agg(app_config_path, agg_config_path, bytecode_path, agg_evm_proof_path, instances).unwrap();
    //     });
    // }
}
