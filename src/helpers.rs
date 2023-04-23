use crate::snark_verifier_sdk::*;
use crate::utils::{get_email_circuit_public_hash_input, get_email_substrs};
use crate::{DefaultEmailVerifyCircuit, EmailVerifyConfig, EMAIL_VERIFY_CONFIG_ENV};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;
use rand::rngs::OsRng;
use rand::thread_rng;
use regex_simple::Regex;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::loader::evm::{compile_yul, encode_calldata, EvmLoader};
// use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
// use snark_verifier::verifier::{Plonk as PlonkApp, PlonkVerifier};
// use snark_verifier_sdk::evm::{encode_calldata, evm_verify, gen_evm_proof, gen_evm_proof_shplonk};
// use snark_verifier_sdk::halo2::aggregation::PublicAggregationCircuit;
// use snark_verifier_sdk::halo2::gen_snark_shplonk;
// use snark_verifier_sdk::{gen_pk, CircuitExt, Plonk as PlonkAgg, LIMBS};
use snark_verifier::loader::LoadedScalar;
use std::env::set_var;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerifyPublicInput {
    pub headerhash: String,
    pub public_key_n_bytes: String,
    pub header_starts: Vec<usize>,
    pub header_substrs: Vec<String>,
    pub body_starts: Vec<usize>,
    pub body_substrs: Vec<String>,
}

pub fn gen_param(param_path: &str, k: u32) -> Result<(), Error> {
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    let f = File::create(param_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

pub async fn gen_app_key(param_path: &str, circuit_config_path: &str, email_path: &str, pk_path: &str, vk_path: &str) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let (circuit, _, _, _, _) = gen_circuit_from_email_path(email_path).await;
    let pk = gen_pk::<DefaultEmailVerifyCircuit<Fr>>(&params, &circuit);
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

pub async fn gen_agg_key(
    param_path: &str,
    circuit_config_path: &str,
    // agg_circuit_config_path: &str,
    email_path: &str,
    app_pk_path: &str,
    agg_pk_path: &str,
    agg_vk_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    // set_var("VERIFY_CONFIG", agg_circuit_config_path);
    let agg_params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    let app_params = {
        let mut params = agg_params.clone();
        params.downsize(app_config.degree);
        params
    };
    let (app_circuit, _, _, _, _) = gen_circuit_from_email_path(email_path).await;
    let app_pk = {
        let f = File::open(Path::new(app_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let snark = gen_application_snark(&app_params, &app_circuit, &app_pk);
    println!("snark generated");
    let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark]);
    let agg_pk = gen_pk::<PublicAggregationCircuit<DefaultEmailVerifyCircuit<Fr>>>(&agg_params, &agg_circuit);
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

pub async fn prove_app(param_path: &str, circuit_config_path: &str, pk_path: &str, email_path: &str, proof_path: &str, public_input_path: &str) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;

    let proof = gen_proof_native(&params, &pk, circuit);
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    let (header_starts, header_substrs): (Vec<usize>, Vec<String>) = header_substrs
        .into_iter()
        .map(|s| {
            let s = s.unwrap();
            (s.0, s.1)
        })
        .unzip();
    let (body_starts, body_substrs): (Vec<usize>, Vec<String>) = body_substrs
        .into_iter()
        .map(|s| {
            let s = s.unwrap();
            (s.0, s.1)
        })
        .unzip();
    let public_input = EmailVerifyPublicInput {
        headerhash: format!("0x{}", hex::encode(&headerhash)),
        public_key_n_bytes: format!("0x{}", hex::encode(&public_key_n.to_bytes_le())),
        header_starts,
        header_substrs,
        body_starts,
        body_substrs,
    };
    {
        let public_input_str = serde_json::to_string(&public_input).unwrap();
        let mut file = File::create(public_input_path)?;
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }
    Ok(())
}

pub async fn evm_prove_app(param_path: &str, circuit_config: &str, pk_path: &str, email_path: &str, proof_path: &str, public_input_path: &str) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    let mut params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let proof = gen_proof_evm(&params, &pk, circuit);
    {
        let proof_hex = hex::encode(&proof);
        let mut file = File::create(proof_path)?;
        write!(file, "0x{}", proof_hex).unwrap();
        file.flush().unwrap();
    };
    let (header_starts, header_substrs): (Vec<usize>, Vec<String>) = header_substrs
        .into_iter()
        .map(|s| {
            let s = s.unwrap();
            (s.0, s.1)
        })
        .unzip();
    let (body_starts, body_substrs): (Vec<usize>, Vec<String>) = body_substrs
        .into_iter()
        .map(|s| {
            let s = s.unwrap();
            (s.0, s.1)
        })
        .unzip();
    let public_input = EmailVerifyPublicInput {
        headerhash: format!("0x{}", hex::encode(&headerhash)),
        public_key_n_bytes: format!("0x{}", hex::encode(&public_key_n.to_bytes_le())),
        header_starts,
        header_substrs,
        body_starts,
        body_substrs,
    };
    {
        let public_input_str = serde_json::to_string(&public_input).unwrap();
        let mut file = File::create(public_input_path)?;
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }
    Ok(())
}

pub async fn evm_prove_agg(
    param_path: &str,
    circuit_config_path: &str,
    // agg_circuit_config_path: &str,
    email_path: &str,
    app_pk_path: &str,
    agg_pk_path: &str,
    acc_path: &str,
    proof_path: &str,
    public_input_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    // set_var("VERIFY_CONFIG", agg_circuit_config_path);
    let agg_params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    let app_params = {
        let mut params = agg_params.clone();
        params.downsize(app_config.degree);
        params
    };
    let (app_circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let app_pk = {
        let f = File::open(Path::new(app_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let snark = gen_application_snark(&app_params, &app_circuit, &app_pk);
    let agg_circuit = PublicAggregationCircuit::<DefaultEmailVerifyCircuit<Fr>>::new(&agg_params, vec![snark]);
    let agg_pk = {
        let f = File::open(Path::new(agg_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, PublicAggregationCircuit<DefaultEmailVerifyCircuit<Fr>>>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
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
    let proof = gen_proof_evm(&agg_params, &agg_pk, agg_circuit);
    {
        let proof_hex = hex::encode(&proof);
        let mut file = File::create(proof_path)?;
        write!(file, "0x{}", proof_hex).unwrap();
        file.flush().unwrap();
    };
    let (header_starts, header_substrs): (Vec<usize>, Vec<String>) = header_substrs
        .into_iter()
        .map(|s| {
            let s = s.unwrap();
            (s.0, s.1)
        })
        .unzip();
    let (body_starts, body_substrs): (Vec<usize>, Vec<String>) = body_substrs
        .into_iter()
        .map(|s| {
            let s = s.unwrap();
            (s.0, s.1)
        })
        .unzip();
    let public_input = EmailVerifyPublicInput {
        headerhash: format!("0x{}", hex::encode(&headerhash)),
        public_key_n_bytes: format!("0x{}", hex::encode(&public_key_n.to_bytes_le())),
        header_starts,
        header_substrs,
        body_starts,
        body_substrs,
    };
    {
        let public_input_str = serde_json::to_string(&public_input).unwrap();
        let mut file = File::create(public_input_path)?;
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }
    Ok(())
}

pub async fn gen_evm_verifier(param_path: &str, circuit_config: &str, vk_path: &str, bytecode_path: &str, solidity_path: &str) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    let mut params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    // let circuit = gen_circuit_from_email_path(email_path).await;
    // let num_instance = DefaultEmailVerifyCircuit::<Fr>::num_instances(0);
    let verifier_yul = gen_app_evm_verifier_yul::<DefaultEmailVerifyCircuit<Fr>>(&params, &vk);
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

pub async fn gen_agg_evm_verifier(
    param_path: &str,
    circuit_config: &str,
    // agg_circuit_config: &str,
    vk_path: &str,
    bytecode_path: &str,
    solidity_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    // set_var("VERIFY_CONFIG", agg_circuit_config);
    let params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, PublicAggregationCircuit<DefaultEmailVerifyCircuit<Fr>>>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let verifier_yul = gen_aggregation_evm_verifier_yul::<DefaultEmailVerifyCircuit<Fr>>(&params, &vk, 1);
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

pub fn evm_verify_app(circuit_config: &str, bytecode_path: &str, proof_path: &str, public_input_path: &str) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
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
    let instances = {
        let public_input = serde_json::from_reader::<File, EmailVerifyPublicInput>(File::open(public_input_path).unwrap()).unwrap();
        let config_params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
        let headerhash = hex::decode(&public_input.headerhash[2..]).unwrap();
        let public_key_n_bytes = hex::decode(&public_input.public_key_n_bytes[2..]).unwrap();
        let header_substrs = public_input
            .header_starts
            .into_iter()
            .zip(public_input.header_substrs.into_iter())
            .map(|(start, substr)| Some((start, substr)))
            .collect_vec();
        let body_substrs = public_input
            .body_starts
            .into_iter()
            .zip(public_input.body_substrs.into_iter())
            .map(|(start, substr)| Some((start, substr)))
            .collect_vec();
        let public_hash_input = get_email_circuit_public_hash_input(
            &headerhash,
            &public_key_n_bytes,
            header_substrs,
            body_substrs,
            config_params.header_max_byte_size,
            config_params.body_max_byte_size,
        );
        let public_hash: Vec<u8> = Sha256::digest(&public_hash_input).to_vec();
        let public_fr = {
            let lo = Fr::from_u128(u128::from_le_bytes(public_hash[0..16].try_into().unwrap()));
            let mut hi_bytes = [0; 16];
            for idx in 0..15 {
                hi_bytes[idx] = public_hash[16 + idx];
            }
            let hi = Fr::from_u128(u128::from_le_bytes(hi_bytes));
            hi * Fr::from(2).pow_const(128) + lo
        };
        vec![public_fr]
    };
    println!("instances {:?}", instances);
    evm_verify(deployment_code, vec![instances], proof);
    Ok(())
}

pub fn evm_verify_agg(
    circuit_config: &str,
    // agg_circuit_config: &str,
    bytecode_path: &str,
    proof_path: &str,
    acc_path: &str,
    public_input_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    // set_var("VERIFY_CONFIG", agg_circuit_config);
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
    let instances = {
        let acc = {
            let hex = fs::read_to_string(acc_path).unwrap();
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
        let public_input = serde_json::from_reader::<File, EmailVerifyPublicInput>(File::open(public_input_path).unwrap()).unwrap();
        let headerhash = hex::decode(&public_input.headerhash[2..]).unwrap();
        let public_key_n_bytes = hex::decode(&public_input.public_key_n_bytes[2..]).unwrap();
        let config_params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
        let header_substrs = public_input
            .header_starts
            .into_iter()
            .zip(public_input.header_substrs.into_iter())
            .map(|(start, substr)| Some((start, substr)))
            .collect_vec();
        let body_substrs = public_input
            .body_starts
            .into_iter()
            .zip(public_input.body_substrs.into_iter())
            .map(|(start, substr)| Some((start, substr)))
            .collect_vec();
        let public_hash_input = get_email_circuit_public_hash_input(
            &headerhash,
            &public_key_n_bytes,
            header_substrs,
            body_substrs,
            config_params.header_max_byte_size,
            config_params.body_max_byte_size,
        );
        let public_hash: Vec<u8> = Sha256::digest(&public_hash_input).to_vec();
        let public_fr = {
            let lo = Fr::from_u128(u128::from_le_bytes(public_hash[0..16].try_into().unwrap()));
            let mut hi_bytes = [0; 16];
            for idx in 0..15 {
                hi_bytes[idx] = public_hash[16 + idx];
            }
            let hi = Fr::from_u128(u128::from_le_bytes(hi_bytes));
            hi * Fr::from(2).pow_const(128) + lo
        };
        vec![acc, vec![public_fr]].concat()
    };
    println!("instances {:?}", instances);
    evm_verify(deployment_code, vec![instances], proof);
    Ok(())
}

async fn gen_circuit_from_email_path(email_path: &str) -> (DefaultEmailVerifyCircuit<Fr>, Vec<u8>, BigUint, Vec<Option<(usize, String)>>, Vec<Option<(usize, String)>>) {
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
    let config_params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
    let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, config_params.header_substr_regexes, config_params.body_substr_regexes);
    let circuit = DefaultEmailVerifyCircuit {
        header_bytes: canonicalized_header,
        body_bytes: canonicalized_body,
        public_key,
        signature,
    };
    (circuit, headerhash, public_key_n, header_substrs, body_substrs)
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
    println!("num_pubinputs {}", num_pubinputs);

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
