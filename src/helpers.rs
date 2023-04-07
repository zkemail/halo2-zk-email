use crate::{
    recursion_and_evm::*, DefaultEmailVerifyCircuit, EmailVerifyConfig, EMAIL_VERIFY_CONFIG_ENV,
};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use clap::{Parser, Subcommand};
use fancy_regex::Regex;
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::Params;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;
use rand::thread_rng;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use std::env::set_var;
use std::fmt::format;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSubstrs {
    header: Vec<(usize, String)>,
    body: Vec<(usize, String)>,
}

pub fn gen_params(
    params_dir: &str,
    app_k: u32,
    app_to_agg_k: Option<u32>,
    agg_to_agg_k: Option<u32>,
) -> Result<(), Error> {
    let rng = thread_rng();
    let mut max_k = app_k;
    if let Some(k) = app_to_agg_k {
        if k > max_k {
            max_k = k;
        }
    }
    if let Some(k) = agg_to_agg_k {
        if k > max_k {
            max_k = k;
        }
    }
    let max_params = ParamsKZG::<Bn256>::setup(max_k, rng);
    for (path, k) in [
        ("app.bin", Some(app_k)),
        ("app_to_agg.bin", app_to_agg_k),
        ("agg_to_agg.bin", agg_to_agg_k),
    ] {
        let path = Path::new(params_dir).join(path);
        match k {
            Some(k) => {
                let _params = if k == max_k {
                    max_params.clone()
                } else {
                    let mut _params = max_params.clone();
                    _params.downsize(k);
                    _params
                };
                let f = File::create(path).unwrap();
                let mut writer = BufWriter::new(f);
                _params.write(&mut writer).unwrap();
                writer.flush().unwrap();
            }
            None => {
                continue;
            }
        };
    }
    Ok(())
}

pub fn gen_keys(
    params_dir: &str,
    circuit_config: &str,
    log2_proofs: u32,
    pks_dir: &str,
    vk: &str,
    num_instances: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    let circuit = DefaultEmailVerifyCircuit::<Fr>::random();
    let [app_params, app_to_agg_params, agg_to_agg_params] =
        ["app.bin", "app_to_agg.bin", "agg_to_agg.bin"].map(|path| {
            let path = Path::new(params_dir).join(path);
            match File::open(path) {
                Ok(f) => {
                    let mut reader = BufReader::new(f);
                    Some(ParamsKZG::<Bn256>::read(&mut reader).unwrap())
                }
                Err(_) => None,
            }
        });
    let (pks, _num_instances) = gen_multi_layer_proving_keys(
        &app_params.expect("app_params should not be null."),
        app_to_agg_params.as_ref(),
        agg_to_agg_params.as_ref(),
        &circuit,
        log2_proofs,
    );
    let lask_vk = pks[pks.len() - 1].get_vk();
    let pks_path = Path::new(pks_dir);
    for (idx, pk) in pks.iter().enumerate() {
        let pk_path = pks_path.join(format!("layer_{}.pk", idx));
        let f = File::create(pk_path).unwrap();
        let mut writer = BufWriter::new(f);
        pk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
        writer.flush().unwrap();
    }
    {
        let f = File::create(vk).unwrap();
        let mut writer = BufWriter::new(f);
        lask_vk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
        writer.flush().unwrap();
    }
    {
        let num_instances_json = serde_json::to_string(&_num_instances).unwrap();
        let mut f = File::create(num_instances).unwrap();
        write!(f, "{}", num_instances_json).unwrap();
        f.flush().unwrap();
    }
    Ok(())
}

pub async fn prove_single_email(
    app_params: &str,
    circuit_config: &str,
    email: &str,
    layer0_pk: &str,
    is_evm_verified: bool,
    proof: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    let email_bytes = {
        let mut f = File::open(email).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    let (canonicalized_header, canonicalized_body, signature_bytes) =
        canonicalize_signed_email(&email_bytes).unwrap();
    let app_params = {
        let f = File::open(app_params).expect(&format!("{} does not exist.", app_params));
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let public_key = {
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        match resolve_public_key(&logger, &email_bytes).await.unwrap() {
            cfdkim::DkimPublicKey::Rsa(_pk) => {
                let n = BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap();
                let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
                RSAPublicKey::<Fr>::new(Value::known(n), e)
            }
            _ => {
                panic!("Only RSA keys are supported.");
            }
        }
    };
    let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    let circuit = DefaultEmailVerifyCircuit {
        header_bytes: canonicalized_header,
        body_bytes: canonicalized_body,
        public_key,
        signature,
    };
    let pk = {
        let f = File::open(layer0_pk).expect(&format!("{} does not exist.", layer0_pk));
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytes,
        )
        .unwrap()
    };
    let _proof = if is_evm_verified {
        prove_multi_layer_evm(&app_params, None, None, &[circuit], &[pk], 0).0
    } else {
        gen_snark(&app_params, circuit, &pk).proof
    };
    {
        let f = File::create(proof).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&_proof).unwrap();
        writer.flush().unwrap();
    }
    Ok(())
}

pub async fn prove_multi_evm(
    params_dir: &str,
    circuit_config: &str,
    pks_dir: &str,
    emails_dir: &str,
    log2_proofs: u32,
    proof: &str,
    public_inputs: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    let [app_params, app_to_agg_params, agg_to_agg_params] =
        ["app.bin", "app_to_agg.bin", "agg_to_agg.bin"].map(|path| {
            let path = Path::new(params_dir).join(path);
            match File::open(path) {
                Ok(f) => {
                    let mut reader = BufReader::new(f);
                    Some(ParamsKZG::<Bn256>::read(&mut reader).unwrap())
                }
                Err(_) => None,
            }
        });
    let email_pathes = fs::read_dir(emails_dir).expect(&format!("{} does not exist.", emails_dir));
    let mut circuits = vec![];
    for path_result in email_pathes {
        let email_bytes = {
            let mut f = File::open(path_result.unwrap().path()).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };
        let (canonicalized_header, canonicalized_body, signature_bytes) =
            canonicalize_signed_email(&email_bytes).unwrap();
        let public_key = {
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            match resolve_public_key(&logger, &email_bytes).await.unwrap() {
                cfdkim::DkimPublicKey::Rsa(_pk) => {
                    let n = BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap();
                    let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
                    RSAPublicKey::<Fr>::new(Value::known(n), e)
                }
                _ => {
                    panic!("Only RSA keys are supported.");
                }
            }
        };
        let signature =
            RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
        let circuit = DefaultEmailVerifyCircuit {
            header_bytes: canonicalized_header,
            body_bytes: canonicalized_body,
            public_key,
            signature,
        };
        circuits.push(circuit);
    }
    assert_eq!(circuits.len(), 2usize.pow(log2_proofs));
    let mut email_substrs = vec![];
    for circuit in circuits.iter() {
        let (header, body) = circuit.get_substrs();
        email_substrs.push(EmailSubstrs { header, body });
    }
    let pks = (0..log2_proofs + 1)
        .map(|idx| {
            let pk_path = Path::new(pks_dir).join(format!("layer_{}.pk", idx));
            let f = File::open(pk_path).unwrap();
            let mut reader = BufReader::new(f);
            ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
                &mut reader,
                SerdeFormat::RawBytes,
            )
            .unwrap()
        })
        .collect_vec();
    let (_proof, _) = prove_multi_layer_evm(
        &app_params.expect("app_params should not be null."),
        app_to_agg_params.as_ref(),
        agg_to_agg_params.as_ref(),
        &circuits,
        &pks,
        log2_proofs,
    );
    {
        let f = File::create(proof).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&_proof).unwrap();
        writer.flush().unwrap();
    }
    {
        let substrs_json = serde_json::to_string(&email_substrs).unwrap();
        let mut f = File::create(public_inputs).unwrap();
        write!(f, "{}", substrs_json).unwrap();
        f.flush().unwrap();
    }
    Ok(())
}

pub fn gen_evm_verifier(
    params_dir: &str,
    vk: &str,
    log2_proofs: u32,
    num_instances: &str,
    evm_verifier: &str,
) -> Result<(), Error> {
    let params = {
        let filepath = if log2_proofs == 0 {
            "app.bin"
        } else if log2_proofs == 1 {
            "app_to_agg.bin"
        } else {
            "agg_to_agg.bin"
        };
        let path = Path::new(params_dir).join(filepath);
        let f = File::open(path).expect(&format!(
            "The {} params is required for log2_proofs = {}",
            filepath, log2_proofs
        ));
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk).unwrap();
        let mut reader = BufReader::new(f);
        if log2_proofs == 0 {
            VerifyingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
                &mut reader,
                SerdeFormat::RawBytes,
            )
            .unwrap()
        } else {
            VerifyingKey::<G1Affine>::read::<_, AggregationCircuit>(
                &mut reader,
                SerdeFormat::RawBytes,
            )
            .unwrap()
        }
    };
    let num_instances = {
        let json =
            fs::read_to_string(num_instances).expect(&format!("{} is not found", num_instances));
        serde_json::from_str(&json).unwrap()
    };
    let verifier = gen_multi_layer_evm_verifier::<DefaultEmailVerifyCircuit<Fr>>(
        &params,
        &vk,
        num_instances,
        log2_proofs,
    );
    let verifier_str = "0x".to_string() + &hex::encode(verifier);
    {
        let mut f = File::create(evm_verifier).unwrap();
        write!(f, "{}", verifier_str).unwrap();
        f.flush().unwrap();
    }
    Ok(())
}
