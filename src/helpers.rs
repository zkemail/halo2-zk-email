use crate::{
    recursion_and_evm::*, DefaultEmailVerifyCircuit, EmailVerifyConfig, EMAIL_VERIFY_CONFIG_ENV,
};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use clap::{Parser, Subcommand};
use fancy_regex::Regex;
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, VerifyingKey,
};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;
use rand::rngs::OsRng;
use rand::thread_rng;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::loader::evm::EvmLoader;
use snark_verifier::pcs::kzg::{Gwc19, Kzg};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier::verifier::PlonkVerifier;
use snark_verifier_sdk::evm::{encode_calldata, gen_evm_proof, gen_evm_proof_gwc};
use snark_verifier_sdk::halo2::aggregation::{AggregationCircuit, PublicAggregationCircuit};
use snark_verifier_sdk::halo2::gen_snark_gwc;
use snark_verifier_sdk::{gen_pk, CircuitExt, Plonk, LIMBS};
use std::env::set_var;
use std::fmt::format;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSubstrs {
    header: Vec<(usize, String)>,
    body: Vec<(usize, String)>,
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

pub async fn gen_app_key(
    param_path: &str,
    circuit_config_path: &str,
    email_path: &str,
    pk_path: &str,
    vk_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let circuit = gen_circuit_from_email_path(email_path).await;
    let pk = gen_pk::<DefaultEmailVerifyCircuit<Fr>>(&params, &circuit, Some(&Path::new(pk_path)));
    println!("app pk generated");

    let vk = pk.get_vk();
    {
        let f = File::create(vk_path).unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
            .unwrap();
        writer.flush().unwrap();
    }
    Ok(())
}

pub async fn gen_agg_key(
    app_param_path: &str,
    agg_param_path: &str,
    app_circuit_config_path: &str,
    agg_circuit_config_path: &str,
    email_path: &str,
    app_pk_path: &str,
    agg_pk_path: &str,
    agg_vk_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
    set_var("VERIFY_CONFIG", agg_circuit_config_path);
    let app_params = {
        let f = File::open(Path::new(app_param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let agg_params = {
        let f = File::open(Path::new(agg_param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_circuit = gen_circuit_from_email_path(email_path).await;
    let app_pk = {
        let f = File::open(Path::new(app_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let snark = gen_snark_gwc(
        &app_params,
        &app_pk,
        app_circuit.clone(),
        &mut OsRng,
        None::<&str>,
    );
    println!("snark generated");
    let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
    let agg_pk =
        gen_pk::<PublicAggregationCircuit>(&agg_params, &agg_circuit, Some(Path::new(agg_pk_path)));
    println!("agg pk generated");

    let vk = agg_pk.get_vk();
    {
        let f = File::create(agg_vk_path).unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
            .unwrap();
        writer.flush().unwrap();
    }
    Ok(())
}

pub async fn prove_app(
    param_path: &str,
    circuit_config_path: &str,
    pk_path: &str,
    email_path: &str,
    proof_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let circuit = gen_circuit_from_email_path(email_path).await;
    let instances = circuit.instances();

    let proof = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &vec![circuit.clone()],
            &[&instances.iter().map(Vec::as_slice).collect_vec()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    {
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&verifier_params);
        verify_proof::<_, VerifierGWC<_>, _, _, _>(
            &params,
            &pk.get_vk(),
            strategy,
            &[&instances.iter().map(Vec::as_slice).collect_vec()],
            &mut transcript,
        )
        .unwrap();
    };
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    Ok(())
}

pub async fn evm_prove_app(
    param_path: &str,
    circuit_config: &str,
    pk_path: &str,
    email_path: &str,
    proof_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    let params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let circuit = gen_circuit_from_email_path(email_path).await;
    let instances = circuit.instances();
    let proof = gen_evm_proof_gwc(&params, &pk, circuit, instances.clone(), &mut OsRng);

    {
        let proof_hex = hex::encode(&proof);
        let mut file = File::create(proof_path)?;
        write!(file, "0x{}", proof_hex).unwrap();
        file.flush().unwrap();
    };
    Ok(())
}

pub async fn evm_prove_agg(
    app_param_path: &str,
    agg_param_path: &str,
    app_circuit_config_path: &str,
    agg_circuit_config_path: &str,
    email_path: &str,
    app_pk_path: &str,
    agg_pk_path: &str,
    proof_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
    set_var("VERIFY_CONFIG", agg_circuit_config_path);
    let app_params = {
        let f = File::open(Path::new(app_param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let agg_params = {
        let f = File::open(Path::new(agg_param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_circuit = gen_circuit_from_email_path(email_path).await;
    let app_pk = {
        let f = File::open(Path::new(app_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let snark = gen_snark_gwc(
        &app_params,
        &app_pk,
        app_circuit.clone(),
        &mut OsRng,
        None::<&str>,
    );
    let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
    let agg_pk = {
        let f = File::open(Path::new(agg_pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let instances = agg_circuit.instances();
    let proof = gen_evm_proof_gwc(
        &agg_params,
        &agg_pk,
        agg_circuit,
        instances.clone(),
        &mut OsRng,
    );

    {
        let proof_hex = hex::encode(&proof);
        let mut file = File::create(proof_path)?;
        write!(file, "0x{}", proof_hex).unwrap();
        file.flush().unwrap();
    };
    Ok(())
}

// pub fn verify_app(
//     params_path: &str,
//     circuit_config: &str,
//     vk_path: &str,
//     proof_path: &str,
//     public_input_path: &str,
// ) -> Result<(), Error> {
//     set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
//     let app_params = {
//         let f = File::open(Path::new(params_dir).join("app.bin")).unwrap();
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     let vk = {
//         let f = File::open(vk_path).unwrap();
//         let mut reader = BufReader::new(f);
//         VerifyingKey::<G1Affine>::read::<_, DefaultVoiceRecoverCircuit>(
//             &mut reader,
//             SerdeFormat::RawBytesUnchecked,
//         )
//         .unwrap()
//     };
//     let public_input = serde_json::from_reader::<File, DefaultVoiceRecoverCircuitPublicInput>(
//         File::open(public_input_path).unwrap(),
//     )
//     .unwrap();
//     let proof = {
//         let f = File::open(proof_path).unwrap();
//         let mut reader = BufReader::new(f);
//         let mut proof = vec![];
//         reader.read_to_end(&mut proof).unwrap();
//         proof
//     };
//     // let acc = hex::decode(&public_input.acc[2..]).unwrap();
//     // let acc_public = acc.iter().map(|byte| Fr::from(*byte as u64)).collect_vec();
//     let mut instances = vec![];
//     let message = hex::decode(&public_input.message[2..]).unwrap();
//     let mut commitment_hash = [0; 32];
//     commitment_hash.copy_from_slice(&hex::decode(&public_input.commitment_hash[2..]).unwrap());
//     instances.push(Fr::from_bytes(&commitment_hash).unwrap());
//     let mut feature_hash = [0; 32];
//     feature_hash.copy_from_slice(&hex::decode(&public_input.feature_hash[2..]).unwrap());
//     instances.push(Fr::from_bytes(&feature_hash).unwrap());
//     let mut message_ext = message.to_vec();
//     {
//         let config_params = DefaultVoiceRecoverCircuit::read_config_params();
//         message_ext.append(&mut vec![0; config_params.max_msg_size - message.len()]);
//     }
//     let mut packed_message = message_ext
//         .chunks(16)
//         .map(|bytes| Fr::from_u128(u128::from_le_bytes(bytes.try_into().unwrap())))
//         .collect_vec();
//     // let mut message_public = message
//     //     .iter()
//     //     .map(|byte| Fr::from(*byte as u64))
//     //     .collect_vec();

//     let mut message_hash = [0; 32];
//     message_hash.copy_from_slice(&hex::decode(&public_input.message_hash[2..]).unwrap());
//     instances.push(Fr::from_bytes(&message_hash).unwrap());
//     instances.append(&mut packed_message);
//     {
//         let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
//         let verifier_params = app_params.verifier_params();
//         let strategy = SingleStrategy::new(&verifier_params);
//         verify_proof::<_, VerifierGWC<_>, _, _, _>(
//             &app_params,
//             &vk,
//             strategy,
//             &[&[instances.as_slice()]],
//             &mut transcript,
//         )
//         .unwrap();
//     };
//     Ok(())
// }

pub async fn gen_evm_verifier(
    param_path: &str,
    circuit_config: &str,
    email_path: &str,
    vk_path: &str,
    code_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config);
    let params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let circuit = gen_circuit_from_email_path(email_path).await;
    let num_instance = circuit.num_instance();
    let verifier_yul =
        gen_evm_verifier_yul::<DefaultEmailVerifyCircuit<Fr>>(&params, &vk, num_instance);
    {
        let mut f = File::create(code_path).unwrap();
        let _ = f.write(verifier_yul.as_bytes());
        let output = fix_verifier_sol(Path::new(code_path).to_path_buf()).unwrap();

        let mut f = File::create(code_path)?;
        let _ = f.write(output.as_bytes());
    };
    Ok(())
}

pub async fn gen_agg_evm_verifier(
    param_path: &str,
    app_circuit_config: &str,
    agg_circuit_config: &str,
    email_path: &str,
    vk_path: &str,
    code_path: &str,
) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config);
    set_var("VERIFY_CONFIG", agg_circuit_config);
    let params = {
        let f = File::open(Path::new(param_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let circuit = gen_circuit_from_email_path(email_path).await;
    let num_instance = vec![4 * LIMBS + circuit.num_instance().iter().sum::<usize>()];
    let verifier_yul = gen_evm_verifier_yul::<PublicAggregationCircuit>(&params, &vk, num_instance);
    {
        let mut f = File::create(code_path).unwrap();
        let _ = f.write(verifier_yul.as_bytes());
        let output = fix_verifier_sol(Path::new(code_path).to_path_buf()).unwrap();

        let mut f = File::create(code_path)?;
        let _ = f.write(output.as_bytes());
    };
    Ok(())
}

async fn gen_circuit_from_email_path(email_path: &str) -> DefaultEmailVerifyCircuit<Fr> {
    let email_bytes = {
        let mut f = File::open(email_path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
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
    let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    let circuit = DefaultEmailVerifyCircuit {
        header_bytes: canonicalized_header,
        body_bytes: canonicalized_body,
        public_key,
        signature,
    };
    circuit
}

fn gen_evm_verifier_yul<C>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> String
where
    C: CircuitExt<Fr>,
{
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(C::accumulator_indices()),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof =
        Plonk::<Kzg<Bn256, Gwc19>>::read_proof(&svk, &protocol, &instances, &mut transcript);
    Plonk::<Kzg<Bn256, Gwc19>>::verify(&svk, &dk, &protocol, &instances, &proof);

    let yul_code = loader.yul_code();
    yul_code
}

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
    let modexp_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x5, (0x[0-9a-fA-F]+), 0xc0, (0x[0-9a-fA-F]+), 0x20)")?;
    let ecmul_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x7, (0x[0-9a-fA-F]+), 0x60, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecadd_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x6, (0x[0-9a-fA-F]+), 0x80, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecpairing_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x8, (0x[0-9a-fA-F]+), 0x180, (0x[0-9a-fA-F]+), 0x20)")?;
    let bool_pattern = Regex::new(r":bool")?;

    // Count the number of pub inputs
    let mut start = None;
    let mut end = None;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().starts_with("mstore(0x20") {
            start = Some(i as u32);
        }

        if line.trim().starts_with("mstore(0x0") {
            end = Some(i as u32);
            break;
        }
    }

    let num_pubinputs = if let Some(s) = start {
        end.unwrap() - s
    } else {
        0
    };

    let mut max_pubinputs_addr = 0;
    if num_pubinputs > 0 {
        max_pubinputs_addr = num_pubinputs * 32 - 32;
    }

    let file = File::open(input_file)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let mut line = line?;
        let m = bool_pattern.captures(&line).unwrap();
        if m.is_some() {
            line = line.replace(":bool", "");
        }

        let m = calldata_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let calldata_and_addr = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;

            if addr_as_num <= max_pubinputs_addr {
                let pub_addr = format!("{:#x}", addr_as_num + 32);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(pubInputs, {}))", pub_addr),
                );
            } else {
                let proof_addr = format!("{:#x}", addr_as_num - max_pubinputs_addr);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(proof, {}))", proof_addr),
                );
            }
        }

        let m = mstore8_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore8(add(transcript, {})", transcript_addr),
            );
        }

        let m = mstoren_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = modexp_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let modexp = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            line = line.replace(
                modexp,
                &format!(
                    "staticcall(gas(), 0x5, add(transcript, {}), 0xc0, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecmul_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let ecmul = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecmul,
                &format!(
                    "staticcall(gas(), 0x7, add(transcript, {}), 0x60, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecadd_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let ecadd = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecadd,
                &format!(
                    "staticcall(gas(), 0x6, add(transcript, {}), 0x80, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecpairing_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let ecpairing = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecpairing,
                &format!(
                    "staticcall(gas(), 0x8, add(transcript, {}), 0x180, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = mstore_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = keccak_pattern.captures(&line).unwrap();
        if let Some(m) = m {
            let keccak = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                keccak,
                &format!("keccak256(add(transcript, {})", transcript_addr),
            );
        }

        // mload can show up multiple times per line
        loop {
            let m = mload_pattern.captures(&line).unwrap();
            if m.is_none() {
                break;
            }
            let mload = m.as_ref().unwrap().get(1).unwrap().as_str();
            let addr = m.as_ref().unwrap().get(2).unwrap().as_str();

            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mload,
                &format!("mload(add(transcript, {})", transcript_addr),
            );
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

// pub fn gen_params(
//     params_dir: &str,
//     app_k: u32,
//     app_to_agg_k: Option<u32>,
//     agg_to_agg_k: Option<u32>,
// ) -> Result<(), Error> {
//     let rng = thread_rng();
//     let mut max_k = app_k;
//     if let Some(k) = app_to_agg_k {
//         if k > max_k {
//             max_k = k;
//         }
//     }
//     if let Some(k) = agg_to_agg_k {
//         if k > max_k {
//             max_k = k;
//         }
//     }
//     let max_params = ParamsKZG::<Bn256>::setup(max_k, rng);
//     for (path, k) in [
//         ("app.bin", Some(app_k)),
//         ("app_to_agg.bin", app_to_agg_k),
//         ("agg_to_agg.bin", agg_to_agg_k),
//     ] {
//         let path = Path::new(params_dir).join(path);
//         match k {
//             Some(k) => {
//                 let _params = if k == max_k {
//                     max_params.clone()
//                 } else {
//                     let mut _params = max_params.clone();
//                     _params.downsize(k);
//                     _params
//                 };
//                 let f = File::create(path).unwrap();
//                 let mut writer = BufWriter::new(f);
//                 _params.write(&mut writer).unwrap();
//                 writer.flush().unwrap();
//             }
//             None => {
//                 continue;
//             }
//         };
//     }
//     Ok(())
// }

// pub fn gen_keys(
//     params_dir: &str,
//     app_circuit_config: &str,
//     app_to_agg_config_path: &str,
//     agg_to_agg_config_path: &str,
//     log2_proofs: u32,
//     pks_dir: &str,
//     vk: &str,
// ) -> Result<(), Error> {
//     set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config);
//     let circuit = DefaultEmailVerifyCircuit::<Fr>::random();
//     let [app_params, app_to_agg_params, agg_to_agg_params] =
//         ["app.bin", "app_to_agg.bin", "agg_to_agg.bin"].map(|path| {
//             let path = Path::new(params_dir).join(path);
//             match File::open(path) {
//                 Ok(f) => {
//                     let mut reader = BufReader::new(f);
//                     Some(ParamsKZG::<Bn256>::read(&mut reader).unwrap())
//                 }
//                 Err(_) => None,
//             }
//         });
//     let (pks, _num_instances) = gen_multi_layer_proving_keys(
//         &app_params.expect("app_params should not be null."),
//         app_to_agg_params.as_ref(),
//         agg_to_agg_params.as_ref(),
//         app_to_agg_config_path,
//         agg_to_agg_config_path,
//         &circuit,
//         log2_proofs,
//     );
//     let lask_vk = pks[pks.len() - 1].get_vk();
//     let pks_path = Path::new(pks_dir);
//     for (idx, pk) in pks.iter().enumerate() {
//         let pk_path = pks_path.join(format!("layer_{}.pk", idx));
//         let f = File::create(pk_path).unwrap();
//         let mut writer = BufWriter::new(f);
//         pk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
//         writer.flush().unwrap();
//     }
//     {
//         let f = File::create(vk).unwrap();
//         let mut writer = BufWriter::new(f);
//         lask_vk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
//         writer.flush().unwrap();
//     }
//     Ok(())
// }

// // pub async fn prove_single_email(
// //     app_params: &str,
// //     app_circuit_config: &str,
// //     app_to_agg_circuit_config: &str,
// //     agg_to_agg_circuit_config: &str,
// //     email: &str,
// //     layer0_pk: &str,
// //     is_evm_verified: bool,
// //     proof: &str,
// // ) -> Result<(), Error> {
// //     set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config);
// //     let email_bytes = {
// //         let mut f = File::open(email).unwrap();
// //         let mut buf = Vec::new();
// //         f.read_to_end(&mut buf).unwrap();
// //         buf
// //     };
// //     let (canonicalized_header, canonicalized_body, signature_bytes) =
// //         canonicalize_signed_email(&email_bytes).unwrap();
// //     let app_params = {
// //         let f = File::open(app_params).expect(&format!("{} does not exist.", app_params));
// //         let mut reader = BufReader::new(f);
// //         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
// //     };
// //     let public_key = {
// //         let logger = slog::Logger::root(slog::Discard, slog::o!());
// //         match resolve_public_key(&logger, &email_bytes).await.unwrap() {
// //             cfdkim::DkimPublicKey::Rsa(_pk) => {
// //                 let n = BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap();
// //                 let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
// //                 RSAPublicKey::<Fr>::new(Value::known(n), e)
// //             }
// //             _ => {
// //                 panic!("Only RSA keys are supported.");
// //             }
// //         }
// //     };
// //     let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
// //     let circuit = DefaultEmailVerifyCircuit {
// //         header_bytes: canonicalized_header,
// //         body_bytes: canonicalized_body,
// //         public_key,
// //         signature,
// //     };
// //     let pk = {
// //         let f = File::open(layer0_pk).expect(&format!("{} does not exist.", layer0_pk));
// //         let mut reader = BufReader::new(f);
// //         ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
// //             &mut reader,
// //             SerdeFormat::RawBytes,
// //         )
// //         .unwrap()
// //     };
// //     let _proof = if is_evm_verified {
// //         prove_multi_layer_evm(
// //             &app_params,
// //             None,
// //             None,
// //             app_to_agg_circuit_config,
// //             agg_to_agg_circuit_config,
// //             &[circuit],
// //             &[pk],
// //             0,
// //         )
// //         .0
// //     } else {
// //         gen_snark(&app_params, circuit, &pk).proof
// //     };
// //     {
// //         let f = File::create(proof).unwrap();
// //         let mut writer = BufWriter::new(f);
// //         writer.write_all(&_proof).unwrap();
// //         writer.flush().unwrap();
// //     }
// //     Ok(())
// // }

// pub async fn prove_multi_evm(
//     params_dir: &str,
//     app_circuit_config: &str,
//     app_to_agg_circuit_config: &str,
//     agg_to_agg_circuit_config: &str,
//     pks_dir: &str,
//     emails_dir: &str,
//     log2_proofs: u32,
//     proof: &str,
//     acc: &str,
// ) -> Result<(), Error> {
//     set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config);
//     let [app_params, app_to_agg_params, agg_to_agg_params] =
//         ["app.bin", "app_to_agg.bin", "agg_to_agg.bin"].map(|path| {
//             let path = Path::new(params_dir).join(path);
//             match File::open(path) {
//                 Ok(f) => {
//                     let mut reader = BufReader::new(f);
//                     Some(ParamsKZG::<Bn256>::read(&mut reader).unwrap())
//                 }
//                 Err(_) => None,
//             }
//         });
//     let email_pathes = fs::read_dir(emails_dir).expect(&format!("{} does not exist.", emails_dir));
//     let mut circuits = vec![];
//     for path_result in email_pathes {
//         let email_bytes = {
//             let mut f = File::open(path_result.unwrap().path()).unwrap();
//             let mut buf = Vec::new();
//             f.read_to_end(&mut buf).unwrap();
//             buf
//         };
//         let (canonicalized_header, canonicalized_body, signature_bytes) =
//             canonicalize_signed_email(&email_bytes).unwrap();
//         let public_key = {
//             let logger = slog::Logger::root(slog::Discard, slog::o!());
//             match resolve_public_key(&logger, &email_bytes).await.unwrap() {
//                 cfdkim::DkimPublicKey::Rsa(_pk) => {
//                     let n = BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap();
//                     let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//                     RSAPublicKey::<Fr>::new(Value::known(n), e)
//                 }
//                 _ => {
//                     panic!("Only RSA keys are supported.");
//                 }
//             }
//         };
//         let signature =
//             RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//         let circuit = DefaultEmailVerifyCircuit {
//             header_bytes: canonicalized_header,
//             body_bytes: canonicalized_body,
//             public_key,
//             signature,
//         };
//         circuits.push(circuit);
//     }
//     assert_eq!(circuits.len(), 2usize.pow(log2_proofs));
//     let mut email_substrs = vec![];
//     for circuit in circuits.iter() {
//         let (header, body) = circuit.get_substrs();
//         email_substrs.push(EmailSubstrs { header, body });
//     }
//     let pks = (0..log2_proofs + 1)
//         .map(|idx| {
//             let pk_path = Path::new(pks_dir).join(format!("layer_{}.pk", idx));
//             let f = File::open(pk_path).unwrap();
//             let mut reader = BufReader::new(f);
//             ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
//                 &mut reader,
//                 SerdeFormat::RawBytes,
//             )
//             .unwrap()
//         })
//         .collect_vec();
//     let (_proof, _acc) = prove_multi_layer_evm(
//         &app_params.expect("app_params should not be null."),
//         app_to_agg_params.as_ref(),
//         agg_to_agg_params.as_ref(),
//         app_to_agg_circuit_config,
//         agg_to_agg_circuit_config,
//         &circuits,
//         &pks,
//         log2_proofs,
//     );
//     {
//         let f = File::create(proof).unwrap();
//         let mut writer = BufWriter::new(f);
//         writer.write_all(&_proof).unwrap();
//         writer.flush().unwrap();
//     }
//     {
//         let encoded = encode_calldata(&[_acc], &[]);
//         let f = File::create(acc).unwrap();
//         let mut writer = BufWriter::new(f);
//         writer.write_all(&encoded).unwrap();
//         writer.flush().unwrap();
//     }
//     Ok(())
// }

// pub fn gen_evm_verifier(
//     params_dir: &str,
//     vk: &str,
//     log2_proofs: u32,
//     evm_verifier: &str,
// ) -> Result<(), Error> {
//     let params = {
//         let filepath = if log2_proofs == 0 {
//             "app.bin"
//         } else if log2_proofs == 1 {
//             "app_to_agg.bin"
//         } else {
//             "agg_to_agg.bin"
//         };
//         let path = Path::new(params_dir).join(filepath);
//         let f = File::open(path).expect(&format!(
//             "The {} params is required for log2_proofs = {}",
//             filepath, log2_proofs
//         ));
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     let vk = {
//         let f = File::open(vk).unwrap();
//         let mut reader = BufReader::new(f);
//         if log2_proofs == 0 {
//             VerifyingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(
//                 &mut reader,
//                 SerdeFormat::RawBytes,
//             )
//             .unwrap()
//         } else {
//             VerifyingKey::<G1Affine>::read::<_, AggregationCircuit>(
//                 &mut reader,
//                 SerdeFormat::RawBytes,
//             )
//             .unwrap()
//         }
//     };
//     let num_instances_per_app = {
//         let c = DefaultEmailVerifyCircuit::<Fr>::random();
//         c.num_instance()
//     };
//     let num_instances = if log2_proofs == 0 {
//         num_instances_per_app
//     } else {
//         compute_agg_num_instances(&num_instances_per_app, log2_proofs)
//     };
//     let verifier = gen_multi_layer_evm_verifier::<DefaultEmailVerifyCircuit<Fr>>(
//         &params,
//         &vk,
//         num_instances,
//         log2_proofs,
//     );
//     let verifier_str = "0x".to_string() + &hex::encode(verifier);
//     {
//         let mut f = File::create(evm_verifier).unwrap();
//         write!(f, "{}", verifier_str).unwrap();
//         f.flush().unwrap();
//     }
//     Ok(())
// }
