use crate::*;
use halo2_base::halo2_proofs::circuit;
use halo2_base::halo2_proofs::circuit::Layouter;
use halo2_base::halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Column, ConstraintSystem, Instance, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_base::halo2_proofs::poly::{
    commitment::{Params, ParamsProver},
    kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    Rotation, VerificationStrategy,
};
use halo2_base::halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::fe_to_biguint;
use halo2_base::utils::{decompose_fe_to_u64_limbs, value_to_option};
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::PrimeField,
};
use js_sys::Uint8Array;
use quad_storage;
use serde_json;
use std::io::BufReader;
use stringreader::StringReader;
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;
extern crate console_error_panic_hook;
use cfdkim::resolve_rsa_public_key;
use js_sys::Promise;
use num_bigint::BigUint;
use rsa::rand_core::OsRng;
use serde_wasm_bindgen::*;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn prove_email(params: JsValue, proving_key: JsValue, email_str: String) -> Promise {
    console_error_panic_hook::set_once();

    future_to_promise(async move {
        let params = Uint8Array::new(&params).to_vec();
        let params = match ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])) {
            Ok(params) => params,
            Err(_) => {
                return Err(JsValue::from_str("fail to read params"));
            }
        };

        let pk: Vec<u8> = Uint8Array::new(&proving_key).to_vec();
        let pk = match ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut BufReader::new(&pk[..]), SerdeFormat::RawBytes) {
            Ok(pk) => pk,
            Err(_) => {
                return Err(JsValue::from_str("fail to read proving key"));
            }
        };
        let circuit = build_circuit::<Fr>(&email_str).await;
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        let instances = circuit.instances();
        match create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(&params, &pk, &[circuit], &[&[instances[0].as_slice()]], OsRng, &mut transcript) {
            Ok(_) => (),
            Err(_) => {
                return Err(JsValue::from_str("fail to create proof"));
            }
        };
        let proof = transcript.finalize();
        {
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            verify_proof::<_, VerifierGWC<_>, _, _, _>(&params, pk.get_vk(), strategy, &[&[instances[0].as_slice()]], &mut transcript).expect("proof invalid");
        }
        Ok(serde_wasm_bindgen::to_value(&proof).unwrap())
    })
}

// #[wasm_bindgen]
// pub fn verify_email_proof(params: JsValue, verifying_key: JsValue, proof: JsValue, public_input: JsValue) -> Promise {
//     console_error_panic_hook::set_once();

//     future_to_promise(async move {
//         let params = Uint8Array::new(&params).to_vec();
//         let params = match ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])) {
//             Ok(params) => params,
//             Err(_) => {
//                 return Err(JsValue::from_str("fail to read params"));
//             }
//         };

//         let vk: Vec<u8> = Uint8Array::new(&verifying_key).to_vec();
//         let vk = match VerifyingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut BufReader::new(&vk[..]), SerdeFormat::RawBytes) {
//             Ok(vk) => vk,
//             Err(_) => {
//                 return Err(JsValue::from_str("fail to read verifying key"));
//             }
//         };

//         let proof: Vec<u8> = Uint8Array::new(&proof).to_vec();
//         let proof = match <KZGCommitmentScheme<_> as VerificationStrategy<DefaultEmailVerifyCircuit<Fr>, _>>::Proof::read(&mut BufReader::new(&proof[..])) {
//             Ok(proof) => proof,
//             Err(_) => {
//                 return Err(JsValue::from_str("fail to read proof"));
//             }
//         };

//         let public_input: Vec<u8> = Uint8Array::new(&public_input).to_vec();
//         let public_input = match <KZGCommitmentScheme<_> as VerificationStrategy<DefaultEmailVerifyCircuit<Fr>, _>>::PublicInput::read(&mut BufReader::new(&public_input[..])) {
//             Ok(public_input) => public_input,
//             Err(_) => {
//                 return Err(JsValue::from_str("fail to read public input"));
//             }
//         };

//         let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof);
//         match proof.verify(&params, &vk, &[public_input], &mut transcript) {
//             Ok(_) => Ok(JsValue::from_bool(true)),
//             Err(_) => Ok(JsValue::from_bool(false)),
//         }
//     })
// }

pub(crate) fn configure_wasm<F: PrimeField>(meta: &mut ConstraintSystem<F>) -> DefaultEmailVerifyConfig<F> {
    let storage = &mut quad_storage::STORAGE.lock().unwrap();
    let params = get_config_params_wasm();
    let range_config = RangeConfig::configure(
        meta,
        Vertical,
        &[params.num_flex_advice],
        &[params.num_range_lookup_advice],
        params.num_flex_advice,
        params.range_lookup_bits,
        0,
        params.degree as usize,
    );
    let header_params = params.header_config.as_ref().expect("header_config is required");
    let body_params = params.body_config.as_ref().expect("body_config is required");
    let sign_verify_params = params.sign_verify_config.as_ref().expect("sign_verify_config is required");
    let sha256_params = params.sha256_config.as_ref().expect("sha256_config is required");
    assert_eq!(header_params.allstr_filepathes.len(), header_params.substr_filepathes.len());
    assert_eq!(body_params.allstr_filepathes.len(), body_params.substr_filepathes.len());

    let sha256_config = Sha256DynamicConfig::configure(
        meta,
        vec![body_params.max_variable_byte_size, header_params.max_variable_byte_size],
        range_config.clone(),
        sha256_params.num_bits_lookup,
        sha256_params.num_advice_columns,
        false,
    );

    let sign_verify_config = SignVerifyConfig::configure(range_config.clone(), sign_verify_params.public_key_bits);

    let bodyhash_allstr_def = {
        let string = storage.get(&header_params.bodyhash_allstr_filepath).expect("failed to get allstr");
        let mut streader = StringReader::new(&string);
        let bufreader = BufReader::new(streader);
        AllstrRegexDef::read_from_reader(bufreader)
    };
    let bodyhash_substr_def = {
        let string = storage.get(&header_params.bodyhash_substr_filepath).expect("failed to get substr");
        let mut streader = StringReader::new(&string);
        let bufreader = BufReader::new(streader);
        SubstrRegexDef::read_from_reader(bufreader)
    };
    let bodyhash_defs = RegexDefs {
        allstr: bodyhash_allstr_def,
        substrs: vec![bodyhash_substr_def],
    };
    let mut bodyhash_substr_id = 1;
    let header_regex_defs = header_params
        .allstr_filepathes
        .iter()
        .zip(header_params.substr_filepathes.iter())
        .map(|(allstr_path, substr_pathes)| {
            let string = storage.get(allstr_path).expect("failed to get allstr");
            let mut streader = StringReader::new(&string);
            let bufreader = BufReader::new(streader);
            let allstr = AllstrRegexDef::read_from_reader(bufreader);
            let substrs = substr_pathes
                .into_iter()
                .map(|path| {
                    let string = storage.get(path).expect("failed to get substr");
                    let mut streader = StringReader::new(&string);
                    let bufreader = BufReader::new(streader);
                    SubstrRegexDef::read_from_reader(bufreader)
                })
                .collect_vec();
            bodyhash_substr_id += substrs.len();
            RegexDefs { allstr, substrs }
        })
        .collect_vec();
    let header_config = RegexSha2Config::configure(
        meta,
        header_params.max_variable_byte_size,
        header_params.skip_prefix_bytes_size.unwrap_or(0),
        range_config.clone(),
        vec![header_regex_defs, vec![bodyhash_defs]].concat(),
    );

    let body_regex_defs = body_params
        .allstr_filepathes
        .iter()
        .zip(body_params.substr_filepathes.iter())
        .map(|(allstr_path, substr_pathes)| {
            let string = storage.get(allstr_path).expect("failed to get allstr");
            let mut streader = StringReader::new(&string);
            let bufreader = BufReader::new(streader);
            let allstr = AllstrRegexDef::read_from_reader(bufreader);
            let substrs = substr_pathes
                .into_iter()
                .map(|path| {
                    let string = storage.get(path).expect("failed to get substr");
                    let mut streader = StringReader::new(&string);
                    let bufreader = BufReader::new(streader);
                    SubstrRegexDef::read_from_reader(bufreader)
                })
                .collect_vec();
            RegexDefs { allstr, substrs }
        })
        .collect_vec();
    let body_config = RegexSha2Base64Config::configure(
        meta,
        body_params.max_variable_byte_size,
        body_params.skip_prefix_bytes_size.unwrap_or(0),
        range_config,
        body_regex_defs,
    );
    let chars_shift_config = CharsShiftConfig::configure(header_params.max_variable_byte_size, 44, bodyhash_substr_id as u64);

    let instances = meta.instance_column();
    meta.enable_equality(instances);
    DefaultEmailVerifyConfig {
        sha256_config,
        sign_verify_config,
        header_config,
        body_config,
        chars_shift_config,
        instances,
    }
}

pub(crate) fn get_config_params_wasm() -> EmailVerifyConfigParams {
    let storage = &mut quad_storage::STORAGE.lock().unwrap();
    let config_params_str = storage.get(EMAIL_VERIFY_CONFIG_ENV).expect("failed to get config params");
    let config_params: EmailVerifyConfigParams = serde_json::from_str(&config_params_str).expect("failed to parse config params");
    config_params
}

pub(crate) async fn build_circuit<F: PrimeField>(email_str: &str) -> DefaultEmailVerifyCircuit<F> {
    let email_bytes = email_str.as_bytes().to_vec();
    let public_key = resolve_rsa_public_key(&email_bytes).await.expect("failed to resolve public key");
    let public_key_n = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    DefaultEmailVerifyCircuit {
        email_bytes,
        public_key_n,
        _f: PhantomData,
    }
}
