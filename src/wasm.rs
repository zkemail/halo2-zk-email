use crate::*;
// use gloo_storage::{LocalStorage, Storage};
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
use serde_json;
use std::io::BufReader;
use stringreader::StringReader;
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;
extern crate console_error_panic_hook;
use cfdkim::{get_google_dns_url, get_rsa_public_key_from_google_dns};
use js_sys::JSON;
use js_sys::{Array as JsArray, Promise};
use log;
use num_bigint::BigUint;
use once_cell::sync::OnceCell;
use rand::rngs::OsRng;
use serde_wasm_bindgen::*;
use snark_verifier_sdk::gen_pk;
use snark_verifier_sdk::halo2::gen_proof_shplonk;
use snark_verifier_sdk::halo2::PoseidonTranscript;
use snark_verifier_sdk::NativeLoader;
use std::io::Read;
use wasm_bindgen_console_logger::DEFAULT_LOGGER;
use wasm_bindgen_futures::future_to_promise;
use web_sys::console::log_1;
// use indexed_db_futures::prelude::*;

const HALO2_ZKEMAIL_SETTINGS_OBJECT: &str = "halo2_zkemail_settings";

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Initialize the configurations for [`DefaultEmailVerifyCircuit`].
/// You must call this function once before calling any other functions in this module.
/// # Arguments
/// * `config_params` - a json string of [`EmailVerifyConfigParams`].
/// * `bodyhash_allstr_def` - a string of [`AllstrRegexDef`] for the bodyhash.
/// * `bodyhash_substr_def` - a string of [`SubstrRegexDef`] for the bodyhash.
/// * `header_allstr_defs` - a list of strings of [`AllstrRegexDef`] for the headers.
/// * `header_substr_defs` - a list of strings of [`SubstrRegexDef`] for the headers.
/// * `body_allstr_defs` - a list of strings of [`AllstrRegexDef`] for the body.
/// * `body_substr_defs` - a list of strings of [`SubstrRegexDef`] for the body.
/// # Return values
/// Return a promise of `null`.
#[wasm_bindgen]
pub fn init_configs(
    config_params: String,
    bodyhash_allstr_def: String,
    bodyhash_substr_def: String,
    header_allstr_defs: JsArray,
    header_substr_defs: JsArray,
    body_allstr_defs: JsArray,
    body_substr_defs: JsArray,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    log::set_logger(&DEFAULT_LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let config_params: EmailVerifyConfigParams = serde_json::from_str(&config_params).map_err(|err| JsValue::from_str(&err.to_string()))?;
    log_1(&JsValue::from_str(&format!("bodyhash_allstr_def: {}", bodyhash_allstr_def)));
    let bodyhash_allstr_def: AllstrRegexDef = {
        let mut bytes = bodyhash_allstr_def.as_bytes();
        let bufreader = BufReader::new(&mut bytes);
        AllstrRegexDef::read_from_reader(bufreader)
    };
    log_1(&JsValue::from_str(&format!("bodyhash_allstr_def: {:?}", bodyhash_allstr_def)));
    let bodyhash_substr_def: SubstrRegexDef = {
        let mut streader = StringReader::new(&bodyhash_substr_def);
        let bufreader = BufReader::new(streader);
        SubstrRegexDef::read_from_reader(bufreader)
    };
    log_1(&JsValue::from_str(&format!("bodyhash_substr_def: {:?}", bodyhash_substr_def)));
    let bodyhash_defs = RegexDefs {
        allstr: bodyhash_allstr_def,
        substrs: vec![bodyhash_substr_def],
    };
    let mut bodyhash_substr_id = 1;

    let header_regex_defs = header_allstr_defs
        .iter()
        .enumerate()
        .map(|(idx, allstr_def)| {
            let allstr_def_str = allstr_def.as_string().unwrap();
            let mut streader = StringReader::new(&allstr_def_str);
            let bufreader = BufReader::new(streader);
            let allstr = AllstrRegexDef::read_from_reader(bufreader);
            let substr_defs_str = header_substr_defs.get(idx as u32).as_string().unwrap();
            let substr_defs_array = parse_js_array_string(&substr_defs_str);
            let substrs = substr_defs_array
                .into_iter()
                .map(|substr_def| {
                    let substr_def_str = substr_def.as_string().unwrap();
                    let mut streader = StringReader::new(&substr_def_str);
                    let bufreader = BufReader::new(streader);
                    SubstrRegexDef::read_from_reader(bufreader)
                })
                .collect_vec();
            bodyhash_substr_id += substrs.len();
            RegexDefs { allstr, substrs }
        })
        .collect_vec();
    let body_regex_defs = body_allstr_defs
        .iter()
        .enumerate()
        .map(|(idx, allstr_def)| {
            let allstr_def_str = allstr_def.as_string().unwrap();
            let mut streader = StringReader::new(&allstr_def_str);
            let bufreader = BufReader::new(streader);
            let allstr = AllstrRegexDef::read_from_reader(bufreader);
            let substr_defs_str = body_substr_defs.get(idx as u32).as_string().unwrap();
            let substr_defs_array = parse_js_array_string(&substr_defs_str);
            let substrs = substr_defs_array
                .into_iter()
                .map(|substr_def| {
                    let substr_def_str = substr_def.as_string().unwrap();
                    let mut streader = StringReader::new(&substr_def_str);
                    let bufreader = BufReader::new(streader);
                    SubstrRegexDef::read_from_reader(bufreader)
                })
                .collect_vec();
            RegexDefs { allstr, substrs }
        })
        .collect_vec();
    GLOBAL_CONFIG_PARAMS.set(config_params).unwrap();
    GLOBAL_BODYHASH_DEFS_AND_ID.set((bodyhash_defs, bodyhash_substr_id)).unwrap();
    GLOBAL_HEADER_DEFS.set(header_regex_defs).unwrap();
    GLOBAL_BODY_DEFS.set(body_regex_defs).unwrap();
    Ok(JsValue::NULL)
}

/// Extract a selector and a domain name from the given email string and generate an url to fetch the public key from the google dns.
/// # Arguments
/// * `email_str` - an email string.
/// # Return values
/// Return a promise of the url string.
#[wasm_bindgen]
pub fn google_dns_url_from_email(email_str: String) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    log_1(&JsValue::from_str(&format!("given email: {}", email_str)));
    log_1(&JsValue::from_str(&format!("given email bytes: {:?}", email_str.as_bytes())));
    let url = get_google_dns_url(&email_str.as_bytes()).map_err(|err| JsValue::from_str(&err.to_string()))?;
    Ok(url)
}

/// Fetch the public key from the response of the google dns.
/// # Arguments
/// * `response` - a response string from the google dns.
/// # Return values
/// Return a promise of the public key string.
#[wasm_bindgen]
pub fn fetch_rsa_public_key(response: String) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    let public_key = get_rsa_public_key_from_google_dns(&response).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let public_key_n = public_key.n().to_bytes_le();
    let hex = format!("0x{}", hex::encode(public_key_n));
    Ok(hex)
}

// #[wasm_bindgen]
// pub fn gen_proving_key(params: JsValue, email_str: String, public_key_n: String) -> Result<JsValue, JsValue> {
//     console_error_panic_hook::set_once();
//     let params = Uint8Array::new(&params).to_vec();
//     let mut params = match ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])) {
//         Ok(params) => params,
//         Err(_) => {
//             return Err(JsValue::from_str("fail to read params"));
//         }
//     };
//     log_1(&JsValue::from_str("params read"));
//     let app_config = default_config_params();
//     log_1(&JsValue::from_str("config params read"));
//     if params.k() > app_config.degree {
//         params.downsize(app_config.degree);
//     }
//     let circuit = build_circuit::<Fr>(&email_str, &public_key_n);
//     log_1(&JsValue::from_str("circuit built"));
//     let pk = gen_pk::<DefaultEmailVerifyCircuit<Fr>>(&params, &circuit, None);
//     PROVING_KEY.set(pk).unwrap();
//     Ok(JsValue::NULL)
// }

/// Generate a proof for the given email string and public key.
/// # Arguments
/// * `params` - a trusted setup parameter bytes.
/// * `pk_chunks` - a list of chunks of the proving key.
/// * `email_str` - an email string.
/// * `public_key_n` - a public key string.
/// # Return values
/// Return a promise of a list of the hex string of the proof and the public input.
#[wasm_bindgen]
pub fn prove_email(params: JsValue, pk_chunks: JsArray, email_str: String, public_key_n: String) -> Result<JsArray, JsValue> {
    console_error_panic_hook::set_once();
    log_1(&JsValue::from_str("prove_email"));
    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).map_err(|err| JsValue::from_str(&err.to_string()))?;
    log_1(&JsValue::from_str("params read"));

    let mut reader = JsArrayReader::new(pk_chunks);
    let pk = ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut BufReader::new(&mut reader), SerdeFormat::RawBytes)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    log_1(&JsValue::from_str("pk read"));
    let circuit = build_circuit::<Fr>(&email_str, &public_key_n);
    log_1(&JsValue::from_str("circuit built"));
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    let instances = circuit.instances();
    log_1(&JsValue::from_str("instances built"));
    let public_input = circuit.gen_default_public_input();
    let proof = gen_proof_shplonk(&params, &pk, circuit, instances.clone(), &mut OsRng, None);
    log_1(&JsValue::from_str("proof generated"));

    let proof_hex = format!("0x{}", hex::encode(&proof));
    let public_input = serde_wasm_bindgen::to_value(&public_input).map_err(|err| JsValue::from_str(&format!("fail to serialize public input. Error: {}", err.to_string())))?;
    let mut js_array = JsArray::new();
    js_array.push(&JsValue::from_str(&proof_hex));
    js_array.push(&public_input);
    Ok(js_array)
}

/// Verify the proof for the given email string and public key.
/// # Arguments
/// * `params` - a trusted setup parameter bytes.
/// * `vk` - a verification key bytes.
/// * `proof` - a hex string of the proof.
/// * `public_input` - a public input json string.
/// # Return values
/// Return a promise of a boolean value.
#[wasm_bindgen]
pub fn verify_email_proof(params: JsValue, vk: JsValue, proof: JsValue, public_input: JsValue) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    log_1(&JsValue::from_str("verify_email"));
    let params = Uint8Array::new(&params).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).map_err(|err| JsValue::from_str(&err.to_string()))?;
    log_1(&JsValue::from_str("params read"));

    let vk = Uint8Array::new(&vk).to_vec();
    let vk = VerifyingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut BufReader::new(&vk[..]), SerdeFormat::RawBytes)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    log_1(&JsValue::from_str("vk read"));

    let public_input: DefaultEmailVerifyPublicInput = serde_wasm_bindgen::from_value(public_input)?;
    let proof = proof.as_string().unwrap();
    let proof = hex::decode(&proof[2..]).map_err(|err| JsValue::from_str(&err.to_string()))?;

    let instances = public_input.instances::<Fr>();
    let result = {
        let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::new(&proof);
        VerificationStrategy::<_, VerifierSHPLONK<Bn256>>::finalize(
            verify_proof::<_, VerifierSHPLONK<Bn256>, _, _, _>(
                params.verifier_params(),
                &vk,
                AccumulatorStrategy::new(params.verifier_params()),
                &[&[instances.as_slice()]],
                &mut transcript_read,
            )
            .map_err(|err| JsValue::from_str(&format!("verification error: {}", err.to_string())))?,
        )
    };
    Ok(JsValue::from_bool(result))
}

/// Configure the constraints definitions for [`DefaultEmailVerifyCircuit`].
/// # Arguments
/// * `meta` - a constraint system.
/// # Return values
/// Return a [`DefaultEmailVerifyConfig`].
pub(crate) fn configure_wasm<F: PrimeField>(meta: &mut ConstraintSystem<F>) -> DefaultEmailVerifyConfig<F> {
    let params = default_config_params();
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
    let (bodyhash_defs, bodyhash_substr_id) = GLOBAL_BODYHASH_DEFS_AND_ID.get().expect("bodyhash_defs is not set").clone();
    let header_regex_defs = GLOBAL_HEADER_DEFS.get().expect("header_regex_defs is not set").clone();
    let header_config = RegexSha2Config::configure(
        meta,
        header_params.max_variable_byte_size,
        header_params.skip_prefix_bytes_size.unwrap_or(0),
        range_config.clone(),
        vec![header_regex_defs, vec![bodyhash_defs]].concat(),
    );
    let body_regex_defs = GLOBAL_BODY_DEFS.get().expect("body_regex_defs is not set").clone();
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

fn build_circuit<F: PrimeField>(email_str: &str, public_key_n: &str) -> DefaultEmailVerifyCircuit<F> {
    let email_bytes = email_str.as_bytes().to_vec();
    let public_key_n = BigUint::from_bytes_le(&hex::decode(&public_key_n[2..]).unwrap());
    DefaultEmailVerifyCircuit {
        email_bytes,
        public_key_n,
        _f: PhantomData,
    }
}

fn parse_js_array_string(string: &str) -> JsArray {
    let parsed = JSON::parse(string).unwrap();
    parsed.into()
}

struct JsArrayReader {
    array: JsArray,
    consumed: (usize, usize),
}
impl Read for JsArrayReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let n = buf.len();
        if n == 0 {
            return Ok(0);
        }
        let mut remaining = n;
        while (remaining > 0) {
            if self.consumed.0 >= self.array.length() as usize {
                return Ok(n - remaining);
            }
            let chunk = Uint8Array::new(&self.array.get(self.consumed.0 as u32)).to_vec();
            let read_bytes = std::cmp::min(chunk.len() - self.consumed.1, remaining);
            buf[n - remaining..n - remaining + read_bytes].copy_from_slice(&chunk[self.consumed.1..self.consumed.1 + read_bytes]);
            remaining -= read_bytes;
            self.consumed.1 += read_bytes;
            if self.consumed.1 >= chunk.len() {
                self.consumed.0 += 1;
                self.consumed.1 = 0;
            }
        }
        Ok(n - remaining)
    }
}

impl JsArrayReader {
    fn new(array: JsArray) -> Self {
        Self { array, consumed: (0, 0) }
    }
}
