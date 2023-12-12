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
use js_sys::{Array as JsArray, Promise};
use num_bigint::BigUint;
use rsa::rand_core::OsRng;
use serde_wasm_bindgen::*;
use snark_verifier_sdk::gen_pk;
use std::io::Read;
use wasm_bindgen_futures::future_to_promise;
use web_sys::console::log_1;
use js_sys::JSON;
// use indexed_db_futures::prelude::*;

const HALO2_ZKEMAIL_SETTINGS_OBJECT: &str = "halo2_zkemail_settings";

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn init_configs(
    config_params: String, 
    bodyhash_allstr_def: String, 
    bodyhash_substr_def: String, 
    header_allstr_defs: JsArray, 
    header_substr_defs: JsArray, 
    body_allstr_defs: JsArray,
    body_substr_defs: JsArray
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let config_params: EmailVerifyConfigParams = serde_json::from_str(&config_params).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let bodyhash_allstr_def: AllstrRegexDef = {
        let mut streader = StringReader::new(&bodyhash_allstr_def);
        let bufreader = BufReader::new(streader);
        AllstrRegexDef::read_from_reader(bufreader)
    };        
    let bodyhash_substr_def: SubstrRegexDef = {
        let mut streader = StringReader::new(&bodyhash_substr_def);
        let bufreader = BufReader::new(streader);
        SubstrRegexDef::read_from_reader(bufreader)
    };
    let bodyhash_defs = RegexDefs {
        allstr: bodyhash_allstr_def,
        substrs: vec![bodyhash_substr_def],
    };
    let mut bodyhash_substr_id = 1;

    let header_regex_defs = header_allstr_defs
        .iter().enumerate()
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
        .iter().enumerate()
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

#[wasm_bindgen]
pub fn google_dns_url_from_email(email_str: String) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    log_1(&JsValue::from_str(&format!("given email: {}", email_str)));
    log_1(&JsValue::from_str(&format!("given email bytes: {:?}", email_str.as_bytes())));
    let url = get_google_dns_url(&email_str.as_bytes()).map_err(|err| JsValue::from_str(&err.to_string()))?;
    Ok(url)
}

#[wasm_bindgen]
pub fn fetch_rsa_public_key(response: String) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    let public_key = get_rsa_public_key_from_google_dns(&response).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let public_key_n = public_key.n().to_bytes_le();
    let hex = format!("0x{}", hex::encode(public_key_n));
    Ok(hex)
}

#[wasm_bindgen]
pub fn gen_proving_key(params: JsValue, email_str: String, public_key_n: String) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let params = Uint8Array::new(&params).to_vec();
    let mut params = match ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])) {
        Ok(params) => params,
        Err(_) => {
            return Err(JsValue::from_str("fail to read params"));
        }
    };
    log_1(&JsValue::from_str("params read"));
    let app_config = default_config_params();
    log_1(&JsValue::from_str("config params read"));
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let circuit = build_circuit::<Fr>(&email_str, &public_key_n);
    log_1(&JsValue::from_str("circuit built"));
    let pk = gen_pk::<DefaultEmailVerifyCircuit<Fr>>(&params, &circuit, None);
    Ok(JsValue::from_str("proof"))
}

#[wasm_bindgen]
pub fn prove_email(params: JsValue, pk_chunks: JsArray, email_str: String, public_key_n: String) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    log_1(&JsValue::from_str("prove_email"));
    let params = Uint8Array::new(&params).to_vec();
    let params = match ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])) {
        Ok(params) => params,
        Err(_) => {
            return Err(JsValue::from_str("fail to read params"));
        }
    };
    log_1(&JsValue::from_str("params read"));

    // // let pk: Vec<u8> = Uint8Array::new(&proving_key).to_vec();
    log_1(&JsValue::from_str(&format!("pk max size {}", 1 * 1024 * 1024 * 1024 as u128)));
    let mut pk_vec = Vec::with_capacity(1 * 1024 * 1024 * 1024);
    log_1(&JsValue::from_str(&format!("pk max size {}", 2 * 1024 * 1024 * 1024 as u128)));
    pk_vec.append(&mut vec![0; 1 * 1024 * 1024 * 1024]);
    log_1(&JsValue::from_str(&format!("pk max size {}", 2987231672 as u128)));
    pk_vec.append(&mut vec![0; 2987231672 - 2 * 1024 * 1024 * 1024]);
    // let mut reader = BufReader::new(pk_vec.as_slice());
    log_1(&JsValue::from_str(&format!("pk_chunks.length(): {}", pk_chunks.length())));
    for idx in 0..pk_chunks.length() {
        // let mut chunk: Vec<u8> = Uint8Array::new(&pk_chunks.get(idx)).to_vec();
        // assert!(chunk.len() < 1 * 1024 * 1024 * 1024);
        // pk_vec.append(&mut chunk);
        // let read_bytes = reader.read(&mut chunk).expect("fail to read chunk");
        // log_1(&JsValue::from_str(&format!("read_bytes: {}", read_bytes)));
        // log_1(&JsValue::from_str(&format!("{}-th chunk added", idx)));
        // log_1(&JsValue::from_str(&format!("pk_vec.len(): {}", pk_vec.len())));
    }
    let pk = match ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut pk_vec.as_slice(), SerdeFormat::RawBytes) {
        Ok(pk) => pk,
        Err(_) => {
            return Err(JsValue::from_str("fail to read proving key"));
        }
    };
    log_1(&JsValue::from_str("pk read"));
    // let circuit = build_circuit::<Fr>(&email_str).await;
    // let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    // let instances = circuit.instances();
    // match create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(&params, &pk, &[circuit], &[&[instances[0].as_slice()]], OsRng, &mut transcript) {
    //     Ok(_) => (),
    //     Err(_) => {
    //         return Err(JsValue::from_str("fail to create proof"));
    //     }
    // };
    // let proof = transcript.finalize();
    // {
    //     let strategy = SingleStrategy::new(&params);
    //     let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    //     verify_proof::<_, VerifierGWC<_>, _, _, _>(&params, pk.get_vk(), strategy, &[&[instances[0].as_slice()]], &mut transcript).expect("proof invalid");
    // }
    // Ok(serde_wasm_bindgen::to_value(&proof).unwrap())
    Ok(JsValue::from_str("proof"))
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
    let params = default_config_params();
    // let mut db_req: OpenDbRequest = IdbDatabase::open_u32("zkemail", 1).expect("invalid request to open database");
    // db_req.set_on_upgrade_needed(Some(|evt: &IdbVersionChangeEvent| -> Result<(), JsValue> {
    //     // Check if the object store exists; create it if it doesn't
    //     if let None = evt.db().object_store_names().find(|n| n == HALO2_ZKEMAIL_SETTINGS_OBJECT) {
    //         evt.db().create_object_store(HALO2_ZKEMAIL_SETTINGS_OBJECT).expect("failed to create object store");
    //     }
    //     Ok(())
    // }));
    // let db: IdbDatabase = db_req.await.expect("failed to open database");
    // let tx = db.transaction_on_one(HALO2_ZKEMAIL_SETTINGS_OBJECT).expect("failed to open transaction");
    // let store = tx.object_store(HALO2_ZKEMAIL_SETTINGS_OBJECT).expect("failed to open object store");
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

    // let bodyhash_allstr_def = {
    //     // let string = LocalStorage::get::<String>(&header_params.bodyhash_allstr_filepath).expect("failed to get allstr");
    //     let value: JsValue = store.get_owned(&header_params.bodyhash_allstr_filepath).unwrap().await.expect("failed to get bodyhash_allstr_filepath").expect("bodyhash_allstr_filepath not found");
    //     let string = value.as_string().unwrap();
    //     let mut streader = StringReader::new(&string);
    //     let bufreader = BufReader::new(streader);
    //     AllstrRegexDef::read_from_reader(bufreader)
    // };
    // let bodyhash_substr_def = {
    //     // let string = LocalStorage::get::<String>(&header_params.bodyhash_substr_filepath).expect("failed to get substr");
    //     let value: JsValue = store.get_owned(&header_params.bodyhash_substr_filepath).unwrap().await.expect("failed to get bodyhash_substr_filepath").expect("bodyhash_substr_filepath not found");
    //     let string = value.as_string().unwrap();
    //     let mut streader = StringReader::new(&string);
    //     let bufreader = BufReader::new(streader);
    //     SubstrRegexDef::read_from_reader(bufreader)
    // };
    let (bodyhash_defs, bodyhash_substr_id) = GLOBAL_BODYHASH_DEFS_AND_ID.get().expect("bodyhash_defs is not set").clone();
    // let mut bodyhash_substr_id = 1;
    // let mut header_regex_defs = vec![];
    // for (allstr_path, substr_pathes) in header_params.allstr_filepathes.iter().zip(header_params.substr_filepathes.iter()) {
    //     // let string = LocalStorage::get::<String>(allstr_path).expect("failed to get allstr");
    //     let value: JsValue = store.get_owned(allstr_path).unwrap().await.expect("failed to get allstr_path").expect("allstr_path not found");
    //     let string = value.as_string().unwrap();
    //     let mut streader = StringReader::new(&string);
    //     let bufreader = BufReader::new(streader);
    //     let allstr = AllstrRegexDef::read_from_reader(bufreader);
    //     let mut substrs = vec![];
    //     for path in substr_pathes {
    //         // let string = LocalStorage::get::<String>(path).expect("failed to get substr");
    //         let value: JsValue = store.get_owned(path).unwrap().await.expect("failed to get path").expect("path not found");
    //         let string = value.as_string().unwrap();
    //         let mut streader = StringReader::new(&string);
    //         let bufreader = BufReader::new(streader);
    //         let substr = SubstrRegexDef::read_from_reader(bufreader);
    //         substrs.push(substr);
    //     }
    //     bodyhash_substr_id += substrs.len();
    //     header_regex_defs.push(RegexDefs { allstr, substrs });
    // }
    // let header_regex_defs = header_params
    //     .allstr_filepathes
    //     .iter()
    //     .zip(header_params.substr_filepathes.iter())
    //     .map(async move |(allstr_path, substr_pathes)| {
    //         // let string = LocalStorage::get::<String>(allstr_path).expect("failed to get allstr");
    //         let value: JsValue = store.get_owned(allstr_path.as_str()).unwrap().await.expect("failed to get allstr_path").expect("allstr_path not found");
    //         let string = value.as_string().unwrap();
    //         let mut streader = StringReader::new(&string);
    //         let bufreader = BufReader::new(streader);
    //         let allstr = AllstrRegexDef::read_from_reader(bufreader);
    //         let substrs = substr_pathes
    //             .into_iter()
    //             .map(async move |path| {
    //                 // let string = LocalStorage::get::<String>(path).expect("failed to get substr");
    //                 let value: JsValue = store.get_owned(JsValue::from_str(&path)).unwrap().await.expect("failed to get path").expect("path not found");
    //                 let string = value.as_string().unwrap();
    //                 let mut streader = StringReader::new(&string);
    //                 let bufreader = BufReader::new(streader);
    //                 SubstrRegexDef::read_from_reader(bufreader)
    //             })
    //             .collect_vec();
    //         bodyhash_substr_id += substrs.len();
    //         RegexDefs { allstr, substrs }
    //     })
    //     .collect_vec();
    let header_regex_defs = GLOBAL_HEADER_DEFS.get().expect("header_regex_defs is not set").clone();
    let header_config = RegexSha2Config::configure(
        meta,
        header_params.max_variable_byte_size,
        header_params.skip_prefix_bytes_size.unwrap_or(0),
        range_config.clone(),
        vec![header_regex_defs, vec![bodyhash_defs]].concat(),
    );

    // let mut body_regex_defs = vec![];
    // for (allstr_path, substr_pathes) in body_params.allstr_filepathes.iter().zip(body_params.substr_filepathes.iter()) {
    //     // let string = LocalStorage::get::<String>(allstr_path).expect("failed to get allstr");
    //     let value: JsValue = store.get_owned(allstr_path).unwrap().await.expect("failed to get allstr_path").expect("allstr_path not found");
    //     let string = value.as_string().unwrap();
    //     let mut streader = StringReader::new(&string);
    //     let bufreader = BufReader::new(streader);
    //     let allstr = AllstrRegexDef::read_from_reader(bufreader);
    //     let mut substrs = vec![];
    //     for path in substr_pathes {
    //         // let string = LocalStorage::get::<String>(path).expect("failed to get substr");
    //         let value: JsValue = store.get_owned(path).unwrap().await.expect("failed to get path").expect("path not found");
    //         let string = value.as_string().unwrap();
    //         let mut streader = StringReader::new(&string);
    //         let bufreader = BufReader::new(streader);
    //         let substr = SubstrRegexDef::read_from_reader(bufreader);
    //         substrs.push(substr);
    //     }
    //     body_regex_defs.push(RegexDefs { allstr, substrs });
    // }
    // let body_regex_defs = body_params
    //     .allstr_filepathes
    //     .iter()
    //     .zip(body_params.substr_filepathes.iter())
    //     .map(async move |(allstr_path, substr_pathes)| {
    //         // let string = LocalStorage::get::<String>(allstr_path).expect("failed to get allstr");
    //         let value: JsValue = store.get_owned(&allstr_path).unwrap().await.expect("failed to get allstr_path").expect("allstr_path not found");
    //         let string = value.as_string().unwrap();
    //         let mut streader = StringReader::new(&string);
    //         let bufreader = BufReader::new(streader);
    //         let allstr = AllstrRegexDef::read_from_reader(bufreader);
    //         let substrs = substr_pathes
    //             .into_iter()
    //             .map(async move |path| {
    //                 // let string = LocalStorage::get::<String>(path).expect("failed to get substr");
    //                 let value: JsValue = store.get_owned(&path).unwrap().await.expect("failed to get path").expect("path not found");
    //                 let string = value.as_string().unwrap();
    //                 let mut streader = StringReader::new(&string);
    //                 let bufreader = BufReader::new(streader);
    //                 SubstrRegexDef::read_from_reader(bufreader)
    //             })
    //             .collect_vec();
    //         RegexDefs { allstr, substrs }
    //     })
    //     .collect_vec();
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

// pub(crate) async fn get_config_params_wasm() -> EmailVerifyConfigParams {
//     let mut db_req: OpenDbRequest = IdbDatabase::open_u32("zk_email", 1).expect("invalid request to open database");
//     db_req.set_on_upgrade_needed(Some(|evt: &IdbVersionChangeEvent| -> Result<(), JsValue> {
//         // Check if the object store exists; create it if it doesn't
//         if let None = evt.db().object_store_names().find(|n| n == "halo2_zkemail_settings") {
//             evt.db().create_object_store("halo2_zkemail_settings")?;
//         }
//         Ok(())
//     }));
//     let db: IdbDatabase = db_req.await.expect("failed to open database");
//     let tx = db.transaction_on_one(HALO2_ZKEMAIL_SETTINGS_OBJECT).expect("failed to open transaction");
//     let store = tx.object_store(HALO2_ZKEMAIL_SETTINGS_OBJECT).expect("failed to open object store");
//     let config_params_str: JsValue = store.get_owned(EMAIL_VERIFY_CONFIG_ENV).unwrap().await.expect("failed to get config params").expect("config params not found");
//     let config_params: EmailVerifyConfigParams = serde_json::from_str(&config_params_str.as_string().unwrap()).expect("failed to parse config params");
//     config_params
// }

pub(crate) fn build_circuit<F: PrimeField>(email_str: &str, public_key_n: &str) -> DefaultEmailVerifyCircuit<F> {
    let email_bytes = email_str.as_bytes().to_vec();
    // let public_key = resolve_rsa_public_key(&email_bytes).await.expect("failed to resolve public key");
    // let public_key_n = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
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

// #[wasm_bindgen]
// pub async fn fetch_params(url: String) -> String {
//     let params = Request::get(&url)
//         .send()
//         .await
//         .expect("failed to send get request for params")
//         .binary()
//         .await
//         .expect("failed to fetch params");
//     // let params = Uint8Array::new(&params).to_vec();
//     log_1(&JsValue::from_str(&format!("params: {:?}", params)));
//     let hex_str = format!("0x{}", hex::encode(params));
//     hex_str
//     // let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params[..])).expect("failed to read params");
//     // params
// }

// #[wasm_bindgen]
// pub async fn fetch_proving_key(url: String) -> String {
//     let pk = Request::get(&url)
//         .send()
//         .await
//         .expect("failed to send get request for pk")
//         .binary()
//         .await
//         .expect("failed to fetch pk");
//     let hex_str = format!("0x{}", hex::encode(pk));
//     hex_str
//     // let pk = Uint8Array::new(&pk).to_vec();
//     // let pk = ProvingKey::<G1Affine>::read::<_, DefaultEmailVerifyCircuit<Fr>>(&mut BufReader::new(&pk[..]), SerdeFormat::RawBytes).expect("failed to read pk");
//     // pk
// }

// #[wasm_bindgen]
// pub async fn fetch_public_key(email_str: &str) -> String {
//     let email_bytes = email_str.as_bytes().to_vec();
//     let public_key = resolve_rsa_public_key(&email_bytes).await.expect("failed to resolve public key");
//     let public_key_n = public_key.n().clone().to_radix_le(16);
//     let hex_str = format!("0x{}", hex::encode(public_key_n));
//     hex_str
// }
