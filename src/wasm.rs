use crate::*;
use halo2_base::halo2_proofs::circuit;
use halo2_base::halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::utils::fe_to_biguint;
use halo2_base::utils::{decompose_fe_to_u64_limbs, value_to_option};
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::PrimeField,
};
use quad_storage;
use serde_json;
use std::io::BufReader;
use stringreader::StringReader;

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
