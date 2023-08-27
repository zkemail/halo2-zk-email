//! Email verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
//!
//! Our email verification circuit [`DefaultEmailVerifyCircuit`] enables you to prove that
//! - your email is authenticated by a domain server with an RSA digital signature according to the DKIM protocol.
//! - the string in your email satisfies regular expressions (regexes) specified in the circuit.
//! - the string in the public input of the circuit is a correct substring in your email.
//!
//! You can specify the configuration of that circuit with two kinds of json files:
//! 1. Decomposed regex json: defining a regex that the string in the email header/body must satisfy and which kinds of substring will be exposed in the public input.
//! 2. Email configuration json: defining some parameters of the email, e.g., the max size of the email header and body, the RSA public key size, pathes to text files to describe the regex definitions.
//!
//! With these files, you can call our CLI commands or helper functions to generate proving and verifying keys, proofs, and verifier Solidity contracts that conform to your configuration.
//!
//! Our circuit consists of three chips: [`RegexSha2Config`], [`RegexSha2Base64Config`], [`SignVerifyConfig`].
//! - The [`RegexSha2Config`] verifies that the input string satisfies the specified regex, extracts its substrings, and computes its SHA256 hash.
//! - The [`RegexSha2Base64Config`] additionally computes the base64 encoding of the SHA256 hash.
//! - The [`SignVerifyConfig`] verifies the RSA signature with the given SHA256 hash and RSA public key.
//!
//! The [`RegexSha2Config`], [`RegexSha2Base64Config`], [`SignVerifyConfig`] are used for the email header, email body, and RSA signature, respectively.
//! If you want to omit some verification in our circuit, you can build your own circuit with these chips.  

pub mod chars_shift;
pub mod config_params;
#[cfg(not(target_arch = "wasm32"))]
pub mod eth;
#[cfg(not(target_arch = "wasm32"))]
pub mod helpers;
/// Regex verification + SHA256 computation.
pub mod regex_sha2;
/// Regex verification + SHA256 computation + base64 encoding.
pub mod regex_sha2_base64;
/// RSA signature verification.
pub mod sign_verify;
/// Util functions.
pub mod utils;
pub mod wtns_commit;
use std::fs::File;
use std::marker::PhantomData;

use crate::chars_shift::CharsShiftConfig;
pub use crate::helpers::*;
use crate::regex_sha2::RegexSha2Config;
use crate::sign_verify::*;
use crate::utils::*;
use crate::wtns_commit::poseidon_circuit::*;
use crate::wtns_commit::*;
use cfdkim::canonicalize_signed_email;
use cfdkim::resolve_public_key;
pub use config_params::*;
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
/// Re-export [halo2_base64](https://github.com/zkemail/halo2-base64).
pub use halo2_base64;
/// Re-export [halo2_dynamic_sha256](https://github.com/zkemail/halo2-dynamic-sha256/tree/feat/lookup)
pub use halo2_dynamic_sha256;
use halo2_dynamic_sha256::*;
/// Re-export [halo2_regex](https://github.com/zkemail/halo2-regex/tree/feat/multi_path)
pub use halo2_regex;
use halo2_regex::defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef};
use halo2_regex::*;
/// Re-export [halo2_rsa](https://github.com/zkemail/halo2-rsa)
pub use halo2_rsa;
use halo2_rsa::*;
use itertools::Itertools;
use num_bigint::BigUint;
use regex_sha2_base64::RegexSha2Base64Config;
use rsa::PublicKeyParts;
use sha2::{Digest, Sha256};
use snark_verifier::loader::LoadedScalar;
use snark_verifier_sdk::CircuitExt;
use std::io::{Read, Write};

/// The name of env variable for the path to the email configuration json.
pub const EMAIL_VERIFY_CONFIG_ENV: &'static str = "EMAIL_VERIFY_CONFIG";

// /// Configuration parameters for [`Sha256DynamicConfig`]
// #[derive(serde::Serialize, serde::Deserialize)]
// pub struct Sha256ConfigParams {
//     /// The bits of lookup table. It must be a divisor of 16, i.e., 1, 2, 4, 8, and 16.
//     pub num_bits_lookup: usize,
//     /// The number of advice columns used to assign values in [`Sha256DynamicConfig`].
//     /// Specifying a larger number of columns increases the verification cost and decreases the proving cost.
//     pub num_advice_columns: usize,
// }

// /// Configuration parameters for [`RegexSha2Config`].
// #[derive(serde::Serialize, serde::Deserialize)]
// pub struct HeaderConfigParams {
//     pub bodyhash_allstr_filepath: String,
//     pub bodyhash_substr_filepath: String,
//     pub allstr_filepathes: Vec<String>,
//     pub substr_filepathes: Vec<Vec<String>>,
//     pub max_variable_byte_size: usize,
//     pub substr_regexes: Vec<Vec<String>>,
//     /// The bytes of the skipped email header that do not satisfy the regexes.
//     /// It must be multiple of 64 and less than `max_variable_byte_size`.
//     pub skip_prefix_bytes_size: Option<usize>,
// }

// /// Configuration parameters for [`RegexSha2Base64Config`].
// #[derive(serde::Serialize, serde::Deserialize)]
// pub struct BodyConfigParams {
//     pub allstr_filepathes: Vec<String>,
//     pub substr_filepathes: Vec<Vec<String>>,
//     pub max_variable_byte_size: usize,
//     pub substr_regexes: Vec<Vec<String>>,
//     /// The bytes of the skipped email body that do not satisfy the regexes.
//     /// It must be multiple of 64 and less than `max_variable_byte_size`.
//     pub skip_prefix_bytes_size: Option<usize>,
// }

// /// Configuration parameters for [`SignVerifyConfig`].
// #[derive(serde::Serialize, serde::Deserialize)]
// pub struct SignVerifyConfigParams {
//     /// The bits of RSA public key.
//     pub public_key_bits: usize,
// }

// /// Configuration parameters for [`DefaultEmailVerifyCircuit`].
// ///
// /// Although the types of some parameters are defined as [`Option`], you will get an error if they are omitted for [`DefaultEmailVerifyCircuit`].
// /// You can build a circuit that accepts the same format configuration file except that some parameters are omitted.
// #[derive(serde::Serialize, serde::Deserialize)]
// pub struct DefaultEmailVerifyConfigParams {
//     /// The degree of the number of rows, i.e., 2^(`degree`) rows are set.
//     pub degree: u32,
//     /// The number of advice columns in [`FlexGateConfig`].
//     pub num_flex_advice: usize,
//     /// The number of advice columns for lookup constraints in [`RangeConfig`].
//     pub num_range_lookup_advice: usize,
//     /// The number of fix columns in [`FlexGateConfig`].
//     pub num_flex_fixed: usize,
//     /// The bits of lookup table in [`RangeConfig`], which must be less than `degree`.
//     pub range_lookup_bits: usize,
//     /// Configuration parameters for [`Sha256DynamicConfig`].
//     pub sha256_config: Option<Sha256ConfigParams>,
//     /// Configuration parameters for [`SignVerifyConfig`].
//     pub sign_verify_config: Option<SignVerifyConfigParams>,
//     /// Configuration parameters for [`RegexSha2Config`].
//     pub header_config: Option<HeaderConfigParams>,
//     /// Configuration parameters for [`RegexSha2Base64Config`].
//     pub body_config: Option<BodyConfigParams>,
// }

/// Public input definition of [`DefaultEmailVerifyCircuit`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefaultEmailVerifyPublicInput {
    /// A hex string of the SHA256 hash computed from the email header.
    pub header_hash_commit: String,
    /// A hex string of the n parameter in the RSA public key. (The e parameter is fixed to 65537.)
    pub public_key_hash: String,
    /// The start position of the substrings in the email header.
    pub header_starts: Vec<usize>,
    /// The substrings in the email header.
    pub header_substrs: Vec<String>,
    /// The start position of the substrings in the email body.
    pub body_starts: Vec<usize>,
    /// The substrings in the email body.
    pub body_substrs: Vec<String>,
}

impl DefaultEmailVerifyPublicInput {
    /// Create a public input for [`DefaultEmailVerifyCircuit`].
    ///
    /// # Arguments
    /// * `headerhash` - a hex string of the SHA256 hash computed from the email header.
    /// * `public_key_n` - a hex string of the n parameter in the RSA public key.
    /// * `header_substrs` a vector of (the start position, the bytes) of the substrings in the email header.
    /// * `body_starts` - a vector of (the start position, the bytes) of the substrings in the email body.
    /// # Return values
    /// Return a new [`DefaultEmailVerifyPublicInput`].
    pub fn new<F: PrimeField>(header_hash_commit: F, public_key_hash: F, header_substrs: Vec<Option<(usize, String)>>, body_substrs: Vec<Option<(usize, String)>>) -> Self {
        let mut header_starts_vec = vec![];
        let mut header_substrs_vec = vec![];
        for s in header_substrs.into_iter() {
            if let Some(s) = s {
                header_starts_vec.push(s.0);
                header_substrs_vec.push(s.1);
            } else {
                header_starts_vec.push(0);
                header_substrs_vec.push("".to_string());
            }
        }
        let mut body_starts_vec = vec![];
        let mut body_substrs_vec = vec![];
        for s in body_substrs.into_iter() {
            if let Some(s) = s {
                body_starts_vec.push(s.0);
                body_substrs_vec.push(s.1);
            } else {
                body_starts_vec.push(0);
                body_substrs_vec.push("".to_string());
            }
        }
        let field2string = |val: &F| {
            let big = fe_to_biguint(val);
            big.to_str_radix(10)
        };
        DefaultEmailVerifyPublicInput {
            header_hash_commit: field2string(&header_hash_commit),
            public_key_hash: field2string(&public_key_hash),
            header_starts: header_starts_vec,
            header_substrs: header_substrs_vec,
            body_starts: body_starts_vec,
            body_substrs: body_substrs_vec,
        }
    }

    /// Output [`DefaultEmailVerifyPublicInput`] to a json file.
    ///
    /// # Arguments
    /// * `public_input_path` - a file path of the output json file.
    pub fn write_file(&self, public_input_path: &str) {
        let public_input_str = serde_json::to_string(&self).unwrap();
        let mut file = File::create(public_input_path).expect("public_input_path creation failed");
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }

    pub fn instances<F: PrimeField>(&self) -> Vec<F> {
        let header_hash_commit = F::from_str_vartime(&self.header_hash_commit).unwrap();
        let public_key_hash = F::from_str_vartime(&self.public_key_hash).unwrap();
        let mut rlc_inputs = vec![];
        let config_params = default_config_params();
        {
            let max_byte_size = config_params.header_config.as_ref().unwrap().max_variable_byte_size;
            let mut expected_masked_chars = vec![0u8; max_byte_size];
            let mut expected_substr_ids = vec![0u8; max_byte_size];
            for (idx, (substr, start_idx)) in self.header_substrs.iter().zip(self.header_starts.iter()).enumerate() {
                for (j, byte) in substr.as_bytes().iter().enumerate() {
                    expected_masked_chars[*start_idx + j] = *byte;
                    expected_substr_ids[*start_idx + j] = idx as u8 + 1;
                }
            }
            rlc_inputs.append(&mut expected_masked_chars);
            rlc_inputs.append(&mut expected_substr_ids);
        }
        {
            let max_byte_size = config_params.body_config.as_ref().unwrap().max_variable_byte_size;
            let mut expected_masked_chars = vec![0u8; max_byte_size];
            let mut expected_substr_ids = vec![0u8; max_byte_size];
            for (idx, (substr, start_idx)) in self.body_substrs.iter().zip(self.body_starts.iter()).enumerate() {
                for (j, byte) in substr.as_bytes().iter().enumerate() {
                    expected_masked_chars[*start_idx + j] = *byte;
                    expected_substr_ids[*start_idx + j] = idx as u8 + 1;
                }
            }
            rlc_inputs.append(&mut expected_masked_chars);
            rlc_inputs.append(&mut expected_substr_ids);
        }
        let mut rlc = F::zero();
        let mut coeff = header_hash_commit.clone();
        for input in rlc_inputs.into_iter() {
            rlc += coeff * F::from(input as u64);
            coeff *= header_hash_commit.clone();
        }
        println!("rlc instance {:?}", rlc);
        vec![header_hash_commit, public_key_hash, rlc]
    }
}

/// Configuration for [`DefaultEmailVerifyCircuit`].
#[derive(Debug, Clone)]
pub struct DefaultEmailVerifyConfig<F: PrimeField> {
    pub sha256_config: Sha256DynamicConfig<F>,
    pub sign_verify_config: SignVerifyConfig<F>,
    pub header_config: RegexSha2Config<F>,
    pub body_config: RegexSha2Base64Config<F>,
    pub chars_shift_config: CharsShiftConfig<F>,
    /// An instance column for the SHA256 hash of the all public inputs, i.e., the SHA256 hash of the email header, the base64 encoded SHA256 hash of the email body, the RSA public key, and the substrings and their ids in the email header and body.
    pub instances: Column<Instance>,
}

/// Default email verification circuit.
#[derive(Debug, Clone)]
pub struct DefaultEmailVerifyCircuit<F: PrimeField> {
    // /// Email header bytes.
    // pub header_bytes: Vec<u8>,
    // /// Email body bytes.
    // pub body_bytes: Vec<u8>,
    pub email_bytes: Vec<u8>,
    /// RSA public key.
    pub public_key_n: BigUint, // pub public_key: RSAPublicKey<F>,
    // / RSA digital signature.
    // pub signature: RSASignature<F>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for DefaultEmailVerifyCircuit<F> {
    type Config = DefaultEmailVerifyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            email_bytes: vec![],
            public_key_n: self.public_key_n.clone(),
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
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
            vec![
                body_params.max_variable_byte_size,
                header_params.max_variable_byte_size,
                // header_params.max_variable_byte_size,
                // header_params.max_variable_byte_size,
                // body_params.max_variable_byte_size,
                // body_params.max_variable_byte_size,
            ],
            range_config.clone(),
            sha256_params.num_bits_lookup,
            sha256_params.num_advice_columns,
            false,
        );

        let sign_verify_config = SignVerifyConfig::configure(range_config.clone(), sign_verify_params.public_key_bits);

        // assert_eq!(params.body_regex_filepathes.len(), params.body_substr_filepathes.len());
        let bodyhash_allstr_def = AllstrRegexDef::read_from_text(&header_params.bodyhash_allstr_filepath);
        let bodyhash_substr_def = SubstrRegexDef::read_from_text(&header_params.bodyhash_substr_filepath);
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
                let allstr = AllstrRegexDef::read_from_text(&allstr_path);
                let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
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
                let allstr = AllstrRegexDef::read_from_text(&allstr_path);
                let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
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

    fn synthesize(&self, mut config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        config.sha256_config.range().load_lookup_table(&mut layouter)?;
        config.sha256_config.load(&mut layouter)?;
        config.header_config.load(&mut layouter)?;
        config.body_config.load(&mut layouter)?;
        let mut first_pass = SKIP_FIRST_PASS;
        let mut public_hash_cell = vec![];
        let params = default_config_params();
        if let Some(sign_config) = params.sign_verify_config.as_ref() {
            assert_eq!(self.public_key_n.bits() as usize, sign_config.public_key_bits);
        }
        let (header_bytes, body_bytes, signature_bytes) = canonicalize_signed_email(&self.email_bytes).unwrap();
        println!("canonicalized_header:\n{}", String::from_utf8(header_bytes.clone()).unwrap());
        println!("canonicalized_body:\n{}", String::from_utf8(body_bytes.clone()).unwrap());

        layouter.assign_region(
            || "zkemail",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = &mut config.sha256_config.new_context(region);
                let header_params = params.header_config.as_ref().expect("header_config is required");
                let body_params = params.body_config.as_ref().expect("body_config is required");

                let range = config.sha256_config.range().clone();
                let gate = range.gate.clone();

                // 1. Extract sub strings in the body and compute the base64 encoded hash of the body.
                let body_result = config.body_config.match_hash_and_base64(ctx, &mut config.sha256_config, &body_bytes)?;

                // 2. Extract sub strings in the header, which includes the body hash, and compute the raw hash of the header.
                let header_result = config.header_config.match_and_hash(ctx, &mut config.sha256_config, &header_bytes)?;

                // 3. Verify the rsa signature.
                let e = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                let public_key = RSAPublicKey::<F>::new(Value::known(self.public_key_n.clone()), e);
                let signature = RSASignature::<F>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
                let (assigned_public_key, assigned_signature) = config.sign_verify_config.verify_signature(ctx, &header_result.hash_bytes, public_key, signature.clone())?;

                // 4. Assert that the bodyhash is included in the email header.
                let (extracted_bodyhash, is_target_vec) = config
                    .chars_shift_config
                    .shift(ctx, &gate, &header_result.regex.masked_characters, &header_result.regex.all_substr_ids);
                for (a, b) in extracted_bodyhash.iter().zip(body_result.encoded_hash.iter()) {
                    ctx.region.constrain_equal(a.cell(), b.cell())?;
                }

                let poseidon = PoseidonChipBn254_8_58::new(ctx, &gate);
                let sign_rand = poseidon.hash_elements(ctx, &gate, &assigned_signature.c.limbs()).unwrap().0[0].clone();
                let header_hash_commit = assigned_commit_wtns_bytes(ctx, &gate, &poseidon, &sign_rand, &header_result.hash_bytes);
                let public_key_n_hash = poseidon.hash_elements(ctx, &gate, &assigned_public_key.n.limbs()).unwrap().0[0].clone();
                public_hash_cell.push(header_hash_commit.cell());
                public_hash_cell.push(public_key_n_hash.cell());

                let mut rlc_inputs = vec![];
                let mut bodyhash_masked_chars = vec![];
                let mut bodyhash_masked_substr_ids = vec![];
                for idx in 0..header_params.max_variable_byte_size {
                    let is_target = &is_target_vec[idx];
                    bodyhash_masked_chars.push(gate.select(
                        ctx,
                        QuantumCell::Constant(F::zero()),
                        QuantumCell::Existing(&header_result.regex.masked_characters[idx]),
                        QuantumCell::Existing(is_target),
                    ));
                    bodyhash_masked_substr_ids.push(gate.select(
                        ctx,
                        QuantumCell::Constant(F::zero()),
                        QuantumCell::Existing(&header_result.regex.all_substr_ids[idx]),
                        QuantumCell::Existing(is_target),
                    ));
                }
                rlc_inputs.append(&mut bodyhash_masked_chars);
                rlc_inputs.append(&mut bodyhash_masked_substr_ids);
                rlc_inputs.append(&mut body_result.regex.masked_characters.clone());
                rlc_inputs.append(&mut body_result.regex.all_substr_ids.clone());
                let mut rlc = gate.load_zero(ctx);
                let mut coeff = header_hash_commit.clone();
                for input in rlc_inputs.into_iter() {
                    rlc = gate.mul_add(ctx, QuantumCell::Existing(&input), QuantumCell::Existing(&coeff), QuantumCell::Existing(&rlc));
                    coeff = gate.mul(ctx, QuantumCell::Existing(&header_hash_commit), QuantumCell::Existing(&coeff));
                }
                public_hash_cell.push(rlc.cell());

                // {
                //     let public_hash_result: AssignedHashResult<F> = config.sha256_config.digest(ctx, &public_hash_input, None)?;
                // }

                // let public_hash_input = get_email_circuit_public_hash_input(
                //     &header_result.hash_value,
                //     &self.public_key_n.to_bytes_le(),
                //     header_substrs,
                //     body_substrs,
                //     header_params.max_variable_byte_size,
                //     body_params.max_variable_byte_size,
                // );
                // let public_hash_result: AssignedHashResult<F> = config.sha256_config.digest(ctx, &public_hash_input, None)?;
                // for (idx, v) in public_hash_result.input_bytes[128..(128 + 256)].iter().enumerate() {
                //     v.value().map(|v| println!("idx {} code {}", idx, v.get_lower_32()));
                // }

                // for (idx, v) in header_result.regex.masked_characters.iter().enumerate() {
                //     v.value().map(|v| {
                //         println!(
                //             "idx {} code {} char {} substr id {:?}",
                //             idx,
                //             v.get_lower_32(),
                //             (v.get_lower_32() as u8) as char,
                //             header_result.regex.all_substr_ids[idx]
                //         )
                //     });
                // }
                // for (idx, v) in body_result.regex.masked_characters.iter().enumerate() {
                //     v.value()
                //         .map(|v| println!("idx {} code {} char {}", idx, v.get_lower_32(), (v.get_lower_32() as u8) as char));
                // }
                // let assigned_public_key_bytes = assigned_public_key
                //     .n
                //     .limbs()
                //     .into_iter()
                //     .flat_map(|limb| {
                //         let limb_val = value_to_option(limb.value()).unwrap();
                //         let bytes = decompose_fe_to_u64_limbs(limb_val, 64 / 8, 8);
                //         let mut sum = gate.load_zero(ctx);
                //         let assigned = bytes
                //             .into_iter()
                //             .enumerate()
                //             .map(|(idx, byte)| {
                //                 let assigned = gate.load_witness(ctx, Value::known(F::from(byte)));
                //                 range.range_check(ctx, &assigned, 8);
                //                 sum = gate.mul_add(
                //                     ctx,
                //                     QuantumCell::Existing(&assigned),
                //                     QuantumCell::Constant(F::from(1u64 << (8 * idx))),
                //                     QuantumCell::Existing(&sum),
                //                 );
                //                 assigned
                //             })
                //             .collect_vec();
                //         gate.assert_equal(ctx, QuantumCell::Existing(&sum), QuantumCell::Existing(limb));
                //         assigned
                //     })
                //     .collect_vec();
                // // for (idx, v) in assigned_public_key_bytes.iter().enumerate() {
                // //     v.value().map(|v| println!("idx {} byte {}", 128 + idx, v.get_lower_32()));
                // // }
                // let assigned_public_hash_input = vec![
                //     header_result.hash_bytes.into_iter().map(|v| v.cell()).collect_vec(),
                //     body_result.encoded_hash.into_iter().map(|v| v.cell()).collect_vec(),
                //     vec![gate.load_zero(ctx).cell(); 128 - 32 - 44],
                //     assigned_public_key_bytes.into_iter().map(|v| v.cell()).collect_vec(),
                //     vec![header_result.regex.masked_characters, body_result.regex.masked_characters]
                //         .concat()
                //         .into_iter()
                //         .map(|v| v.cell())
                //         .collect_vec(),
                //     vec![header_result.regex.all_substr_ids, body_result.regex.all_substr_ids]
                //         .concat()
                //         .into_iter()
                //         .map(|v| v.cell())
                //         .collect_vec(),
                // ]
                // .concat();
                // for (a, b) in public_hash_result.input_bytes[0..assigned_public_hash_input.len()]
                //     .into_iter()
                //     .map(|v| v.cell())
                //     .collect_vec()
                //     .into_iter()
                //     .zip(assigned_public_hash_input.into_iter())
                // {
                //     ctx.region.constrain_equal(a, b)?;
                // }
                // debug_assert_eq!(public_hash_result.output_bytes.len(), 32);
                // let mut packed_public_hash = gate.load_zero(ctx);
                // let mut coeff = F::from(1u64);
                // for byte in public_hash_result.output_bytes[0..31].iter() {
                //     packed_public_hash = gate.mul_add(ctx, QuantumCell::Existing(byte), QuantumCell::Constant(coeff), QuantumCell::Existing(&packed_public_hash));
                //     coeff *= F::from(256u64);
                // }
                range.finalize(ctx);
                Ok(())
            },
        )?;
        for (idx, cell) in public_hash_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instances, idx)?;
        }
        Ok(())
    }
}

impl<F: PrimeField> CircuitExt<F> for DefaultEmailVerifyCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![3]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let public_input = self.gen_default_public_input();
        vec![public_input.instances()]

        // let header_str = String::from_utf8(header_bytes).unwrap();
        // let body_str = String::from_utf8(body_bytes).unwrap();
        // let params = Self::read_config_params();
        // let header_params = params.header_config.as_ref().expect("header_config is required");
        // let body_params = params.body_config.as_ref().expect("body_config is required");
        // let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_params.substr_regexes.clone(), body_params.substr_regexes.clone());
        // let public_input = DefaultEmailVerifyPublicInput::new(headerhash, self.public_key_n.clone(), header_substrs, body_substrs);
        // vec![Self::_get_instances_from_default_public_input(public_input)]
    }
}

impl<F: PrimeField> DefaultEmailVerifyCircuit<F> {
    pub const DEFAULT_E: u128 = 65537;

    pub fn new(email_bytes: Vec<u8>, public_key_n: BigUint) -> Self {
        Self {
            email_bytes,
            public_key_n,
            _f: PhantomData,
        }
    }

    /// Generate a new circuit from the given email file.
    ///
    /// # Arguments
    /// * `email_path` - a file path of the email file.
    ///
    /// # Return values
    /// Return a new [`DefaultEmailVerifyCircuit`], the SHA256 hash bytes of the email header, a vector of (`start_position`, `substr`) in the email header, and a vector of (`start_position`, `substr`) in the email body.
    pub async fn gen_circuit_from_email_path(email_path: &str) -> Self {
        let email_bytes = {
            let mut f = File::open(email_path).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };
        // println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
        // let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
        // let headerhash = Sha256::digest(&canonicalized_header).to_vec();
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
        // let config_params = default_config_params();
        // let header_config = config_params.header_config.as_ref().expect("header_config is required");
        // let body_config = config_params.body_config.as_ref().expect("body_config is required");
        // let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes.clone(), body_config.substr_regexes.clone());
        // let circuit = Self {
        //     email_bytes,
        //     public_key_n,
        //     _f: PhantomData,
        // };
        let circuit = Self::new(email_bytes, public_key_n);
        circuit
    }

    pub fn gen_default_public_input(&self) -> DefaultEmailVerifyPublicInput {
        let (header_bytes, body_bytes, signature_bytes) = canonicalize_signed_email(&self.email_bytes).unwrap();
        let header_hash = Sha256::digest(&header_bytes).to_vec();
        let signature = BigUint::from_bytes_be(&signature_bytes);
        let config_params = default_config_params();
        let num_limbs = config_params.sign_verify_config.as_ref().unwrap().public_key_bits / LIMB_BITS;
        let sign_rand: F = {
            let limbs = decompose_biguint(&signature, num_limbs, LIMB_BITS);
            poseidon_hash_fields(&limbs)
        };
        let header_hash_commit = value_commit_wtns_bytes(&sign_rand, &header_hash);
        let public_key_hash = {
            let limbs = decompose_biguint(&self.public_key_n, num_limbs, LIMB_BITS);
            poseidon_hash_fields(&limbs)
        };
        let header_params: &HeaderConfigParams = config_params.header_config.as_ref().unwrap();
        let body_params = config_params.body_config.as_ref().unwrap();
        let header_str = String::from_utf8(header_bytes[header_params.skip_prefix_bytes_size.unwrap_or(0)..].to_vec()).unwrap();
        let body_str = String::from_utf8(body_bytes[body_params.skip_prefix_bytes_size.unwrap_or(0)..].to_vec()).unwrap();
        let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_params.substr_regexes.clone(), body_params.substr_regexes.clone());
        DefaultEmailVerifyPublicInput::new(header_hash_commit, public_key_hash, header_substrs, body_substrs)
    }

    // /// Retrieve instance values from the given [`DefaultEmailVerifyPublicInput`] json file.
    // ///
    // /// # Arguments
    // /// * `public_input_path` - a file path of the [`DefaultEmailVerifyPublicInput`] json file.
    // ///
    // /// # Return values
    // /// Return a vector of the instance values.
    // pub fn get_instances_from_default_public_input(public_input_path: &str) -> Vec<F> {
    //     let public_input = serde_json::from_reader::<File, DefaultEmailVerifyPublicInput>(File::open(public_input_path).unwrap()).unwrap();
    //     Self::_get_instances_from_default_public_input(public_input)
    // }

    // fn _get_instances_from_default_public_input(public_input: DefaultEmailVerifyPublicInput) -> Vec<F> {
    //     let config_params = default_config_params();
    //     let header_params = config_params.header_config.as_ref().expect("header_config is required");
    //     let body_params = config_params.body_config.as_ref().expect("body_config is required");
    //     let headerhash = hex::decode(&public_input.headerhash[2..]).unwrap();
    //     let public_key_n_bytes = hex::decode(&public_input.public_key_n_bytes[2..]).unwrap();
    //     let header_substrs = public_input
    //         .header_starts
    //         .into_iter()
    //         .zip(public_input.header_substrs.into_iter())
    //         .map(|(start, substr)| Some((start, substr)))
    //         .collect_vec();
    //     let body_substrs = public_input
    //         .body_starts
    //         .into_iter()
    //         .zip(public_input.body_substrs.into_iter())
    //         .map(|(start, substr)| Some((start, substr)))
    //         .collect_vec();
    //     let public_hash_input = get_email_circuit_public_hash_input(
    //         &headerhash,
    //         &public_key_n_bytes,
    //         header_substrs,
    //         body_substrs,
    //         header_params.max_variable_byte_size,
    //         body_params.max_variable_byte_size,
    //     );
    //     let public_hash: Vec<u8> = Sha256::digest(&public_hash_input).to_vec();
    //     let public_fr = {
    //         let lo = F::from_u128(u128::from_le_bytes(public_hash[0..16].try_into().unwrap()));
    //         let mut hi_bytes = [0; 16];
    //         for idx in 0..15 {
    //             hi_bytes[idx] = public_hash[16 + idx];
    //         }
    //         let hi = F::from_u128(u128::from_le_bytes(hi_bytes));
    //         hi * F::from(2).pow_const(128) + lo
    //     };
    //     vec![public_fr]
    // }
}

#[cfg(test)]
mod test {
    use super::*;
    use cfdkim::{canonicalize_signed_email, resolve_public_key, SignerBuilder};
    use halo2_base::halo2_proofs::{
        circuit::Value,
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
    };
    use halo2_regex::vrm::DecomposedRegexConfig;
    use halo2_rsa::RSAPubE;
    use mailparse::parse_mail;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use rsa::{PublicKeyParts, RsaPrivateKey};
    use snark_verifier_sdk::CircuitExt;
    use std::{fs::File, io::Read, path::Path};
    use temp_env;

    #[test]
    fn test_generated_email1() {
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test1_email_verify.config"), || {
            let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
            regex_bodyhash_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                    &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
                )
                .unwrap();
            let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
            regex_from_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/from_allstr.txt").to_path_buf(),
                    &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
                )
                .unwrap();
            let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test1_email_body_defs.json").unwrap()).unwrap();
            regex_body_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/test1_email_body_allstr.txt").to_path_buf(),
                    &[Path::new("./test_data/test1_email_body_substr_0.txt").to_path_buf()],
                )
                .unwrap();
            let params = default_config_params();
            let sign_verify_config = params.sign_verify_config.as_ref().expect("sign_verify_config is required");
            let mut rng = thread_rng();
            let _private_key = RsaPrivateKey::new(&mut rng, sign_verify_config.public_key_bits).expect("failed to generate a key");
            let public_key = rsa::RsaPublicKey::from(&_private_key);
            let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
            let message = concat!("From: alice@zkemail.com\r\n", "\r\n", "email was meant for @zkemailverify.",).as_bytes();
            let email = parse_mail(message).unwrap();
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            let signer = SignerBuilder::new()
                .with_signed_headers(&["From"])
                .unwrap()
                .with_private_key(private_key)
                .with_selector("default")
                .with_signing_domain("zkemail.com")
                .with_logger(&logger)
                .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .build()
                .unwrap();
            let signature = signer.sign(&email).unwrap();
            let email_bytes = vec![signature.as_bytes(), b"\r\n", message].concat();
            println!("email: {}", String::from_utf8(email_bytes.clone()).unwrap());
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultEmailVerifyCircuit::<Fr>::new(email_bytes, public_key_n);
            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[test]
    fn test_generated_email2() {
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test2_email_verify.config"), || {
            let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
            regex_bodyhash_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                    &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
                )
                .unwrap();
            let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
            regex_from_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/from_allstr.txt").to_path_buf(),
                    &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
                )
                .unwrap();
            let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
            regex_to_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/to_allstr.txt").to_path_buf(),
                    &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
                )
                .unwrap();
            let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test2_email_body_defs.json").unwrap()).unwrap();
            regex_body_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/test2_email_body_allstr.txt").to_path_buf(),
                    &[
                        Path::new("./test_data/test2_email_body_substr_0.txt").to_path_buf(),
                        Path::new("./test_data/test2_email_body_substr_1.txt").to_path_buf(),
                    ],
                )
                .unwrap();
            let params = default_config_params();
            let sign_verify_config = params.sign_verify_config.as_ref().expect("sign_verify_config is required");
            let mut rng = thread_rng();
            let _private_key = RsaPrivateKey::new(&mut rng, sign_verify_config.public_key_bits).expect("failed to generate a key");
            let public_key = rsa::RsaPublicKey::from(&_private_key);
            let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
            let message = concat!(
                "From: alice@zkemail.com\r\n",
                "To: bob@example.com\r\n",
                "\r\n",
                "email was meant for @zkemailverify and halo.",
            )
            .as_bytes();
            let email = parse_mail(message).unwrap();
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            let signer = SignerBuilder::new()
                .with_signed_headers(&["To", "From"])
                .unwrap()
                .with_private_key(private_key)
                .with_selector("default")
                .with_signing_domain("zkemail.com")
                .with_logger(&logger)
                .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .build()
                .unwrap();
            let signature = signer.sign(&email).unwrap();
            println!("signature {}", signature);
            let email_bytes = vec![signature.as_bytes(), b"\r\n", message].concat();
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultEmailVerifyCircuit::<Fr>::new(email_bytes, public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[tokio::test]
    async fn test_existing_email1() {
        let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
        regex_bodyhash_decomposed
            .gen_regex_files(
                &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
        regex_from_decomposed
            .gen_regex_files(
                &Path::new("./test_data/from_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
        regex_to_decomposed
            .gen_regex_files(
                &Path::new("./test_data/to_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
        regex_subject_decomposed
            .gen_regex_files(
                &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex1_email_body_defs.json").unwrap()).unwrap();
        regex_body_decomposed
            .gen_regex_files(
                &Path::new("./test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let email_bytes = {
            let mut f = File::open("./test_data/test_email1.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
            let params = default_config_params();
            // let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
            // println!("header len\n {}", canonicalized_header.len());
            // println!("body len\n {}", canonicalized_body.len());
            // println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
            // println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultEmailVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[tokio::test]
    async fn test_existing_email2() {
        let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
        regex_bodyhash_decomposed
            .gen_regex_files(
                &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
        regex_from_decomposed
            .gen_regex_files(
                &Path::new("./test_data/from_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
        regex_to_decomposed
            .gen_regex_files(
                &Path::new("./test_data/to_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
        regex_subject_decomposed
            .gen_regex_files(
                &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex2_email_body_defs.json").unwrap()).unwrap();
        regex_body_decomposed
            .gen_regex_files(
                &Path::new("./test_data/test_ex2_email_body_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/test_ex2_email_body_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/test_ex2_email_body_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/test_ex2_email_body_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let email_bytes = {
            let mut f = File::open("./test_data/test_email2.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex2_email_verify.config"), move || {
            let params = default_config_params();
            // let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
            // println!("header len\n {}", canonicalized_header.len());
            // println!("body len\n {}", canonicalized_body.len());
            // println!("body\n{:?}", canonicalized_body);
            // println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
            // println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultEmailVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[ignore]
    #[tokio::test]
    async fn test_existing_email3() {
        let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
        regex_bodyhash_decomposed
            .gen_regex_files(
                &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_timestamp_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/timestamp_defs.json").unwrap()).unwrap();
        regex_timestamp_decomposed
            .gen_regex_files(
                &Path::new("./test_data/timestamp_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/timestamp_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex3_email_body_defs.json").unwrap()).unwrap();
        regex_body_decomposed
            .gen_regex_files(
                &Path::new("./test_data/test_ex3_email_body_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/test_ex3_email_body_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let email_bytes = {
            let mut f = File::open("./test_data/test_email3.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex3_email_verify.config"), move || {
            let params = default_config_params();
            // let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
            // println!("header len\n {}", canonicalized_header.len());
            // println!("body len\n {}", canonicalized_body.len());
            // println!("body\n{:?}", canonicalized_body);
            // println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
            // println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultEmailVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[tokio::test]
    async fn test_existing_email_invalid1() {
        let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
        regex_bodyhash_decomposed
            .gen_regex_files(
                &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
        regex_from_decomposed
            .gen_regex_files(
                &Path::new("./test_data/from_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
        regex_to_decomposed
            .gen_regex_files(
                &Path::new("./test_data/to_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
        regex_subject_decomposed
            .gen_regex_files(
                &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex1_email_body_defs.json").unwrap()).unwrap();
        regex_body_decomposed
            .gen_regex_files(
                &Path::new("./test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let email_bytes = {
            let mut f = File::open("./test_data/test_email1.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
            let params = default_config_params();
            // let (canonicalized_header, canonicalized_body, mut signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
            // println!("header len\n {}", canonicalized_header.len());
            // println!("body len\n {}", canonicalized_body.len());
            // println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
            // println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
            let mut public_key_n_bytes = public_key.n().clone().to_bytes_be();
            for i in 0..256 {
                public_key_n_bytes[i] = 255;
            }
            let public_key_n = BigUint::from_bytes_be(&public_key_n_bytes);
            let circuit = DefaultEmailVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert!(prover.verify().is_err());
        });
    }

    #[tokio::test]
    async fn test_existing_email_invalid2() {
        let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
        regex_bodyhash_decomposed
            .gen_regex_files(
                &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
        regex_from_decomposed
            .gen_regex_files(
                &Path::new("./test_data/from_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
        regex_to_decomposed
            .gen_regex_files(
                &Path::new("./test_data/to_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
        regex_subject_decomposed
            .gen_regex_files(
                &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex1_email_body_defs.json").unwrap()).unwrap();
        regex_body_decomposed
            .gen_regex_files(
                &Path::new("./test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let email_bytes = {
            let mut f = File::open("./test_data/invalid_test_email1.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
            let params = default_config_params();
            // let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
            // println!("header len\n {}", canonicalized_header.len());
            // println!("body len\n {}", canonicalized_body.len());
            // println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
            // println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultEmailVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert!(prover.verify().is_err());
        });
    }
}
