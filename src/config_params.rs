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

use std::fs::File;

// pub use crate::helpers::*;
// use crate::regex_sha2::RegexSha2Config;
use crate::sign_verify::*;
use cfdkim::canonicalize_signed_email;
use cfdkim::resolve_public_key;
use halo2_base::halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
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
// use regex_sha2_base64::RegexSha2Base64Config;
use once_cell::sync::OnceCell;
use rsa::PublicKeyParts;
use sha2::{Digest, Sha256};
use snark_verifier::loader::LoadedScalar;
use snark_verifier_sdk::CircuitExt;
use std::io::{Read, Write};

#[cfg(not(test))]
#[cfg(not(target_arch = "wasm32"))]
pub fn default_config_params() -> &'static EmailVerifyConfigParams {
    if GLOBAL_CONFIG_PARAMS.get().is_none() {
        EmailVerifyConfigParams::set_from_env();
    }
    EmailVerifyConfigParams::global()
}

#[cfg(test)]
pub fn default_config_params() -> &'static EmailVerifyConfigParams {
    let params = EmailVerifyConfigParams::get_from_env();
    let params = Box::new(params);
    let static_ref: &'static mut EmailVerifyConfigParams = Box::leak(params);
    static_ref
}

static GLOBAL_CONFIG_PARAMS: OnceCell<EmailVerifyConfigParams> = OnceCell::new();

/// The name of env variable for the path to the email configuration json.
pub const EMAIL_VERIFY_CONFIG_ENV: &'static str = "EMAIL_VERIFY_CONFIG";

/// Configuration parameters for [`Sha256DynamicConfig`]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Sha256ConfigParams {
    /// The bits of lookup table. It must be a divisor of 16, i.e., 1, 2, 4, 8, and 16.
    pub num_bits_lookup: usize,
    /// The number of advice columns used to assign values in [`Sha256DynamicConfig`].
    /// Specifying a larger number of columns increases the verification cost and decreases the proving cost.
    pub num_advice_columns: usize,
}

/// Configuration parameters for [`RegexSha2Config`].
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct HeaderConfigParams {
    pub bodyhash_allstr_filepath: String,
    pub bodyhash_substr_filepath: String,
    pub allstr_filepathes: Vec<String>,
    pub substr_filepathes: Vec<Vec<String>>,
    pub max_variable_byte_size: usize,
    pub substr_regexes: Vec<Vec<String>>,
    /// The bytes of the skipped email header that do not satisfy the regexes.
    /// It must be multiple of 64 and less than `max_variable_byte_size`.
    pub skip_prefix_bytes_size: Option<usize>,
    pub expose_substrs: Option<bool>,
}

/// Configuration parameters for [`RegexSha2Base64Config`].
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BodyConfigParams {
    pub allstr_filepathes: Vec<String>,
    pub substr_filepathes: Vec<Vec<String>>,
    pub max_variable_byte_size: usize,
    pub substr_regexes: Vec<Vec<String>>,
    /// The bytes of the skipped email body that do not satisfy the regexes.
    /// It must be multiple of 64 and less than `max_variable_byte_size`.
    pub skip_prefix_bytes_size: Option<usize>,
    pub expose_substrs: Option<bool>,
}

/// Configuration parameters for [`SignVerifyConfig`].
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SignVerifyConfigParams {
    /// The bits of RSA public key.
    pub public_key_bits: usize,
    /// A flag whether the public key is hidden.
    pub hide_public_key: Option<bool>,
}

/// Configuration parameters for the email verification circuits.
///
/// Although the types of some parameters are defined as [`Option`], you will get an error if they are omitted for [`DefaultEmailVerifyCircuit`].
/// You can build a circuit that accepts the same format configuration file except that some parameters are omitted.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct EmailVerifyConfigParams {
    /// The degree of the number of rows, i.e., 2^(`degree`) rows are set.
    pub degree: u32,
    /// The number of advice columns in [`FlexGateConfig`].
    pub num_flex_advice: usize,
    /// The number of advice columns for lookup constraints in [`RangeConfig`].
    pub num_range_lookup_advice: usize,
    /// The number of fix columns in [`FlexGateConfig`].
    pub num_flex_fixed: usize,
    /// The bits of lookup table in [`RangeConfig`], which must be less than `degree`.
    pub range_lookup_bits: usize,
    /// Configuration parameters for [`Sha256DynamicConfig`].
    pub sha256_config: Option<Sha256ConfigParams>,
    /// Configuration parameters for [`SignVerifyConfig`].
    pub sign_verify_config: Option<SignVerifyConfigParams>,
    /// Configuration parameters for [`RegexSha2Config`].
    pub header_config: Option<HeaderConfigParams>,
    /// Configuration parameters for [`RegexSha2Base64Config`].
    pub body_config: Option<BodyConfigParams>,
}

impl EmailVerifyConfigParams {
    pub fn global() -> &'static Self {
        GLOBAL_CONFIG_PARAMS.get().expect("GLOBAL_CONFIG_PARAMS is not set.")
    }

    pub fn set_from_env() {
        let params: Self = Self::get_from_env();
        GLOBAL_CONFIG_PARAMS.set(params).unwrap();
    }

    pub fn get_from_env() -> Self {
        let path = std::env::var(EMAIL_VERIFY_CONFIG_ENV).expect("You must set the configure file path to EMAIL_VERIFY_CONFIG.");
        serde_json::from_reader(File::open(path.as_str()).expect(&format!("{} does not exist.", path))).expect("File is found but invalid.")
    }
}
