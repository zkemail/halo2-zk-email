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

pub mod base64_circuit;
pub mod chars_shift;
pub mod config_params;
pub mod regex_circuit;
pub mod sha2_circuit;
pub mod sign_verify;
pub mod wtns_commit;

#[cfg(not(target_arch = "wasm32"))]
pub mod eth;
pub mod helpers;

/// Regex verification + SHA256 computation.
// pub mod regex_sha2;
/// Regex verification + SHA256 computation + base64 encoding.
// pub mod regex_sha2_base64;
/// RSA signature verification.
/// Util functions.
// pub mod utils;
use std::fs::File;
use std::marker::PhantomData;

// pub use crate::helpers::*;
// use crate::regex_sha2::RegexSha2Config;
pub use crate::sign_verify::*;
// use crate::utils::*;
pub use crate::base64_circuit::*;
pub use crate::chars_shift::*;
pub use crate::config_params::*;
pub use crate::regex_circuit::*;
pub use crate::sha2_circuit::*;
use crate::wtns_commit::poseidon_circuit::*;
pub use crate::wtns_commit::*;
use base64::{engine::general_purpose, Engine as _};
use cfdkim::canonicalize_signed_email;
use cfdkim::resolve_public_key;
use config_params::default_config_params;
use config_params::EmailVerifyConfigParams;
use fancy_regex::Regex;
use halo2_base::halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::dev::CircuitCost;
use halo2_base::halo2_proofs::dev::CircuitGates;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_base::halo2_proofs::halo2curves::bn256::G1;
use halo2_base::halo2_proofs::plonk::verify_proof;
use halo2_base::halo2_proofs::plonk::ProvingKey;
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_base::halo2_proofs::poly::VerificationStrategy;
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::utils::fe_to_biguint;
use halo2_base::utils::{decompose_fe_to_u64_limbs, value_to_option};
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::PrimeField,
    Context, ContextParams,
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
use snark_verifier_sdk::evm::gen_evm_proof_shplonk;
use snark_verifier_sdk::gen_pk;
use snark_verifier_sdk::halo2::gen_proof_shplonk;
use snark_verifier_sdk::halo2::PoseidonTranscript;
use snark_verifier_sdk::NativeLoader;
// use regex_sha2_base64::RegexSha2Base64Config;
use ark_std::{end_timer, start_timer};
use base64_circuit::*;
use halo2_base64::Base64Config;
use regex_circuit::*;
use rsa::PublicKeyParts;
use sha2::{Digest, Sha256};
use sha2_circuit::*;
use snark_verifier::loader::LoadedScalar;
use snark_verifier_sdk::CircuitExt;
use std::io::{Read, Write};

pub const BODYHASH_BYTES: usize = 44;

#[derive(Debug, Clone)]
pub struct EmailVerifyCircuits<F: PrimeField> {
    pub sha2_header: Sha256HeaderCircuit<F>,
    pub sign_verify: SignVerifyCircuit<F>,
    pub regex_header: RegexHeaderCircuit<F>,
    pub sha2_header_masked_chars: Option<Sha256HeaderMaskedCharsCircuit<F>>,
    pub sha2_header_substr_ids: Option<Sha256HeaderSubstrIdsCircuit<F>>,
    pub regex_bodyhash: Option<RegexBodyHashCircuit<F>>,
    pub chars_shift_bodyhash: Option<CharsShiftBodyHashCircuit<F>>,
    pub sha2_body: Option<Sha256BodyCircuit<F>>,
    pub base64: Option<Base64Circuit<F>>,
    pub regex_body: Option<RegexBodyCircuit<F>>,
    pub sha2_body_masked_chars: Option<Sha256BodyMaskedCharsCircuit<F>>,
    pub sha2_body_substr_ids: Option<Sha256BodySubstrIdsCircuit<F>>,
    pub sign_rand: F,
    pub tag: F,
    pub header_expose_substrs: bool,
    pub body_enable: bool,
    pub body_expose_substrs: bool,
}

impl<F: PrimeField> EmailVerifyCircuits<F> {
    const BODYHASH_REGEX: &'static str =
        r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)";
    pub fn new(email_bytes: &[u8], public_key_n: BigUint, tag: F) -> Self {
        let config_params = default_config_params();
        let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).expect("fail to parse the given email bytes");
        let signature = BigUint::from_bytes_be(&signature_bytes);
        let sign_rand = derive_sign_rand(&signature, config_params.sign_verify_config.as_ref().unwrap().public_key_bits);
        let sha2_header = Sha256HeaderCircuit::new(canonicalized_header.clone(), sign_rand);
        let headerhash = Sha256::digest(&canonicalized_header).to_vec();
        let sign_verify = SignVerifyCircuit::new(headerhash, public_key_n, signature, tag);
        let header_config = config_params.header_config.as_ref().unwrap();
        let header_regex_defs = header_config
            .allstr_filepathes
            .iter()
            .zip(header_config.substr_filepathes.iter())
            .map(|(allstr_path, substr_pathes)| {
                let allstr = AllstrRegexDef::read_from_text(&allstr_path);
                let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
                RegexDefs { allstr, substrs }
            })
            .collect_vec();
        let header_str = String::from_utf8(canonicalized_header.clone()).expect("invalid utf8 of header");
        let header_substrs = header_config.substr_regexes.iter().map(|regex| Self::get_substr(&header_str, regex)).collect_vec();
        let regex_header = RegexHeaderCircuit::new(canonicalized_header.clone(), header_regex_defs, header_substrs, sign_rand);
        let (sha2_header_masked_chars, sha2_header_substr_ids) = if header_config.expose_substrs.unwrap_or(false) {
            let (expected_masked_chars, expected_substr_ids) = substrs2expected_chars_and_ids(header_config.max_variable_byte_size, &regex_header.substrs);
            let sha2_header_masked_chars = Sha256HeaderMaskedCharsCircuit::new(expected_masked_chars, sign_rand);
            let sha2_header_substr_ids = Sha256HeaderSubstrIdsCircuit::new(expected_substr_ids, sign_rand);
            (Some(sha2_header_masked_chars), Some(sha2_header_substr_ids))
        } else {
            (None, None)
        };
        let (regex_bodyhash, chars_shift_bodyhash, sha2_body, base64, regex_body, sha2_body_masked_chars, sha2_body_substr_ids) =
            if let Some(body_config) = config_params.body_config.as_ref() {
                let bodyhash_regex_def = {
                    let allstr = AllstrRegexDef::read_from_text(&header_config.bodyhash_allstr_filepath);
                    let substr = SubstrRegexDef::read_from_text(&header_config.bodyhash_substr_filepath);
                    RegexDefs { allstr, substrs: vec![substr] }
                };
                let bodyhash_substr = Self::get_substr(&header_str, &[Self::BODYHASH_REGEX.to_string()]);
                let regex_bodyhash = RegexBodyHashCircuit::new(canonicalized_header.clone(), vec![bodyhash_regex_def], vec![bodyhash_substr], sign_rand);
                let (expected_bodyhash_substrs, expected_bodyhash_substr_ids) = substrs2expected_chars_and_ids(header_config.max_variable_byte_size, &regex_bodyhash.substrs);
                let chars_shift_bodyhash = CharsShiftBodyHashCircuit::new(1, expected_bodyhash_substrs, expected_bodyhash_substr_ids, BODYHASH_BYTES, sign_rand);
                // let (expected_masked_chars, expected_substr_ids) =
                //     get_expected_substr_chars_and_ids(&canonicalized_body, &body_config.substr_regexes, body_config.max_variable_byte_size);
                let sha2_body = Sha256BodyCircuit::new(canonicalized_body.clone(), sign_rand);
                let bodyhash = Sha256::digest(&canonicalized_body).to_vec();
                let base64 = Base64Circuit::new(bodyhash, sign_rand);
                let body_regex_defs = body_config
                    .allstr_filepathes
                    .iter()
                    .zip(body_config.substr_filepathes.iter())
                    .map(|(allstr_path, substr_pathes)| {
                        let allstr = AllstrRegexDef::read_from_text(&allstr_path);
                        let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
                        RegexDefs { allstr, substrs }
                    })
                    .collect_vec();
                let body_str = String::from_utf8(canonicalized_body.clone()).expect("invalid utf8 of body");
                let body_substrs = body_config.substr_regexes.iter().map(|regex| Self::get_substr(&body_str, regex)).collect_vec();
                let regex_body = RegexBodyCircuit::new(canonicalized_body.clone(), body_regex_defs, body_substrs, sign_rand);
                let (sha2_body_masked_chars, sha2_body_substr_ids) = if body_config.expose_substrs.unwrap_or(false) {
                    let (expected_masked_chars, expected_substr_ids) = substrs2expected_chars_and_ids(body_config.max_variable_byte_size, &regex_body.substrs);
                    let sha2_body_masked_chars = Sha256BodyMaskedCharsCircuit::new(expected_masked_chars, sign_rand);
                    let sha2_body_substr_ids = Sha256BodySubstrIdsCircuit::new(expected_substr_ids, sign_rand);
                    (Some(sha2_body_masked_chars), Some(sha2_body_substr_ids))
                } else {
                    (None, None)
                };
                (
                    Some(regex_bodyhash),
                    Some(chars_shift_bodyhash),
                    Some(sha2_body),
                    Some(base64),
                    Some(regex_body),
                    sha2_body_masked_chars,
                    sha2_body_substr_ids,
                )
            } else {
                (None, None, None, None, None, None, None)
            };
        let header_expose_substrs = header_config.expose_substrs.unwrap_or(false);
        let body_enable = config_params.body_config.is_some();
        let body_expose_substrs = if let Some(body_config) = config_params.body_config.as_ref() {
            body_config.expose_substrs.unwrap_or(false)
        } else {
            false
        };
        Self {
            sha2_header,
            sign_verify,
            regex_header,
            sha2_header_masked_chars,
            sha2_header_substr_ids,
            regex_bodyhash,
            chars_shift_bodyhash,
            sha2_body,
            base64,
            regex_body,
            sha2_body_masked_chars,
            sha2_body_substr_ids,
            sign_rand,
            tag,
            header_expose_substrs,
            body_enable,
            body_expose_substrs,
        }
    }

    pub fn instances(&self) -> EmailVerifyInstances<F> {
        let sha2_header_ins = &self.sha2_header.instances()[0];
        let header_bytes_commit = sha2_header_ins[0];
        let header_hash_commit = sha2_header_ins[1];
        let sign_verify_ins = &self.sign_verify.instances()[0];
        let public_key_n_hash = sign_verify_ins[0];
        debug_assert_eq!(header_hash_commit, sign_verify_ins[1]);
        let tag = sign_verify_ins[2];
        let regex_header_ins = &self.regex_header.instances()[0];
        debug_assert_eq!(header_bytes_commit, regex_header_ins[0]);
        let header_masked_chars_commit = regex_header_ins[1];
        let header_substr_ids_commit = regex_header_ins[2];
        let mut header_substrs = vec![];
        let mut header_substr_idxes = vec![];
        for substr in &self.regex_header.substrs {
            if let Some((substr, idx)) = substr {
                header_substrs.push(substr.clone());
                header_substr_idxes.push(*idx as usize);
            } else {
                header_substrs.push("".to_string());
                header_substr_idxes.push(0);
            }
        }
        let (header_masked_chars_hash, header_substr_ids_hash) = if self.header_expose_substrs {
            let sha2_header_masked_chars_ins = &self.sha2_header_masked_chars.as_ref().unwrap().instances()[0];
            debug_assert_eq!(header_masked_chars_commit, sha2_header_masked_chars_ins[0]);
            let header_masked_chars_hash = sha2_header_masked_chars_ins[1..].to_vec();
            let sha2_header_substr_ids_ins = &self.sha2_header_substr_ids.as_ref().unwrap().instances()[0];
            debug_assert_eq!(header_substr_ids_commit, sha2_header_substr_ids_ins[0]);
            let header_substr_ids_hash = sha2_header_substr_ids_ins[1..].to_vec();
            (Some(header_masked_chars_hash), Some(header_substr_ids_hash))
        } else {
            (None, None)
        };
        let (
            bodyhash_masked_chars_commit,
            bodyhash_substr_ids_commit,
            bodyhash_base64_commit,
            body_bytes_commit,
            bodyhash_commit,
            body_masked_chars_commit,
            body_substr_ids_commit,
            body_masked_chars_hash,
            body_substr_ids_hash,
        ) = if self.body_enable {
            let regex_bodyhash_ins = &self.regex_bodyhash.as_ref().unwrap().instances()[0];
            debug_assert_eq!(header_bytes_commit, regex_bodyhash_ins[0]);
            let bodyhash_masked_chars_commit = regex_bodyhash_ins[1];
            let bodyhash_substr_ids_commit = regex_bodyhash_ins[2];
            let chars_shift_ins = &self.chars_shift_bodyhash.as_ref().unwrap().instances()[0];
            debug_assert_eq!(bodyhash_masked_chars_commit, chars_shift_ins[0]);
            debug_assert_eq!(bodyhash_substr_ids_commit, chars_shift_ins[1]);
            let bodyhash_base64_commit = chars_shift_ins[2];
            let sha2_body_ins = &self.sha2_body.as_ref().unwrap().instances()[0];
            let body_bytes_commit = sha2_body_ins[0];
            let bodyhash_commit = sha2_body_ins[1];
            let base64_ins = &self.base64.as_ref().unwrap().instances()[0];
            debug_assert_eq!(bodyhash_commit, base64_ins[0]);
            debug_assert_eq!(bodyhash_base64_commit, base64_ins[1]);
            let regex_body_ins = &self.regex_body.as_ref().unwrap().instances()[0];
            debug_assert_eq!(body_bytes_commit, regex_body_ins[0]);
            let body_masked_chars_commit = regex_body_ins[1];
            let body_substr_ids_commit = regex_body_ins[2];
            let (body_masked_chars_hash, body_substr_ids_hash) = if self.body_expose_substrs {
                let sha2_body_masked_chars_ins = &self.sha2_body_masked_chars.as_ref().unwrap().instances()[0];
                debug_assert_eq!(body_masked_chars_commit, sha2_body_masked_chars_ins[0]);
                let body_masked_chars_hash = sha2_body_masked_chars_ins[1..].to_vec();
                let sha2_body_substr_ids_ins = &self.sha2_body_substr_ids.as_ref().unwrap().instances()[0];
                debug_assert_eq!(body_substr_ids_commit, sha2_body_substr_ids_ins[0]);
                let body_substr_ids_hash = sha2_body_substr_ids_ins[1..].to_vec();
                (Some(body_masked_chars_hash), Some(body_substr_ids_hash))
            } else {
                (None, None)
            };
            (
                Some(bodyhash_masked_chars_commit),
                Some(bodyhash_substr_ids_commit),
                Some(bodyhash_base64_commit),
                Some(body_bytes_commit),
                Some(bodyhash_commit),
                Some(body_masked_chars_commit),
                Some(body_substr_ids_commit),
                body_masked_chars_hash,
                body_substr_ids_hash,
            )
        } else {
            (None, None, None, None, None, None, None, None, None)
        };
        let (body_substrs, body_substr_idxes) = if let Some(regex_body) = self.regex_body.as_ref() {
            let mut body_substrs = vec![];
            let mut body_substr_idxes = vec![];
            for substr in &regex_body.substrs {
                if let Some((substr, idx)) = substr {
                    body_substrs.push(substr.clone());
                    body_substr_idxes.push(*idx as usize);
                } else {
                    body_substrs.push("".to_string());
                    body_substr_idxes.push(0);
                }
            }
            (Some(body_substrs), Some(body_substr_idxes))
        } else {
            (None, None)
        };
        EmailVerifyInstances {
            header_bytes_commit,
            header_hash_commit,
            public_key_n_hash,
            tag,
            header_masked_chars_commit,
            header_substr_ids_commit,
            header_substrs,
            header_substr_idxes,
            header_masked_chars_hash,
            header_substr_ids_hash,
            bodyhash_masked_chars_commit,
            bodyhash_substr_ids_commit,
            bodyhash_base64_commit,
            body_bytes_commit,
            bodyhash_commit,
            body_substrs,
            body_substr_idxes,
            body_masked_chars_commit,
            body_substr_ids_commit,
            body_masked_chars_hash,
            body_substr_ids_hash,
        }
    }

    pub fn check_constraints(&self) -> Result<bool, Error> {
        let config_params = default_config_params();
        let k = config_params.degree;
        let instances = self.instances();
        let mut result = true;
        let timer = start_timer!(|| "check_constraints: sha2_header");
        result &= MockProver::run(k, &self.sha2_header, vec![vec![instances.header_bytes_commit, instances.header_hash_commit]])?
            .verify()
            .is_ok();
        end_timer!(timer);
        let timer = start_timer!(|| "check_constraints: sign_verify");
        result &= MockProver::run(k, &self.sign_verify, vec![vec![instances.public_key_n_hash, instances.header_hash_commit, instances.tag]])?
            .verify()
            .is_ok();
        end_timer!(timer);
        let timer = start_timer!(|| "check_constraints: regex_header");
        result &= MockProver::run(
            k,
            &self.regex_header,
            vec![vec![
                instances.header_bytes_commit,
                instances.header_masked_chars_commit,
                instances.header_substr_ids_commit,
            ]],
        )?
        .verify()
        .is_ok();
        end_timer!(timer);
        if self.header_expose_substrs {
            let timer = start_timer!(|| "check_constraints: sha2_header_masked_chars");
            result &= MockProver::run(
                k,
                self.sha2_header_masked_chars.as_ref().unwrap(),
                vec![vec![vec![instances.header_masked_chars_commit], instances.header_masked_chars_hash.as_ref().unwrap().clone()].concat()],
            )?
            .verify()
            .is_ok();
            end_timer!(timer);
            let timer = start_timer!(|| "check_constraints: sha2_header_substr_ids");
            result &= MockProver::run(
                k,
                self.sha2_header_substr_ids.as_ref().unwrap(),
                vec![vec![vec![instances.header_substr_ids_commit], instances.header_substr_ids_hash.as_ref().unwrap().clone()].concat()],
            )?
            .verify()
            .is_ok();
            end_timer!(timer);
        }
        if self.body_enable {
            let timer = start_timer!(|| "check_constraints: regex_bodyhash");
            result &= MockProver::run(
                k,
                self.regex_bodyhash.as_ref().unwrap(),
                vec![vec![
                    instances.header_bytes_commit,
                    instances.bodyhash_masked_chars_commit.unwrap().clone(),
                    instances.bodyhash_substr_ids_commit.unwrap().clone(),
                ]],
            )?
            .verify()
            .is_ok();
            end_timer!(timer);
            let timer = start_timer!(|| "check_constraints: chars_shift_bodyhash");
            result &= MockProver::run(
                k,
                self.chars_shift_bodyhash.as_ref().unwrap(),
                vec![vec![
                    instances.bodyhash_masked_chars_commit.unwrap().clone(),
                    instances.bodyhash_substr_ids_commit.unwrap().clone(),
                    instances.bodyhash_base64_commit.unwrap().clone(),
                ]],
            )?
            .verify()
            .is_ok();
            end_timer!(timer);
            let timer = start_timer!(|| "check_constraints: sha2_body");
            result &= MockProver::run(
                k,
                self.sha2_body.as_ref().unwrap(),
                vec![vec![instances.body_bytes_commit.unwrap().clone(), instances.bodyhash_commit.unwrap().clone()]],
            )?
            .verify()
            .is_ok();
            end_timer!(timer);
            let timer = start_timer!(|| "check_constraints: base64");
            result &= MockProver::run(
                k,
                self.base64.as_ref().unwrap(),
                vec![vec![instances.bodyhash_commit.unwrap().clone(), instances.bodyhash_base64_commit.unwrap().clone()]],
            )?
            .verify()
            .is_ok();
            end_timer!(timer);
            let timer = start_timer!(|| "check_constraints: regex_body");
            result &= MockProver::run(
                k,
                self.regex_body.as_ref().unwrap(),
                vec![vec![
                    instances.body_bytes_commit.unwrap().clone(),
                    instances.body_masked_chars_commit.unwrap().clone(),
                    instances.body_substr_ids_commit.unwrap().clone(),
                ]],
            )?
            .verify()
            .is_ok();
            end_timer!(timer);
            if self.body_expose_substrs {
                let timer = start_timer!(|| "check_constraints: sha2_body_masked_chars");
                result &= MockProver::run(
                    k,
                    self.sha2_body_masked_chars.as_ref().unwrap(),
                    vec![vec![
                        vec![instances.body_masked_chars_commit.unwrap().clone()],
                        instances.body_masked_chars_hash.as_ref().unwrap().clone(),
                    ]
                    .concat()],
                )?
                .verify()
                .is_ok();
                end_timer!(timer);
                let timer = start_timer!(|| "check_constraints: sha2_body_substr_ids");
                result &= MockProver::run(
                    k,
                    self.sha2_body_substr_ids.as_ref().unwrap(),
                    vec![vec![
                        vec![instances.body_substr_ids_commit.unwrap().clone()],
                        instances.body_substr_ids_hash.as_ref().unwrap().clone(),
                    ]
                    .concat()],
                )?
                .verify()
                .is_ok();
                end_timer!(timer);
            }
        }
        Ok(result)
    }

    pub fn get_substr(input_str: &str, regexes: &[String]) -> Option<(String, usize)> {
        let regexes = regexes.into_iter().map(|raw| Regex::new(&raw).unwrap()).collect_vec();
        let mut start = 0;
        let mut substr = input_str;
        // println!("first regex {}", regexes[0]);
        for regex in regexes.into_iter() {
            // println!(r"regex {}", regex);
            match regex.find(substr).unwrap() {
                Some(m) => {
                    start += m.start();
                    substr = m.as_str();
                }
                None => {
                    return None;
                }
            };
        }
        // println!("substr {}", substr);
        // println!("start {}", start);
        Some((substr.to_string(), start))
    }
}

impl EmailVerifyCircuits<Fr> {
    pub fn setup<R: rand::RngCore>(&self, rng: R) -> ParamsKZG<Bn256> {
        let config_params = default_config_params();
        ParamsKZG::<Bn256>::setup(config_params.degree, rng)
    }

    pub fn gen_pks(&self, params: &ParamsKZG<Bn256>) -> Vec<ProvingKey<G1Affine>> {
        let mut pks = vec![];
        pks.push(gen_pk(params, &self.sha2_header, None));
        pks.push(gen_pk(params, &self.sign_verify, None));
        pks.push(gen_pk(params, &self.regex_header, None));
        if self.header_expose_substrs {
            pks.push(gen_pk(params, self.sha2_header_masked_chars.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.sha2_header_substr_ids.as_ref().unwrap(), None));
        }
        if self.body_enable {
            pks.push(gen_pk(params, self.regex_bodyhash.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.chars_shift_bodyhash.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.sha2_body.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.base64.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.regex_body.as_ref().unwrap(), None));
            if self.body_expose_substrs {
                pks.push(gen_pk(params, self.sha2_body_masked_chars.as_ref().unwrap(), None));
                pks.push(gen_pk(params, self.sha2_body_substr_ids.as_ref().unwrap(), None));
            }
        }
        pks
    }

    pub fn gen_vks(&self, pks: &[ProvingKey<G1Affine>]) -> Vec<VerifyingKey<G1Affine>> {
        pks.iter().map(|pk| pk.get_vk().clone()).collect_vec()
    }

    pub fn prove<R: rand::Rng + Send>(&self, params: &ParamsKZG<Bn256>, pks: &[ProvingKey<G1Affine>], rng: &mut R) -> Vec<Vec<u8>> {
        let mut proofs = vec![];
        let mut pk_index = 0;
        let instances = self.instances();
        let timer = start_timer!(|| "prove: sha2_header");
        proofs.push(gen_proof_shplonk(
            params,
            &pks[pk_index],
            self.sha2_header.clone(),
            vec![vec![instances.header_bytes_commit, instances.header_hash_commit]],
            rng,
            None,
        ));
        end_timer!(timer);
        pk_index += 1;
        let timer = start_timer!(|| "prove: sign_verify");
        proofs.push(gen_proof_shplonk(
            params,
            &pks[pk_index],
            self.sign_verify.clone(),
            vec![vec![instances.public_key_n_hash, instances.header_hash_commit, instances.tag]],
            rng,
            None,
        ));
        end_timer!(timer);
        pk_index += 1;
        let timer = start_timer!(|| "prove: regex_header");
        proofs.push(gen_proof_shplonk(
            params,
            &pks[pk_index],
            self.regex_header.clone(),
            vec![vec![
                instances.header_bytes_commit,
                instances.header_masked_chars_commit,
                instances.header_substr_ids_commit,
            ]],
            rng,
            None,
        ));
        end_timer!(timer);
        pk_index += 1;
        if self.header_expose_substrs {
            let timer = start_timer!(|| "prove: sha2_header_masked_chars");
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_masked_chars.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_masked_chars_commit], instances.header_masked_chars_hash.unwrap()].concat()],
                rng,
                None,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: sha2_header_substr_ids");
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_substr_ids.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_substr_ids_commit], instances.header_substr_ids_hash.unwrap()].concat()],
                rng,
                None,
            ));
            end_timer!(timer);
            pk_index += 1;
        }
        if self.body_enable {
            let timer = start_timer!(|| "prove: regex_bodyhash");
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.header_bytes_commit,
                    instances.bodyhash_masked_chars_commit.unwrap().clone(),
                    instances.bodyhash_substr_ids_commit.unwrap().clone(),
                ]],
                rng,
                None,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: chars_shift_bodyhash");
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.chars_shift_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.bodyhash_masked_chars_commit.unwrap().clone(),
                    instances.bodyhash_substr_ids_commit.unwrap().clone(),
                    instances.bodyhash_base64_commit.unwrap().clone(),
                ]],
                rng,
                None,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: sha2_body");
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_body.as_ref().unwrap().clone(),
                vec![vec![instances.body_bytes_commit.unwrap().clone(), instances.bodyhash_commit.unwrap().clone()]],
                rng,
                None,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: base64");
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.base64.as_ref().unwrap().clone(),
                vec![vec![instances.bodyhash_commit.unwrap().clone(), instances.bodyhash_base64_commit.unwrap().clone()]],
                rng,
                None,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: regex_body");
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_body.as_ref().unwrap().clone(),
                vec![vec![
                    instances.body_bytes_commit.unwrap().clone(),
                    instances.body_masked_chars_commit.unwrap().clone(),
                    instances.body_substr_ids_commit.unwrap().clone(),
                ]],
                rng,
                None,
            ));
            end_timer!(timer);
            pk_index += 1;
            if self.body_expose_substrs {
                let timer = start_timer!(|| "prove: sha2_body_masked_chars");
                proofs.push(gen_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_masked_chars.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_masked_chars_commit.unwrap().clone()], instances.body_masked_chars_hash.unwrap().clone()].concat()],
                    rng,
                    None,
                ));
                end_timer!(timer);
                pk_index += 1;
                let timer = start_timer!(|| "prove: sha2_body_substr_ids");
                proofs.push(gen_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_substr_ids.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_substr_ids_commit.unwrap().clone()], instances.body_substr_ids_hash.unwrap().clone()].concat()],
                    rng,
                    None,
                ));
                end_timer!(timer);
            }
        }
        proofs
    }

    pub fn evm_prove<R: rand::Rng + Send>(&self, params: &ParamsKZG<Bn256>, pks: &[ProvingKey<G1Affine>], rng: &mut R) -> Vec<Vec<u8>> {
        let mut proofs = vec![];
        let mut pk_index = 0;
        let instances = self.instances();
        let timer = start_timer!(|| "prove: sha2_header");
        proofs.push(gen_evm_proof_shplonk(
            params,
            &pks[pk_index],
            self.sha2_header.clone(),
            vec![vec![instances.header_bytes_commit, instances.header_hash_commit]],
            rng,
        ));
        end_timer!(timer);
        pk_index += 1;
        let timer = start_timer!(|| "prove: sign_verify");
        proofs.push(gen_evm_proof_shplonk(
            params,
            &pks[pk_index],
            self.sign_verify.clone(),
            vec![vec![instances.public_key_n_hash, instances.header_hash_commit, instances.tag]],
            rng,
        ));
        end_timer!(timer);
        pk_index += 1;
        let timer = start_timer!(|| "prove: regex_header");
        proofs.push(gen_evm_proof_shplonk(
            params,
            &pks[pk_index],
            self.regex_header.clone(),
            vec![vec![
                instances.header_bytes_commit,
                instances.header_masked_chars_commit,
                instances.header_substr_ids_commit,
            ]],
            rng,
        ));
        end_timer!(timer);
        pk_index += 1;
        if self.header_expose_substrs {
            let timer = start_timer!(|| "prove: sha2_header_masked_chars");
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_masked_chars.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_masked_chars_commit], instances.header_masked_chars_hash.unwrap()].concat()],
                rng,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: sha2_header_substr_ids");
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_substr_ids.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_substr_ids_commit], instances.header_substr_ids_hash.unwrap()].concat()],
                rng,
            ));
            end_timer!(timer);
            pk_index += 1;
        }
        if self.body_enable {
            let timer = start_timer!(|| "prove: regex_bodyhash");
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.header_bytes_commit,
                    instances.bodyhash_masked_chars_commit.unwrap().clone(),
                    instances.bodyhash_substr_ids_commit.unwrap().clone(),
                ]],
                rng,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: chars_shift_bodyhash");
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.chars_shift_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.bodyhash_masked_chars_commit.unwrap().clone(),
                    instances.bodyhash_substr_ids_commit.unwrap().clone(),
                    instances.bodyhash_base64_commit.unwrap().clone(),
                ]],
                rng,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: sha2_body");
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_body.as_ref().unwrap().clone(),
                vec![vec![instances.body_bytes_commit.unwrap().clone(), instances.bodyhash_commit.unwrap().clone()]],
                rng,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: base64");
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.base64.as_ref().unwrap().clone(),
                vec![vec![instances.bodyhash_commit.unwrap().clone(), instances.bodyhash_base64_commit.unwrap().clone()]],
                rng,
            ));
            end_timer!(timer);
            pk_index += 1;
            let timer = start_timer!(|| "prove: regex_body");
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_body.as_ref().unwrap().clone(),
                vec![vec![
                    instances.body_bytes_commit.unwrap().clone(),
                    instances.body_masked_chars_commit.unwrap().clone(),
                    instances.body_substr_ids_commit.unwrap().clone(),
                ]],
                rng,
            ));
            end_timer!(timer);
            pk_index += 1;
            if self.body_expose_substrs {
                let timer = start_timer!(|| "prove: sha2_body_masked_chars");
                proofs.push(gen_evm_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_masked_chars.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_masked_chars_commit.unwrap().clone()], instances.body_masked_chars_hash.unwrap().clone()].concat()],
                    rng,
                ));
                end_timer!(timer);
                pk_index += 1;
                let timer = start_timer!(|| "prove: sha2_body_substr_ids");
                proofs.push(gen_evm_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_substr_ids.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_substr_ids_commit.unwrap().clone()], instances.body_substr_ids_hash.unwrap().clone()].concat()],
                    rng,
                ));
                end_timer!(timer);
            }
        }
        proofs
    }

    pub fn print_costs(&self) {
        let config_params = default_config_params();
        let k = config_params.degree as usize;
        let measured = CircuitCost::<G1, _>::measure(k, &self.sha2_header);
        println!("sha2_header: {:?}", measured);
        let gates = CircuitGates::collect::<Fr, Sha256HeaderCircuit<Fr>>();
        println!("sha2_header gates: {}", gates);
        let measured = CircuitCost::<G1, _>::measure(k, &self.sign_verify);
        println!("sign_verify: {:?}", measured);
        let gates = CircuitGates::collect::<Fr, SignVerifyCircuit<Fr>>();
        println!("sign_verify gates: {}", gates);
        let measured = CircuitCost::<G1, _>::measure(k, &self.regex_header);
        println!("regex_header: {:?}", measured);
        let gates = CircuitGates::collect::<Fr, RegexHeaderCircuit<Fr>>();
        println!("regex_header gates: {}", gates);
        if self.header_expose_substrs {
            let measured = CircuitCost::<G1, _>::measure(k, self.sha2_header_masked_chars.as_ref().unwrap());
            println!("sha2_header_masked_chars: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, Sha256HeaderMaskedCharsCircuit<Fr>>();
            println!("sha2_header_masked_chars gates: {}", gates);
            let measured = CircuitCost::<G1, _>::measure(k, self.sha2_header_substr_ids.as_ref().unwrap());
            println!("sha2_header_substr_ids: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, Sha256HeaderSubstrIdsCircuit<Fr>>();
            println!("sha2_header_substr_ids gates: {}", gates);
        }
        if self.body_enable {
            let measured = CircuitCost::<G1, _>::measure(k, self.regex_bodyhash.as_ref().unwrap());
            println!("regex_bodyhash: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, RegexBodyHashCircuit<Fr>>();
            println!("regex_bodyhash gates: {}", gates);
            let measured = CircuitCost::<G1, _>::measure(k, self.chars_shift_bodyhash.as_ref().unwrap());
            println!("chars_shift_bodyhash: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, CharsShiftBodyHashCircuit<Fr>>();
            println!("chars_shift_bodyhash gates: {}", gates);
            let measured = CircuitCost::<G1, _>::measure(k, self.sha2_body.as_ref().unwrap());
            println!("sha2_body: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, Sha256BodyCircuit<Fr>>();
            println!("sha2_body gates: {}", gates);
            let measured = CircuitCost::<G1, _>::measure(k, self.base64.as_ref().unwrap());
            println!("base64: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, Base64Circuit<Fr>>();
            println!("base64 gates: {}", gates);
            let measured = CircuitCost::<G1, _>::measure(k, self.regex_body.as_ref().unwrap());
            println!("regex_body: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, RegexBodyCircuit<Fr>>();
            println!("regex_body gates: {}", gates);
            if self.body_expose_substrs {
                let measured = CircuitCost::<G1, _>::measure(k, self.sha2_body_masked_chars.as_ref().unwrap());
                println!("sha2_body_masked_chars: {:?}", measured);
                let gates = CircuitGates::collect::<Fr, Sha256BodyMaskedCharsCircuit<Fr>>();
                println!("sha256_body_masked_chars gates: {}", gates);
                let measured = CircuitCost::<G1, _>::measure(k, self.sha2_body_substr_ids.as_ref().unwrap());
                println!("sha2_body_substr_ids: {:?}", measured);
                let gates = CircuitGates::collect::<Fr, Sha256BodySubstrIdsCircuit<Fr>>();
                println!("sha2_body_substr_ids gates: {}", gates);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmailVerifyInstances<F: PrimeField> {
    header_bytes_commit: F,
    header_hash_commit: F,
    public_key_n_hash: F,
    tag: F,
    header_masked_chars_commit: F,
    header_substr_ids_commit: F,
    header_substrs: Vec<String>,
    header_substr_idxes: Vec<usize>,
    header_masked_chars_hash: Option<Vec<F>>,
    header_substr_ids_hash: Option<Vec<F>>,
    bodyhash_masked_chars_commit: Option<F>,
    bodyhash_substr_ids_commit: Option<F>,
    bodyhash_base64_commit: Option<F>,
    body_bytes_commit: Option<F>,
    bodyhash_commit: Option<F>,
    body_masked_chars_commit: Option<F>,
    body_substr_ids_commit: Option<F>,
    body_substrs: Option<Vec<String>>,
    body_substr_idxes: Option<Vec<usize>>,
    body_masked_chars_hash: Option<Vec<F>>,
    body_substr_ids_hash: Option<Vec<F>>,
}

impl<F: PrimeField> EmailVerifyInstances<F> {
    pub fn to_json(&self) -> EmailVerifyInstancesJson {
        let field2string = |val: &F| {
            let big = fe_to_biguint(val);
            big.to_str_radix(10)
        };
        let field_vec2string = |vals: &[F]| {
            let mut sum = BigUint::from(0u32);
            let mut coeff = BigUint::from(1u32);
            let two_pow = BigUint::from(2u32).pow(8 * 31);
            for val in vals.iter() {
                sum += coeff.clone() * fe_to_biguint(val);
                coeff *= &two_pow;
            }
            sum.to_str_radix(10)
        };
        let config_params = default_config_params();
        let header_bytes_commit = field2string(&self.header_bytes_commit);
        let header_hash_commit = field2string(&self.header_hash_commit);
        let public_key_n_hash = field2string(&self.public_key_n_hash);
        let tag = field2string(&self.tag);
        let header_masked_chars_commit = field2string(&self.header_masked_chars_commit);
        let header_substr_ids_commit = field2string(&self.header_substr_ids_commit);
        let (
            bodyhash_masked_chars_commit,
            bodyhash_substr_ids_commit,
            bodyhash_base64_commit,
            body_bytes_commit,
            bodyhash_commit,
            body_masked_chars_commit,
            body_substr_ids_commit,
        ) = if let Some(body_config) = config_params.body_config.as_ref() {
            let bodyhash_masked_chars_commit = field2string(&self.bodyhash_masked_chars_commit.unwrap());
            let bodyhash_substr_ids_commit = field2string(&self.bodyhash_substr_ids_commit.unwrap());
            let bodyhash_base64_commit = field2string(&self.bodyhash_base64_commit.unwrap());
            let body_bytes_commit = field2string(&self.body_bytes_commit.unwrap());
            let bodyhash_commit = field2string(&self.bodyhash_commit.unwrap());
            let body_masked_chars_commit = field2string(&self.body_masked_chars_commit.unwrap());
            let body_substr_ids_commit = field2string(&self.body_substr_ids_commit.unwrap());
            (
                Some(bodyhash_masked_chars_commit),
                Some(bodyhash_substr_ids_commit),
                Some(bodyhash_base64_commit),
                Some(body_bytes_commit),
                Some(bodyhash_commit),
                Some(body_masked_chars_commit),
                Some(body_substr_ids_commit),
            )
        } else {
            (None, None, None, None, None, None, None)
        };

        EmailVerifyInstancesJson {
            header_bytes_commit,
            header_hash_commit,
            public_key_n_hash,
            tag,
            header_masked_chars_commit,
            header_substr_ids_commit,
            header_substrs: self.header_substrs.clone(),
            header_substr_idxes: self.header_substr_idxes.clone(),
            bodyhash_masked_chars_commit,
            bodyhash_substr_ids_commit,
            bodyhash_base64_commit,
            body_bytes_commit,
            bodyhash_commit,
            body_masked_chars_commit,
            body_substr_ids_commit,
            body_substrs: self.body_substrs.clone(),
            body_substr_idxes: self.body_substr_idxes.clone(),
        }
    }
}

impl EmailVerifyInstances<Fr> {
    pub fn verify_proof(&self, params: &ParamsKZG<Bn256>, vks: &[VerifyingKey<G1Affine>], proofs: &[&[u8]]) -> bool {
        let config_params = default_config_params();
        let mut result = true;
        let mut vk_index = 0;
        let verify_proof = |params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, proof: &[u8], instances: &[Fr]| {
            let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::new(proof);
            VerificationStrategy::<_, VerifierSHPLONK<Bn256>>::finalize(
                verify_proof::<_, VerifierSHPLONK<Bn256>, _, _, _>(
                    params.verifier_params(),
                    vk,
                    AccumulatorStrategy::new(params.verifier_params()),
                    &[&[instances]],
                    &mut transcript_read,
                )
                .unwrap(),
            )
        };
        result &= verify_proof(params, &vks[vk_index], proofs[vk_index], &vec![self.header_bytes_commit, self.header_hash_commit]);
        vk_index += 1;
        result &= verify_proof(params, &vks[vk_index], proofs[vk_index], &vec![self.public_key_n_hash, self.header_hash_commit, self.tag]);
        vk_index += 1;
        result &= verify_proof(
            params,
            &vks[vk_index],
            proofs[vk_index],
            &vec![self.header_bytes_commit, self.header_masked_chars_commit, self.header_substr_ids_commit],
        );
        vk_index += 1;
        if config_params.header_config.as_ref().unwrap().expose_substrs.unwrap_or(false) {
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![vec![self.header_masked_chars_commit], self.header_masked_chars_hash.as_ref().unwrap().clone()].concat(),
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![vec![self.header_substr_ids_commit], self.header_substr_ids_hash.as_ref().unwrap().clone()].concat(),
            );
            vk_index += 1;
        }
        if let Some(body_config) = config_params.body_config.as_ref() {
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![
                    self.header_bytes_commit,
                    self.bodyhash_masked_chars_commit.unwrap().clone(),
                    self.bodyhash_substr_ids_commit.unwrap().clone(),
                ],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![
                    self.bodyhash_masked_chars_commit.unwrap().clone(),
                    self.bodyhash_substr_ids_commit.unwrap().clone(),
                    self.bodyhash_base64_commit.unwrap().clone(),
                ],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![self.body_bytes_commit.unwrap().clone(), self.bodyhash_commit.unwrap().clone()],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![self.bodyhash_commit.unwrap().clone(), self.bodyhash_base64_commit.unwrap().clone()],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![
                    self.body_bytes_commit.unwrap().clone(),
                    self.body_masked_chars_commit.unwrap().clone(),
                    self.body_substr_ids_commit.unwrap().clone(),
                ],
            );
            vk_index += 1;
            if body_config.expose_substrs.unwrap_or(false) {
                result &= verify_proof(
                    params,
                    &vks[vk_index],
                    proofs[vk_index],
                    &vec![vec![self.body_masked_chars_commit.unwrap().clone()], self.body_masked_chars_hash.as_ref().unwrap().clone()].concat(),
                );
                vk_index += 1;
                result &= verify_proof(
                    params,
                    &vks[vk_index],
                    proofs[vk_index],
                    &vec![vec![self.body_substr_ids_commit.unwrap().clone()], self.body_substr_ids_hash.as_ref().unwrap().clone()].concat(),
                );
            }
        }
        result
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailVerifyInstancesJson {
    header_bytes_commit: String,
    header_hash_commit: String,
    public_key_n_hash: String,
    tag: String,
    header_masked_chars_commit: String,
    header_substr_ids_commit: String,
    header_substrs: Vec<String>,
    header_substr_idxes: Vec<usize>,
    bodyhash_masked_chars_commit: Option<String>,
    bodyhash_substr_ids_commit: Option<String>,
    bodyhash_base64_commit: Option<String>,
    body_bytes_commit: Option<String>,
    bodyhash_commit: Option<String>,
    body_masked_chars_commit: Option<String>,
    body_substr_ids_commit: Option<String>,
    body_substrs: Option<Vec<String>>,
    body_substr_idxes: Option<Vec<usize>>,
}

impl EmailVerifyInstancesJson {
    pub fn from_json_str(json_str: &str) -> Self {
        serde_json::from_str(json_str).unwrap()
    }

    pub fn to_json_str(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn to_instances<F: PrimeField>(&self) -> EmailVerifyInstances<F> {
        let config_params = default_config_params();
        let header_bytes_commit = F::from_str_vartime(&self.header_bytes_commit).unwrap();
        let header_hash_commit = F::from_str_vartime(&self.header_hash_commit).unwrap();
        let public_key_n_hash = F::from_str_vartime(&self.public_key_n_hash).unwrap();
        let tag = F::from_str_vartime(&self.tag).unwrap();
        let header_masked_chars_commit = F::from_str_vartime(&self.header_masked_chars_commit).unwrap();
        let header_substr_ids_commit = F::from_str_vartime(&self.header_substr_ids_commit).unwrap();
        let header_config = config_params.header_config.as_ref().unwrap();
        let header_substrs = self
            .header_substrs
            .iter()
            .zip(self.header_substr_idxes.iter())
            .map(|(substr, substr_idx)| Some((substr.clone(), *substr_idx)))
            .collect_vec();
        let (header_masked_chars, header_substr_ids) = substrs2expected_chars_and_ids(header_config.max_variable_byte_size, &header_substrs);
        let (header_masked_chars_hash, header_substr_ids_hash) = if header_config.expose_substrs.unwrap_or(false) {
            let header_masked_chars_hash = Sha256::digest(&header_masked_chars).to_vec();
            let header_substr_ids_hash = Sha256::digest(&header_substr_ids).to_vec();
            (Some(value_bytes2fields(&header_masked_chars_hash)), Some(value_bytes2fields(&header_substr_ids_hash)))
        } else {
            (None, None)
        };
        let (
            bodyhash_masked_chars_commit,
            bodyhash_substr_ids_commit,
            bodyhash_base64_commit,
            body_bytes_commit,
            bodyhash_commit,
            body_masked_chars_commit,
            body_substr_ids_commit,
            body_masked_chars_hash,
            body_substr_ids_hash,
        ) = if let Some(body_config) = config_params.body_config.as_ref() {
            let bodyhash_masked_chars_commit = F::from_str_vartime(&self.bodyhash_masked_chars_commit.as_ref().unwrap()).unwrap();
            let bodyhash_substr_ids_commit = F::from_str_vartime(&self.bodyhash_substr_ids_commit.as_ref().unwrap()).unwrap();
            let bodyhash_base64_commit = F::from_str_vartime(&self.bodyhash_base64_commit.as_ref().unwrap()).unwrap();
            let body_bytes_commit = F::from_str_vartime(&self.body_bytes_commit.as_ref().unwrap()).unwrap();
            let bodyhash_commit = F::from_str_vartime(&self.bodyhash_commit.as_ref().unwrap()).unwrap();
            let body_masked_chars_commit = F::from_str_vartime(&self.body_masked_chars_commit.as_ref().unwrap()).unwrap();
            let body_substr_ids_commit = F::from_str_vartime(&self.body_substr_ids_commit.as_ref().unwrap()).unwrap();
            let body_substrs = self
                .body_substrs
                .as_ref()
                .unwrap()
                .iter()
                .zip(self.body_substr_idxes.as_ref().unwrap().iter())
                .map(|(substr, substr_idx)| Some((substr.clone(), *substr_idx)))
                .collect_vec();
            let (body_masked_chars, body_substr_ids) = substrs2expected_chars_and_ids(body_config.max_variable_byte_size, &body_substrs);
            let (body_masked_chars_hash, body_substr_ids_hash) = if body_config.expose_substrs.unwrap_or(false) {
                let body_masked_chars_hash = Sha256::digest(&body_masked_chars).to_vec();
                let body_substr_ids_hash = Sha256::digest(&body_substr_ids).to_vec();
                (Some(value_bytes2fields(&body_masked_chars_hash)), Some(value_bytes2fields(&body_substr_ids_hash)))
            } else {
                (None, None)
            };
            (
                Some(bodyhash_masked_chars_commit),
                Some(bodyhash_substr_ids_commit),
                Some(bodyhash_base64_commit),
                Some(body_bytes_commit),
                Some(bodyhash_commit),
                Some(body_masked_chars_commit),
                Some(body_substr_ids_commit),
                body_masked_chars_hash,
                body_substr_ids_hash,
            )
        } else {
            (None, None, None, None, None, None, None, None, None)
        };
        EmailVerifyInstances {
            header_bytes_commit,
            header_hash_commit,
            public_key_n_hash,
            tag,
            header_masked_chars_commit,
            header_substr_ids_commit,
            header_substrs: self.header_substrs.clone(),
            header_substr_idxes: self.header_substr_idxes.clone(),
            header_masked_chars_hash,
            header_substr_ids_hash,
            bodyhash_masked_chars_commit,
            bodyhash_substr_ids_commit,
            bodyhash_base64_commit,
            body_bytes_commit,
            bodyhash_commit,
            body_masked_chars_commit,
            body_substr_ids_commit,
            body_substrs: self.body_substrs.clone(),
            body_substr_idxes: self.body_substr_idxes.clone(),
            body_masked_chars_hash,
            body_substr_ids_hash,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::config_params::EMAIL_VERIFY_CONFIG_ENV;

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
    use rand::{rngs::OsRng, thread_rng};
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
            let config_params = default_config_params();
            let sign_verify_config = config_params.sign_verify_config.as_ref().expect("sign_verify_config is required");
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
            // let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();

            // println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
            // println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());

            // let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
            let public_key_n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            circuits.print_costs();
            assert!(circuits.check_constraints().unwrap());
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
            let config_params = default_config_params();
            let sign_verify_config = config_params.sign_verify_config.as_ref().expect("sign_verify_config is required");
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
            let public_key_n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            circuits.print_costs();
            assert!(circuits.check_constraints().unwrap());
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
            let public_key_n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            circuits.print_costs();
            assert!(circuits.check_constraints().unwrap());
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
            let public_key_n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            circuits.print_costs();
            assert!(circuits.check_constraints().unwrap());
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
            let public_key_n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            circuits.print_costs();
            assert!(circuits.check_constraints().unwrap());
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
            let mut public_key_n_bytes = public_key.n().to_bytes_be();
            for idx in 0..256 {
                public_key_n_bytes[idx] = 255;
            }
            let public_key_n = BigUint::from_bytes_be(&public_key_n_bytes);
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            circuits.print_costs();
            assert_eq!(circuits.check_constraints().unwrap(), false);
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
            let public_key_n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            circuits.print_costs();
            assert_eq!(circuits.check_constraints().unwrap(), false);
        });
    }

    #[tokio::test]
    async fn test_proof_gen() {
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
            let public_key_n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
            let tag = Fr::zero();
            let circuits = EmailVerifyCircuits::new(&email_bytes, public_key_n, tag);
            let config_params = default_config_params();
            let params = ParamsKZG::<Bn256>::new(config_params.degree);
            let pks = circuits.gen_pks(&params);
            let vks = circuits.gen_vks(&pks);
            let proofs = circuits.prove(&params, &pks, &mut OsRng);
            let instances = circuits.instances();
            assert!(instances.verify_proof(&params, &vks, &proofs.iter().map(|vec| vec.as_slice()).collect_vec().as_slice()));
        });
    }
}
