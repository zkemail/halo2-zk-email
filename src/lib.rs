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
// #[cfg(not(target_arch = "wasm32"))]
// mod helpers;
pub mod chars_shift;
pub mod config_params;
pub mod eth;
pub mod regex_circuit;
pub mod sha2_circuit;
/// Regex verification + SHA256 computation.
// pub mod regex_sha2;
/// Regex verification + SHA256 computation + base64 encoding.
// pub mod regex_sha2_base64;
/// RSA signature verification.
pub mod sign_verify;
/// Util functions.
// pub mod utils;
pub mod wtns_commit;
use std::fs::File;
use std::marker::PhantomData;

// pub use crate::helpers::*;
// use crate::regex_sha2::RegexSha2Config;
use crate::sign_verify::*;
// use crate::utils::*;
use crate::wtns_commit::poseidon_circuit::*;
use crate::wtns_commit::*;
use base64::{engine::general_purpose, Engine as _};
use cfdkim::canonicalize_signed_email;
use cfdkim::resolve_public_key;
use chars_shift::CharsShiftBodyHashCircuit;
use config_params::default_config_params;
use config_params::EmailVerifyConfigParams;
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
    pub sha2_header_masked_substrs: Option<Sha256HeaderMaskedSubstrsCircuit<F>>,
    pub sha2_header_substr_ids: Option<Sha256HeaderSubstrIdsCircuit<F>>,
    pub regex_bodyhash: Option<RegexBodyHashCircuit<F>>,
    pub chars_shift_bodyhash: Option<CharsShiftBodyHashCircuit<F>>,
    pub sha2_body: Option<Sha256BodyCircuit<F>>,
    pub base64: Option<Base64Circuit<F>>,
    pub regex_body: Option<RegexBodyCircuit<F>>,
    pub sha2_body_masked_substrs: Option<Sha256BodyMaskedSubstrsCircuit<F>>,
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
        let regex_header = RegexHeaderCircuit::new(canonicalized_header.clone(), header_regex_defs, header_config.substr_regexes.clone(), sign_rand);
        let (sha2_header_masked_substrs, sha2_header_substr_ids) = if header_config.expose_substrs.unwrap_or(false) {
            let (expected_masked_chars, expected_substr_ids) =
                get_expected_substr_chars_and_ids(&canonicalized_header, &header_config.substr_regexes, header_config.max_variable_byte_size);
            let sha2_header_masked_substrs = Sha256HeaderMaskedSubstrsCircuit::new(expected_masked_chars, sign_rand);
            let sha2_header_substr_ids = Sha256HeaderSubstrIdsCircuit::new(expected_substr_ids, sign_rand);
            (Some(sha2_header_masked_substrs), Some(sha2_header_substr_ids))
        } else {
            (None, None)
        };
        let (regex_bodyhash, chars_shift_bodyhash, sha2_body, base64, regex_body, sha2_body_masked_substrs, sha2_body_substr_ids) =
            if let Some(body_config) = config_params.body_config.as_ref() {
                let bodyhash_regex_def = {
                    let allstr = AllstrRegexDef::read_from_text(&header_config.bodyhash_allstr_filepath);
                    let substr = SubstrRegexDef::read_from_text(&header_config.bodyhash_substr_filepath);
                    RegexDefs { allstr, substrs: vec![substr] }
                };
                let bodyhash_substr_regexes = vec![vec![Self::BODYHASH_REGEX.to_string()]];
                let (bodyhash_masked_chars, bodyhash_substr_ids) =
                    get_expected_substr_chars_and_ids(&canonicalized_header, &bodyhash_substr_regexes, header_config.max_variable_byte_size);
                let regex_bodyhash = RegexBodyHashCircuit::new(canonicalized_header.clone(), vec![bodyhash_regex_def], bodyhash_substr_regexes, sign_rand);
                let chars_shift_bodyhash = CharsShiftBodyHashCircuit::new(1, bodyhash_masked_chars, bodyhash_substr_ids, BODYHASH_BYTES, sign_rand);
                let (expected_masked_chars, expected_substr_ids) =
                    get_expected_substr_chars_and_ids(&canonicalized_body, &body_config.substr_regexes, body_config.max_variable_byte_size);
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
                let regex_body = RegexBodyCircuit::new(canonicalized_body.clone(), body_regex_defs, body_config.substr_regexes.clone(), sign_rand);
                let (sha2_body_masked_substrs, sha2_body_substr_ids) = if body_config.expose_substrs.unwrap_or(false) {
                    let sha2_body_masked_substrs = Sha256BodyMaskedSubstrsCircuit::new(expected_masked_chars, sign_rand);
                    let sha2_body_substr_ids = Sha256BodySubstrIdsCircuit::new(expected_substr_ids, sign_rand);
                    (Some(sha2_body_masked_substrs), Some(sha2_body_substr_ids))
                } else {
                    (None, None)
                };
                (
                    Some(regex_bodyhash),
                    Some(chars_shift_bodyhash),
                    Some(sha2_body),
                    Some(base64),
                    Some(regex_body),
                    sha2_body_masked_substrs,
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
            sha2_header_masked_substrs,
            sha2_header_substr_ids,
            regex_bodyhash,
            chars_shift_bodyhash,
            sha2_body,
            base64,
            regex_body,
            sha2_body_masked_substrs,
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
        let header_bytes = sha2_header_ins[0];
        let header_hash = sha2_header_ins[1];
        let sign_verify_ins = &self.sign_verify.instances()[0];
        let public_key_n_hash = sign_verify_ins[0];
        debug_assert_eq!(header_hash, sign_verify_ins[1]);
        let tag = sign_verify_ins[2];
        let regex_header_ins = &self.regex_header.instances()[0];
        debug_assert_eq!(header_bytes, regex_header_ins[0]);
        let header_masked_substr = regex_header_ins[1];
        let header_substr_ids = regex_header_ins[2];
        let (header_masked_substr_hash, header_substr_ids_hash) = if self.header_expose_substrs {
            let sha2_header_masked_substrs_ins = &self.sha2_header_masked_substrs.as_ref().unwrap().instances()[0];
            debug_assert_eq!(header_masked_substr, sha2_header_masked_substrs_ins[0]);
            let header_masked_substr_hash = sha2_header_masked_substrs_ins[1..].to_vec();
            let sha2_header_substr_ids_ins = &self.sha2_header_substr_ids.as_ref().unwrap().instances()[0];
            debug_assert_eq!(header_substr_ids, sha2_header_substr_ids_ins[0]);
            let header_substr_ids_hash = sha2_header_substr_ids_ins[1..].to_vec();
            (Some(header_masked_substr_hash), Some(header_substr_ids_hash))
        } else {
            (None, None)
        };
        let (
            bodyhash_masked_substr,
            bodyhash_substr_ids,
            bodyhash_base64,
            body_bytes,
            bodyhash,
            body_masked_substr,
            body_substr_ids,
            body_masked_substr_hash,
            body_substr_ids_hash,
        ) = if self.body_enable {
            let regex_bodyhash_ins = &self.regex_bodyhash.as_ref().unwrap().instances()[0];
            debug_assert_eq!(header_bytes, regex_bodyhash_ins[0]);
            let bodyhash_masked_substr = regex_bodyhash_ins[1];
            let bodyhash_substr_ids = regex_bodyhash_ins[2];
            let chars_shift_ins = &self.chars_shift_bodyhash.as_ref().unwrap().instances()[0];
            debug_assert_eq!(bodyhash_masked_substr, chars_shift_ins[0]);
            debug_assert_eq!(bodyhash_substr_ids, chars_shift_ins[1]);
            let bodyhash_base64 = chars_shift_ins[2];
            let sha2_body_ins = &self.sha2_body.as_ref().unwrap().instances()[0];
            let body_bytes = sha2_body_ins[0];
            let bodyhash = sha2_body_ins[1];
            let base64_ins = &self.base64.as_ref().unwrap().instances()[0];
            debug_assert_eq!(bodyhash, base64_ins[0]);
            debug_assert_eq!(bodyhash_base64, base64_ins[1]);
            let regex_body_ins = &self.regex_body.as_ref().unwrap().instances()[0];
            debug_assert_eq!(body_bytes, regex_body_ins[0]);
            let body_masked_substr = regex_body_ins[1];
            let body_substr_ids = regex_body_ins[2];
            let (body_masked_substr_hash, body_substr_ids_hash) = if self.body_expose_substrs {
                let sha2_body_masked_substrs_ins = &self.sha2_body_masked_substrs.as_ref().unwrap().instances()[0];
                debug_assert_eq!(body_masked_substr, sha2_body_masked_substrs_ins[0]);
                let body_masked_substr_hash = sha2_body_masked_substrs_ins[1..].to_vec();
                let sha2_body_substr_ids_ins = &self.sha2_body_substr_ids.as_ref().unwrap().instances()[0];
                debug_assert_eq!(body_substr_ids, sha2_body_substr_ids_ins[0]);
                let body_substr_ids_hash = sha2_body_substr_ids_ins[1..].to_vec();
                (Some(body_masked_substr_hash), Some(body_substr_ids_hash))
            } else {
                (None, None)
            };
            (
                Some(bodyhash_masked_substr),
                Some(bodyhash_substr_ids),
                Some(bodyhash_base64),
                Some(body_bytes),
                Some(bodyhash),
                Some(body_masked_substr),
                Some(body_substr_ids),
                body_masked_substr_hash,
                body_substr_ids_hash,
            )
        } else {
            (None, None, None, None, None, None, None, None, None)
        };
        EmailVerifyInstances {
            header_bytes,
            header_hash,
            public_key_n_hash,
            tag,
            header_masked_substr,
            header_substr_ids,
            header_masked_substr_hash,
            header_substr_ids_hash,
            bodyhash_masked_substr,
            bodyhash_substr_ids,
            bodyhash_base64,
            body_bytes,
            bodyhash,
            body_masked_substr,
            body_substr_ids,
            body_masked_substr_hash,
            body_substr_ids_hash,
        }
    }

    pub fn check_constraints(&self) -> Result<bool, Error> {
        let config_params = default_config_params();
        let k = config_params.degree;
        let instances = self.instances();
        let mut result = true;
        result &= MockProver::run(k, &self.sha2_header, vec![vec![instances.header_bytes, instances.header_hash]])?
            .verify()
            .is_ok();
        result &= MockProver::run(k, &self.sign_verify, vec![vec![instances.public_key_n_hash, instances.header_hash, instances.tag]])?
            .verify()
            .is_ok();
        result &= MockProver::run(
            k,
            &self.regex_header,
            vec![vec![instances.header_bytes, instances.header_masked_substr, instances.header_substr_ids]],
        )?
        .verify()
        .is_ok();
        if self.header_expose_substrs {
            result &= MockProver::run(
                k,
                self.sha2_header_masked_substrs.as_ref().unwrap(),
                vec![vec![vec![instances.header_masked_substr], instances.header_masked_substr_hash.as_ref().unwrap().clone()].concat()],
            )?
            .verify()
            .is_ok();
            result &= MockProver::run(
                k,
                self.sha2_header_substr_ids.as_ref().unwrap(),
                vec![vec![vec![instances.header_substr_ids], instances.header_substr_ids_hash.as_ref().unwrap().clone()].concat()],
            )?
            .verify()
            .is_ok();
        }
        if self.body_enable {
            result &= MockProver::run(
                k,
                self.regex_bodyhash.as_ref().unwrap(),
                vec![vec![
                    instances.header_bytes,
                    instances.bodyhash_masked_substr.unwrap().clone(),
                    instances.bodyhash_substr_ids.unwrap().clone(),
                ]],
            )?
            .verify()
            .is_ok();
            result &= MockProver::run(
                k,
                self.chars_shift_bodyhash.as_ref().unwrap(),
                vec![vec![
                    instances.bodyhash_masked_substr.unwrap().clone(),
                    instances.bodyhash_substr_ids.unwrap().clone(),
                    instances.bodyhash_base64.unwrap().clone(),
                ]],
            )?
            .verify()
            .is_ok();
            result &= MockProver::run(
                k,
                self.sha2_body.as_ref().unwrap(),
                vec![vec![instances.body_bytes.unwrap().clone(), instances.bodyhash.unwrap().clone()]],
            )?
            .verify()
            .is_ok();
            result &= MockProver::run(
                k,
                self.base64.as_ref().unwrap(),
                vec![vec![instances.bodyhash.unwrap().clone(), instances.bodyhash_base64.unwrap().clone()]],
            )?
            .verify()
            .is_ok();
            result &= MockProver::run(
                k,
                self.regex_body.as_ref().unwrap(),
                vec![vec![
                    instances.body_bytes.unwrap().clone(),
                    instances.body_masked_substr.unwrap().clone(),
                    instances.body_substr_ids.unwrap().clone(),
                ]],
            )?
            .verify()
            .is_ok();
            if self.body_expose_substrs {
                result &= MockProver::run(
                    k,
                    self.sha2_body_masked_substrs.as_ref().unwrap(),
                    vec![vec![
                        vec![instances.body_masked_substr.unwrap().clone()],
                        instances.body_masked_substr_hash.as_ref().unwrap().clone(),
                    ]
                    .concat()],
                )?
                .verify()
                .is_ok();
                result &= MockProver::run(
                    k,
                    self.sha2_body_substr_ids.as_ref().unwrap(),
                    vec![vec![vec![instances.body_substr_ids.unwrap().clone()], instances.body_substr_ids_hash.as_ref().unwrap().clone()].concat()],
                )?
                .verify()
                .is_ok();
            }
        }
        Ok(result)
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
            pks.push(gen_pk(params, self.sha2_header_masked_substrs.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.sha2_header_substr_ids.as_ref().unwrap(), None));
        }
        if self.body_enable {
            pks.push(gen_pk(params, self.regex_bodyhash.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.chars_shift_bodyhash.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.sha2_body.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.base64.as_ref().unwrap(), None));
            pks.push(gen_pk(params, self.regex_body.as_ref().unwrap(), None));
            if self.body_expose_substrs {
                pks.push(gen_pk(params, self.sha2_body_masked_substrs.as_ref().unwrap(), None));
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
        proofs.push(gen_proof_shplonk(
            params,
            &pks[pk_index],
            self.sha2_header.clone(),
            vec![vec![instances.header_bytes, instances.header_hash]],
            rng,
            None,
        ));
        pk_index += 1;
        proofs.push(gen_proof_shplonk(
            params,
            &pks[pk_index],
            self.sign_verify.clone(),
            vec![vec![instances.public_key_n_hash, instances.header_hash, instances.tag]],
            rng,
            None,
        ));
        pk_index += 1;
        proofs.push(gen_proof_shplonk(
            params,
            &pks[pk_index],
            self.regex_header.clone(),
            vec![vec![instances.header_bytes, instances.header_masked_substr, instances.header_substr_ids]],
            rng,
            None,
        ));
        pk_index += 1;
        if self.header_expose_substrs {
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_masked_substrs.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_masked_substr], instances.header_masked_substr_hash.unwrap()].concat()],
                rng,
                None,
            ));
            pk_index += 1;
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_substr_ids.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_substr_ids], instances.header_substr_ids_hash.unwrap()].concat()],
                rng,
                None,
            ));
            pk_index += 1;
        }
        if self.body_enable {
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.header_bytes,
                    instances.bodyhash_masked_substr.unwrap().clone(),
                    instances.bodyhash_substr_ids.unwrap().clone(),
                ]],
                rng,
                None,
            ));
            pk_index += 1;
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.chars_shift_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.bodyhash_masked_substr.unwrap().clone(),
                    instances.bodyhash_substr_ids.unwrap().clone(),
                    instances.bodyhash_base64.unwrap().clone(),
                ]],
                rng,
                None,
            ));
            pk_index += 1;
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_body.as_ref().unwrap().clone(),
                vec![vec![instances.body_bytes.unwrap().clone(), instances.bodyhash.unwrap().clone()]],
                rng,
                None,
            ));
            pk_index += 1;
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.base64.as_ref().unwrap().clone(),
                vec![vec![instances.bodyhash.unwrap().clone(), instances.bodyhash_base64.unwrap().clone()]],
                rng,
                None,
            ));
            pk_index += 1;
            proofs.push(gen_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_body.as_ref().unwrap().clone(),
                vec![vec![
                    instances.body_bytes.unwrap().clone(),
                    instances.body_masked_substr.unwrap().clone(),
                    instances.body_substr_ids.unwrap().clone(),
                ]],
                rng,
                None,
            ));
            pk_index += 1;
            if self.body_expose_substrs {
                proofs.push(gen_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_masked_substrs.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_masked_substr.unwrap().clone()], instances.body_masked_substr_hash.unwrap().clone()].concat()],
                    rng,
                    None,
                ));
                pk_index += 1;
                proofs.push(gen_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_substr_ids.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_substr_ids.unwrap().clone()], instances.body_substr_ids_hash.unwrap().clone()].concat()],
                    rng,
                    None,
                ));
            }
        }
        proofs
    }

    pub fn evm_prove<R: rand::Rng + Send>(&self, params: &ParamsKZG<Bn256>, pks: &[ProvingKey<G1Affine>], rng: &mut R) -> Vec<Vec<u8>> {
        let mut proofs = vec![];
        let mut pk_index = 0;
        let instances = self.instances();
        proofs.push(gen_evm_proof_shplonk(
            params,
            &pks[pk_index],
            self.sha2_header.clone(),
            vec![vec![instances.header_bytes, instances.header_hash]],
            rng,
        ));
        pk_index += 1;
        proofs.push(gen_evm_proof_shplonk(
            params,
            &pks[pk_index],
            self.sign_verify.clone(),
            vec![vec![instances.public_key_n_hash, instances.header_hash, instances.tag]],
            rng,
        ));
        pk_index += 1;
        proofs.push(gen_evm_proof_shplonk(
            params,
            &pks[pk_index],
            self.regex_header.clone(),
            vec![vec![instances.header_bytes, instances.header_masked_substr, instances.header_substr_ids]],
            rng,
        ));
        pk_index += 1;
        if self.header_expose_substrs {
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_masked_substrs.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_masked_substr], instances.header_masked_substr_hash.unwrap()].concat()],
                rng,
            ));
            pk_index += 1;
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_header_substr_ids.as_ref().unwrap().clone(),
                vec![vec![vec![instances.header_substr_ids], instances.header_substr_ids_hash.unwrap()].concat()],
                rng,
            ));
            pk_index += 1;
        }
        if self.body_enable {
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.header_bytes,
                    instances.bodyhash_masked_substr.unwrap().clone(),
                    instances.bodyhash_substr_ids.unwrap().clone(),
                ]],
                rng,
            ));
            pk_index += 1;
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.chars_shift_bodyhash.as_ref().unwrap().clone(),
                vec![vec![
                    instances.bodyhash_masked_substr.unwrap().clone(),
                    instances.bodyhash_substr_ids.unwrap().clone(),
                    instances.bodyhash_base64.unwrap().clone(),
                ]],
                rng,
            ));
            pk_index += 1;
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.sha2_body.as_ref().unwrap().clone(),
                vec![vec![instances.body_bytes.unwrap().clone(), instances.bodyhash.unwrap().clone()]],
                rng,
            ));
            pk_index += 1;
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.base64.as_ref().unwrap().clone(),
                vec![vec![instances.bodyhash.unwrap().clone(), instances.bodyhash_base64.unwrap().clone()]],
                rng,
            ));
            pk_index += 1;
            proofs.push(gen_evm_proof_shplonk(
                params,
                &pks[pk_index],
                self.regex_body.as_ref().unwrap().clone(),
                vec![vec![
                    instances.body_bytes.unwrap().clone(),
                    instances.body_masked_substr.unwrap().clone(),
                    instances.body_substr_ids.unwrap().clone(),
                ]],
                rng,
            ));
            pk_index += 1;
            if self.body_expose_substrs {
                proofs.push(gen_evm_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_masked_substrs.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_masked_substr.unwrap().clone()], instances.body_masked_substr_hash.unwrap().clone()].concat()],
                    rng,
                ));
                pk_index += 1;
                proofs.push(gen_evm_proof_shplonk(
                    params,
                    &pks[pk_index],
                    self.sha2_body_substr_ids.as_ref().unwrap().clone(),
                    vec![vec![vec![instances.body_substr_ids.unwrap().clone()], instances.body_substr_ids_hash.unwrap().clone()].concat()],
                    rng,
                ));
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
            let measured = CircuitCost::<G1, _>::measure(k, self.sha2_header_masked_substrs.as_ref().unwrap());
            println!("sha2_header_masked_substrs: {:?}", measured);
            let gates = CircuitGates::collect::<Fr, Sha256HeaderMaskedSubstrsCircuit<Fr>>();
            println!("sha2_header_masked_substrs gates: {}", gates);
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
                let measured = CircuitCost::<G1, _>::measure(k, self.sha2_body_masked_substrs.as_ref().unwrap());
                println!("sha2_body_masked_substrs: {:?}", measured);
                let gates = CircuitGates::collect::<Fr, Sha256BodyMaskedSubstrsCircuit<Fr>>();
                println!("sha256_body_masked_substrs gates: {}", gates);
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
    header_bytes: F,
    header_hash: F,
    public_key_n_hash: F,
    tag: F,
    header_masked_substr: F,
    header_substr_ids: F,
    header_masked_substr_hash: Option<Vec<F>>,
    header_substr_ids_hash: Option<Vec<F>>,
    bodyhash_masked_substr: Option<F>,
    bodyhash_substr_ids: Option<F>,
    bodyhash_base64: Option<F>,
    body_bytes: Option<F>,
    bodyhash: Option<F>,
    body_masked_substr: Option<F>,
    body_substr_ids: Option<F>,
    body_masked_substr_hash: Option<Vec<F>>,
    body_substr_ids_hash: Option<Vec<F>>,
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
        result &= verify_proof(params, &vks[vk_index], proofs[vk_index], &vec![self.header_bytes, self.header_hash]);
        vk_index += 1;
        result &= verify_proof(params, &vks[vk_index], proofs[vk_index], &vec![self.public_key_n_hash, self.header_hash, self.tag]);
        vk_index += 1;
        result &= verify_proof(
            params,
            &vks[vk_index],
            proofs[vk_index],
            &vec![self.header_bytes, self.header_masked_substr, self.header_substr_ids],
        );
        vk_index += 1;
        if config_params.header_config.as_ref().unwrap().expose_substrs.unwrap_or(false) {
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![vec![self.header_masked_substr], self.header_masked_substr_hash.as_ref().unwrap().clone()].concat(),
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![vec![self.header_substr_ids], self.header_substr_ids_hash.as_ref().unwrap().clone()].concat(),
            );
            vk_index += 1;
        }
        if let Some(body_config) = config_params.body_config.as_ref() {
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![self.header_bytes, self.bodyhash_masked_substr.unwrap().clone(), self.bodyhash_substr_ids.unwrap().clone()],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![
                    self.bodyhash_masked_substr.unwrap().clone(),
                    self.bodyhash_substr_ids.unwrap().clone(),
                    self.bodyhash_base64.unwrap().clone(),
                ],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![self.body_bytes.unwrap().clone(), self.bodyhash.unwrap().clone()],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![self.bodyhash.unwrap().clone(), self.bodyhash_base64.unwrap().clone()],
            );
            vk_index += 1;
            result &= verify_proof(
                params,
                &vks[vk_index],
                proofs[vk_index],
                &vec![
                    self.body_bytes.unwrap().clone(),
                    self.body_masked_substr.unwrap().clone(),
                    self.body_substr_ids.unwrap().clone(),
                ],
            );
            vk_index += 1;
            if body_config.expose_substrs.unwrap_or(false) {
                result &= verify_proof(
                    params,
                    &vks[vk_index],
                    proofs[vk_index],
                    &vec![vec![self.body_masked_substr.unwrap().clone()], self.body_masked_substr_hash.as_ref().unwrap().clone()].concat(),
                );
                vk_index += 1;
                result &= verify_proof(
                    params,
                    &vks[vk_index],
                    proofs[vk_index],
                    &vec![vec![self.body_substr_ids.unwrap().clone()], self.body_substr_ids_hash.as_ref().unwrap().clone()].concat(),
                );
            }
        }
        result
    }
}

// /// Public input definition of [`DefaultEmailVerifyCircuit`].
// #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
// pub struct DefaultEmailVerifyPublicInput {
//     /// A hex string of the SHA256 hash computed from the email header.
//     pub headerhash: String,
//     /// A hex string of the n parameter in the RSA public key. (The e parameter is fixed to 65537.)
//     pub public_key_n_bytes: String,
//     /// The start position of the substrings in the email header.
//     pub header_starts: Vec<usize>,
//     /// The substrings in the email header.
//     pub header_substrs: Vec<String>,
//     /// The start position of the substrings in the email body.
//     pub body_starts: Vec<usize>,
//     /// The substrings in the email body.
//     pub body_substrs: Vec<String>,
// }

// impl DefaultEmailVerifyPublicInput {
//     /// Create a public input for [`DefaultEmailVerifyCircuit`].
//     ///
//     /// # Arguments
//     /// * `headerhash` - a hex string of the SHA256 hash computed from the email header.
//     /// * `public_key_n` - a hex string of the n parameter in the RSA public key.
//     /// * `header_substrs` a vector of (the start position, the bytes) of the substrings in the email header.
//     /// * `body_starts` - a vector of (the start position, the bytes) of the substrings in the email body.
//     /// # Return values
//     /// Return a new [`DefaultEmailVerifyPublicInput`].
//     pub fn new(headerhash: Vec<u8>, public_key_n: BigUint, header_substrs: Vec<Option<(usize, String)>>, body_substrs: Vec<Option<(usize, String)>>) -> Self {
//         let mut header_starts_vec = vec![];
//         let mut header_substrs_vec = vec![];
//         for s in header_substrs.into_iter() {
//             if let Some(s) = s {
//                 header_starts_vec.push(s.0);
//                 header_substrs_vec.push(s.1);
//             }
//         }
//         let mut body_starts_vec = vec![];
//         let mut body_substrs_vec = vec![];
//         for s in body_substrs.into_iter() {
//             if let Some(s) = s {
//                 body_starts_vec.push(s.0);
//                 body_substrs_vec.push(s.1);
//             }
//         }
//         DefaultEmailVerifyPublicInput {
//             headerhash: format!("0x{}", hex::encode(&headerhash)),
//             public_key_n_bytes: format!("0x{}", hex::encode(&public_key_n.to_bytes_le())),
//             header_starts: header_starts_vec,
//             header_substrs: header_substrs_vec,
//             body_starts: body_starts_vec,
//             body_substrs: body_substrs_vec,
//         }
//     }

//     /// Output [`DefaultEmailVerifyPublicInput`] to a json file.
//     ///
//     /// # Arguments
//     /// * `public_input_path` - a file path of the output json file.
//     pub fn write_file(&self, public_input_path: &str) {
//         let public_input_str = serde_json::to_string(&self).unwrap();
//         let mut file = File::create(public_input_path).expect("public_input_path creation failed");
//         write!(file, "{}", public_input_str).unwrap();
//         file.flush().unwrap();
//     }
// }

// /// Configuration for [`DefaultEmailVerifyCircuit`].
// #[derive(Debug, Clone)]
// pub struct DefaultEmailVerifyConfig<F: PrimeField> {
//     pub sha256_config: Sha256DynamicConfig<F>,
//     pub sign_verify_config: SignVerifyConfig<F>,
//     pub header_config: RegexSha2Config<F>,
//     pub body_config: RegexSha2Base64Config<F>,
//     /// An instance column for the SHA256 hash of the all public inputs, i.e., the SHA256 hash of the email header, the base64 encoded SHA256 hash of the email body, the RSA public key, and the substrings and their ids in the email header and body.
//     pub public_hash: Column<Instance>,
// }

// /// Default email verification circuit.
// #[derive(Debug, Clone)]
// pub struct DefaultEmailVerifyCircuit<F: PrimeField> {
//     /// Email header bytes.
//     pub header_bytes: Vec<u8>,
//     /// Email body bytes.
//     pub body_bytes: Vec<u8>,
//     /// RSA public key.
//     pub public_key: RSAPublicKey<F>,
//     /// RSA digital signature.
//     pub signature: RSASignature<F>,
// }

// impl<F: PrimeField> Circuit<F> for DefaultEmailVerifyCircuit<F> {
//     type Config = DefaultEmailVerifyConfig<F>;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self {
//             header_bytes: vec![],
//             body_bytes: vec![],
//             public_key: self.public_key.clone(),
//             signature: self.signature.clone(),
//         }
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         let params = Self::read_config_params();
//         let range_config = RangeConfig::configure(
//             meta,
//             Vertical,
//             &[params.num_flex_advice],
//             &[params.num_range_lookup_advice],
//             params.num_flex_advice,
//             params.range_lookup_bits,
//             0,
//             params.degree as usize,
//         );
//         let header_params = params.header_config.expect("header_config is required");
//         let body_params = params.body_config.expect("body_config is required");
//         let sign_verify_params = params.sign_verify_config.expect("sign_verify_config is required");
//         let sha256_params = params.sha256_config.expect("sha256_config is required");
//         assert_eq!(header_params.allstr_filepathes.len(), header_params.substr_filepathes.len());
//         assert_eq!(body_params.allstr_filepathes.len(), body_params.substr_filepathes.len());

//         let sha256_config = Sha256DynamicConfig::configure(
//             meta,
//             vec![
//                 body_params.max_variable_byte_size,
//                 header_params.max_variable_byte_size,
//                 128 + sign_verify_params.public_key_bits / 8 + 2 * (header_params.max_variable_byte_size + body_params.max_variable_byte_size) + 64, // (header hash, base64 body hash, padding, RSA public key, masked chars, substr ids)
//             ],
//             range_config.clone(),
//             sha256_params.num_bits_lookup,
//             sha256_params.num_advice_columns,
//             false,
//         );

//         let sign_verify_config = SignVerifyConfig::configure(range_config.clone(), sign_verify_params.public_key_bits);

//         // assert_eq!(params.body_regex_filepathes.len(), params.body_substr_filepathes.len());
//         let bodyhash_allstr_def = AllstrRegexDef::read_from_text(&header_params.bodyhash_allstr_filepath);
//         let bodyhash_substr_def = SubstrRegexDef::read_from_text(&header_params.bodyhash_substr_filepath);
//         let bodyhash_defs = RegexDefs {
//             allstr: bodyhash_allstr_def,
//             substrs: vec![bodyhash_substr_def],
//         };
//         let header_regex_defs = header_params
//             .allstr_filepathes
//             .iter()
//             .zip(header_params.substr_filepathes.iter())
//             .map(|(allstr_path, substr_pathes)| {
//                 let allstr = AllstrRegexDef::read_from_text(&allstr_path);
//                 let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
//                 RegexDefs { allstr, substrs }
//             })
//             .collect_vec();
//         let header_config = RegexSha2Config::configure(
//             meta,
//             header_params.max_variable_byte_size,
//             header_params.skip_prefix_bytes_size.unwrap_or(0),
//             range_config.clone(),
//             vec![vec![bodyhash_defs], header_regex_defs].concat(),
//         );

//         let body_regex_defs = body_params
//             .allstr_filepathes
//             .iter()
//             .zip(body_params.substr_filepathes.iter())
//             .map(|(allstr_path, substr_pathes)| {
//                 let allstr = AllstrRegexDef::read_from_text(&allstr_path);
//                 let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
//                 RegexDefs { allstr, substrs }
//             })
//             .collect_vec();
//         let body_config = RegexSha2Base64Config::configure(
//             meta,
//             body_params.max_variable_byte_size,
//             body_params.skip_prefix_bytes_size.unwrap_or(0),
//             range_config,
//             body_regex_defs,
//         );

//         let public_hash = meta.instance_column();
//         meta.enable_equality(public_hash);
//         DefaultEmailVerifyConfig {
//             sha256_config,
//             sign_verify_config,
//             header_config,
//             body_config,
//             public_hash,
//         }
//     }

//     fn synthesize(&self, mut config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
//         config.sha256_config.range().load_lookup_table(&mut layouter)?;
//         config.sha256_config.load(&mut layouter)?;
//         config.header_config.load(&mut layouter)?;
//         config.body_config.load(&mut layouter)?;
//         let mut first_pass = SKIP_FIRST_PASS;
//         let mut public_hash_cell = vec![];
//         let params = Self::read_config_params();
//         if let Some(sign_config) = params.sign_verify_config.as_ref() {
//             self.public_key.n.as_ref().map(|v| assert_eq!(v.bits() as usize, sign_config.public_key_bits));
//         }
//         layouter.assign_region(
//             || "zkemail",
//             |region| {
//                 if first_pass {
//                     first_pass = false;
//                     return Ok(());
//                 }
//                 let ctx = &mut config.sha256_config.new_context(region);
//                 let params = Self::read_config_params();
//                 let header_params = params.header_config.expect("header_config is required");
//                 let body_params = params.body_config.expect("body_config is required");

//                 // 1. Extract sub strings in the body and compute the base64 encoded hash of the body.
//                 let body_result = config.body_config.match_hash_and_base64(ctx, &mut config.sha256_config, &self.body_bytes)?;

//                 // 2. Extract sub strings in the header, which includes the body hash, and compute the raw hash of the header.
//                 let header_result = config.header_config.match_and_hash(ctx, &mut config.sha256_config, &self.header_bytes)?;

//                 // 3. Verify the rsa signature.
//                 let (assigned_public_key, _) = config
//                     .sign_verify_config
//                     .verify_signature(ctx, &header_result.hash_bytes, self.public_key.clone(), self.signature.clone())?;

//                 let header_str = String::from_utf8(self.header_bytes[header_params.skip_prefix_bytes_size.unwrap_or(0)..].to_vec()).unwrap();
//                 let body_str = String::from_utf8(self.body_bytes[body_params.skip_prefix_bytes_size.unwrap_or(0)..].to_vec()).unwrap();
//                 let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_params.substr_regexes, body_params.substr_regexes);
//                 let public_hash_input = get_email_circuit_public_hash_input(
//                     &header_result.hash_value,
//                     &value_to_option(self.public_key.n.clone()).unwrap().to_bytes_le(),
//                     header_substrs,
//                     body_substrs,
//                     header_params.max_variable_byte_size,
//                     body_params.max_variable_byte_size,
//                 );
//                 let public_hash_result: AssignedHashResult<F> = config.sha256_config.digest(ctx, &public_hash_input, None)?;
//                 // for (idx, v) in public_hash_result.input_bytes[128..(128 + 256)].iter().enumerate() {
//                 //     v.value().map(|v| println!("idx {} code {}", idx, v.get_lower_32()));
//                 // }
//                 let range = config.sha256_config.range().clone();
//                 let gate = range.gate.clone();
//                 // for (idx, v) in header_result.regex.masked_characters.iter().enumerate() {
//                 //     v.value()
//                 //         .map(|v| println!("idx {} code {} char {}", idx, v.get_lower_32(), (v.get_lower_32() as u8) as char));
//                 // }
//                 // for (idx, v) in body_result.regex.masked_characters.iter().enumerate() {
//                 //     v.value()
//                 //         .map(|v| println!("idx {} code {} char {}", idx, v.get_lower_32(), (v.get_lower_32() as u8) as char));
//                 // }
//                 let assigned_public_key_bytes = assigned_public_key
//                     .n
//                     .limbs()
//                     .into_iter()
//                     .flat_map(|limb| {
//                         let limb_val = value_to_option(limb.value()).unwrap();
//                         let bytes = decompose_fe_to_u64_limbs(limb_val, 64 / 8, 8);
//                         let mut sum = gate.load_zero(ctx);
//                         let assigned = bytes
//                             .into_iter()
//                             .enumerate()
//                             .map(|(idx, byte)| {
//                                 let assigned = gate.load_witness(ctx, Value::known(F::from(byte)));
//                                 range.range_check(ctx, &assigned, 8);
//                                 sum = gate.mul_add(
//                                     ctx,
//                                     QuantumCell::Existing(&assigned),
//                                     QuantumCell::Constant(F::from(1u64 << (8 * idx))),
//                                     QuantumCell::Existing(&sum),
//                                 );
//                                 assigned
//                             })
//                             .collect_vec();
//                         gate.assert_equal(ctx, QuantumCell::Existing(&sum), QuantumCell::Existing(limb));
//                         assigned
//                     })
//                     .collect_vec();
//                 // for (idx, v) in assigned_public_key_bytes.iter().enumerate() {
//                 //     v.value().map(|v| println!("idx {} byte {}", 128 + idx, v.get_lower_32()));
//                 // }
//                 let assigned_public_hash_input = vec![
//                     header_result.hash_bytes.into_iter().map(|v| v.cell()).collect_vec(),
//                     body_result.encoded_hash.into_iter().map(|v| v.cell()).collect_vec(),
//                     vec![gate.load_zero(ctx).cell(); 128 - 32 - 44],
//                     assigned_public_key_bytes.into_iter().map(|v| v.cell()).collect_vec(),
//                     vec![header_result.regex.masked_characters, body_result.regex.masked_characters]
//                         .concat()
//                         .into_iter()
//                         .map(|v| v.cell())
//                         .collect_vec(),
//                     vec![header_result.regex.all_substr_ids, body_result.regex.all_substr_ids]
//                         .concat()
//                         .into_iter()
//                         .map(|v| v.cell())
//                         .collect_vec(),
//                 ]
//                 .concat();
//                 for (a, b) in public_hash_result.input_bytes[0..assigned_public_hash_input.len()]
//                     .into_iter()
//                     .map(|v| v.cell())
//                     .collect_vec()
//                     .into_iter()
//                     .zip(assigned_public_hash_input.into_iter())
//                 {
//                     // ctx.region.constrain_equal(a, b)?;
//                 }
//                 debug_assert_eq!(public_hash_result.output_bytes.len(), 32);
//                 let mut packed_public_hash = gate.load_zero(ctx);
//                 let mut coeff = F::from(1u64);
//                 for byte in public_hash_result.output_bytes[0..31].iter() {
//                     packed_public_hash = gate.mul_add(ctx, QuantumCell::Existing(byte), QuantumCell::Constant(coeff), QuantumCell::Existing(&packed_public_hash));
//                     coeff *= F::from(256u64);
//                 }
//                 config.sha256_config.range().finalize(ctx);
//                 public_hash_cell.push(packed_public_hash.cell());
//                 Ok(())
//             },
//         )?;
//         // layouter.constrain_instance(public_hash_cell[0], config.public_hash, 0)?;
//         Ok(())
//     }
// }

// impl<F: PrimeField> CircuitExt<F> for DefaultEmailVerifyCircuit<F> {
//     fn num_instance(&self) -> Vec<usize> {
//         vec![1]
//     }

//     fn instances(&self) -> Vec<Vec<F>> {
//         let headerhash = Sha256::digest(&self.header_bytes).to_vec();
//         let header_str = String::from_utf8(self.header_bytes.clone()).unwrap();
//         let body_str = String::from_utf8(self.body_bytes.clone()).unwrap();
//         let params = Self::read_config_params();
//         let header_params = params.header_config.expect("header_config is required");
//         let body_params = params.body_config.expect("body_config is required");
//         let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_params.substr_regexes, body_params.substr_regexes);
//         let public_input = DefaultEmailVerifyPublicInput::new(headerhash, value_to_option(self.public_key.n.clone()).unwrap(), header_substrs, body_substrs);
//         vec![Self::_get_instances_from_default_public_input(public_input)]
//     }
// }

// impl<F: PrimeField> DefaultEmailVerifyCircuit<F> {
//     pub const DEFAULT_E: u128 = 65537;

//     /// Read [`DefaultEmailVerifyConfigParams`] from a json file at the file path of [`EMAIL_VERIFY_CONFIG_ENV`].
//     pub fn read_config_params() -> DefaultEmailVerifyConfigParams {
//         read_default_circuit_config_params()
//     }

//     /// Generate a new circuit from the given email file.
//     ///
//     /// # Arguments
//     /// * `email_path` - a file path of the email file.
//     ///
//     /// # Return values
//     /// Return a new [`DefaultEmailVerifyCircuit`], the SHA256 hash bytes of the email header, the `n` parameter of the RSA public key, a vector of (`start_position`, `substr`) in the email header, and a vector of (`start_position`, `substr`) in the email body.
//     pub async fn gen_circuit_from_email_path(email_path: &str) -> (Self, Vec<u8>, BigUint, Vec<Option<(usize, String)>>, Vec<Option<(usize, String)>>) {
//         let email_bytes = {
//             let mut f = File::open(email_path).unwrap();
//             let mut buf = Vec::new();
//             f.read_to_end(&mut buf).unwrap();
//             buf
//         };
//         // println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
//         let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
//         let headerhash = Sha256::digest(&canonicalized_header).to_vec();
//         let public_key_n = {
//             let logger = slog::Logger::root(slog::Discard, slog::o!());
//             match resolve_public_key(&logger, &email_bytes).await.unwrap() {
//                 cfdkim::DkimPublicKey::Rsa(_pk) => BigUint::from_radix_le(&_pk.n().clone().to_radix_le(16), 16).unwrap(),
//                 _ => {
//                     panic!("Only RSA keys are supported.");
//                 }
//             }
//         };
//         let e = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
//         let public_key = RSAPublicKey::<F>::new(Value::known(public_key_n.clone()), e);
//         let signature = RSASignature::<F>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//         let header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
//         let body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
//         let config_params = Self::read_config_params();
//         let header_config = config_params.header_config.expect("header_config is required");
//         let body_config = config_params.body_config.expect("body_config is required");
//         let (header_substrs, body_substrs) = get_email_substrs(&header_str, &body_str, header_config.substr_regexes, body_config.substr_regexes);
//         let circuit = Self {
//             header_bytes: canonicalized_header,
//             body_bytes: canonicalized_body,
//             public_key,
//             signature,
//         };
//         (circuit, headerhash, public_key_n, header_substrs, body_substrs)
//     }

//     /// Retrieve instance values from the given [`DefaultEmailVerifyPublicInput`] json file.
//     ///
//     /// # Arguments
//     /// * `public_input_path` - a file path of the [`DefaultEmailVerifyPublicInput`] json file.
//     ///
//     /// # Return values
//     /// Return a vector of the instance values.
//     pub fn get_instances_from_default_public_input(public_input_path: &str) -> Vec<F> {
//         let public_input = serde_json::from_reader::<File, DefaultEmailVerifyPublicInput>(File::open(public_input_path).unwrap()).unwrap();
//         Self::_get_instances_from_default_public_input(public_input)
//     }

//     fn _get_instances_from_default_public_input(public_input: DefaultEmailVerifyPublicInput) -> Vec<F> {
//         let config_params = read_default_circuit_config_params();
//         let header_params = config_params.header_config.expect("header_config is required");
//         let body_params = config_params.body_config.expect("body_config is required");
//         let headerhash = hex::decode(&public_input.headerhash[2..]).unwrap();
//         let public_key_n_bytes = hex::decode(&public_input.public_key_n_bytes[2..]).unwrap();
//         let header_substrs = public_input
//             .header_starts
//             .into_iter()
//             .zip(public_input.header_substrs.into_iter())
//             .map(|(start, substr)| Some((start, substr)))
//             .collect_vec();
//         let body_substrs = public_input
//             .body_starts
//             .into_iter()
//             .zip(public_input.body_substrs.into_iter())
//             .map(|(start, substr)| Some((start, substr)))
//             .collect_vec();
//         let public_hash_input = get_email_circuit_public_hash_input(
//             &headerhash,
//             &public_key_n_bytes,
//             header_substrs,
//             body_substrs,
//             header_params.max_variable_byte_size,
//             body_params.max_variable_byte_size,
//         );
//         let public_hash: Vec<u8> = Sha256::digest(&public_hash_input).to_vec();
//         let public_fr = {
//             let lo = F::from_u128(u128::from_le_bytes(public_hash[0..16].try_into().unwrap()));
//             let mut hi_bytes = [0; 16];
//             for idx in 0..15 {
//                 hi_bytes[idx] = public_hash[16 + idx];
//             }
//             let hi = F::from_u128(u128::from_le_bytes(hi_bytes));
//             hi * F::from(2).pow_const(128) + lo
//         };
//         vec![public_fr]
//     }
// }

// #[cfg(test)]
// mod test {
//     use super::*;
//     use cfdkim::{canonicalize_signed_email, resolve_public_key, SignerBuilder};
//     use halo2_base::halo2_proofs::{
//         circuit::Value,
//         dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
//         halo2curves::bn256::{Fr, G1},
//     };
//     use halo2_regex::vrm::DecomposedRegexConfig;
//     use halo2_rsa::RSAPubE;
//     use mailparse::parse_mail;
//     use num_bigint::BigUint;
//     use rand::thread_rng;
//     use rsa::{PublicKeyParts, RsaPrivateKey};
//     use snark_verifier_sdk::CircuitExt;
//     use std::{fs::File, io::Read, path::Path};
//     use temp_env;

//     #[test]
//     fn test_generated_email1() {
//         temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test1_email_verify.config"), || {
//             let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
//             regex_bodyhash_decomposed
//                 .gen_regex_files(
//                     &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
//                     &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
//                 )
//                 .unwrap();
//             let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
//             regex_from_decomposed
//                 .gen_regex_files(
//                     &Path::new("./test_data/from_allstr.txt").to_path_buf(),
//                     &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
//                 )
//                 .unwrap();
//             let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test1_email_body_defs.json").unwrap()).unwrap();
//             regex_body_decomposed
//                 .gen_regex_files(
//                     &Path::new("./test_data/test1_email_body_allstr.txt").to_path_buf(),
//                     &[Path::new("./test_data/test1_email_body_substr_0.txt").to_path_buf()],
//                 )
//                 .unwrap();
//             let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
//             let sign_verify_config = params.sign_verify_config.expect("sign_verify_config is required");
//             let mut rng = thread_rng();
//             let _private_key = RsaPrivateKey::new(&mut rng, sign_verify_config.public_key_bits).expect("failed to generate a key");
//             let public_key = rsa::RsaPublicKey::from(&_private_key);
//             let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
//             let message = concat!("From: alice@zkemail.com\r\n", "\r\n", "email was meant for @zkemailverify.",).as_bytes();
//             let email = parse_mail(message).unwrap();
//             let logger = slog::Logger::root(slog::Discard, slog::o!());
//             let signer = SignerBuilder::new()
//                 .with_signed_headers(&["From"])
//                 .unwrap()
//                 .with_private_key(private_key)
//                 .with_selector("default")
//                 .with_signing_domain("zkemail.com")
//                 .with_logger(&logger)
//                 .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
//                 .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
//                 .build()
//                 .unwrap();
//             let signature = signer.sign(&email).unwrap();
//             let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
//             println!("email: {}", String::from_utf8(new_msg.clone()).unwrap());
//             let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&new_msg).unwrap();

//             println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
//             println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());

//             let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//             let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
//             let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
//             let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//             let circuit = DefaultEmailVerifyCircuit {
//                 header_bytes: canonicalized_header,
//                 body_bytes: canonicalized_body,
//                 public_key,
//                 signature,
//             };
//             let instances = circuit.instances();
//             let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
//             assert_eq!(prover.verify(), Ok(()));
//         });
//     }

//     #[test]
//     fn test_generated_email2() {
//         temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test2_email_verify.config"), || {
//             let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
//             regex_bodyhash_decomposed
//                 .gen_regex_files(
//                     &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
//                     &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
//                 )
//                 .unwrap();
//             let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
//             regex_from_decomposed
//                 .gen_regex_files(
//                     &Path::new("./test_data/from_allstr.txt").to_path_buf(),
//                     &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
//                 )
//                 .unwrap();
//             let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
//             regex_to_decomposed
//                 .gen_regex_files(
//                     &Path::new("./test_data/to_allstr.txt").to_path_buf(),
//                     &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
//                 )
//                 .unwrap();
//             let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test2_email_body_defs.json").unwrap()).unwrap();
//             regex_body_decomposed
//                 .gen_regex_files(
//                     &Path::new("./test_data/test2_email_body_allstr.txt").to_path_buf(),
//                     &[
//                         Path::new("./test_data/test2_email_body_substr_0.txt").to_path_buf(),
//                         Path::new("./test_data/test2_email_body_substr_1.txt").to_path_buf(),
//                     ],
//                 )
//                 .unwrap();
//             let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
//             let sign_verify_config = params.sign_verify_config.expect("sign_verify_config is required");
//             let mut rng = thread_rng();
//             let _private_key = RsaPrivateKey::new(&mut rng, sign_verify_config.public_key_bits).expect("failed to generate a key");
//             let public_key = rsa::RsaPublicKey::from(&_private_key);
//             let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
//             let message = concat!(
//                 "From: alice@zkemail.com\r\n",
//                 "To: bob@example.com\r\n",
//                 "\r\n",
//                 "email was meant for @zkemailverify and halo.",
//             )
//             .as_bytes();
//             let email = parse_mail(message).unwrap();
//             let logger = slog::Logger::root(slog::Discard, slog::o!());
//             let signer = SignerBuilder::new()
//                 .with_signed_headers(&["To", "From"])
//                 .unwrap()
//                 .with_private_key(private_key)
//                 .with_selector("default")
//                 .with_signing_domain("zkemail.com")
//                 .with_logger(&logger)
//                 .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
//                 .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
//                 .build()
//                 .unwrap();
//             let signature = signer.sign(&email).unwrap();
//             println!("signature {}", signature);
//             let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
//             let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&new_msg).unwrap();

//             println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
//             println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());

//             let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//             let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
//             let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
//             let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//             let circuit = DefaultEmailVerifyCircuit {
//                 header_bytes: canonicalized_header,
//                 body_bytes: canonicalized_body,
//                 public_key,
//                 signature,
//             };

//             let instances = circuit.instances();
//             let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
//             assert_eq!(prover.verify(), Ok(()));
//         });
//     }

//     #[tokio::test]
//     async fn test_existing_email1() {
//         let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
//         regex_bodyhash_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
//         regex_from_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/from_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
//         regex_to_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/to_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
//         regex_subject_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex1_email_body_defs.json").unwrap()).unwrap();
//         regex_body_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let email_bytes = {
//             let mut f = File::open("./test_data/test_email1.eml").unwrap();
//             let mut buf = Vec::new();
//             f.read_to_end(&mut buf).unwrap();
//             buf
//         };

//         let logger = slog::Logger::root(slog::Discard, slog::o!());
//         let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
//         let public_key = match public_key {
//             cfdkim::DkimPublicKey::Rsa(pk) => pk,
//             _ => panic!("not supportted public key type."),
//         };
//         temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
//             let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
//             let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
//             println!("header len\n {}", canonicalized_header.len());
//             println!("body len\n {}", canonicalized_body.len());
//             println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
//             println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
//             let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//             let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
//             let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
//             let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//             let circuit = DefaultEmailVerifyCircuit {
//                 header_bytes: canonicalized_header,
//                 body_bytes: canonicalized_body,
//                 public_key,
//                 signature,
//             };

//             let instances = circuit.instances();
//             let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
//             assert_eq!(prover.verify(), Ok(()));
//         });
//     }

//     #[tokio::test]
//     async fn test_existing_email2() {
//         let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
//         regex_bodyhash_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
//         regex_from_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/from_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
//         regex_to_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/to_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
//         regex_subject_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex2_email_body_defs.json").unwrap()).unwrap();
//         regex_body_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/test_ex2_email_body_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/test_ex2_email_body_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex2_email_body_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex2_email_body_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let email_bytes = {
//             let mut f = File::open("./test_data/test_email2.eml").unwrap();
//             let mut buf = Vec::new();
//             f.read_to_end(&mut buf).unwrap();
//             buf
//         };

//         let logger = slog::Logger::root(slog::Discard, slog::o!());
//         let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
//         let public_key = match public_key {
//             cfdkim::DkimPublicKey::Rsa(pk) => pk,
//             _ => panic!("not supportted public key type."),
//         };
//         temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex2_email_verify.config"), move || {
//             let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
//             let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
//             println!("header len\n {}", canonicalized_header.len());
//             println!("body len\n {}", canonicalized_body.len());
//             // println!("body\n{:?}", canonicalized_body);
//             println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
//             println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
//             let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//             let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
//             let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
//             let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//             let circuit = DefaultEmailVerifyCircuit {
//                 header_bytes: canonicalized_header,
//                 body_bytes: canonicalized_body,
//                 public_key,
//                 signature,
//             };

//             let instances = circuit.instances();
//             let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
//             assert_eq!(prover.verify(), Ok(()));
//         });
//     }

//     #[ignore]
//     #[tokio::test]
//     async fn test_existing_email3() {
//         let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
//         regex_bodyhash_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_timestamp_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/timestamp_defs.json").unwrap()).unwrap();
//         regex_timestamp_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/timestamp_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/timestamp_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex3_email_body_defs.json").unwrap()).unwrap();
//         regex_body_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/test_ex3_email_body_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/test_ex3_email_body_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let email_bytes = {
//             let mut f = File::open("./test_data/test_email3.eml").unwrap();
//             let mut buf = Vec::new();
//             f.read_to_end(&mut buf).unwrap();
//             buf
//         };

//         let logger = slog::Logger::root(slog::Discard, slog::o!());
//         let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
//         let public_key = match public_key {
//             cfdkim::DkimPublicKey::Rsa(pk) => pk,
//             _ => panic!("not supportted public key type."),
//         };
//         temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex3_email_verify.config"), move || {
//             let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
//             let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
//             println!("header len\n {}", canonicalized_header.len());
//             println!("body len\n {}", canonicalized_body.len());
//             // println!("body\n{:?}", canonicalized_body);
//             println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
//             println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
//             let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//             let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
//             let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
//             let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//             let circuit = DefaultEmailVerifyCircuit {
//                 header_bytes: canonicalized_header,
//                 body_bytes: canonicalized_body,
//                 public_key,
//                 signature,
//             };

//             let instances = circuit.instances();
//             let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
//             assert_eq!(prover.verify(), Ok(()));
//         });
//     }

//     #[tokio::test]
//     async fn test_existing_email_invalid1() {
//         let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
//         regex_bodyhash_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
//         regex_from_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/from_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
//         regex_to_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/to_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
//         regex_subject_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex1_email_body_defs.json").unwrap()).unwrap();
//         regex_body_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let email_bytes = {
//             let mut f = File::open("./test_data/test_email1.eml").unwrap();
//             let mut buf = Vec::new();
//             f.read_to_end(&mut buf).unwrap();
//             buf
//         };

//         let logger = slog::Logger::root(slog::Discard, slog::o!());
//         let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
//         let public_key = match public_key {
//             cfdkim::DkimPublicKey::Rsa(pk) => pk,
//             _ => panic!("not supportted public key type."),
//         };
//         temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
//             let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
//             let (canonicalized_header, canonicalized_body, mut signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
//             println!("header len\n {}", canonicalized_header.len());
//             println!("body len\n {}", canonicalized_body.len());
//             println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
//             println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
//             let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//             let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
//             let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
//             signature_bytes[0] = 0;
//             let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//             let circuit = DefaultEmailVerifyCircuit {
//                 header_bytes: canonicalized_header,
//                 body_bytes: canonicalized_body,
//                 public_key,
//                 signature,
//             };

//             let instances = circuit.instances();
//             let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
//             assert!(prover.verify().is_err());
//         });
//     }

//     #[tokio::test]
//     async fn test_existing_email_invalid2() {
//         let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
//         regex_bodyhash_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
//         regex_from_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/from_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
//         regex_to_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/to_allstr.txt").to_path_buf(),
//                 &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
//             )
//             .unwrap();
//         let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
//         regex_subject_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex1_email_body_defs.json").unwrap()).unwrap();
//         regex_body_decomposed
//             .gen_regex_files(
//                 &Path::new("./test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
//                 &[
//                     Path::new("./test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
//                     Path::new("./test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
//                 ],
//             )
//             .unwrap();
//         let email_bytes = {
//             let mut f = File::open("./test_data/invalid_test_email1.eml").unwrap();
//             let mut buf = Vec::new();
//             f.read_to_end(&mut buf).unwrap();
//             buf
//         };

//         let logger = slog::Logger::root(slog::Discard, slog::o!());
//         let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
//         let public_key = match public_key {
//             cfdkim::DkimPublicKey::Rsa(pk) => pk,
//             _ => panic!("not supportted public key type."),
//         };
//         temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
//             let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
//             let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&email_bytes).unwrap();
//             println!("header len\n {}", canonicalized_header.len());
//             println!("body len\n {}", canonicalized_body.len());
//             println!("canonicalized_header:\n{}", String::from_utf8(canonicalized_header.clone()).unwrap());
//             println!("canonicalized_body:\n{}", String::from_utf8(canonicalized_body.clone()).unwrap());
//             let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
//             let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
//             let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
//             let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
//             let circuit = DefaultEmailVerifyCircuit {
//                 header_bytes: canonicalized_header,
//                 body_bytes: canonicalized_body,
//                 public_key,
//                 signature,
//             };

//             let instances = circuit.instances();
//             let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
//             assert!(prover.verify().is_err());
//         });
//     }
// }

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

    #[ignore]
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
