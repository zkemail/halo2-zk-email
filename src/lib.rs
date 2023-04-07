#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
#[cfg(not(target_arch = "wasm32"))]
pub mod recursion_and_evm;

pub mod regex_sha2;
pub mod regex_sha2_base64;
use crate::regex_sha2::RegexSha2Config;
use halo2_base::halo2_proofs::circuit::{AssignedCell, Cell, Region, SimpleFloorPlanner};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    utils::PrimeField,
    Context,
};
use halo2_base::{AssignedValue, QuantumCell};
use halo2_dynamic_sha256::Field;
use halo2_regex::{
    defs::{AllstrRegexDef, SubstrRegexDef},
    AssignedRegexResult,
};
use halo2_rsa::{
    AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPublicKey,
    RSASignature,
};
use regex_sha2_base64::RegexSha2Base64Config;
use serde_json;
use snark_verifier_sdk::CircuitExt;
use std::env::set_var;
use std::fs::File;

#[derive(Debug, Clone)]
pub struct EmailVerifyConfig<F: Field> {
    header_processer: RegexSha2Config<F>,
    body_processer: RegexSha2Base64Config<F>,
    rsa_config: RSAConfig<F>,
}

impl<F: Field> EmailVerifyConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        header_max_byte_size: usize,
        header_regex_def: AllstrRegexDef,
        body_hash_substr_def: SubstrRegexDef,
        header_substr_defs: Vec<SubstrRegexDef>,
        body_max_byte_size: usize,
        body_regex_def: AllstrRegexDef,
        body_substr_defs: Vec<SubstrRegexDef>,
        public_key_bits: usize,
    ) -> Self {
        let header_substr_defs = [vec![body_hash_substr_def], header_substr_defs].concat();
        let header_processer = RegexSha2Config::configure(
            meta,
            header_max_byte_size,
            num_sha2_compression_per_column,
            range_config.clone(),
            header_regex_def,
            header_substr_defs,
        );
        let body_processer = RegexSha2Base64Config::configure(
            meta,
            body_max_byte_size,
            num_sha2_compression_per_column,
            range_config.clone(),
            body_regex_def,
            body_substr_defs,
        );
        let biguint_config = halo2_rsa::BigUintConfig::construct(range_config, 64);
        let rsa_config = RSAConfig::construct(biguint_config, public_key_bits, 5);
        Self {
            header_processer,
            body_processer,
            rsa_config,
        }
    }

    pub fn assign_public_key<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<'v, F>, Error> {
        self.rsa_config.assign_public_key(ctx, public_key)
    }

    pub fn assign_signature<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<'v, F>, Error> {
        self.rsa_config.assign_signature(ctx, signature)
    }

    pub fn verify_email<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        header_bytes: &[u8],
        body_bytes: &[u8],
        public_key: &AssignedRSAPublicKey<'v, F>,
        signature: &AssignedRSASignature<'v, F>,
    ) -> Result<
        (
            Vec<AssignedCell<F, F>>,
            AssignedRegexResult<'a, F>,
            AssignedRegexResult<'a, F>,
        ),
        Error,
    > {
        let gate = self.gate();

        // 1. Extract sub strings in the body and compute the base64 encoded hash of the body.
        let body_result = self.body_processer.match_hash_and_base64(ctx, body_bytes)?;

        // 2. Extract sub strings in the header, which includes the body hash, and compute the raw hash of the header.
        let header_result = self.header_processer.match_and_hash(ctx, header_bytes)?;

        // 3. Verify the rsa signature.
        let mut hashed_bytes = header_result.hash_bytes;
        hashed_bytes.reverse();
        let bytes_bits = hashed_bytes.len() * 8;
        let limb_bits = self.rsa_config.biguint_config().limb_bits;
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];
        let bases = (0..limb_bytes)
            .map(|i| F::from((1u64 << (8 * i)) as u64))
            .map(QuantumCell::Constant)
            .collect::<Vec<QuantumCell<F>>>();
        for i in 0..(bytes_bits / limb_bits) {
            let left = hashed_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                .iter()
                .map(QuantumCell::Existing)
                .collect::<Vec<QuantumCell<F>>>();
            let sum = gate.inner_product(ctx, left, bases.clone());
            hashed_u64s.push(sum);
        }
        let is_sign_valid =
            self.rsa_config
                .verify_pkcs1v15_signature(ctx, public_key, &hashed_u64s, signature)?;
        gate.assert_is_const(ctx, &is_sign_valid, F::one());

        // [IMPORTANT] Here, we don't verify that the encoded hash value is equal to the value in the email header.
        // To constraint their equivalences, you should put these values in the instance column and specify the same hash bytes.

        // 4. Check that the encoded hash value is equal to the value in the email header.
        // let hash_body_substr = &header_result.regex.substrs_bytes[0];
        // let body_encoded_hash = body_result.encoded_hash;
        // debug_assert_eq!(hash_body_substr.len(), body_encoded_hash.len());
        // for (substr_byte, encoded_byte) in
        //     hash_body_substr.iter().zip(body_encoded_hash.into_iter())
        // {
        //     ctx.region
        //         .constrain_equal(substr_byte.cell(), encoded_byte.cell())?;
        // }
        // gate.assert_is_const(ctx, &header_result.substrs.substrs_length[0], F::from(44));
        Ok((
            body_result.encoded_hash,
            header_result.regex,
            body_result.regex,
        ))
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.header_processer.load(layouter)?;
        self.body_processer.load(layouter)?;
        // self.rsa_config.range().load_lookup_table(layouter)?;
        Ok(())
    }

    pub fn finalize(&self, ctx: &mut Context<F>) {
        self.header_processer.finalize(ctx);
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        self.header_processer.new_context(region)
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.header_processer.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.header_processer.gate()
    }
}

pub const EMAIL_VERIFY_CONFIG_ENV: &'static str = "EMAIL_VERIFY_CONFIG";
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DefaultEmailVerifyConfigParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub header_regex_filepath: String,
    pub body_regex_filepath: String,
    pub header_substr_filepathes: Vec<String>,
    pub body_hash_substr_filepath: String,
    pub body_substr_filepathes: Vec<String>,
    pub num_sha2_compression_per_column: usize,
    pub header_max_byte_size: usize,
    pub body_max_byte_size: usize,
    pub public_key_bits: usize,
}

#[derive(Debug, Clone)]
pub struct DefaultEmailVerifyConfig<F: Field> {
    inner: EmailVerifyConfig<F>,
    encoded_bodyhash_instance: Column<Instance>,
    masked_str_instance: Column<Instance>,
    substr_ids_instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct DefaultEmailVerifyCircuit<F: Field> {
    pub header_bytes: Vec<u8>,
    pub body_bytes: Vec<u8>,
    pub public_key: RSAPublicKey<F>,
    pub signature: RSASignature<F>,
    pub bodyhash: (usize, String),
    pub header_substrings: Vec<(usize, String)>,
    pub body_substrings: Vec<(usize, String)>,
}

impl<F: Field> Circuit<F> for DefaultEmailVerifyCircuit<F> {
    type Config = DefaultEmailVerifyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            header_bytes: vec![],
            body_bytes: vec![],
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
            bodyhash: (0, "".to_string()),
            header_substrings: vec![],
            body_substrings: vec![],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = Self::read_config_params();
        let range_config = RangeConfig::configure(
            meta,
            Vertical,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            0,
            params.degree as usize,
        );
        let header_regex_def = AllstrRegexDef::read_from_text(&params.header_regex_filepath);
        let body_regex_def = AllstrRegexDef::read_from_text(&params.body_regex_filepath);
        let header_substr_defs = params
            .header_substr_filepathes
            .into_iter()
            .map(|path| SubstrRegexDef::read_from_text(&path))
            .collect::<Vec<SubstrRegexDef>>();
        let body_hash_substr_def =
            SubstrRegexDef::read_from_text(&params.body_hash_substr_filepath);
        let body_substr_defs = params
            .body_substr_filepathes
            .into_iter()
            .map(|path| SubstrRegexDef::read_from_text(&path))
            .collect::<Vec<SubstrRegexDef>>();
        let inner = EmailVerifyConfig::configure(
            meta,
            params.num_sha2_compression_per_column,
            range_config,
            params.header_max_byte_size,
            header_regex_def,
            body_hash_substr_def,
            header_substr_defs,
            params.body_max_byte_size,
            body_regex_def,
            body_substr_defs,
            params.public_key_bits,
        );
        let encoded_bodyhash_instance = meta.instance_column();
        meta.enable_equality(encoded_bodyhash_instance);
        let masked_str_instance = meta.instance_column();
        meta.enable_equality(masked_str_instance);
        let substr_ids_instance = meta.instance_column();
        meta.enable_equality(substr_ids_instance);
        DefaultEmailVerifyConfig {
            inner,
            encoded_bodyhash_instance,
            masked_str_instance,
            substr_ids_instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.inner.load(&mut layouter)?;
        config.inner.range().load_lookup_table(&mut layouter)?;
        let mut first_pass = SKIP_FIRST_PASS;
        let mut encoded_bodyhash_cell = vec![];
        let mut masked_str_cell = vec![];
        let mut substr_id_cell = vec![];
        layouter.assign_region(
            || "zkemail",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = &mut config.inner.new_context(region);
                let assigned_public_key = config
                    .inner
                    .assign_public_key(ctx, self.public_key.clone())?;
                let assigned_signature =
                    config.inner.assign_signature(ctx, self.signature.clone())?;
                let (encoded_bodyhash, header_regex, body_regex) = config.inner.verify_email(
                    ctx,
                    &self.header_bytes,
                    &self.body_bytes,
                    &assigned_public_key,
                    &assigned_signature,
                )?;
                config.inner.finalize(ctx);
                encoded_bodyhash_cell.append(
                    &mut encoded_bodyhash
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                masked_str_cell.append(
                    &mut header_regex
                        .masked_characters
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                masked_str_cell.append(
                    &mut body_regex
                        .masked_characters
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                substr_id_cell.append(
                    &mut header_regex
                        .all_substr_ids
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                substr_id_cell.append(
                    &mut body_regex
                        .all_substr_ids
                        .into_iter()
                        .map(|v| v.cell())
                        .collect::<Vec<Cell>>(),
                );
                Ok(())
            },
        )?;
        for (idx, cell) in encoded_bodyhash_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.encoded_bodyhash_instance, idx)?;
        }
        for (idx, cell) in masked_str_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.masked_str_instance, idx)?;
        }
        for (idx, cell) in substr_id_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.substr_ids_instance, idx)?;
        }
        Ok(())
    }
}

impl<F: Field> CircuitExt<F> for DefaultEmailVerifyCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        let params = Self::read_config_params();
        let max_len = params.header_max_byte_size + params.body_max_byte_size;
        vec![44, max_len, max_len]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let params = Self::read_config_params();
        let max_len = params.header_max_byte_size + params.body_max_byte_size;
        let hash_fs = self
            .bodyhash
            .1
            .as_bytes()
            .into_iter()
            .map(|byte| F::from(*byte as u64))
            .collect::<Vec<F>>();
        let header_substrings =
            vec![&[self.bodyhash.clone()][..], &self.header_substrings].concat();
        let mut expected_masked_chars = vec![F::from(0); max_len];
        let mut expected_substr_ids = vec![F::from(0); max_len];
        for (substr_idx, (start, chars)) in header_substrings.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = F::from(*char as u64);
                expected_substr_ids[start + idx] = F::from(substr_idx as u64 + 1);
            }
        }
        for (substr_idx, (start, chars)) in self.body_substrings.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[params.header_max_byte_size + start + idx] =
                    F::from(*char as u64);
                expected_substr_ids[params.header_max_byte_size + start + idx] =
                    F::from(substr_idx as u64 + 1);
            }
        }
        vec![hash_fs, expected_masked_chars, expected_substr_ids]
    }
}

impl<F: Field> DefaultEmailVerifyCircuit<F> {
    pub const DEFAULT_E: u128 = 65537;

    pub fn read_config_params() -> DefaultEmailVerifyConfigParams {
        let path = std::env::var(EMAIL_VERIFY_CONFIG_ENV)
            .expect("You should set the configure file path to EMAIL_VERIFY_CONFIG.");
        let params: DefaultEmailVerifyConfigParams = serde_json::from_reader(
            File::open(path.as_str()).expect(&format!("{} does not exist.", path)),
        )
        .expect("File is found but invalid.");
        params
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cfdkim::{canonicalize_signed_email, SignerBuilder};
    use halo2_base::halo2_proofs::{
        circuit::{floor_planner::V1, Cell, SimpleFloorPlanner, Value},
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit, Column, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use halo2_rsa::RSAPubE;
    use mailparse::parse_mail;
    use rand::thread_rng;
    // use mail_auth::{dkim::{self, Canonicalization}, common::{headers::Writable, verify::VerifySignature}, AuthenticatedMessage, Resolver, DkimResult};
    use num_bigint::BigUint;
    use sha2::{self, Digest, Sha256};
    use std::collections::HashSet;
    // use mail_auth::{common::{crypto::{RsaKey},headers::HeaderWriter},dkim::DkimSigner};
    // use mail_parser::{decoders::base64::base64_decode,  Message, Addr, HeaderValue};
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use fancy_regex::Regex;
    use hex;
    use rsa::{pkcs1::DecodeRsaPrivateKey, PublicKeyParts, RsaPrivateKey};
    use snark_verifier_sdk::CircuitExt;

    // impl_email_verify_circuit!(
    //     Test1EmailVerifyConfig,
    //     Test1EmailVerifyCircuit,
    //     1,
    //     1024,
    //     "./test_data/regex_header_test1.txt",
    //     "./test_data/substr_header_test1_1.txt",
    //     vec!["./test_data/substr_header_test1_2.txt"],
    //     1024,
    //     "./test_data/regex_body_test1.txt",
    //     vec!["./test_data/substr_body_test1_1.txt"],
    //     2048,
    //     60,
    //     4,
    //     13
    // );

    #[test]
    fn test_generated_email1() {
        // let private_key = include_str!("../test_data/test_rsa_key.pem");
        // let pk_rsa = RsaKey::<mail_auth::common::crypto::Sha256>::from_rsa_pem(private_key).unwrap();
        set_var(
            EMAIL_VERIFY_CONFIG_ENV,
            "./configs/test1_email_verify.config",
        );
        let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
        let mut rng = thread_rng();
        let _private_key =
            RsaPrivateKey::new(&mut rng, params.public_key_bits).expect("failed to generate a key");
        let public_key = rsa::RsaPublicKey::from(&_private_key);
        let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
        // let body = "email was meant for @zkemailverify.";
        let message = concat!(
            "From: alice@zkemail.com\r\n",
            "\r\n",
            "email was meant for @zkemailverify.",
        )
        .as_bytes();
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
        println!("signature {}", signature);
        let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
        let (canonicalized_header, canonicalized_body, signature_bytes) =
            canonicalize_signed_email(&new_msg).unwrap();

        println!(
            "canonicalized_header:\n{}",
            String::from_utf8(canonicalized_header.clone()).unwrap()
        );
        println!(
            "canonicalized_body:\n{}",
            String::from_utf8(canonicalized_body.clone()).unwrap()
        );

        let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
        // let private_key = rsa::RsaPrivateKey::read_pkcs1_pem_file("./test_data/test_rsa_key.pem").unwrap();
        let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
        let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
        let signature =
            RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
        let hash = Sha256::digest(&canonicalized_body);
        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        BASE64_STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let bodyhash_regex = Regex::new(r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)").unwrap();
        let canonicalized_header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
        let bodyhash_match = bodyhash_regex
            .find(&canonicalized_header_str)
            .unwrap()
            .unwrap();
        println!(
            "bodyhash {} {}",
            bodyhash_match.start(),
            bodyhash_match.as_str()
        );
        let bodyhash = (
            bodyhash_match.start(),
            String::from_utf8(expected_output).unwrap(),
        );
        let header_substr1_regex = Regex::new(r"(?<=from:)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|.)+(?=\r)").unwrap();
        let header_substr1_match = header_substr1_regex
            .find(&canonicalized_header_str)
            .unwrap()
            .unwrap();
        println!(
            "from {} {}",
            header_substr1_match.start(),
            header_substr1_match.as_str()
        );
        let body_substr1_regex = Regex::new(r"(?<=email was meant for @)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+(?=.)").unwrap();
        let canonicalized_body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
        let body_substr1_match = body_substr1_regex
            .find(&canonicalized_body_str)
            .unwrap()
            .unwrap();
        println!(
            "body {} {}",
            body_substr1_match.start(),
            body_substr1_match.as_str()
        );
        let header_substrings = vec![(
            header_substr1_match.start(),
            header_substr1_match.as_str().to_string(),
        )];
        let body_substrings = vec![(
            body_substr1_match.start(),
            body_substr1_match.as_str().to_string(),
        )];
        let circuit = DefaultEmailVerifyCircuit {
            header_bytes: canonicalized_header,
            body_bytes: canonicalized_body,
            public_key,
            signature,
            bodyhash,
            header_substrings,
            body_substrings,
        };
        let instances = circuit.instances();
        let prover = MockProver::run(13, &circuit, instances).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // impl_email_verify_circuit!(
    //     Test2EmailVerifyConfig,
    //     Test2EmailVerifyCircuit,
    //     1,
    //     1024,
    //     "./test_data/regex_header_test2.txt",
    //     "./test_data/substr_header_test2_1.txt",
    //     vec![
    //         "./test_data/substr_header_test2_2.txt",
    //         "./test_data/substr_header_test2_3.txt",
    //         "./test_data/substr_header_test2_4.txt"
    //     ], // SubstrDef::new(44, 0, 1024 - 1, HashSet::from([(9, 10), (10, 10)])),
    //     //vec![SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(38, 39), (39, 39), (39,40), (40,41), (41,41)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(24, 25), (25, 25), (25,29), (29,31), (31,31)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(30, 1), (1, 1)]))],
    //     1024,
    //     "./test_data/regex_body_test2.txt",
    //     vec![
    //         "./test_data/substr_body_test2_1.txt",
    //         "./test_data/substr_body_test2_2.txt"
    //     ],
    //     // vec![SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(31, 1), (1, 1)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(13, 15), (15, 15), (4,8), (8,10), (10,12),(12,13)]))],
    //     2048,
    //     60,
    //     4,
    //     13
    // );

    #[test]
    fn test_generated_email2() {
        set_var(
            EMAIL_VERIFY_CONFIG_ENV,
            "./configs/test2_email_verify.config",
        );
        let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
        let mut rng = thread_rng();
        let _private_key =
            RsaPrivateKey::new(&mut rng, params.public_key_bits).expect("failed to generate a key");
        let public_key = rsa::RsaPublicKey::from(&_private_key);
        let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
        let message = concat!(
            "From: alice@zkemail.com\r\n",
            "To: bob@example.com\r\n",
            "Subject: Hello.\r\n",
            "\r\n",
            "email was meant for @zkemailverify and halo.",
        )
        .as_bytes();
        let email = parse_mail(message).unwrap();
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let signer = SignerBuilder::new()
            .with_signed_headers(&["Subject", "To", "From"])
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
        let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
        let (canonicalized_header, canonicalized_body, signature_bytes) =
            canonicalize_signed_email(&new_msg).unwrap();

        println!(
            "canonicalized_header:\n{}",
            String::from_utf8(canonicalized_header.clone()).unwrap()
        );
        println!(
            "canonicalized_body:\n{}",
            String::from_utf8(canonicalized_body.clone()).unwrap()
        );

        let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
        let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
        let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
        let signature =
            RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
        let hash = Sha256::digest(&canonicalized_body);
        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        BASE64_STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();

        let bodyhash_regex = Regex::new(r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)").unwrap();
        let canonicalized_header_str = String::from_utf8(canonicalized_header.clone()).unwrap();
        let bodyhash_match = bodyhash_regex
            .find(&canonicalized_header_str)
            .unwrap()
            .unwrap();
        println!(
            "bodyhash {} {}",
            bodyhash_match.start(),
            bodyhash_match.as_str()
        );
        let bodyhash = (
            bodyhash_match.start(),
            String::from_utf8(expected_output).unwrap(),
        );
        let header_substr1_regex = Regex::new(r"(?<=from:)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|.)+(?=\r)").unwrap();
        let header_substr1_match = header_substr1_regex
            .find(&canonicalized_header_str)
            .unwrap()
            .unwrap();
        println!(
            "from {} {}",
            header_substr1_match.start(),
            header_substr1_match.as_str()
        );
        let header_substr2_regex = Regex::new(r"(?<=to:)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|.)+(?=\r)").unwrap();
        let header_substr2_match = header_substr2_regex
            .find(&canonicalized_header_str)
            .unwrap()
            .unwrap();
        println!(
            "to {} {}",
            header_substr2_match.start(),
            header_substr2_match.as_str()
        );
        let header_substr3_regex = Regex::new(r"(?<=subject:)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|.)+(?=\r)").unwrap();
        let header_substr3_match = header_substr3_regex
            .find(&canonicalized_header_str)
            .unwrap()
            .unwrap();
        println!(
            "subject {} {}",
            header_substr3_match.start(),
            header_substr3_match.as_str()
        );
        let canonicalized_body_str = String::from_utf8(canonicalized_body.clone()).unwrap();
        let body_substr1_regex = Regex::new(r"(?<=email was meant for @)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+").unwrap();
        let body_substr1_match = body_substr1_regex
            .find(&canonicalized_body_str)
            .unwrap()
            .unwrap();
        println!(
            "body1 {} {}",
            body_substr1_match.start(),
            body_substr1_match.as_str()
        );
        let body_substr2_regex =
            Regex::new(r"and (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+").unwrap();
        let body_substr2_match = body_substr2_regex
            .find(&canonicalized_body_str)
            .unwrap()
            .unwrap();
        println!(
            "body2 {} {}",
            body_substr2_match.start(),
            body_substr2_match.as_str()
        );
        let header_substrings = vec![
            (
                header_substr1_match.start(),
                header_substr1_match.as_str().to_string(),
            ),
            (
                header_substr2_match.start(),
                header_substr2_match.as_str().to_string(),
            ),
            (
                header_substr3_match.start(),
                header_substr3_match.as_str().to_string(),
            ),
        ];
        let body_substrings = vec![
            (
                body_substr1_match.start(),
                body_substr1_match.as_str().to_string(),
            ),
            (
                body_substr2_match.start(),
                body_substr2_match.as_str().to_string(),
            ),
        ];
        let circuit = DefaultEmailVerifyCircuit {
            header_bytes: canonicalized_header,
            body_bytes: canonicalized_body,
            public_key,
            signature,
            bodyhash,
            header_substrings,
            body_substrings,
        };

        let instances = circuit.instances();
        let prover = MockProver::run(13, &circuit, instances).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
