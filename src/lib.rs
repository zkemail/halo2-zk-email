mod macros;
mod recursion;
pub mod regex_sha2;
pub mod regex_sha2_base64;
use crate::regex_sha2::RegexSha2Config;
use halo2_base::halo2_proofs::circuit::{AssignedCell, Region, SimpleFloorPlanner};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
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
pub use macros::*;
pub use recursion::*;
use regex_sha2_base64::RegexSha2Base64Config;

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
// macro_rules!  {
//     () => {

//     };
// }

// #[derive(Debug, Clone)]
// pub struct EmailVerifyCircuit<F: Field> {
//     max_byte_size: usize,
//     num_sha2_compression_per_column: usize,
//     range_config: RangeConfig<F>,
//     header_state_lookup: HashMap<(u8, u64), u64>,
//     header_first_state: u64,
//     header_accepted_state_vals: Vec<u64>,
//     header_substr_defs: Vec<SubstrDef>,
//     body_state_lookup: HashMap<(u8, u64), u64>,
//     body_first_state: u64,
//     body_accepted_state_vals: Vec<u64>,
//     body_substr_defs: Vec<SubstrDef>,
//     public_key_bits: usize,
// }

// impl<F: Field> Circuit<F> for EmailVerifyCircuit<F> {
//     type Config = EmailVerifyConfig<F>;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         Self::Config::configure()
//     }
// }

// impl<F: Field> EmailVerifyCircuit<F> {
//     const HEADER_REGEX_FILEPATH: &'static str = "./test_regexes/email_header"
// }

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

    impl_email_verify_circuit!(
        Test1EmailVerifyConfig,
        Test1EmailVerifyCircuit,
        1,
        1024,
        "./test_data/regex_header_test1.txt",
        "./test_data/substr_header_test1_1.txt",
        vec!["./test_data/substr_header_test1_2.txt"],
        1024,
        "./test_data/regex_body_test1.txt",
        vec!["./test_data/substr_body_test1_1.txt"],
        2048,
        60,
        4,
        13
    );

    #[test]
    fn test_generated_email1() {
        // let private_key = include_str!("../test_data/test_rsa_key.pem");
        // let pk_rsa = RsaKey::<mail_auth::common::crypto::Sha256>::from_rsa_pem(private_key).unwrap();
        let mut rng = thread_rng();
        let _private_key = RsaPrivateKey::new(&mut rng, Test1EmailVerifyCircuit::<Fr>::BITS_LEN)
            .expect("failed to generate a key");
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

        let e = RSAPubE::Fix(BigUint::from(Test1EmailVerifyCircuit::<Fr>::DEFAULT_E));
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
        let circuit = Test1EmailVerifyCircuit {
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

    impl_email_verify_circuit!(
        Test2EmailVerifyConfig,
        Test2EmailVerifyCircuit,
        1,
        1024,
        "./test_data/regex_header_test2.txt",
        "./test_data/substr_header_test2_1.txt",
        vec![
            "./test_data/substr_header_test2_2.txt",
            "./test_data/substr_header_test2_3.txt",
            "./test_data/substr_header_test2_4.txt"
        ], // SubstrDef::new(44, 0, 1024 - 1, HashSet::from([(9, 10), (10, 10)])),
        //vec![SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(38, 39), (39, 39), (39,40), (40,41), (41,41)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(24, 25), (25, 25), (25,29), (29,31), (31,31)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(30, 1), (1, 1)]))],
        1024,
        "./test_data/regex_body_test2.txt",
        vec![
            "./test_data/substr_body_test2_1.txt",
            "./test_data/substr_body_test2_2.txt"
        ],
        // vec![SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(31, 1), (1, 1)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(13, 15), (15, 15), (4,8), (8,10), (10,12),(12,13)]))],
        2048,
        60,
        4,
        13
    );

    #[test]
    fn test_generated_email2() {
        let mut rng = thread_rng();
        let _private_key = RsaPrivateKey::new(&mut rng, Test1EmailVerifyCircuit::<Fr>::BITS_LEN)
            .expect("failed to generate a key");
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

        let e = RSAPubE::Fix(BigUint::from(Test2EmailVerifyCircuit::<Fr>::DEFAULT_E));
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
        let circuit = Test2EmailVerifyCircuit {
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
