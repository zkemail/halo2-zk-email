mod macros;
pub mod regex_sha2;
pub mod regex_sha2_base64;
use crate::regex_sha2::RegexSha2Config;
use halo2_base::halo2_proofs::circuit::{Region, SimpleFloorPlanner};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    utils::PrimeField,
    Context,
};
use halo2_dynamic_sha256::Field;
use halo2_regex::{AssignedSubstrsResult, RegexDef, SubstrDef};
use halo2_rsa::{
    AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPublicKey,
    RSASignature,
};
pub use macros::*;
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
        header_regex_def: RegexDef,
        body_hash_substr_def: SubstrDef,
        header_substr_defs: Vec<SubstrDef>,
        body_max_byte_size: usize,
        body_regex_def: RegexDef,
        body_substr_defs: Vec<SubstrDef>,
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
    ) -> Result<(AssignedSubstrsResult<'a, F>, AssignedSubstrsResult<'a, F>), Error> {
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

        // 4. Check that the encoded hash value is equal to the value in the email header.
        let hash_body_substr = &header_result.substrs.substrs_bytes[0];
        let body_encoded_hash = body_result.encoded_hash;
        debug_assert_eq!(hash_body_substr.len(), body_encoded_hash.len());
        for (substr_byte, encoded_byte) in
            hash_body_substr.iter().zip(body_encoded_hash.into_iter())
        {
            ctx.region
                .constrain_equal(substr_byte.cell(), encoded_byte.cell())?;
        }
        gate.assert_is_const(
            ctx,
            &header_result.substrs.substrs_length[0],
            F::from(44),
        );
        Ok((header_result.substrs, body_result.substrs))
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
    use cfdkim::{SignerBuilder, canonicalize_signed_email};
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
    use sha2::{self, Digest, Sha256};
    use std::collections::HashSet;
    use num_bigint::BigUint;
    // use mail_auth::{common::{crypto::{RsaKey},headers::HeaderWriter},dkim::DkimSigner};
    // use mail_parser::{decoders::base64::base64_decode,  Message, Addr, HeaderValue};
    use rsa::{pkcs1::DecodeRsaPrivateKey, PublicKeyParts, RsaPrivateKey};
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use hex;

    impl_email_verify_circuit!(
        Test1EmailVerifyConfig,
        Test1EmailVerifyCircuit,
        1,
        1024,
        "./test_data/regex_header_test1.txt",
        "./test_data/substr_header_test1_1.txt",
        vec!["./test_data/substr_header_test1_2.txt"],
        //SubstrDef::new(44, 0, 1024 - 1, HashSet::from([(39, 3), (3, 3)])),
        //vec![SubstrDef::new(20, 0, 1024 - 1, HashSet::from([(16, 1), (1, 1), (1,12), (12,15), (15,15)]))],
        1024,
        "./test_data/regex_body_test1.txt",
        vec!["./test_data/substr_body_test1_1.txt"],
        // vec![SubstrDef::new(15, 0, 1024 - 1, HashSet::from([(25, 1), (1, 1)]))],
        2048,
        13
    );

    #[test]
    fn test_generated_email1() {
        // let private_key = include_str!("../test_data/test_rsa_key.pem");
        // let pk_rsa = RsaKey::<mail_auth::common::crypto::Sha256>::from_rsa_pem(private_key).unwrap();
        let mut rng = thread_rng();
        let _private_key = RsaPrivateKey::new(&mut rng, Test1EmailVerifyCircuit::<Fr>::BITS_LEN).expect("failed to generate a key");
        let public_key = rsa::RsaPublicKey::from(&_private_key);
        let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
        // let body = "email was meant for @zkemailverify.";
        let message = concat!(
            "From: alice@zkemail.com\r\n",
            "\r\n",
            "email was meant for @zkemailverify.",
        ).as_bytes();
        let email = parse_mail(message).unwrap();
// "(from:(a-z)+|to:(a-z)+|subject:(a-z)+|^(from|to...)(a-z)+)+ "
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let signer = SignerBuilder::new().with_signed_headers(&["From"]).unwrap().with_private_key(private_key).with_selector("default").with_signing_domain("zkemail.com").with_logger(&logger).with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed).with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed).build().unwrap();
        let signature = signer.sign(&email).unwrap();
        println!("signature {}",signature);
        let new_msg = vec![signature.as_bytes(),b"\r\n",message].concat();
        let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&new_msg).unwrap();

        // let signature_rsa = DkimSigner::from_key(pk_rsa)
        // .domain("zkemail.com")
        // .selector("default")
        // .headers(["From"])
        // .header_canonicalization(Canonicalization::Relaxed)
        // .body_canonicalization(Canonicalization::Relaxed)
        // .sign(&message)
        // .unwrap();
        // println!("signature {}",signature_rsa.to_header());
        // println!("signature {}",String::from_utf8(signature_rsa.signature().to_vec()).unwrap());
        // let mut signed_msg = Vec::with_capacity(message.len()+100);
        // signature_rsa.write_header(&mut signed_msg);
        // signed_msg.extend_from_slice(&message);
        // let auth_msg = AuthenticatedMessage::parse(&signed_msg).unwrap();
        // // println!("auth_msg:\n{}",String::from_utf8(auth_msg.raw_headers().to_vec()).unwrap());
        // let canonicalized_header = auth_msg.get_canonicalized_header().unwrap();
        // let canonicalization = Canonicalization::Relaxed;
        // let body_canonicalization = canonicalization.canonical_body(body.as_bytes(), u64::MAX);
        // let mut canonicalized_body = Vec::new();
        // body_canonicalization.write(&mut canonicalized_body);
        println!("canonicalized_header:\n{}",String::from_utf8(canonicalized_header.clone()).unwrap());
        println!("canonicalized_body:\n{}",String::from_utf8(canonicalized_body.clone()).unwrap());
        
        let e = RSAPubE::Fix(BigUint::from(Test1EmailVerifyCircuit::<Fr>::DEFAULT_E));
        // let private_key = rsa::RsaPrivateKey::read_pkcs1_pem_file("./test_data/test_rsa_key.pem").unwrap();
        let n_big =
                BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
        let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
        let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
        let hash = Sha256::digest(&canonicalized_body);
        let circuit = Test1EmailVerifyCircuit {
            header_bytes: canonicalized_header,
            body_bytes: canonicalized_body,
            public_key,
            signature,
        };

        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        BASE64_STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let mut substr_bytes_fes = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let header_substr = b"alice@zkemail.com";
        for idx in 0..20 {
            if idx < header_substr.len() {
                substr_bytes_fes.push(Fr::from(header_substr[idx] as u64));
            } else {
                substr_bytes_fes.push(Fr::from(0));
            }
        }
        let body_substr = b"zkemailverify";
        for idx in 0..15 {
            if idx < body_substr.len() {
                substr_bytes_fes.push(Fr::from(body_substr[idx] as u64));
            } else {
                substr_bytes_fes.push(Fr::from(0));
            }
        }
        let substr_lens_fes = vec![Fr::from(44),Fr::from(17),Fr::from(13)];
        let prover = MockProver::run(
            13,
            &circuit,
            vec![substr_bytes_fes,substr_lens_fes],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    impl_email_verify_circuit!(
        Test2EmailVerifyConfig,
        Test2EmailVerifyCircuit,
        1,
        1024,
        "./test_data/regex_header_test2.txt",
        "./test_data/substr_header_test2_1.txt",
        vec!["./test_data/substr_header_test2_2.txt","./test_data/substr_header_test2_3.txt","./test_data/substr_header_test2_4.txt"],// SubstrDef::new(44, 0, 1024 - 1, HashSet::from([(9, 10), (10, 10)])),
        //vec![SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(38, 39), (39, 39), (39,40), (40,41), (41,41)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(24, 25), (25, 25), (25,29), (29,31), (31,31)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(30, 1), (1, 1)]))],
        1024,
        "./test_data/regex_body_test2.txt",
        vec!["./test_data/substr_body_test2_1.txt","./test_data/substr_body_test2_2.txt"],
        // vec![SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(31, 1), (1, 1)])),SubstrDef::new(40, 0, 1024 - 1, HashSet::from([(13, 15), (15, 15), (4,8), (8,10), (10,12),(12,13)]))],
        2048,
        13
    );

    #[test]
    fn test_generated_email2() {
        // let private_key = include_str!("../test_data/test_rsa_key.pem");
        // let pk_rsa = RsaKey::<mail_auth::common::crypto::Sha256>::from_rsa_pem(private_key).unwrap();
        let mut rng = thread_rng();
        let _private_key = RsaPrivateKey::new(&mut rng, Test1EmailVerifyCircuit::<Fr>::BITS_LEN).expect("failed to generate a key");
        let public_key = rsa::RsaPublicKey::from(&_private_key);
        let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
        // let body = "email was meant for @zkemailverify.";
        let message = concat!(
                    "From: alice@zkemail.com\r\n",
                    "To: bob@example.com\r\n",
                    "Subject: Hello.\r\n",
                    "\r\n",
                    "email was meant for @zkemailverify and halo.",
                ).as_bytes();
        let email = parse_mail(message).unwrap();
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let signer = SignerBuilder::new().with_signed_headers(&["Subject","To","From"]).unwrap().with_private_key(private_key).with_selector("default").with_signing_domain("zkemail.com").with_logger(&logger).with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed).with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed).build().unwrap();
        let signature = signer.sign(&email).unwrap();
        println!("signature {}",signature);
        let new_msg = vec![signature.as_bytes(),b"\r\n",message].concat();
        let (canonicalized_header, canonicalized_body, signature_bytes) = canonicalize_signed_email(&new_msg).unwrap();

        println!("canonicalized_header:\n{}",String::from_utf8(canonicalized_header.clone()).unwrap());
        println!("canonicalized_body:\n{}",String::from_utf8(canonicalized_body.clone()).unwrap());
        
        let e = RSAPubE::Fix(BigUint::from(Test2EmailVerifyCircuit::<Fr>::DEFAULT_E));
        // let private_key = rsa::RsaPrivateKey::read_pkcs1_pem_file("./test_data/test_rsa_key.pem").unwrap();
        let n_big =
                BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
        let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
        let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
        let hash = Sha256::digest(&canonicalized_body);
        let circuit = Test2EmailVerifyCircuit {
            header_bytes: canonicalized_header,
            body_bytes: canonicalized_body,
            public_key,
            signature,
        };

        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        BASE64_STANDARD
            .encode_slice(&hash, &mut expected_output)
            .unwrap();
        let mut substr_bytes_fes = expected_output
            .iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<Fr>>();
        let header_substrs = vec!["alice@zkemail.com".as_bytes(),"bob@example.com".as_bytes(),"Hello.".as_bytes()];
        for header_substr in header_substrs.into_iter() {
            for idx in 0..40 {
                if idx < header_substr.len() {
                    substr_bytes_fes.push(Fr::from(header_substr[idx] as u64));
                } else {
                    substr_bytes_fes.push(Fr::from(0));
                }
            }
        }
        let body_substrs = vec!["zkemailverify".as_bytes(),"and halo".as_bytes()];
        for body_substr in body_substrs.into_iter() {
            for idx in 0..40 {
                if idx < body_substr.len() {
                    substr_bytes_fes.push(Fr::from(body_substr[idx] as u64));
                } else {
                    substr_bytes_fes.push(Fr::from(0));
                }
            }
        }
        let substr_lens_fes = vec![Fr::from(44),Fr::from(17),Fr::from(15),Fr::from(6),Fr::from(13),Fr::from(8)];
        let prover = MockProver::run(
            13,
            &circuit,
            vec![substr_bytes_fes,substr_lens_fes],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }



    // #[test]
    // fn test_generated_email2() {
    //     let private_key = include_str!("../test_data/test_rsa_key.pem");
    //     let pk_rsa = RsaKey::<mail_auth::common::crypto::Sha256>::from_rsa_pem(private_key).unwrap();
    //     let body = "email was meant for @zkemailverify and halo2.";
    //     let message = concat!(
    //         "From: alice@zkemail.com\r\n",
    //         "To: bob@example.com\r\n",
    //         "Subject: Hell.\r\n",
    //         "\r\n",
    //         "email was meant for @zkemailverify and halo2.",
    //     ).as_bytes();
    //     let signature_rsa = DkimSigner::from_key(pk_rsa)
    //     .domain("zkemail.com")
    //     .selector("default")
    //     .headers(["Subject","To","From"])
    //     .header_canonicalization(Canonicalization::Relaxed)
    //     .body_canonicalization(Canonicalization::Relaxed)
    //     .sign(&message)
    //     .unwrap();
    //     println!("signature {}",signature_rsa.to_header());
    //     // println!("signature {}",String::from_utf8(signature_rsa.signature().to_vec()).unwrap());
    //     let mut signed_msg = Vec::with_capacity(message.len()+100);
    //     signature_rsa.write_header(&mut signed_msg);
    //     signed_msg.extend_from_slice(&message);
    //     let auth_msg = AuthenticatedMessage::parse(&signed_msg).unwrap();
    //     // println!("auth_msg:\n{}",String::from_utf8(auth_msg.raw_headers().to_vec()).unwrap());
    //     let canonicalized_header = auth_msg.get_canonicalized_header().unwrap();
    //     let canonicalization = Canonicalization::Relaxed;
    //     let body_canonicalization = canonicalization.canonical_body(body.as_bytes(), u64::MAX);
    //     let mut canonicalized_body = Vec::new();
    //     body_canonicalization.write(&mut canonicalized_body);
    //     println!("canonicalized_header:\n{}",String::from_utf8(canonicalized_header.clone()).unwrap());
    //     println!("canonicalized_header:\n{:?}",canonicalized_header.clone());
    //     println!("canonicalized_body:\n{}",String::from_utf8(canonicalized_body.clone()).unwrap());
        
    //     let e = RSAPubE::Fix(BigUint::from(Test1EmailVerifyCircuit::<Fr>::DEFAULT_E));
    //     let private_key = rsa::RsaPrivateKey::read_pkcs1_pem_file("./test_data/test_rsa_key.pem").unwrap();
    //     let public_key = rsa::RsaPublicKey::from(&private_key);
    //     let n_big =
    //             BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    //     let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
    //     let signature_base64 = signature_rsa.signature();
    //     let signature_bytes = base64_decode(signature_base64).unwrap();
    //     let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    //     let hash = Sha256::digest(&canonicalized_body);
    //     let circuit = Test2EmailVerifyCircuit {
    //         header_bytes: canonicalized_header,
    //         body_bytes: canonicalized_body,
    //         public_key,
    //         signature,
    //     };

    //     let mut expected_output = Vec::new();
    //     expected_output.resize(44, 0);
    //     BASE64_STANDARD
    //         .encode_slice(&hash, &mut expected_output)
    //         .unwrap();
    //     let mut substr_bytes_fes = expected_output
    //         .iter()
    //         .map(|byte| Fr::from(*byte as u64))
    //         .collect::<Vec<Fr>>();
    //     let header_substrs = vec!["alice@zkemail.com".as_bytes(),"bob@example.com".as_bytes(),"Hello.".as_bytes()];
    //     for header_substr in header_substrs.into_iter() {
    //         for idx in 0..40 {
    //             if idx < header_substr.len() {
    //                 substr_bytes_fes.push(Fr::from(header_substr[idx] as u64));
    //             } else {
    //                 substr_bytes_fes.push(Fr::from(0));
    //             }
    //         }
    //     }
        
    //     let body_substrs = vec!["zkemailverify".as_bytes(),"and halo2".as_bytes()];
    //     for body_substr in body_substrs.into_iter() {
    //         for idx in 0..40 {
    //             if idx < body_substr.len() {
    //                 substr_bytes_fes.push(Fr::from(body_substr[idx] as u64));
    //             } else {
    //                 substr_bytes_fes.push(Fr::from(0));
    //             }
    //         }
    //     }
    //     let substr_lens_fes = vec![Fr::from(44),Fr::from(17),Fr::from(15),Fr::from(6),Fr::from(13),Fr::from(9)];
    //     let prover = MockProver::run(
    //         13,
    //         &circuit,
    //         vec![vec![],vec![]],
    //     )
    //     .unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }
}
