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
use halo2_rsa::{AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPublicKey, RSASignature};
pub use macros::*;
use mail_auth::common::verify::VerifySignature;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};
mod parse_email;
use parse_email::parse_external_eml;
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

    pub fn assign_public_key<'v>(&self, ctx: &mut Context<'v, F>, public_key: RSAPublicKey<F>) -> Result<AssignedRSAPublicKey<'v, F>, Error> {
        self.rsa_config.assign_public_key(ctx, public_key)
    }

    pub fn assign_signature<'v>(&self, ctx: &mut Context<'v, F>, signature: RSASignature<F>) -> Result<AssignedRSASignature<'v, F>, Error> {
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
        let is_sign_valid = self.rsa_config.verify_pkcs1v15_signature(ctx, public_key, &hashed_u64s, signature)?;
        gate.assert_is_const(ctx, &is_sign_valid, F::one());

        // 4. Check that the encoded hash value is equal to the value in the email header.
        let hash_body_substr = &header_result.substrs.substrs_bytes[0];
        let body_encoded_hash = body_result.encoded_hash;
        debug_assert_eq!(hash_body_substr.len(), body_encoded_hash.len());
        for (substr_byte, encoded_byte) in hash_body_substr.iter().zip(body_encoded_hash.into_iter()) {
            ctx.region.constrain_equal(substr_byte.cell(), encoded_byte.cell())?;
        }
        gate.assert_is_const(ctx, &header_result.substrs.substrs_length[0], F::from(32 * 4 / 3 + 4));
        Ok((header_result.substrs, body_result.substrs))
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.header_processer.load(layouter)?;
        self.body_processer.load(layouter)?;
        self.rsa_config.range().load_lookup_table(layouter)?;
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
    use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
    use halo2_base::halo2_proofs::{
        circuit::{floor_planner::V1, Cell, SimpleFloorPlanner, Value},
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit, Column, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use halo2_rsa::RSAPubE;
    use mail_auth::{
        common::{crypto::RsaKey, headers::HeaderWriter},
        dkim::DkimSigner,
    };
    use mail_auth::{
        common::{headers::Writable, verify::VerifySignature},
        dkim::{self, Canonicalization},
    };
    // use mail_parser::{decoders::base64::base64_decode, Addr, HeaderValue, Message};
    use num_bigint::BigUint;
    use rsa::{pkcs1::DecodeRsaPrivateKey, PublicKeyParts};
    use sha2::{self, Digest, Sha256};
    use std::collections::HashSet;

    impl_email_verify_circuit!(
        TestEmailVerifyConfig,
        TestEmailVerifyCircuit,
        5,
        1024,
        "./test_data/regex_bh.txt",
        SubstrDef::new(44, 0, 1024 - 1, HashSet::from([(23, 24), (24, 24)])),
        vec![SubstrDef::new(44, 0, 1024 - 1, HashSet::from([(23, 24), (24, 24)]))],
        6000,
        "./text_data/regex_body.txt",
        vec![SubstrDef::new(15, 0, 6000 - 1, HashSet::from([(29, 1), (1, 1)]))],
        2048,
        13
    );

    // Tokio on and test
    #[tokio::test]

    async fn test_dkim_verify_local_eml() {
        // Parse message
        let raw_email = std::fs::read_to_string("./test_email/testemail.eml").unwrap();
        let (header_bytes, body_bytes, public_key_bytes, signature_bytes) = parse_external_eml(&raw_email).await.unwrap();

        // Convert public_key_bytes to BigUint
        let public_key_n = BigUint::from_bytes_le(&public_key_bytes);
        let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_le(&signature_bytes)));

        let e = RSAPubE::Fix(BigUint::from(TestEmailVerifyCircuit::<Fr>::DEFAULT_E));
        // let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
        let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from_bytes_le(&public_key_bytes)), e);

        let hash = Sha256::digest(&body_bytes);
        println!("hash: {:?}", hash);
        println!("public_key: {:?}", public_key);
        println!("signature: {:?}", signature);
        let circuit = TestEmailVerifyCircuit {
            header_bytes,
            body_bytes,
            public_key,
            signature,
        };

        // let mut expected_output = Vec::new();
        // expected_output.resize(44, 0);
        // BASE64_STANDARD_NO_PAD.encode_slice(&hash, &mut expected_output).unwrap();
        // let mut substr_bytes_fes = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        // for byte in b"zkemailverify".into_iter() {
        //     substr_bytes_fes.push(Fr::from(*byte as u64));
        // }
        // let substr_lens_fes = vec![Fr::from(44), Fr::from(13)];
        // let prover = MockProver::run(13, &circuit, vec![substr_bytes_fes, substr_lens_fes]).unwrap();
        // println!("Next line fails: ");
        // assert_eq!(prover.verify(), Ok(()));

        // Make sure all signatures passed verification
    }

    #[test]
    fn test_simple_email_headers() {
        let private_key = include_str!("../test_data/test_rsa_key.pem");
        let pk_rsa = RsaKey::<mail_auth::common::crypto::Sha256>::from_rsa_pem(private_key).unwrap();
        let mut message = br#"From: Sora Suegami <suegamisora@gmail.com>
To: "zkemailverify@example.com" <zkemailverify@example.com>
Subject: Hello, zkemail!

this email was meant for @zkemailverify
"#
        .to_vec();
        let signature_rsa = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "To", "Subject"])
            .header_canonicalization(Canonicalization::Relaxed)
            .body_canonicalization(Canonicalization::Relaxed)
            .sign(&message)
            .unwrap();
        // println!("signature {}",signature_rsa.to_header());
        // println!("signature {}",String::from_utf8(signature_rsa.signature().to_vec()).unwrap());
        // let mut complete_msg = Vec::new();
        // signature_rsa.write_header(&mut complete_msg);
        // complete_msg.append(&mut message);
        // let header = signature_rsa.to_header();
        // println!("header {}",String::from_utf8(message).unwrap());
        // let message = Message::parse(&complete_msg).unwrap();
        // println!("message {:?}",message);
        // if let HeaderValue::Address(addr) = message.from() {
        //     println!("name {}, address {}",addr.name.as_ref().unwrap(),addr.address.as_ref().unwrap());
        // }
        // println!("to: {:?}",message.to());
        // println!("subject: {:?}",message.subject());
        // println!("header: {}",message.header_raw("DKIM-Signature").unwrap());
        // println!("body: {:?}",message.body_text(0).unwrap());
        let signature_header_str = signature_rsa.to_header();
        let canonicalization = Canonicalization::Relaxed;
        let canonicaled_header = canonicalization.canonical_headers(vec![
            (b"From", b"Sora Suegami <suegamisora@gmail.com>"),
            (b"To", b"\"zkemailverify@example.com\" <zkemailverify@example.com>"),
            (b"Subject", b"Hello, zkemail!"),
            (b"DKIM-Signature", &(signature_header_str.as_bytes())),
        ]);
        let canonicaled_body = canonicalization.canonical_body(b"this email was meant for @zkemailverify", u64::MAX);
        let mut header_bytes = Vec::new();
        canonicaled_header.write(&mut header_bytes);
        let mut body_bytes = Vec::new();
        canonicaled_body.write(&mut body_bytes);
        println!("canonicaled_header: {}", String::from_utf8(header_bytes.clone()).unwrap());
        println!("canonicaled_body {}", String::from_utf8(body_bytes.clone()).unwrap());

        // let hash_fs = expected_output
        //     .iter()
        //     .map(|byte| Fr::from(*byte as u64))
        //     .collect::<Vec<Fr>>();
        let e = RSAPubE::Fix(BigUint::from(TestEmailVerifyCircuit::<Fr>::DEFAULT_E));
        let private_key = rsa::RsaPrivateKey::read_pkcs1_pem_file("./test_data/test_rsa_key.pem").unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
        let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
        let signature_base64 = signature_rsa.signature();
        let signature_bytes = BASE64_STANDARD_NO_PAD.decode(signature_base64).unwrap();
        let signature = RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_le(&signature_bytes)));
        let hash = Sha256::digest(&body_bytes);
        let circuit = TestEmailVerifyCircuit {
            header_bytes,
            body_bytes,
            public_key,
            signature,
        };

        let mut expected_output = Vec::new();
        expected_output.resize(44, 0);
        BASE64_STANDARD_NO_PAD.encode_slice(&hash, &mut expected_output).unwrap();
        let mut substr_bytes_fes = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        for byte in b"zkemailverify".into_iter() {
            substr_bytes_fes.push(Fr::from(*byte as u64));
        }
        let substr_lens_fes = vec![Fr::from(44), Fr::from(13)];
        let prover = MockProver::run(13, &circuit, vec![substr_bytes_fes, substr_lens_fes]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // let header_bytes = include_str!("./test_data/test_header1.txt").as_bytes();
        // let body_bytes =  include_str!("./test_data/test_body1.txt").as_bytes();

        // let cirucit = TestEmailVerifyCircuit {
        //     header_bytes,
        //     body_bytes,
        //     public_key: RSAPublicKey<F>,
        //     signature: RSASignature<F>,
        //     substrings: Vec<String>,
        // }
        // let input: Vec<u8> = "email was meant for @@".chars().map(|c| c as u8).collect();
        // let circuit = TestRegexSha2::<Fr> {
        //     input,
        //     _f: PhantomData,
        // };
        // let expected_output = Sha256::digest(&circuit.input);
        // let hash_fs = expected_output
        //     .iter()
        //     .map(|byte| Fr::from(*byte as u64))
        //     .collect::<Vec<Fr>>();
        // let len_f = Fr::from(1);
        // let prover =
        //     MockProver::run(TestRegexSha2::<Fr>::K, &circuit, vec![hash_fs, vec![len_f]]).unwrap();
        // match prover.verify() {
        //     Err(_) => {
        //         println!("Error successfully achieved!");
        //     }
        //     _ => assert!(false, "Should be error."),
        // }
    }
}
