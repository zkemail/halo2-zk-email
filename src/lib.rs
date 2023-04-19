#[cfg(not(target_arch = "wasm32"))]
mod helpers;
#[cfg(not(target_arch = "wasm32"))]
pub mod recursion_and_evm;

pub mod regex_sha2;
pub mod regex_sha2_base64;
mod utils;
pub use crate::helpers::*;
use crate::regex_sha2::RegexSha2Config;
use crate::utils::*;
use cfdkim::{canonicalize_signed_email, SignerBuilder};
use fancy_regex::Regex;
use halo2_base::halo2_proofs::circuit::{AssignedCell, Cell, Region, SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    utils::PrimeField,
    Context,
};
use halo2_base::{AssignedValue, QuantumCell};
use halo2_dynamic_sha256::{Field, Sha256CompressionConfig, Sha256DynamicConfig};
use halo2_regex::{
    defs::{AllstrRegexDef, SubstrRegexDef},
    AssignedRegexResult,
};
use halo2_rsa::{
    AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey,
    RSASignature,
};
use itertools::Itertools;
use mailparse::parse_mail;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use rand::{thread_rng, CryptoRng, Rng, RngCore};
use regex_sha2_base64::RegexSha2Base64Config;
use rsa::{PublicKeyParts, RsaPrivateKey};
use serde_json;
use sha2::{Digest, Sha256};
use snark_verifier_sdk::CircuitExt;
use std::env::set_var;
use std::fmt::format;
use std::fs::File;

#[derive(Debug, Clone)]
pub struct EmailVerifyResult<'a, F: Field> {
    pub assigned_bodyhash: Vec<AssignedCell<F, F>>,
    pub header_result: AssignedRegexResult<'a, F>,
    pub body_result: AssignedRegexResult<'a, F>,
    pub bodyhash_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EmailVerifyConfig<F: Field> {
    header_processer: RegexSha2Config<F>,
    body_processer: RegexSha2Base64Config<F>,
    rsa_config: RSAConfig<F>,
}

impl<F: Field> EmailVerifyConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        // num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        header_max_byte_size: usize,
        bodyhash_def: (AllstrRegexDef, SubstrRegexDef),
        header_regex_defs: Vec<(AllstrRegexDef, SubstrRegexDef)>,
        body_max_byte_size: usize,
        body_regex_defs: Vec<(AllstrRegexDef, SubstrRegexDef)>,
        public_key_bits: usize,
    ) -> Self {
        let header_defs = [vec![bodyhash_def], header_regex_defs].concat();
        let header_processer = RegexSha2Config::configure(
            meta,
            header_max_byte_size,
            // num_sha2_compression_per_column,
            range_config.clone(),
            header_defs,
        );
        let body_processer = RegexSha2Base64Config::configure(
            meta,
            body_max_byte_size,
            // num_sha2_compression_per_column,
            range_config.clone(),
            body_regex_defs,
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
        sha256_config: &mut Sha256DynamicConfig<F>,
        header_bytes: &[u8],
        body_bytes: &[u8],
        public_key: &AssignedRSAPublicKey<'v, F>,
        signature: &AssignedRSASignature<'v, F>,
    ) -> Result<EmailVerifyResult<'a, F>, Error> {
        let gate = sha256_config.range().gate.clone();

        // 1. Extract sub strings in the body and compute the base64 encoded hash of the body.
        let body_result =
            self.body_processer
                .match_hash_and_base64(ctx, sha256_config, body_bytes)?;

        // 2. Extract sub strings in the header, which includes the body hash, and compute the raw hash of the header.
        let header_result =
            self.header_processer
                .match_and_hash(ctx, sha256_config, header_bytes)?;

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
        Ok(EmailVerifyResult {
            assigned_bodyhash: body_result.encoded_hash,
            header_result: header_result.regex,
            body_result: body_result.regex,
            bodyhash_value: body_result.encoded_hash_value,
        })
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.header_processer.load(layouter)?;
        self.body_processer.load(layouter)?;
        Ok(())
    }

    // pub fn finalize(&self, ctx: &mut Context<F>) {
    //     self.header_processer.finalize(ctx);
    // }

    // pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
    //     self.header_processer.new_context(region)
    // }

    // pub fn range(&self) -> &RangeConfig<F> {
    //     self.header_processer.range()
    // }

    // pub fn gate(&self) -> &FlexGateConfig<F> {
    //     self.header_processer.gate()
    // }
}

pub const EMAIL_VERIFY_CONFIG_ENV: &'static str = "EMAIL_VERIFY_CONFIG";
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DefaultEmailVerifyConfigParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub bodyhash_regex_filepath: String,
    pub bodyhash_substr_filepath: String,
    pub header_regex_filepathes: Vec<String>,
    pub header_substr_filepathes: Vec<String>,
    pub body_regex_filepathes: Vec<String>,
    pub body_substr_filepathes: Vec<String>,
    pub num_sha2_compression_per_column: usize,
    pub header_max_byte_size: usize,
    pub body_max_byte_size: usize,
    pub public_key_bits: usize,
    pub header_substr_regexes: Vec<Vec<String>>,
    pub body_substr_regexes: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct DefaultEmailVerifyConfig<F: Field> {
    inner: EmailVerifyConfig<F>,
    sha256_config: Sha256DynamicConfig<F>,
    public_hash: Column<Instance>,
    // encoded_bodyhash_instance: Column<Instance>,
    // masked_str_instance: Column<Instance>,
    // substr_ids_instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct DefaultEmailVerifyCircuit<F: Field> {
    pub header_bytes: Vec<u8>,
    pub body_bytes: Vec<u8>,
    pub public_key: RSAPublicKey<F>,
    pub signature: RSASignature<F>,
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
        assert_eq!(
            params.header_regex_filepathes.len(),
            params.header_substr_filepathes.len()
        );
        assert_eq!(
            params.body_regex_filepathes.len(),
            params.body_substr_filepathes.len()
        );
        let bodyhash_allstr_def = AllstrRegexDef::read_from_text(&params.bodyhash_regex_filepath);
        let bodyhash_substr_def = SubstrRegexDef::read_from_text(&params.bodyhash_substr_filepath);
        let header_allstr_defs = params
            .header_regex_filepathes
            .into_iter()
            .map(|path| AllstrRegexDef::read_from_text(&path))
            .collect::<Vec<AllstrRegexDef>>();
        let header_substr_defs = params
            .header_substr_filepathes
            .into_iter()
            .map(|path| SubstrRegexDef::read_from_text(&path))
            .collect::<Vec<SubstrRegexDef>>();
        let body_allstr_defs = params
            .body_regex_filepathes
            .into_iter()
            .map(|path| AllstrRegexDef::read_from_text(&path))
            .collect::<Vec<AllstrRegexDef>>();
        let body_substr_defs = params
            .body_substr_filepathes
            .into_iter()
            .map(|path| SubstrRegexDef::read_from_text(&path))
            .collect::<Vec<SubstrRegexDef>>();
        let header_regex_defs = header_allstr_defs
            .into_iter()
            .zip(header_substr_defs.into_iter())
            .collect::<Vec<(AllstrRegexDef, SubstrRegexDef)>>();
        let body_regex_defs = body_allstr_defs
            .into_iter()
            .zip(body_substr_defs.into_iter())
            .collect::<Vec<(AllstrRegexDef, SubstrRegexDef)>>();
        let inner = EmailVerifyConfig::configure(
            meta,
            // params.num_sha2_compression_per_column,
            range_config.clone(),
            params.header_max_byte_size,
            (bodyhash_allstr_def, bodyhash_substr_def),
            header_regex_defs,
            params.body_max_byte_size,
            body_regex_defs,
            params.public_key_bits,
        );
        let sha256_comp_configs = (0..params.num_sha2_compression_per_column)
            .map(|_| Sha256CompressionConfig::configure(meta))
            .collect();
        let sha256_config = Sha256DynamicConfig::construct(
            sha256_comp_configs,
            vec![
                params.body_max_byte_size,
                params.header_max_byte_size,
                64 + 2 * (params.header_max_byte_size + params.body_max_byte_size) + 64,
            ],
            range_config.clone(),
        );
        let public_hash = meta.instance_column();
        meta.enable_equality(public_hash);
        // let encoded_bodyhash_instance = meta.instance_column();
        // meta.enable_equality(encoded_bodyhash_instance);
        // let masked_str_instance = meta.instance_column();
        // meta.enable_equality(masked_str_instance);
        // let substr_ids_instance = meta.instance_column();
        // meta.enable_equality(substr_ids_instance);
        DefaultEmailVerifyConfig {
            inner,
            sha256_config,
            public_hash,
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.inner.load(&mut layouter)?;
        config
            .sha256_config
            .range()
            .load_lookup_table(&mut layouter)?;
        let mut first_pass = SKIP_FIRST_PASS;
        let mut public_hash_cell = vec![];
        let params = Self::read_config_params();
        layouter.assign_region(
            || "zkemail",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = &mut config.sha256_config.new_context(region);
                let assigned_public_key = config
                    .inner
                    .assign_public_key(ctx, self.public_key.clone())?;
                let assigned_signature =
                    config.inner.assign_signature(ctx, self.signature.clone())?;
                let result = config.inner.verify_email(
                    ctx,
                    &mut config.sha256_config,
                    &self.header_bytes,
                    &self.body_bytes,
                    &assigned_public_key,
                    &assigned_signature,
                )?;
                let public_hash_input = self.get_public_hash_input();
                let public_hash_result = config.sha256_config.digest(ctx, &public_hash_input)?;
                // for (idx, v) in public_hash_result.input_bytes.iter().enumerate() {
                //     v.value().map(|v| {
                //         println!(
                //             "idx {} code {} char {}",
                //             idx,
                //             v.get_lower_32(),
                //             (v.get_lower_32() as u8) as char
                //         )
                //     });
                // }
                let gate = config.sha256_config.range().gate.clone();
                // for (idx, v) in result.header_result.masked_characters.iter().enumerate() {
                //     v.value().map(|v| {
                //         println!(
                //             "idx {} code {} char {}",
                //             idx,
                //             v.get_lower_32(),
                //             (v.get_lower_32() as u8) as char
                //         )
                //     });
                // }
                // for (idx, v) in result.body_result.masked_characters.iter().enumerate() {
                //     v.value().map(|v| {
                //         println!(
                //             "idx {} code {} char {}",
                //             idx,
                //             v.get_lower_32(),
                //             (v.get_lower_32() as u8) as char
                //         )
                //     });
                // }
                let assigned_public_hash_input = vec![
                    result
                        .assigned_bodyhash
                        .into_iter()
                        .map(|v| v.cell())
                        .collect_vec(),
                    vec![gate.load_zero(ctx).cell(); 64 - 44],
                    vec![
                        result.header_result.masked_characters,
                        result.body_result.masked_characters,
                    ]
                    .concat()
                    .into_iter()
                    .map(|v| v.cell())
                    .collect_vec(),
                    vec![
                        result.header_result.all_substr_ids,
                        result.body_result.all_substr_ids,
                    ]
                    .concat()
                    .into_iter()
                    .map(|v| v.cell())
                    .collect_vec(),
                ]
                .concat();
                for (a, b) in public_hash_result.input_bytes[0..assigned_public_hash_input.len()]
                    .into_iter()
                    .map(|v| v.cell())
                    .collect_vec()
                    .into_iter()
                    .zip(assigned_public_hash_input.into_iter())
                {
                    ctx.region.constrain_equal(a, b)?;
                }
                debug_assert_eq!(public_hash_result.output_bytes.len(), 32);
                let packed_public_hash = public_hash_result
                    .output_bytes
                    .chunks(16)
                    .map(|bytes| {
                        let mut sum = gate.load_zero(ctx);
                        for (idx, byte) in bytes.into_iter().enumerate() {
                            sum = gate.mul_add(
                                ctx,
                                QuantumCell::Existing(byte),
                                QuantumCell::Constant(F::from_u128(1u128 << (8 * idx))),
                                QuantumCell::Existing(&sum),
                            )
                        }
                        sum
                    })
                    .collect_vec();
                config.sha256_config.range().finalize(ctx);
                public_hash_cell = packed_public_hash
                    .into_iter()
                    .map(|v| v.cell())
                    .collect_vec();

                // encoded_bodyhash_cell.append(
                //     &mut encoded_bodyhash
                //         .into_iter()
                //         .enumerate()
                //         .map(|(idx, v)| {
                //             v.value().map(|v| {
                //                 // println!(
                //                 //     "idx {} code {} char {}",
                //                 //     idx,
                //                 //     v.get_lower_32(),
                //                 //     (v.get_lower_32() as u8) as char
                //                 // )
                //             });
                //             v.cell()
                //         })
                //         .collect::<Vec<Cell>>(),
                // );
                // masked_str_cell.append(
                //     &mut header_regex
                //         .masked_characters
                //         .into_iter()
                //         .enumerate()
                //         .map(|(idx, v)| {
                //             v.value().map(|v| {
                //                 // println!(
                //                 //     "idx {} code {} char {}",
                //                 //     idx,
                //                 //     v.get_lower_32(),
                //                 //     (v.get_lower_32() as u8) as char
                //                 // )
                //             });
                //             v.cell()
                //         })
                //         .collect::<Vec<Cell>>(),
                // );
                // masked_str_cell.append(
                //     &mut body_regex
                //         .masked_characters
                //         .into_iter()
                //         .enumerate()
                //         .map(|(idx, v)| {
                //             v.value().map(|v| {
                //                 // println!(
                //                 //     "idx {} code {} char {}",
                //                 //     idx,
                //                 //     v.get_lower_32(),
                //                 //     (v.get_lower_32() as u8) as char
                //                 // )
                //             });
                //             v.cell()
                //         })
                //         .collect::<Vec<Cell>>(),
                // );
                // substr_id_cell.append(
                //     &mut header_regex
                //         .all_substr_ids
                //         .into_iter()
                //         .map(|v| v.cell())
                //         .collect::<Vec<Cell>>(),
                // );
                // substr_id_cell.append(
                //     &mut body_regex
                //         .all_substr_ids
                //         .into_iter()
                //         .map(|v| v.cell())
                //         .collect::<Vec<Cell>>(),
                // );
                Ok(())
            },
        )?;
        for (idx, cell) in public_hash_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.public_hash, idx)?;
        }
        Ok(())
    }
}

impl<F: Field> CircuitExt<F> for DefaultEmailVerifyCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        // let params = Self::read_config_params();
        // let max_len = params.header_max_byte_size + params.body_max_byte_size;
        // vec![44, max_len, max_len]
        vec![2]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let public_hash_input = self.get_public_hash_input();
        let public_hash: Vec<u8> = Sha256::digest(&public_hash_input).to_vec();
        let public_frs = public_hash
            .chunks(16)
            .map(|bytes| F::from_u128(u128::from_le_bytes(bytes.try_into().unwrap())))
            .collect_vec();
        vec![public_frs]
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

    // pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
    //     let params = DefaultEmailVerifyCircuit::<F>::read_config_params();
    //     let _private_key =
    //         RsaPrivateKey::new(rng, params.public_key_bits).expect("failed to generate a key");
    //     let public_key = rsa::RsaPublicKey::from(&_private_key);
    //     let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
    //     let message = concat!("From:random\r\n",).as_bytes();
    //     let email = parse_mail(message).unwrap();
    //     let logger = slog::Logger::root(slog::Discard, slog::o!());
    //     let signer = SignerBuilder::new()
    //         .with_signed_headers(&["From"])
    //         .unwrap()
    //         .with_private_key(private_key)
    //         .with_selector("default")
    //         .with_signing_domain("random")
    //         .with_logger(&logger)
    //         .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
    //         .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
    //         .build()
    //         .unwrap();
    //     let signature = signer.sign(&email).unwrap();
    //     let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
    //     let (canonicalized_header, canonicalized_body, signature_bytes) =
    //         canonicalize_signed_email(&new_msg).unwrap();

    //     let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<F>::DEFAULT_E));
    //     let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    //     let public_key = RSAPublicKey::<F>::new(Value::known(BigUint::from(n_big)), e);
    //     let signature =
    //         RSASignature::<F>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
    //     let circuit = DefaultEmailVerifyCircuit {
    //         header_bytes: canonicalized_header,
    //         body_bytes: canonicalized_body,
    //         public_key,
    //         signature,
    //     };

    //     // let mut rng = thread_rng();
    //     // let params = Self::read_config_params();
    //     // let mut n = BigUint::default();
    //     // while n.bits() != params.public_key_bits as u64 {
    //     //     n = rng.sample(RandomBits::new(params.public_key_bits as u64));
    //     // }
    //     // let public_key = RSAPublicKey::new(
    //     //     Value::known(n),
    //     //     RSAPubE::Fix(BigUint::from_u128(Self::DEFAULT_E).unwrap()),
    //     // );

    //     // let mut c = BigUint::default();
    //     // while c.bits() != params.public_key_bits as u64 {
    //     //     c = rng.sample(RandomBits::new(params.public_key_bits as u64));
    //     // }
    //     // let signature = RSASignature::new(Value::known(c));
    //     // Self {
    //     //     header_bytes: vec![],
    //     //     body_bytes: vec![],
    //     //     public_key,
    //     //     signature,
    //     // }
    //     circuit
    // }

    pub fn get_public_hash_input(&self) -> Vec<u8> {
        let (header_substrs, body_substrs) = self.get_substrs();
        let bodyhash = header_substrs[0].as_ref().unwrap().1.as_bytes();
        let params = Self::read_config_params();
        let max_len = params.header_max_byte_size + params.body_max_byte_size;
        let mut expected_masked_chars = vec![0u8; max_len];
        let mut expected_substr_ids = vec![0u8; max_len]; // We only support up to 256 substring patterns.
        for (substr_idx, m) in header_substrs.iter().enumerate() {
            if let Some((start, chars)) = m {
                for (idx, char) in chars.as_bytes().iter().enumerate() {
                    expected_masked_chars[start + idx] = *char;
                    expected_substr_ids[start + idx] = substr_idx as u8 + 1;
                }
            }
        }
        for (substr_idx, m) in body_substrs.iter().enumerate() {
            if let Some((start, chars)) = m {
                for (idx, char) in chars.as_bytes().iter().enumerate() {
                    expected_masked_chars[params.header_max_byte_size + start + idx] = *char;
                    expected_substr_ids[params.header_max_byte_size + start + idx] =
                        substr_idx as u8 + 1;
                }
            }
        }
        vec![
            bodyhash,
            &[0u8; (64 - 44)][..],
            &expected_masked_chars,
            &expected_substr_ids,
        ]
        .concat()
    }

    pub fn get_substrs(&self) -> (Vec<Option<(usize, String)>>, Vec<Option<(usize, String)>>) {
        let params = Self::read_config_params();
        let header_str = String::from_utf8(self.header_bytes.clone())
            .expect("fail to encode header bytes to utf8 string");
        let bodyhash_substr = get_substr(
            &header_str,
            &[
                r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)".to_string(),
            ],
        );
        let header_substrs = params
            .header_substr_regexes
            .iter()
            .map(|raws| {
                let raws = raws
                    .into_iter()
                    .map(|raw| format!(r"{}", raw))
                    .collect_vec();
                get_substr(&header_str, raws.as_slice())
            })
            .collect_vec();
        let header_substrings = vec![vec![bodyhash_substr], header_substrs].concat();
        let body_str = String::from_utf8(self.body_bytes.clone())
            .expect("fail to encode body bytes to utf8 string");
        let body_substrings = params
            .body_substr_regexes
            .iter()
            .map(|raws| {
                let raws = raws
                    .into_iter()
                    .map(|raw| format!(r"{}", raw))
                    .collect_vec();
                get_substr(&body_str, raws.as_slice())
            })
            .collect_vec();
        (header_substrings, body_substrings)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cfdkim::{canonicalize_signed_email, resolve_public_key, verify_email, SignerBuilder};
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
    use std::{collections::HashSet, io::Read};
    // use mail_auth::{common::{crypto::{RsaKey},headers::HeaderWriter},dkim::DkimSigner};
    // use mail_parser::{decoders::base64::base64_decode,  Message, Addr, HeaderValue};
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use fancy_regex::Regex;
    use hex;
    use rsa::{pkcs1::DecodeRsaPrivateKey, PublicKeyParts, RsaPrivateKey};
    use snark_verifier_sdk::CircuitExt;
    use temp_env;

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
        temp_env::with_var(
            EMAIL_VERIFY_CONFIG_ENV,
            Some("./configs/test1_email_verify.config"),
            || {
                let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
                let mut rng = thread_rng();
                let _private_key = RsaPrivateKey::new(&mut rng, params.public_key_bits)
                    .expect("failed to generate a key");
                let public_key = rsa::RsaPublicKey::from(&_private_key);
                let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
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
                let new_msg = vec![signature.as_bytes(), b"\r\n", message].concat();
                println!("email: {}", String::from_utf8(new_msg.clone()).unwrap());
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
                let n_big =
                    BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
                let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
                let signature =
                    RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
                let circuit = DefaultEmailVerifyCircuit {
                    header_bytes: canonicalized_header,
                    body_bytes: canonicalized_body,
                    public_key,
                    signature,
                };
                let instances = circuit.instances();
                let prover = MockProver::run(13, &circuit, instances).unwrap();
                assert_eq!(prover.verify(), Ok(()));
            },
        );
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
        temp_env::with_var(
            EMAIL_VERIFY_CONFIG_ENV,
            Some("./configs/test2_email_verify.config"),
            || {
                let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
                let mut rng = thread_rng();
                let _private_key = RsaPrivateKey::new(&mut rng, params.public_key_bits)
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

                let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
                let n_big =
                    BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
                let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
                let signature =
                    RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
                let circuit = DefaultEmailVerifyCircuit {
                    header_bytes: canonicalized_header,
                    body_bytes: canonicalized_body,
                    public_key,
                    signature,
                };

                let instances = circuit.instances();
                let prover = MockProver::run(13, &circuit, instances).unwrap();
                assert_eq!(prover.verify(), Ok(()));
            },
        );
    }

    #[tokio::test]
    async fn test_existing_email1() {
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
        temp_env::with_var(
            EMAIL_VERIFY_CONFIG_ENV,
            Some("./configs/test_ex1_email_verify.config"),
            move || {
                let params = DefaultEmailVerifyCircuit::<Fr>::read_config_params();
                let (canonicalized_header, canonicalized_body, signature_bytes) =
                    canonicalize_signed_email(&email_bytes).unwrap();
                println!("header len\n {}", canonicalized_header.len());
                println!("body len\n {}", canonicalized_body.len());
                // println!("body\n{:?}", canonicalized_body);
                println!(
                    "canonicalized_header:\n{}",
                    String::from_utf8(canonicalized_header.clone()).unwrap()
                );
                println!(
                    "canonicalized_body:\n{}",
                    String::from_utf8(canonicalized_body.clone()).unwrap()
                );
                let e = RSAPubE::Fix(BigUint::from(DefaultEmailVerifyCircuit::<Fr>::DEFAULT_E));
                let n_big =
                    BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
                let public_key = RSAPublicKey::<Fr>::new(Value::known(BigUint::from(n_big)), e);
                let signature =
                    RSASignature::<Fr>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
                let circuit = DefaultEmailVerifyCircuit {
                    header_bytes: canonicalized_header,
                    body_bytes: canonicalized_body,
                    public_key,
                    signature,
                };

                let instances = circuit.instances();
                let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
                assert_eq!(prover.verify(), Ok(()));
            },
        );
    }
}
