use std::collections::HashSet;

use crate::regex_sha2::RegexSha2Config;
use crate::regex_sha2_base64::RegexSha2Base64Config;
use crate::EmailVerifyConfig;
use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Layouter, SimpleFloorPlanner},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    halo2curves::bn256::{Fr, G1},
    plonk::{Any, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
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
use num_bigint::BigUint;

#[macro_export]
macro_rules! impl_email_verify_circuit {
    ($config_name:ident, $circuit_name:ident, $num_sha2_compression_per_column:expr, $header_max_byte_size:expr, $header_regex_filepath:expr, $body_hash_substr_def:expr, $header_substr_defs:expr, $body_max_byte_size:expr, $body_regex_filepath:expr, $body_substr_defs:expr, $public_key_bits:expr, $k:expr) => {
        #[derive(Debug, Clone)]
        pub struct $config_name<F: Field> {
            inner: EmailVerifyConfig<F>,
            substr_bytes_instance: Column<Instance>,
            substr_lens_instance: Column<Instance>,
        }

        #[derive(Debug, Clone)]
        pub struct $circuit_name<F: Field> {
            header_bytes: Vec<u8>,
            body_bytes: Vec<u8>,
            public_key: RSAPublicKey<F>,
            signature: RSASignature<F>,
            substrings: Vec<String>,
        }

        impl<F: Field> Circuit<F> for $circuit_name<F> {
            type Config = $config_name<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    header_bytes: vec![],
                    body_bytes: vec![],
                    public_key: RSAPublicKey::without_witness(BigUint::from(Self::DEFAULT_E)),
                    signature: RSASignature::without_witness(),
                    substrings: vec![],
                }
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let range_config = RangeConfig::configure(
                    meta,
                    Vertical,
                    &[Self::NUM_ADVICE],
                    &[Self::NUM_LOOKUP_ADVICE],
                    Self::NUM_FIXED,
                    Self::LOOKUP_BITS,
                    0,
                    $k,
                );
                let header_regex_def = RegexDef::read_from_text($header_regex_filepath);
                let body_regex_def = RegexDef::read_from_text($body_regex_filepath);
                let inner = EmailVerifyConfig::configure(
                    meta,
                    $num_sha2_compression_per_column,
                    range_config,
                    $header_max_byte_size,
                    header_regex_def,
                    $body_hash_substr_def,
                    $header_substr_defs,
                    $body_max_byte_size,
                    body_regex_def,
                    $body_substr_defs,
                    $public_key_bits,
                );
                let substr_bytes_instance = meta.instance_column();
                meta.enable_equality(substr_bytes_instance);
                let substr_lens_instance = meta.instance_column();
                meta.enable_equality(substr_lens_instance);
                $config_name {
                    inner,
                    substr_bytes_instance,
                    substr_lens_instance,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                config.inner.load(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                let mut substr_bytes = Vec::<Cell>::new();
                let mut substr_lens = Vec::<Cell>::new();
                layouter.assign_region(
                    || "regex",
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
                        let (header_substrs, body_substrs) = config.inner.verify_email(
                            ctx,
                            &self.header_bytes,
                            &self.body_bytes,
                            &assigned_public_key,
                            &assigned_signature,
                        )?;
                        let mut bytes_cells =
                            vec![&header_substrs.substrs_bytes[1..], &body_substrs.substrs_bytes]
                                .concat()
                                .into_iter()
                                .flatten()
                                .map(|val| val.cell())
                                .collect();
                        substr_bytes.append(&mut bytes_cells);
                        let mut lens_cells =
                            vec![&header_substrs.substrs_length[1..], &body_substrs.substrs_length]
                                .concat()
                                .into_iter()
                                .map(|val| val.cell())
                                .collect();
                        substr_lens.append(&mut lens_cells);
                        config.inner.finalize(ctx);
                        Ok(())
                    },
                )?;
                for (idx, cell) in substr_bytes.into_iter().enumerate() {
                    layouter.constrain_instance(cell, config.substr_bytes_instance, idx)?;
                }
                for (idx, cell) in substr_lens.into_iter().enumerate() {
                    layouter.constrain_instance(cell, config.substr_lens_instance, idx)?;
                }
                Ok(())
            }
        }

        impl<F: Field> $circuit_name<F> {
            const DEFAULT_E: u128 = 65537;
            const NUM_ADVICE: usize = 154;
            const NUM_FIXED: usize = 1;
            const NUM_LOOKUP_ADVICE: usize = 8;
            const LOOKUP_BITS: usize = 12;
        }
    };
}

// impl_email_verify_circuit!(
//     DummyConfig,
//     DummyCircuit,
//     1,
//     1024,
//     "./",
//     SubstrDef::new(4, 0, 1024 - 1, HashSet::new()),
//     vec![SubstrDef::new(4, 0, 1024 - 1, HashSet::new())],
//     1024,
//     "./",
//     vec![SubstrDef::new(4, 0, 1024 - 1, HashSet::new())],
//     2048,
//     13
// );
