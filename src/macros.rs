use crate::regex_sha2::RegexSha2Config;
use crate::regex_sha2_base64::RegexSha2Base64Config;
use crate::EmailVerifyConfig;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
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
use num_bigint::BigUint;

#[macro_export]
macro_rules! impl_email_verify_circuit {
    ($config_name:ident, $circuit_name:ident, $num_sha2_compression_per_column:expr, $header_max_byte_size:expr, $header_regex_filepath:expr, $header_substr_defs:expr, $body_max_byte_size:expr, $body_regex_filepath:expr, $body_substr_defs:expr, $public_key_bits:expr, $k:expr) => {
        #[derive(Debug, Clone)]
        pub struct $config_name<F: Filed> {
            inner: EmailVerifyConfig<F>,
            header_substr_instances: Vec<Column<Instance>>,
            body_substr_instances: Vec<Column<Instance>>,
            substr_len_instance: Column<Instance>,
        }

        #[derive(Debug, Clone)]
        pub struct $circuit_name {
            header_bytes: Vec<u8>,
            body_bytes: Vec<u8>,
            public_key: RSAPublicKey<F>,
            signature: RSASignature<F>,
        }

        impl<F: Field> Circuit<F> for $circuit_name<F> {
            type Config = $config_name<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    header_bytes: vec![],
                    body_bytes: vec![],
                    public_key: RSAPublicKey::without_witnesses(BigUint::from(Self::DEFAULT_E)),
                    signature: RSASignature::without_witnesses(),
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
                let inner = Self::Config::configure(
                    meta,
                    $num_sha2_compression_per_column,
                    range_config,
                    $header_max_byte_size,
                    $header_regex_def,
                    $header_substr_defs,
                    $body_max_byte_size,
                    $body_regex_def,
                    $body_substr_defs,
                    $public_key_bits,
                );
                let header_substr_instances = (0..$header_substr_defs.len())
                    .into_iter()
                    .map(|_| {
                        let column = meta.instance_column();
                        meta.enable_equality(column);
                        column
                    })
                    .collect::<Vec<Column<Instance>>>();
                let body_substr_instances = (0..$body_substr_defs.len())
                    .into_iter()
                    .map(|_| {
                        let column = meta.instance_column();
                        meta.enable_equality(column);
                        column
                    })
                    .collect::<Vec<Column<Instance>>>();
                let substr_len_instance = meta.instance_column();
                meta.enable_equality(substr_len_instance);
                $config_name {
                    inner,
                    header_substr_instances,
                    body_substr_instances,
                    substr_len_instance,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                config.inner.load(&mut layouter)?;
                let mut first_pass = SKIP_FIRST_PASS;
                let mut header_substrs = None;
                let mut bodt_substrs = None;
                layouter.assign_region(
                    || "regex",
                    |region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }
                        let ctx = &mut config.inner.new_context(region);
                        let assigned_public_key =
                            config.inner.assign_public_key(ctx, self.public_key)?;
                        let assigned_signature =
                            config.inner.assign_signature(ctx, self.signature)?;
                        (header_substrs, body_substrs) = config.inner.verify_email(
                            ctx,
                            &self.header_bytes,
                            &self.body_bytes,
                            &assigned_public_key,
                            &assigned_signature,
                        )?;
                        config.inner.finalize(ctx);
                        Ok(())
                    },
                )?;
            }
        }

        impl<F: Field> $circuit_name<F> {
            const DEFAULT_E: u128 = 65537;
            const NUM_ADVICE: usize = 80;
            const NUM_FIXED: usize = 1;
            const NUM_LOOKUP_ADVICE: usize = 8;
            const LOOKUP_BITS: usize = 12;
            const DEFAULT_E: u128 = 65537;
        }
    };
}
