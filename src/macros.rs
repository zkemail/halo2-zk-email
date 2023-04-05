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
use halo2_regex::{
    defs::{AllstrRegexDef, SubstrRegexDef},
    AssignedRegexResult,
};
use halo2_rsa::{
    AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPublicKey,
    RSASignature,
};
use num_bigint::BigUint;
use snark_verifier_sdk::CircuitExt;

#[macro_export]
macro_rules! impl_email_verify_circuit {
    ($config_name:ident, $circuit_name:ident, $num_sha2_compression_per_column:expr, $header_max_byte_size:expr, $header_regex_filepath:expr, $body_hash_substr_filepath:expr, $header_substr_filepathes:expr, $body_max_byte_size:expr, $body_regex_filepath:expr, $body_substr_filepathes:expr, $public_key_bits:expr, $num_advice:expr, $num_lookup_advice:expr, $k:expr) => {
        #[derive(Debug, Clone)]
        pub struct $config_name<F: Field> {
            inner: EmailVerifyConfig<F>,
            encoded_bodyhash_instance: Column<Instance>,
            masked_str_instance: Column<Instance>,
            substr_ids_instance: Column<Instance>
        }

        #[derive(Debug, Clone)]
        pub struct $circuit_name<F: Field> {
            header_bytes: Vec<u8>,
            body_bytes: Vec<u8>,
            public_key: RSAPublicKey<F>,
            signature: RSASignature<F>,
            bodyhash: (usize, String),
            header_substrings: Vec<(usize,String)>,
            body_substrings: Vec<(usize,String)>,
        }

        impl<F: Field> Circuit<F> for $circuit_name<F> {
            type Config = $config_name<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    header_bytes: vec![],
                    body_bytes: vec![],
                    public_key: self.public_key.clone(),
                    signature: self.signature.clone(),
                    bodyhash: (0, "".to_string()),
                    header_substrings: vec![],
                    body_substrings: vec![]
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
                let header_regex_def = AllstrRegexDef::read_from_text($header_regex_filepath);
                let body_regex_def = AllstrRegexDef::read_from_text($body_regex_filepath);
                let header_substr_defs = $header_substr_filepathes.into_iter().map(|path| SubstrRegexDef::read_from_text(path)).collect::<Vec<SubstrRegexDef>>();
                let body_hash_substr_def = SubstrRegexDef::read_from_text($body_hash_substr_filepath);
                let body_substr_defs = $body_substr_filepathes.into_iter().map(|path| SubstrRegexDef::read_from_text(path)).collect::<Vec<SubstrRegexDef>>();
                let inner = EmailVerifyConfig::configure(
                    meta,
                    $num_sha2_compression_per_column,
                    range_config,
                    $header_max_byte_size,
                    header_regex_def,
                    body_hash_substr_def,
                    header_substr_defs,
                    $body_max_byte_size,
                    body_regex_def,
                    body_substr_defs,
                    $public_key_bits,
                );
                let encoded_bodyhash_instance = meta.instance_column();
                meta.enable_equality(encoded_bodyhash_instance);
                let masked_str_instance = meta.instance_column();
                meta.enable_equality(masked_str_instance);
                let substr_ids_instance = meta.instance_column();
                meta.enable_equality(substr_ids_instance);
                $config_name {
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
                        let (encoded_bodyhash,header_regex, body_regex) = config.inner.verify_email(
                            ctx,
                            &self.header_bytes,
                            &self.body_bytes,
                            &assigned_public_key,
                            &assigned_signature,
                        )?;
                        config.inner.finalize(ctx);
                        encoded_bodyhash_cell.append(&mut encoded_bodyhash.into_iter().map(|v| v.cell()).collect::<Vec<Cell>>());
                        masked_str_cell.append(&mut header_regex.masked_characters.into_iter().map(|v| v.cell()).collect::<Vec<Cell>>());
                        masked_str_cell.append(&mut body_regex.masked_characters.into_iter().map(|v| v.cell()).collect::<Vec<Cell>>());
                        substr_id_cell.append(&mut header_regex.all_substr_ids.into_iter().map(|v| v.cell()).collect::<Vec<Cell>>());
                        substr_id_cell.append(&mut body_regex.all_substr_ids.into_iter().map(|v| v.cell()).collect::<Vec<Cell>>());
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

        impl<F:Field> CircuitExt<F> for $circuit_name<F> {
            fn num_instance(&self) -> Vec<usize> {
                // let header_substr_defs = $header_substr_filepathes.into_iter().map(|path| SubstrRegexDef::read_from_text(path)).collect::<Vec<SubstrRegexDef>>();
                // let body_hash_substr_def = SubstrRegexDef::read_from_text($body_hash_substr_filepath);
                // let body_substr_defs = $body_substr_filepathes.into_iter().map(|path| SubstrRegexDef::read_from_text(path)).collect::<Vec<SubstrRegexDef>>();
                let max_len = $header_max_byte_size + $body_max_byte_size;

                // let num_subst_defs = 1 + header_substr_defs.len() + body_substr_defs.len();
                // let mut substr_bytes_sum = body_hash_substr_def.max_length;
                // for substr_def in header_substr_defs.iter() {
                //     substr_bytes_sum += substr_def.max_length;
                // }
                // for substr_def in body_substr_defs.iter() {
                //     substr_bytes_sum += substr_def.max_length;
                // }
                vec![44,max_len,max_len]
            }

            fn instances(&self) -> Vec<Vec<F>> {
                let max_len = $header_max_byte_size + $body_max_byte_size;
                let hash_fs = self.bodyhash.1.as_bytes().into_iter().map(|byte| F::from(*byte as u64)).collect::<Vec<F>>();
                let header_substrings = vec![&[self.bodyhash.clone()][..], &self.header_substrings].concat();
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
                        expected_masked_chars[$header_max_byte_size+ start + idx] = F::from(*char as u64);
                        expected_substr_ids[$header_max_byte_size+ start + idx] = F::from(substr_idx as u64 + 1);
                    }
                }


                // let header_substr_defs = $header_substr_filepathes.into_iter().map(|path| SubstrDef::read_from_text(path)).collect::<Vec<SubstrDef>>();
                // let body_hash_substr_def = SubstrDef::read_from_text($body_hash_substr_filepath);
                // let body_substr_defs = $body_substr_filepathes.into_iter().map(|path| SubstrDef::read_from_text(path)).collect::<Vec<SubstrDef>>();
                // let mut max_lens = vec![body_hash_substr_def.max_length];
                // for substr_def in header_substr_defs.iter() {
                //     max_lens.push(substr_def.max_length);
                // }
                // for substr_def in body_substr_defs.iter() {
                //     max_lens.push(substr_def.max_length);
                // }
                // let bytes_frs = self.substrings.iter().enumerate().flat_map(|(idx,chars)| {
                //     let mut frs = Vec::new();
                //     for _char in chars.as_bytes().into_iter() {
                //         frs.push(F::from(*_char as u64));
                //     }
                //     for _ in chars.len() .. max_lens[idx] {
                //         frs.push(F::from(0));
                //     }
                //     frs
                // }).collect::<Vec<F>>();
                // let lens = self.substrings.iter().map(|chars| F::from(chars.len() as u64)).collect::<Vec<F>>();
                vec![hash_fs, expected_masked_chars, expected_substr_ids]
            }

        }

        impl<F: Field> $circuit_name<F> {
            const DEFAULT_E: u128 = 65537;
            const NUM_ADVICE: usize = $num_advice;//510;
            const NUM_FIXED: usize = 1;
            const NUM_LOOKUP_ADVICE: usize = $num_lookup_advice;//15;
            const LOOKUP_BITS: usize = 12;
            const BITS_LEN: usize = $public_key_bits;
        }
    };
}
