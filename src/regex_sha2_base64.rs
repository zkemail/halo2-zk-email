use std::collections::HashMap;

use crate::regex_sha2::RegexSha2Config;
use base64::{engine::general_purpose, Engine as _};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, RangeInstructions},
    utils::PrimeField,
    Context,
};
use halo2_base::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Region},
        plonk::{ConstraintSystem, Error},
    },
    AssignedValue,
};
use halo2_base64::Base64Config;
use halo2_dynamic_sha256::Sha256DynamicConfig;
use halo2_regex::RegexVerifyConfig;
use halo2_regex::{
    defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef},
    AssignedRegexResult,
};
use sha2::{Digest, Sha256};

/// Output type definition of [`RegexSha2Base64Config`].
#[derive(Debug, Clone)]
pub struct RegexSha2Base64Result<'a, F: PrimeField> {
    /// The output of [`AssignedRegexResult`].
    pub regex: AssignedRegexResult<'a, F>,
    /// The assigned bytes of the base64 encoded SHA256 hash value constrained in [`Sha256DynamicConfig`].
    pub encoded_hash: Vec<AssignedValue<'a, F>>,
    /// The actual bytes of the base64 encoded SHA256 hash value.
    pub encoded_hash_value: Vec<u8>,
}

/// Configuration to combine the [`RegexVerifyConfig`], [`Sha256DynamicConfig`], and [`Base64Config`] for the same bytes.  
#[derive(Debug, Clone)]
pub struct RegexSha2Base64Config<F: PrimeField> {
    /// Configuration for [`RegexSha2Config`].
    pub regex_sha2: RegexSha2Config<F>,
    /// Configuration for [`Base64Config`].
    pub base64_config: Base64Config<F>,
}

impl<F: PrimeField> RegexSha2Base64Config<F> {
    /// Configure a new [`RegexSha2Base64Config`].
    ///
    /// # Arguments
    /// * `meta` - a constrain system in which contraints are defined.
    /// * `max_byte_size` - the maximum byte size that this configuration can support.
    /// * `skip_prefix_bytes_size` - the bytes of the skipped input string that do not satisfy the regexes.
    /// * `range_config` - a configuration for [`RangeConfig`].
    /// * `regex_defs` - a definition of regexes that the input string must satisfy.
    ///
    /// # Return values
    /// Returns a new [`RegexSha2Base64Config`].
    pub fn configure(meta: &mut ConstraintSystem<F>, max_byte_size: usize, skip_prefix_bytes_size: usize, range_config: RangeConfig<F>, regex_defs: Vec<RegexDefs>) -> Self {
        let regex_sha2 = RegexSha2Config::configure(
            meta,
            max_byte_size,
            skip_prefix_bytes_size,
            // num_sha2_compression_per_column,
            range_config,
            regex_defs,
        );
        let base64_config = Base64Config::configure(meta, 32);
        Self { regex_sha2, base64_config }
    }

    /// Returns a base64 encoded SHA256 hash value and extracted substrings of the input string.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `sha256_config` - a configuration for [`Sha256DynamicConfig`].
    /// * `input` - the bytes of the input string.
    ///
    /// # Returns
    /// Returns the base64 encoded SHA256 hash value and extracted substrings of the input string as [`RegexSha2Result`].
    pub fn match_hash_and_base64<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        sha256_config: &mut Sha256DynamicConfig<F>,
        input: &[u8],
    ) -> Result<RegexSha2Base64Result<'a, F>, Error> {
        let regex_sha2_result = self.regex_sha2.match_and_hash(ctx, sha256_config, input)?;

        let actual_hash = Sha256::digest(input).to_vec();
        debug_assert_eq!(actual_hash.len(), 32);
        let mut hash_base64 = Vec::new();
        hash_base64.resize(44, 0);
        let bytes_written = general_purpose::STANDARD
            .encode_slice(&actual_hash, &mut hash_base64)
            .expect("fail to convert the hash bytes into the base64 strings");
        debug_assert_eq!(bytes_written, 44);
        let encoded_hash = self.base64_config.encode(ctx, &sha256_config.range().gate(), &regex_sha2_result.hash_bytes)?;
        // let base64_result = self.base64_config.assign_values(&mut ctx.region, &hash_base64)?;
        debug_assert_eq!(encoded_hash.len(), 44);
        // for (assigned_hash, assigned_decoded) in regex_sha2_result.hash_bytes.into_iter().zip(base64_result.decoded.into_iter()) {
        //     ctx.region.constrain_equal(assigned_hash.cell(), assigned_decoded.cell())?;
        // }
        let result = RegexSha2Base64Result {
            regex: regex_sha2_result.regex,
            encoded_hash: encoded_hash,
            encoded_hash_value: hash_base64,
        };
        Ok(result)
    }

    /// Load lookup tables used in the [`RegexSha2Base64Config`].
    ///
    /// # Arguments
    /// * `layouter` - a [`Layouter`] in which the lookup tables are loaded.
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.regex_sha2.load(layouter)?;
        self.base64_config.load(layouter)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use cfdkim::canonicalize_signed_email;
    use halo2_base::halo2_proofs::plonk::ConstraintSystem;
    use halo2_regex::vrm::DecomposedRegexConfig;
    use std::marker::PhantomData;
    use std::path::Path;

    use super::*;

    use crate::utils::*;
    use halo2_base::halo2_proofs::{
        circuit::{Cell, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Column, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
    use sha2::{self, Digest, Sha256};
    use std::fs::File;
    use std::io::Read;

    #[macro_export]
    macro_rules! impl_regex_sha2_base64_circuit {
        ($config_name:ident, $circuit_name:ident, $regex_defs:expr, $max_bytes_size:expr, $skip_prefix_bytes_size:expr, $num_advice:expr, $num_lookup_advice:expr, $lookup_bits:expr, $k:expr) => {
            #[derive(Debug, Clone)]
            struct $config_name<F: PrimeField> {
                inner: RegexSha2Base64Config<F>,
                sha256_config: Sha256DynamicConfig<F>,
                hash_instance: Column<Instance>,
                masked_str_instance: Column<Instance>,
                substr_ids_instance: Column<Instance>,
            }

            #[derive(Debug, Clone)]
            struct $circuit_name<F: PrimeField> {
                input: Vec<u8>,
                _f: PhantomData<F>,
            }

            impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
                type Config = $config_name<F>;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    Self { input: vec![], _f: PhantomData }
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
                        Self::K as usize,
                    );
                    let sha256_config = Sha256DynamicConfig::configure(meta, vec![Self::MAX_BYTES_SIZE], range_config.clone(), 16, 1, false);
                    let regex_defs = $regex_defs;
                    let inner = RegexSha2Base64Config::configure(meta, Self::MAX_BYTES_SIZE, Self::SKIP_PREFIX_BYTES_SIZE, range_config, regex_defs);
                    let hash_instance = meta.instance_column();
                    meta.enable_equality(hash_instance);
                    let masked_str_instance = meta.instance_column();
                    meta.enable_equality(masked_str_instance);
                    let substr_ids_instance = meta.instance_column();
                    meta.enable_equality(substr_ids_instance);
                    Self::Config {
                        inner,
                        sha256_config,
                        hash_instance,
                        masked_str_instance,
                        substr_ids_instance,
                    }
                }

                fn synthesize(&self, mut config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
                    config.inner.load(&mut layouter)?;
                    config.sha256_config.range().load_lookup_table(&mut layouter)?;
                    config.sha256_config.load(&mut layouter)?;
                    let mut first_pass = SKIP_FIRST_PASS;
                    let mut hash_bytes_cell = vec![];
                    let mut masked_str_cell = vec![];
                    let mut substr_id_cell = vec![];

                    layouter.assign_region(
                        || "regex",
                        |region| {
                            if first_pass {
                                first_pass = false;
                                return Ok(());
                            }
                            let ctx = &mut config.sha256_config.new_context(region);
                            let result = config.inner.match_hash_and_base64(ctx, &mut config.sha256_config, &self.input)?;
                            config.sha256_config.range().finalize(ctx);
                            hash_bytes_cell.append(&mut result.encoded_hash.into_iter().map(|byte| byte.cell()).collect::<Vec<Cell>>());
                            masked_str_cell.append(&mut result.regex.masked_characters.into_iter().map(|character| character.cell()).collect::<Vec<Cell>>());
                            substr_id_cell.append(&mut result.regex.all_substr_ids.into_iter().map(|id| id.cell()).collect::<Vec<Cell>>());
                            Ok(())
                        },
                    )?;
                    for (idx, cell) in hash_bytes_cell.into_iter().enumerate() {
                        layouter.constrain_instance(cell, config.hash_instance, idx)?;
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

            impl<F: PrimeField> $circuit_name<F> {
                const MAX_BYTES_SIZE: usize = $max_bytes_size;
                const SKIP_PREFIX_BYTES_SIZE: usize = $skip_prefix_bytes_size;
                const NUM_ADVICE: usize = $num_advice;
                const NUM_FIXED: usize = 1;
                const NUM_LOOKUP_ADVICE: usize = $num_lookup_advice;
                const LOOKUP_BITS: usize = $lookup_bits;
                const K: u32 = $k;
            }
        };
    }

    impl_regex_sha2_base64_circuit!(
        TestRegexSha2Base64Config1,
        TestRegexSha2Base64Circuit1,
        vec![
            RegexDefs {
                allstr: AllstrRegexDef::read_from_text("./test_data/from_allstr.txt"),
                substrs: vec![SubstrRegexDef::read_from_text("./test_data/from_substr_0.txt")],
            },
            RegexDefs {
                allstr: AllstrRegexDef::read_from_text("./test_data/subject_allstr.txt"),
                substrs: vec![
                    SubstrRegexDef::read_from_text("./test_data/subject_substr_0.txt"),
                    SubstrRegexDef::read_from_text("./test_data/subject_substr_1.txt"),
                    SubstrRegexDef::read_from_text("./test_data/subject_substr_2.txt"),
                ],
            },
        ],
        1024,
        0,
        12,
        1,
        18,
        19
    );

    #[test]
    fn test_regex_sha2_base64_valid_case1() {
        let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
        regex_from_decomposed
            .gen_regex_files(
                &Path::new("./test_data/from_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
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
        let email_bytes = {
            let mut f = File::open("./test_data/test_email1.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };
        let (input, _, _) = canonicalize_signed_email(&email_bytes).unwrap();
        let input_str = String::from_utf8(input.clone()).unwrap();
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2Base64Circuit1::<Fr>::MAX_BYTES_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2Base64Circuit1::<Fr>::MAX_BYTES_SIZE];
        let correct_substrs = vec![
            get_substr(&input_str, &[r"(?<=from:).*@.*(?=\r)".to_string(), "<?(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+>?".to_string(), "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+".to_string()]).unwrap(),
            get_substr(&input_str, &[r"(?<=subject:).*(?=\r)".to_string()]).unwrap(),
        ];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let circuit = TestRegexSha2Base64Circuit1::<Fr> { input, _f: PhantomData };
        let actual_hash = Sha256::digest(&circuit.input);
        let mut expected_output = vec![];
        expected_output.resize(44, 0);
        general_purpose::STANDARD
            .encode_slice(&actual_hash, &mut expected_output)
            .expect("fail to convert the hash bytes into the base64 strings");

        let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        let prover = MockProver::run(TestRegexSha2Base64Circuit1::<Fr>::K, &circuit, vec![hash_fs, expected_masked_chars, expected_substr_ids]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    impl_regex_sha2_base64_circuit!(
        TestRegexSha2Base64Config2,
        TestRegexSha2Base64Circuit2,
        vec![
            RegexDefs {
                allstr: AllstrRegexDef::read_from_text("./test_data/bodyhash_allstr.txt"),
                substrs: vec![SubstrRegexDef::read_from_text("./test_data/bodyhash_substr_0.txt")],
            },
            RegexDefs {
                allstr: AllstrRegexDef::read_from_text("./test_data/from_allstr.txt"),
                substrs: vec![SubstrRegexDef::read_from_text("./test_data/from_substr_0.txt")],
            },
            RegexDefs {
                allstr: AllstrRegexDef::read_from_text("./test_data/to_allstr.txt"),
                substrs: vec![SubstrRegexDef::read_from_text("./test_data/to_substr_0.txt")],
            },
            RegexDefs {
                allstr: AllstrRegexDef::read_from_text("./test_data/subject_allstr.txt"),
                substrs: vec![
                    SubstrRegexDef::read_from_text("./test_data/subject_substr_0.txt"),
                    SubstrRegexDef::read_from_text("./test_data/subject_substr_1.txt"),
                    SubstrRegexDef::read_from_text("./test_data/subject_substr_2.txt"),
                ],
            },
        ],
        1024,
        0,
        12,
        1,
        18,
        19
    );

    #[test]
    fn test_regex_sha2_base64_valid_case2() {
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
        let email_bytes = {
            let mut f = File::open("./test_data/test_email2.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };
        let (input, _, _) = canonicalize_signed_email(&email_bytes).unwrap();
        let input_str = String::from_utf8(input.clone()).unwrap();
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2Base64Circuit2::<Fr>::MAX_BYTES_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2Base64Circuit2::<Fr>::MAX_BYTES_SIZE];
        let correct_substrs = vec![
            get_substr(
                &input_str,
                &[
                    r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)"
                        .to_string(),
                ],
            )
            .unwrap(),
            get_substr(&input_str, &[r"(?<=from:).*@.*(?=\r)".to_string(), "<?(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+>?".to_string(), "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+".to_string()]).unwrap(),
            get_substr(&input_str, &[r"(?<=to:).*@.*(?=\r)".to_string()]).unwrap(),
            get_substr(&input_str, &[r"(?<=subject:).*(?=\r)".to_string()]).unwrap(),
        ];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let circuit = TestRegexSha2Base64Circuit2::<Fr> { input, _f: PhantomData };
        let actual_hash = Sha256::digest(&circuit.input);
        let mut expected_output = vec![];
        expected_output.resize(44, 0);
        general_purpose::STANDARD
            .encode_slice(&actual_hash, &mut expected_output)
            .expect("fail to convert the hash bytes into the base64 strings");
        let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        let prover = MockProver::run(TestRegexSha2Base64Circuit2::<Fr>::K, &circuit, vec![hash_fs, expected_masked_chars, expected_substr_ids]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
