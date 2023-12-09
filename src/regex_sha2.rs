use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::PrimeField,
    AssignedValue, Context,
};
use halo2_dynamic_sha256::Sha256DynamicConfig;
use halo2_regex::{
    defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef},
    AssignedRegexResult, RegexVerifyConfig,
};
use sha2::{Digest, Sha256};

/// Output type definition of [`RegexSha2Config`].
#[derive(Debug, Clone, Default)]
pub struct RegexSha2Result<'a, F: PrimeField> {
    /// The output of [`RegexVerifyConfig`].
    pub regex: AssignedRegexResult<'a, F>,
    /// The assigned bytes of the SHA256 hash value constrained in [`Sha256DynamicConfig`].
    pub hash_bytes: Vec<AssignedValue<'a, F>>,
    /// The actual bytes of the SHA256 hash value.
    pub hash_value: Vec<u8>,
}

/// Configuration to combine the [`RegexVerifyConfig`] and [`Sha256DynamicConfig`] for the same bytes.  
#[derive(Debug, Clone)]
pub struct RegexSha2Config<F: PrimeField> {
    /// Configuration for [`RegexVerifyConfig`].
    pub regex_config: RegexVerifyConfig<F>,
    /// The maximum byte size that this configuration can support.
    /// It must be multiple of 64.
    pub max_variable_byte_size: usize,
    /// The bytes of the skipped input string that do not satisfy the regexes.
    /// It must be multiple of 64 and less than `max_variable_byte_size`.
    pub skip_prefix_bytes_size: usize,
}

impl<F: PrimeField> RegexSha2Config<F> {
    /// Configure a new [`RegexSha2Config`].
    ///
    /// # Arguments
    /// * `meta` - a constrain system in which contraints are defined.
    /// * `max_byte_size` - the maximum byte size that this configuration can support.
    /// * `skip_prefix_bytes_size` - the bytes of the skipped input string that do not satisfy the regexes.
    /// * `range_config` - a configuration for [`RangeConfig`].
    /// * `regex_defs` - a definition of regexes that the input string must satisfy.
    ///
    /// # Return values
    /// Returns a new [`RegexSha2Config`].
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_variable_byte_size: usize,
        skip_prefix_bytes_size: usize,
        range_config: RangeConfig<F>,
        regex_defs: Vec<RegexDefs>,
    ) -> Self {
        debug_assert!(max_variable_byte_size > skip_prefix_bytes_size);
        let regex_config = RegexVerifyConfig::configure(meta, max_variable_byte_size, range_config.gate().clone(), regex_defs);
        Self {
            regex_config,
            max_variable_byte_size,
            skip_prefix_bytes_size,
        }
    }

    /// Returns a SHA256 hash value and extracted substrings of the input string.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `sha256_config` - a configuration for [`Sha256DynamicConfig`].
    /// * `input` - the bytes of the input string.
    ///
    /// # Returns
    /// Returns the SHA256 hash value and extracted substrings of the input string as [`RegexSha2Result`].
    pub fn match_and_hash<'v: 'a, 'a>(&self, ctx: &mut Context<'v, F>, sha256_config: &mut Sha256DynamicConfig<F>, input: &[u8]) -> Result<RegexSha2Result<'a, F>, Error> {
        // 1. Let's match sub strings!
        let regex_result = self.regex_config.match_substrs(ctx, &input[self.skip_prefix_bytes_size..])?;

        // Let's compute the hash!
        let assigned_hash_result = sha256_config.digest(ctx, input, Some(self.skip_prefix_bytes_size))?;
        // Assert that the same input is used in the regex circuit and the sha2 circuit.
        let gate = &sha256_config.range().gate();
        let mut input_len_sum = gate.load_constant(ctx, F::from(self.skip_prefix_bytes_size as u64));
        for idx in 0..self.max_variable_byte_size {
            let flag = &regex_result.all_enable_flags[idx];
            let regex_input = gate.mul(ctx, QuantumCell::Existing(flag), QuantumCell::Existing(&regex_result.all_characters[idx]));
            let sha2_input = gate.mul(ctx, QuantumCell::Existing(flag), QuantumCell::Existing(&assigned_hash_result.input_bytes[idx]));
            gate.assert_equal(ctx, QuantumCell::Existing(&regex_input), QuantumCell::Existing(&sha2_input));
            input_len_sum = gate.add(ctx, QuantumCell::Existing(&input_len_sum), QuantumCell::Existing(flag));
        }
        gate.assert_equal(ctx, QuantumCell::Existing(&input_len_sum), QuantumCell::Existing(&assigned_hash_result.input_len));
        let hash_value = Sha256::digest(input).to_vec();
        let result = RegexSha2Result {
            regex: regex_result,
            hash_bytes: assigned_hash_result.output_bytes,
            hash_value,
        };
        Ok(result)
    }

    /// Load lookup tables used in the [`RegexSha2Config`].
    ///
    /// # Arguments
    /// * `layouter` - a [`Layouter`] in which the lookup tables are loaded.
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.regex_config.load(layouter)?;
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
    macro_rules! impl_regex_sha2_circuit {
        ($config_name:ident, $circuit_name:ident, $regex_defs:expr, $max_bytes_size:expr, $skip_prefix_bytes_size:expr, $num_advice:expr, $num_lookup_advice:expr, $lookup_bits:expr, $k:expr) => {
            #[derive(Debug, Clone)]
            struct $config_name<F: PrimeField> {
                inner: RegexSha2Config<F>,
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
                    let inner = RegexSha2Config::configure(meta, Self::MAX_BYTES_SIZE, Self::SKIP_PREFIX_BYTES_SIZE, range_config, regex_defs);
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
                            let result = config.inner.match_and_hash(ctx, &mut config.sha256_config, &self.input)?;
                            config.sha256_config.range().finalize(ctx);
                            hash_bytes_cell.append(&mut result.hash_bytes.into_iter().map(|byte| byte.cell()).collect::<Vec<Cell>>());
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

    impl_regex_sha2_circuit!(
        TestRegexSha2Config1,
        TestRegexSha2Circuit1,
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
    fn test_regex_sha2_valid_case1() {
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
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2Circuit1::<Fr>::MAX_BYTES_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2Circuit1::<Fr>::MAX_BYTES_SIZE];
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
        let circuit = TestRegexSha2Circuit1::<Fr> { input, _f: PhantomData };
        let expected_output = Sha256::digest(&circuit.input);
        let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        let prover = MockProver::run(TestRegexSha2Circuit1::<Fr>::K, &circuit, vec![hash_fs, expected_masked_chars, expected_substr_ids]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    impl_regex_sha2_circuit!(
        TestRegexSha2Config2,
        TestRegexSha2Circuit2,
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
    fn test_regex_sha2_valid_case2() {
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
        let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2Circuit2::<Fr>::MAX_BYTES_SIZE];
        let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2Circuit2::<Fr>::MAX_BYTES_SIZE];
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
            get_substr(&input_str, &[
                r"(?<=subject:).*(?=\r)".to_string(),
                r"(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-| )*((a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+)?".to_string(),
                r"(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-| )*".to_string()
                ]).unwrap(),
        ];
        for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
            for (idx, char) in chars.as_bytes().iter().enumerate() {
                expected_masked_chars[start + idx] = Fr::from(*char as u64);
                expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
            }
        }
        let circuit = TestRegexSha2Circuit2::<Fr> { input, _f: PhantomData };
        let expected_output = Sha256::digest(&circuit.input);
        let hash_fs = expected_output.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
        let prover = MockProver::run(TestRegexSha2Circuit2::<Fr>::K, &circuit, vec![hash_fs, expected_masked_chars, expected_substr_ids]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
