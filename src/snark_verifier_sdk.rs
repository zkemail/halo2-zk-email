use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_base::utils::value_to_option;
use halo2_wrong_ecc::halo2::circuit::AssignedCell;
use itertools::Itertools;
use rand::rngs::OsRng;
use snark_verifier::{
    loader::{
        evm::{self, encode_calldata, Address, EvmLoader, ExecutorBuilder},
        native::NativeLoader,
    },
    pcs::kzg::{Gwc19, KzgAs, LimbsEncoding},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::marker::PhantomData;
use std::{io::Cursor, rc::Rc};

pub const LIMBS: usize = 3; //4;
pub const NUM_ACC_INSTANCES: usize = 4 * LIMBS;
const BITS: usize = 88; //68;

type As = KzgAs<Bn256, Gwc19>;
type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;

use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{self, ConstraintSystem, Error},
};
use halo2_wrong_ecc::{
    integer::rns::Rns,
    maingate::{
        MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
        RegionCtx,
    },
    EccConfig,
};
use snark_verifier::{
    loader::{self},
    pcs::{
        kzg::{KzgAccumulator, KzgSuccinctVerifyingKey, LimbsEncodingInstructions},
        AccumulationScheme, AccumulationSchemeProver,
    },
    system,
    util::arithmetic::{fe_to_limbs, FieldExt},
    verifier::plonk::PlonkProtocol,
};

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 60;

type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, BaseFieldEccChip>;
pub type PoseidonTranscript<L, S> =
    system::halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

pub struct Snark {
    protocol: PlonkProtocol<G1Affine>,
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
}

impl Snark {
    pub fn new(protocol: PlonkProtocol<G1Affine>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> Self {
        Self {
            protocol,
            instances,
            proof,
        }
    }
}

impl From<Snark> for SnarkWitness {
    fn from(snark: Snark) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

#[derive(Clone)]
pub struct SnarkWitness {
    protocol: PlonkProtocol<G1Affine>,
    instances: Vec<Vec<Value<Fr>>>,
    proof: Value<Vec<u8>>,
}

impl SnarkWitness {
    fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }

    fn proof(&self) -> Value<&[u8]> {
        self.proof.as_ref().map(Vec::as_slice)
    }
}

pub trait CircuitExt<F: FieldExt>: Circuit<F> + Clone {
    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        None
    }
    fn num_instances(num_snarks: usize) -> Vec<usize>;
    fn instances(&self) -> Vec<Vec<F>>;
}

pub fn aggregate<'a>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[SnarkWitness],
    as_proof: Value<&'_ [u8]>,
) -> (
    KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
    Vec<AssignedCell<Fr, Fr>>,
) {
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances
                    .iter()
                    .map(|instance| loader.assign_scalar(*instance))
                    .collect_vec()
            })
            .collect_vec()
    };

    let snark_assigned_instances = snarks
        .iter()
        .map(|snark| assign_instances(&snark.instances))
        .collect_vec();

    let accumulators = snarks
        .iter()
        .zip(snark_assigned_instances.iter())
        .flat_map(|(snark, instances)| {
            let protocol = snark.protocol.loaded(loader);
            // let instances = assign_instances(&snark.instances);
            let mut transcript =
                PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, snark.proof());
            let proof =
                PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript)
                    .unwrap();
            PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap()
        })
        .collect_vec();

    let acccumulator = {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, as_proof);
        let proof = As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
        As::verify(&Default::default(), &accumulators, &proof).unwrap()
    };

    let prev_instances = snark_assigned_instances
        .iter()
        .flat_map(|instances| {
            instances
                .iter()
                .flat_map(|instances| {
                    instances
                        .iter()
                        .map(|instance| instance.assigned().clone())
                        .collect::<Vec<AssignedCell<_, _>>>()
                })
                .collect::<Vec<AssignedCell<_, _>>>()
        })
        .collect::<Vec<AssignedCell<_, _>>>();

    (acccumulator, prev_instances)
}

#[derive(Clone)]
pub struct PublicAggregationConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl PublicAggregationConfig {
    pub fn configure<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
        composition_bits: Vec<usize>,
        overflow_bits: Vec<usize>,
    ) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config =
            RangeChip::<F>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
        PublicAggregationConfig {
            main_gate_config,
            range_config,
        }
    }

    pub fn main_gate(&self) -> MainGate<Fr> {
        MainGate::new(self.main_gate_config.clone())
    }

    pub fn range_chip(&self) -> RangeChip<Fr> {
        RangeChip::new(self.range_config.clone())
    }

    pub fn ecc_chip(&self) -> BaseFieldEccChip {
        BaseFieldEccChip::new(EccConfig::new(
            self.range_config.clone(),
            self.main_gate_config.clone(),
        ))
    }
}

#[derive(Clone)]
pub struct PublicAggregationCircuit<C: CircuitExt<Fr>> {
    svk: Svk,
    snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
    as_proof: Value<Vec<u8>>,
    _c: PhantomData<C>,
}

impl<C: CircuitExt<Fr>> PublicAggregationCircuit<C> {
    pub fn new(params: &ParamsKZG<Bn256>, snarks: impl IntoIterator<Item = Snark>) -> Self {
        let svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();

        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
                let proof = PlonkSuccinctVerifier::read_proof(
                    &svk,
                    &snark.protocol,
                    &snark.instances,
                    &mut transcript,
                )
                .unwrap();
                PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof)
                    .unwrap()
            })
            .collect_vec();

        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
            let accumulator =
                As::create_proof(&Default::default(), &accumulators, &mut transcript, OsRng)
                    .unwrap();
            (accumulator, transcript.finalize())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_proof: Value::known(as_proof),
            _c: PhantomData,
        }
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl<C: CircuitExt<Fr>> CircuitExt<Fr> for PublicAggregationCircuit<C> {
    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..NUM_ACC_INSTANCES).map(|idx| (0, idx)).collect())
    }

    fn num_instances(num_snarks: usize) -> Vec<usize> {
        let num_instance_per_snark = C::num_instances(0).iter().sum::<usize>();
        vec![NUM_ACC_INSTANCES + num_instance_per_snark * num_snarks]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        let acc = self.instances.clone();
        let app_instances = self
            .snarks
            .iter()
            .flat_map(|snark| {
                snark.instances.iter().flat_map(|instances| {
                    instances
                        .iter()
                        .map(|instance| value_to_option(*instance).unwrap())
                        .collect_vec()
                })
            })
            .collect_vec();
        vec![vec![acc, app_instances].concat()]
    }
}

impl<C: CircuitExt<Fr>> Circuit<Fr> for PublicAggregationCircuit<C> {
    type Config = PublicAggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: Vec::new(),
            as_proof: Value::unknown(),
            _c: PhantomData,
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        PublicAggregationConfig::configure(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();

        range_chip.load_table(&mut layouter)?;

        let (accumulator_limbs, prev_instances) = layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let (accumulator, prev_instances) =
                    aggregate(&self.svk, &loader, &self.snarks, self.as_proof());

                let accumulator_limbs = [accumulator.lhs, accumulator.rhs]
                    .iter()
                    .map(|ec_point| {
                        loader
                            .ecc_chip()
                            .assign_ec_point_to_limbs(&mut loader.ctx_mut(), ec_point.assigned())
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten();
                Ok((accumulator_limbs, prev_instances))
            },
        )?;
        let mut num_acc_limbs = 0;
        for (row, limb) in accumulator_limbs.enumerate() {
            main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
            num_acc_limbs += 1;
        }

        for (row, value) in prev_instances.into_iter().enumerate() {
            main_gate.expose_public(layouter.namespace(|| ""), value, num_acc_limbs + row)?;
        }

        Ok(())
    }
}

pub fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

pub fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

pub fn gen_proof_native<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
) -> Vec<u8> {
    let instances = circuit.instances();
    gen_proof::<C, _, PoseidonTranscript<NativeLoader, _>, PoseidonTranscript<NativeLoader, _>>(
        params, pk, circuit, instances,
    )
}

pub fn gen_proof_evm<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
) -> Vec<u8> {
    let instances = circuit.instances();
    gen_proof::<C, _, EvmTranscript<G1Affine, _, _, _>, EvmTranscript<G1Affine, _, _, _>>(
        params, pk, circuit, instances,
    )
}

fn gen_proof<C, E, TR, TW>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8>
where
    C: Circuit<Fr>,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
{
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, TR, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

pub fn gen_application_snark<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    circuit: &C,
    pk: &ProvingKey<G1Affine>,
) -> Snark {
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg().with_num_instance(C::num_instances(0)),
    );
    let instances = circuit.instances();
    let proof = gen_proof::<
        _,
        _,
        PoseidonTranscript<NativeLoader, _>,
        PoseidonTranscript<NativeLoader, _>,
    >(params, &pk, circuit.clone(), instances.clone());
    Snark::new(protocol, instances, proof)
}

pub fn gen_app_evm_verifier_yul<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
) -> String {
    let num_instance = C::num_instances(0);
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    loader.yul_code()
}

pub fn gen_aggregation_evm_verifier_yul<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_aggregated_snarks: usize,
) -> String {
    let num_instance = PublicAggregationCircuit::<C>::num_instances(num_aggregated_snarks);
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(PublicAggregationCircuit::<C>::accumulator_indices()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    loader.yul_code()
}

pub fn evm_verify(bytecode: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm
            .deploy(caller, bytecode.into(), 0.into())
            .address
            .unwrap();
        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        dbg!(result.gas_used);

        !result.reverted
    };
    assert!(success);
}
