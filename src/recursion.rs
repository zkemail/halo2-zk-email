use crate::eth::deploy_and_call_verifiers;
// use crate::snark_verifier_sdk::*;
use crate::eth::gen_verifier::gen_sol_verifiers;
use crate::{default_config_params, DefaultEmailVerifyPublicInput};
// use crate::eth::{gen_evm_verifier_sols, gen_evm_verifier_yul};
use crate::utils::get_email_substrs;
use crate::vrm::DecomposedRegexConfig;
use crate::EMAIL_VERIFY_CONFIG_ENV;
use ark_std::{end_timer, start_timer};
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use ethereum_types::Address;
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{verify_proof, Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_base::halo2_proofs::poly::VerificationStrategy;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::thread_rng;
use regex_simple::Regex;
use rsa::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::loader::evm::{compile_yul, EvmLoader, ExecutorBuilder};
use snark_verifier::loader::LoadedScalar;
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier::verifier::PlonkVerifier;
use snark_verifier_sdk::evm::{encode_calldata, evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
// use snark_verifier_sdk::evm::{encode_calldata, gen_evm_proof_shplonk};
use snark_verifier_sdk::halo2::aggregation::PublicAggregationCircuit;
use snark_verifier_sdk::halo2::{gen_proof_shplonk, gen_snark_shplonk, PoseidonTranscript};
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use snark_verifier_sdk::{NativeLoader, Plonk};
use std::env::set_var;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// The number of limbs of the accumulator in the aggregation circuit.
pub const NUM_ACC_INSTANCES: usize = 4 * LIMBS;
/// The name of env variable for the path to the configuration json of the aggregation circuit.
pub const AGG_CONFIG_KEY: &'static str = "VERIFY_CONFIG";

pub fn gen_agg_key<C: CircuitExt<Fr>>(app_params: &ParamsKZG<Bn256>, agg_params: &ParamsKZG<Bn256>, app_pk: &ProvingKey<G1Affine>, app_circuits: Vec<C>) -> ProvingKey<G1Affine> {
    // set_var(EMAIL_VERIFY_CONFIG_ENV, app_circuit_config_path);
    // set_var(VERIFY_CONFIG_KEY, agg_circuit_config_path);
    let snarks = app_circuits
        .into_iter()
        .map(|c| gen_snark_shplonk(&app_params, &app_pk, c, &mut OsRng, None::<&str>))
        .collect_vec();
    println!("snarks generated");
    let agg_circuit = PublicAggregationCircuit::new(&agg_params, snarks, false, &mut OsRng);
    let agg_pk = gen_pk::<PublicAggregationCircuit>(&agg_params, &agg_circuit, None);
    println!("agg pk generated");
    agg_pk
}

pub fn evm_prove_agg<C: CircuitExt<Fr>>(
    app_params: &ParamsKZG<Bn256>,
    agg_params: &ParamsKZG<Bn256>,
    app_pk: &ProvingKey<G1Affine>,
    agg_pk: &ProvingKey<G1Affine>,
    app_circuits: Vec<C>,
) -> (Vec<u8>, Vec<Vec<Fr>>) {
    let snarks = app_circuits
        .into_iter()
        .map(|c| gen_snark_shplonk(&app_params, &app_pk, c, &mut OsRng, None::<&str>))
        .collect_vec();
    println!("snark generated");
    let agg_circuit = PublicAggregationCircuit::new(&agg_params, snarks, false, &mut OsRng);
    let instances = agg_circuit.instances();
    println!("instances {:?}", instances[0]);
    let proof = gen_evm_proof_shplonk(&agg_params, &agg_pk, agg_circuit, instances.clone(), &mut OsRng);
    println!("proof generated");
    (proof, instances)
}

pub fn gen_evm_verifier_agg(agg_params: &ParamsKZG<Bn256>, agg_vk: &VerifyingKey<G1Affine>, app_num_instances: usize) -> Vec<u8> {
    let num_instance = vec![app_num_instances + NUM_ACC_INSTANCES];
    let bytecode = gen_evm_verifier_shplonk::<PublicAggregationCircuit>(agg_params, agg_vk, num_instance, None::<&Path>);
    bytecode
}

pub fn evm_verify_agg(bytecode: Vec<u8>, proof: Vec<u8>, instances: Vec<Vec<Fr>>) {
    evm_verify(bytecode, true, instances, proof);
}
