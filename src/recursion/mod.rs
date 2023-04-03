use crate::impl_email_verify_circuit;
use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_dynamic_sha256::Field;
use halo2_regex::defs::{AllstrRegexDef, SubstrRegexDef};
use halo2_rsa::{RSAPublicKey, RSASignature};
use rand::rngs::OsRng;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_proof_shplonk, gen_snark_shplonk},
    CircuitExt, Snark,
};
use std::env::set_var;

use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
// use mail_auth::{dkim::{self, Canonicalization}, common::{headers::Writable, verify::VerifySignature}, AuthenticatedMessage, Resolver, DkimResult};
use num_bigint::BigUint;
// use mail_auth::{common::{crypto::{RsaKey},headers::HeaderWriter},dkim::DkimSigner};
// use mail_parser::{decoders::base64::base64_decode,  Message, Addr, HeaderValue};
use crate::EmailVerifyConfig;
use rand::Rng;

pub fn gen_app_proving_key<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    circuit: &C,
) -> ProvingKey<G1Affine> {
    gen_pk(params, circuit, None)
}

pub fn gen_snark<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    circuit: C,
    pk: &ProvingKey<G1Affine>,
) -> Snark {
    gen_snark_shplonk(params, pk, circuit, &mut OsRng, None::<&str>)
}

pub fn gen_aggregation_proving_key(
    params: &ParamsKZG<Bn256>,
    snarks: impl IntoIterator<Item = Snark>,
    config_filepath: &str,
) -> ProvingKey<G1Affine> {
    set_var("VERIFY_CONFIG", config_filepath);
    let agg_circuit = AggregationCircuit::new(params, snarks, &mut OsRng);
    gen_pk(params, &agg_circuit, None)
}

pub fn gen_aggregation_snark(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    snarks: impl IntoIterator<Item = Snark>,
    config_filepath: &str,
) -> Snark {
    set_var("VERIFY_CONFIG", config_filepath);
    let agg_circuit = AggregationCircuit::new(params, snarks, &mut OsRng);
    gen_snark(params, agg_circuit.clone(), pk)
}

pub fn gen_aggregation_proof(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    snarks: impl IntoIterator<Item = Snark>,
    config_filepath: &str,
) -> Vec<u8> {
    let snark = gen_aggregation_snark(params, pk, snarks, config_filepath);
    snark.proof
}

pub fn gen_multi_layer_proving_keys<C: CircuitExt<Fr> + Clone>(
    params: &ParamsKZG<Bn256>,
    circuit: &C,
) -> (
    ProvingKey<G1Affine>,
    ProvingKey<G1Affine>,
    ProvingKey<G1Affine>,
) {
    let app_pk = gen_app_proving_key(params, circuit);
    let app_snarks = [(); 2].map(|_| gen_snark(params, circuit.clone(), &app_pk));
    let app_to_agg_pk =
        gen_aggregation_proving_key(params, app_snarks.clone(), "./configs/app_to_agg.config");
    let app_to_agg_snarks = (0..2)
        .map(|_| {
            gen_aggregation_snark(
                params,
                &app_to_agg_pk,
                app_snarks.to_vec(),
                "./configs/app_to_agg.config",
            )
        })
        .collect::<Vec<Snark>>();
    let agg_to_agg_pk =
        gen_aggregation_proving_key(params, app_to_agg_snarks, "./configs/agg_to_agg.config");
    (app_pk, app_to_agg_pk, agg_to_agg_pk)
}

pub fn gen_multi_layer_proof<C: CircuitExt<Fr> + Clone>(
    params: &ParamsKZG<Bn256>,
    circuits: &[C],
    app_pk: &ProvingKey<G1Affine>,
    app_to_agg_pk: &ProvingKey<G1Affine>,
    agg_to_agg_pk: &ProvingKey<G1Affine>,
    log2_proofs: u32,
) -> Vec<u8> {
    let mut n_proof = circuits.len();
    assert_eq!(2usize.pow(log2_proofs), n_proof);
    let mock = start_timer!(|| format!("{} app snarks generation", n_proof));
    let app_snarks = (0..n_proof)
        .map(|i| gen_snark(params, circuits[i].clone(), app_pk))
        .collect::<Vec<Snark>>();
    end_timer!(mock);
    if log2_proofs == 0 {
        return (&app_snarks[0].proof).clone();
    }
    n_proof = n_proof >> 1;
    let mut agg_snarks = (0..n_proof)
        .map(|idx| {
            let mock = start_timer!(|| "app_to_agg snarks generation");
            let snark = gen_aggregation_snark(
                params,
                &app_to_agg_pk,
                [app_snarks[2 * idx].clone(), app_snarks[2 * idx + 1].clone()],
                "./configs/app_to_agg.config",
            );
            end_timer!(mock);
            snark
        })
        .collect::<Vec<Snark>>();
    if log2_proofs == 1 {
        debug_assert_eq!(agg_snarks.len(), 1);
        return agg_snarks[0].proof.clone();
    }
    n_proof = n_proof >> 1;
    while n_proof > 0 {
        for idx in 0..n_proof {
            let mock = start_timer!(|| "agg_to_agg snarks generation");
            agg_snarks[idx] = gen_aggregation_snark(
                params,
                agg_to_agg_pk,
                [agg_snarks[2 * idx].clone(), agg_snarks[2 * idx + 1].clone()],
                "./configs/agg_to_agg.config",
            );
            end_timer!(mock);
        }
        agg_snarks.drain(n_proof..);
        n_proof = n_proof >> 1;
    }
    debug_assert_eq!(agg_snarks.len(), 1);
    agg_snarks[0].proof.clone()
}
