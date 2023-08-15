// Orriginal https://github.com/SoraSuegami/halo2-fri-gadget/blob/main/src/hash/poseidon_bn254/chip.rs
use halo2_base::halo2_proofs::halo2curves::{bn256::Fr, group::ff::PrimeField};
use halo2_base::halo2_proofs::{arithmetic::FieldExt, plonk::*};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use poseidon::{Poseidon, SparseMDSMatrix, Spec, State};
use std::marker::PhantomData;

pub trait HasherChip<F: FieldExt> {
    type Digest<'v>: HasherChipDigest<F>;

    fn new(ctx: &mut Context<F>, main_gate: &FlexGateConfig<F>) -> Self;

    fn hash_elements<'v>(&'v self, ctx: &mut Context<'_, F>, main_chip: &FlexGateConfig<F>, values: &[AssignedValue<'v, F>]) -> Result<Self::Digest<'v>, Error>;

    fn hash_digests<'v>(&self, ctx: &mut Context<'_, F>, main_chip: &FlexGateConfig<F>, values: Vec<Self::Digest<'v>>) -> Result<Self::Digest<'v>, Error> {
        todo!();
        //let elements = values
        //    .iter()
        //    .flat_map(|x| x.to_assigned().to_vec())
        //    .collect::<Vec<_>>();
        //self.hash_elements(ctx, main_chip, &elements)
    }
}

// HASHER CHIP DIGEST
// =========================================================================

pub trait HasherChipDigest<F: FieldExt>: Clone {
    fn to_assigned(&self) -> &[AssignedValue<F>];
}

#[derive(Clone)]
pub struct Digest<'v, F: FieldExt, const N: usize>(pub [AssignedValue<'v, F>; N]);

impl<'a, F: FieldExt, const N: usize> Digest<'a, F, N> {
    pub fn new(values: Vec<AssignedValue<'a, F>>) -> Digest<'a, F, N> {
        Self(values.try_into().unwrap())
    }
}

impl<F: FieldExt, const N: usize> HasherChipDigest<F> for Digest<'_, F, N> {
    fn to_assigned(&self) -> &[AssignedValue<F>] {
        self.0[..].as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct PoseidonChipBn254_8_58<'a, F: FieldExt>(PoseidonChip<'a, F, FlexGateConfig<F>, 4, 3>);

impl<F: FieldExt> HasherChip<F> for PoseidonChipBn254_8_58<'_, F> {
    type Digest<'v> = Digest<'v, F, 1>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self(PoseidonChip::<F, FlexGateConfig<F>, 4, 3>::new(ctx, flex_gate, 8, 58).unwrap())
    }

    fn hash_elements<'v>(&'v self, ctx: &mut Context<'_, F>, main_chip: &FlexGateConfig<F>, values: &[AssignedValue<'v, F>]) -> Result<Self::Digest<'v>, Error> {
        let value = self.0.hash(ctx, main_chip, &values)?;
        Ok(Digest([value; 1]))
    }
}

#[derive(Clone)]
struct PoseidonState<'a, F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize> {
    s: [AssignedValue<'a, F>; T],
    _marker: PhantomData<A>,
}

impl<'a, F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize> PoseidonState<'a, F, A, T, RATE> {
    fn x_power5_with_constant<'v>(ctx: &mut Context<'_, F>, chip: &A, x: &AssignedValue<'v, F>, constant: &F) -> AssignedValue<'v, F> {
        let x2 = chip.mul(ctx, Existing(x), Existing(x));
        let x4 = chip.mul(ctx, Existing(&x2), Existing(&x2));
        chip.mul_add(ctx, Existing(x), Existing(&x4), Constant(*constant))
    }

    fn sbox_full(&mut self, ctx: &mut Context<'_, F>, chip: &A, constants: &[F; T]) -> Result<(), Error> {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(ctx, chip, x, constant);
        }
        Ok(())
    }

    fn sbox_part(&mut self, ctx: &mut Context<'_, F>, chip: &A, constant: &F) -> Result<(), Error> {
        let x = &mut self.s[0];
        *x = Self::x_power5_with_constant(ctx, chip, x, constant);

        Ok(())
    }

    fn absorb_with_pre_constants(&mut self, ctx: &mut Context<'_, F>, chip: &A, inputs: Vec<AssignedValue<'a, F>>, pre_constants: &[F; T]) -> Result<(), Error> {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;

        if let Some(s_0) = self.s.get_mut(offset) {
            *s_0 = chip.add(ctx, Existing(&s_0), Constant(F::one()));
        }

        for (x, input) in self.s.iter_mut().skip(1).zip(inputs.iter()) {
            *x = chip.add(ctx, Existing(x), Existing(input));
        }

        for (i, (x, constant)) in self.s.iter_mut().zip(pre_constants.iter()).enumerate() {
            *x = chip.add(ctx, Existing(x), Constant(*constant));
        }

        Ok(())
    }

    fn apply_mds(&mut self, ctx: &mut Context<'_, F>, chip: &A, mds: &[[F; T]; T]) -> Result<(), Error> {
        let res = mds
            .iter()
            .map(|row| {
                let sum = chip.inner_product(ctx, self.s.iter().map(|a| Existing(a)), row.iter().map(|c| Constant(*c)));
                Ok(sum)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        self.s = res.try_into().unwrap();

        Ok(())
    }

    fn apply_sparse_mds(&mut self, ctx: &mut Context<'_, F>, chip: &A, mds: &SparseMDSMatrix<F, T, RATE>) -> Result<(), Error> {
        let sum = chip.inner_product(ctx, self.s.iter().map(|a| Existing(a)), mds.row().iter().map(|c| Constant(*c)));
        let mut res = vec![sum];

        for (e, x) in mds.col_hat().iter().zip(self.s.iter().skip(1)) {
            res.push(chip.mul_add(ctx, Existing(&self.s[0]), Constant(*e), Existing(x)));
        }

        for (x, new_x) in self.s.iter_mut().zip(res.into_iter()) {
            *x = new_x
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PoseidonChip<'a, F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize> {
    init_state: [AssignedValue<'a, F>; T],
    spec: Spec<F, T, RATE>,
    _marker: PhantomData<A>,
}

impl<F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize> PoseidonChip<'_, F, A, T, RATE> {
    pub fn new(ctx: &mut Context<'_, F>, chip: &A, r_f: usize, r_p: usize) -> Result<Self, Error> {
        let init_state = State::<F, T>::default()
            .words()
            .into_iter()
            .map(|x| Ok(chip.assign_region(ctx, vec![Constant(x)], vec![]).pop().unwrap()))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        Ok(Self {
            spec: Spec::new(r_f, r_p),
            init_state: init_state.clone().try_into().unwrap(),
            _marker: PhantomData,
        })
    }

    pub fn hash<'v>(&self, ctx: &mut Context<'_, F>, chip: &A, elements: &[AssignedValue<'v, F>]) -> Result<AssignedValue<'v, F>, Error> {
        let init_state = State::<F, T>::default()
            .words()
            .into_iter()
            .map(|x| Ok(chip.assign_region(ctx, vec![Constant(x)], vec![]).pop().unwrap()))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let mut state = PoseidonState {
            s: init_state.try_into().unwrap(),
            _marker: PhantomData,
        };
        let mut absorbing = vec![];

        // Update
        absorbing.extend_from_slice(elements);

        // Squeeze
        let mut input_elements = vec![];
        input_elements.append(&mut absorbing);
        let mut padding_offset = 0;
        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, chip, &mut state, chunk.to_vec())?;
        }
        if padding_offset == 0 {
            self.permutation(ctx, chip, &mut state, vec![])?;
        }
        let out = state.s[1].clone();

        Ok(out)
    }

    fn permutation<'v>(&self, ctx: &mut Context<'_, F>, chip: &A, state: &mut PoseidonState<'v, F, A, T, RATE>, inputs: Vec<AssignedValue<'v, F>>) -> Result<(), Error> {
        let r_f = self.spec.r_f() / 2;
        let mds = &self.spec.mds_matrices().mds().rows();

        let constants = &self.spec.constants().start();
        state.absorb_with_pre_constants(ctx, chip, inputs, &constants[0])?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            state.sbox_full(ctx, chip, constants)?;
            state.apply_mds(ctx, chip, mds)?;
        }

        let pre_sparse_mds = &self.spec.mds_matrices().pre_sparse_mds().rows();
        state.sbox_full(ctx, chip, constants.last().unwrap())?;
        state.apply_mds(ctx, chip, pre_sparse_mds)?;

        let sparse_matrices = &self.spec.mds_matrices().sparse_matrices();
        let constants = &self.spec.constants().partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            state.sbox_part(ctx, chip, constant)?;
            state.apply_sparse_mds(ctx, chip, sparse_mds)?;
        }

        let constants = &self.spec.constants().end();
        for constants in constants.iter() {
            state.sbox_full(ctx, chip, constants)?;
            state.apply_mds(ctx, chip, mds)?;
        }
        state.sbox_full(ctx, chip, &[F::zero(); T])?;
        state.apply_mds(ctx, chip, mds)?;

        Ok(())
    }
}

// pub fn poseidon_hash(bytes: &[u8]) -> Fr {
//     let inputs = bytes.into_iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
//     poseidon_hash_fields(&inputs)
// }
pub fn poseidon_hash_fields<F: FieldExt>(inputs: &[F]) -> F {
    let mut hasher = Poseidon::<F, 4, 3>::new(8, 58);
    hasher.update(inputs);
    hasher.squeeze()
}
