use acir::native_types::Witness;

pub(crate) struct CoWitnessMap<T: Clone> {
    // we maybe switch the internal working from the witness map. For now take a vec
    witnesses: Vec<WitnessState<T>>,
}

#[derive(Clone)]
pub(crate) enum WitnessState<T: Clone> {
    Known(T),
    Unknown,
}

impl<T: Clone> Default for WitnessState<T> {
    fn default() -> Self {
        Self::Unknown
    }
}

impl<T: Clone> CoWitnessMap<T> {
    pub(super) fn new(witness_size: usize) -> Self {
        Self {
            witnesses: vec![WitnessState::Unknown; witness_size],
        }
    }

    pub(super) fn get(&self, witness: &Witness) -> WitnessState<T> {
        self.witnesses[usize::try_from(witness.0).expect("u32 fits into usize")].clone()
    }

    pub(super) fn insert(&mut self, witness: &Witness, value: T) {
        debug_assert!(
            self.is_unknown(witness),
            "witness must be unknown if you want to set"
        );
        self.witnesses[usize::try_from(witness.0).expect("u32 fits into usize")] =
            WitnessState::Known(value);
    }

    pub(super) fn is_unknown(&self, witness: &Witness) -> bool {
        matches!(
            self.witnesses[usize::try_from(witness.0).expect("u32 fits into usize")],
            WitnessState::Unknown
        )
    }

    pub(super) fn is_known(&self, witness: &Witness) -> bool {
        !self.is_unknown(witness)
    }
}
