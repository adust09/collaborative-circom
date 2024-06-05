use std::{collections::HashMap, rc::Rc};

use ark_ec::pairing::Pairing;
use mpc_core::protocols::{
    aby3::network::{Aby3MpcNet, Aby3Network},
    plain::PlainDriver,
};
use mpc_net::config::NetworkConfig;

use crate::{
    mpc_vm::{Aby3WitnessExtension, PlainWitnessExtension, WitnessExtension},
    op_codes::CodeBlock,
};
use eyre::Result;

#[derive(Clone)]
pub struct TemplateDecl {
    pub(crate) symbol: String,
    pub(crate) input_signals: usize,
    pub(crate) signal_size: usize,
    pub(crate) sub_components: usize,
    pub(crate) vars: usize,
    pub(crate) mappings: Vec<usize>,
    pub(crate) body: Rc<CodeBlock>,
}

impl TemplateDecl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol: String,
        input_signals: usize,
        signal_size: usize,
        sub_components: usize,
        vars: usize,
        mappings: Vec<usize>,
        body: CodeBlock,
    ) -> Self {
        Self {
            symbol,
            input_signals,
            signal_size,
            sub_components,
            vars,
            mappings,
            body: Rc::new(body),
        }
    }
}

pub struct FunDecl {
    pub(crate) num_params: usize,
    pub(crate) vars: usize,
    pub(crate) body: Rc<CodeBlock>,
}

impl FunDecl {
    pub fn new(num_params: usize, vars: usize, body: CodeBlock) -> Self {
        Self {
            num_params,
            vars,
            body: Rc::new(body),
        }
    }
}

pub type InputList = Vec<(String, usize, usize)>;

pub struct CollaborativeCircomCompilerParsed<P: Pairing> {
    pub(crate) main: String,
    pub(crate) amount_signals: usize,
    pub(crate) constant_table: Vec<P::ScalarField>,
    pub(crate) string_table: Vec<String>,
    pub(crate) fun_decls: HashMap<String, FunDecl>,
    pub(crate) templ_decls: HashMap<String, TemplateDecl>,
    pub(crate) signal_to_witness: Vec<usize>,
    pub(crate) main_inputs: usize,
    pub(crate) main_outputs: usize,
    pub(crate) main_input_list: InputList,
}

impl<P: Pairing> CollaborativeCircomCompilerParsed<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        main: String,
        amount_signals: usize,
        constant_table: Vec<P::ScalarField>,
        string_table: Vec<String>,
        fun_decls: HashMap<String, FunDecl>,
        templ_decls: HashMap<String, TemplateDecl>,
        signal_to_witness: Vec<usize>,
        main_inputs: usize,
        main_outputs: usize,
        main_input_list: InputList,
    ) -> Self {
        Self {
            main,
            amount_signals,
            constant_table,
            string_table,
            fun_decls,
            templ_decls,
            signal_to_witness,
            main_inputs,
            main_outputs,
            main_input_list,
        }
    }
}

impl<P: Pairing> CollaborativeCircomCompilerParsed<P> {
    pub fn to_plain_vm(self) -> WitnessExtension<P, PlainDriver> {
        PlainWitnessExtension::new(self)
    }

    pub fn to_aby3_vm(
        self,
        network_config: NetworkConfig,
    ) -> Result<Aby3WitnessExtension<P, Aby3MpcNet>> {
        Aby3WitnessExtension::new(self, network_config)
    }

    pub fn to_aby3_vm_with_network<N: Aby3Network>(
        self,
        network: N,
    ) -> Result<Aby3WitnessExtension<P, N>> {
        Aby3WitnessExtension::from_network(self, network)
    }
}
