use esvm;

use forge::{
    multi_runner::{TestContract, TestRunnerConfig},
    decode::SkipReason,
    result::{SuiteResult, TestResult, TestSetup},
    TestFilter,
    ContractRunner, MultiContractRunner,
    multi_runner::DeployableContracts,
};
use foundry_compilers::{
    artifacts::Contract,
    compilers::Compiler,
    Artifact, ArtifactId, ProjectCompileOutput,
};
use foundry_common::{
    get_contract_name,
    TestFunctionExt,
    TestFunctionKind,
    ContractsByArtifact,
};
use foundry_config::{Config, InlineConfig};
use foundry_evm::{
    executors::{Executor, ITest},
    traces::{TraceMode, InternalTraceMode},
    decode::RevertDecoder,
    backend::Backend,
    fork::CreateFork,
    opts::EvmOpts,
    Env,
};
use foundry_linking::{LinkOutput, Linker};
use revm::primitives::{Address, U256, hardfork::SpecId, address, Bytes};
use alloy_json_abi::Function;
use serde::{Serialize, Deserialize};
use std::{
    borrow::{Cow, Borrow},
    collections::BTreeMap,
    sync::{mpsc, Arc},
    time::Instant,
    path::Path,
};
use eyre::Result;
use rayon::prelude::*;
use tracing::{Span, debug, debug_span, enabled};

pub const LIBRARY_DEPLOYER: Address = address!("0x1F95D37F27EA0dEA9C252FC09D5A6eaA97647353");

/// Arguments for symbolic execution testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::Args)]
pub struct SymbolicConfig {
    /// The flag indicating whether to assume that default storage values are symbolic
    #[arg(long)]
    pub symbolic_storage: bool,
    /// The flag indicating whether to perform concrete counterexample validation
    #[arg(long)]
    pub concrete_validation: bool,
    /// The SMT solver to be used during symbolic analysis {0: z3, 1: boolector, 2: yices2}
    #[arg(long, default_value = "0")]
    pub solver: u8,
    /// The timeout (ms) for the solver
    #[arg(long, default_value = "100000")]
    pub solver_timeout: u32,
    /// The number of loops to be unrolled in a single execution
    #[arg(long, default_value = "5")]
    pub loop_bound: u32,
    /// The number of calls symbolically analyzed in a sequence
    #[arg(long, default_value = "1")]
    pub call_bound: u32,
}

impl Default for SymbolicConfig {
    fn default() -> Self {
        SymbolicConfig {
            symbolic_storage: false,
            concrete_validation: true,
            solver: 0, // z3
            solver_timeout: 100_000,
            loop_bound: 5,
            call_bound: 1, // symbolically executing tests
        }
    }
}

pub struct CustomMultiContractBuilder {
    // Options taken from MultiContractRunnerBuilder
    /// The sender address for the tests
    pub sender: Option<Address>,
    /// The initial balance for each one of the deployed smart contracts
    pub initial_balance: U256,
    /// The EVM spec to use
    pub evm_spec: Option<SpecId>,
    /// The fork to use at launch
    pub fork: Option<CreateFork>,
    /// Project config.
    pub config: Arc<Config>,
    /// Whether to enable steps tracking in the tracer.
    pub decode_internal: InternalTraceMode,
    /// Whether to enable call isolation
    pub isolation: bool,
    /// The additional symbolic configurations
    pub symbolic: SymbolicConfig,
}

impl CustomMultiContractBuilder {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            sender: Default::default(),
            initial_balance: Default::default(),
            evm_spec: Default::default(),
            fork: Default::default(),
            config,
            decode_internal: Default::default(),
            isolation: Default::default(),
            symbolic: Default::default(),
        }
    }

    pub fn sender(mut self, sender: Address) -> Self {
        self.sender = Some(sender);
        self
    }

    pub fn initial_balance(mut self, initial_balance: U256) -> Self {
        self.initial_balance = initial_balance;
        self
    }

    pub fn evm_spec(mut self, spec: SpecId) -> Self {
        self.evm_spec = Some(spec);
        self
    }

    pub fn with_fork(mut self, fork: Option<CreateFork>) -> Self {
        self.fork = fork;
        self
    }

    pub fn set_decode_internal(mut self, mode: InternalTraceMode) -> Self {
        self.decode_internal = mode;
        self
    }

    pub fn enable_isolation(mut self, enable: bool) -> Self {
        self.isolation = enable;
        self
    }

    pub fn with_symbolic_config(mut self, config: SymbolicConfig) -> Self {
        self.symbolic = config;
        self
    }

    /// Given an EVM, proceeds to return a runner which is able to execute all tests
    /// against that evm
    pub fn build<C: Compiler<CompilerContract = Contract>>(
        self,
        root: &Path,
        output: &ProjectCompileOutput,
        env: Env,
        evm_opts: EvmOpts,
    ) -> Result<CustomMultiContractRunner> {
        let contracts = output
            .artifact_ids()
            .map(|(id, v)| (id.with_stripped_file_prefixes(root), v))
            .collect();
        let linker = Linker::new(root, contracts);

        // Build revert decoder from ABIs of all artifacts.
        let abis = linker
            .contracts
            .iter()
            .filter_map(|(_, contract)| contract.abi.as_ref().map(|abi| abi.borrow()));
        let revert_decoder = RevertDecoder::new().with_abis(abis);

        let LinkOutput { libraries, libs_to_deploy } = linker.link_with_nonce_or_address(
            Default::default(),
            LIBRARY_DEPLOYER,
            0,
            linker.contracts.keys(),
        )?;

        let linked_contracts = linker.get_linked_artifacts(&libraries)?;

        // Create a mapping of name => (abi, deployment code, Vec<library deployment code>)
        let mut deployable_contracts = DeployableContracts::default();

        for (id, contract) in linked_contracts.iter() {
            let Some(abi) = &contract.abi else { continue };

            // if it's a test, link it and add to deployable contracts
            if abi.constructor.as_ref().map(|c| c.inputs.is_empty()).unwrap_or(true) &&
                abi.functions().any(|func| func.name.is_any_test())
            {
                let Some(bytecode) =
                    contract.get_bytecode_bytes().map(|b| b.into_owned()).filter(|b| !b.is_empty())
                else {
                    continue;
                };

                deployable_contracts
                    .insert(id.clone(), TestContract { abi: abi.clone(), bytecode });
            }
        }

        let known_contracts = ContractsByArtifact::new(linked_contracts);

        Ok(CustomMultiContractRunner {
            symbolic: self.symbolic,
            inner: MultiContractRunner {
                contracts: deployable_contracts,
                revert_decoder,
                known_contracts,
                libs_to_deploy,
                libraries,

                fork: self.fork,

                tcfg: TestRunnerConfig {
                    evm_opts,
                    env,
                    spec_id: self.evm_spec.unwrap_or_else(|| self.config.evm_spec_id()),
                    sender: self.sender.unwrap_or(self.config.sender),

                    decode_internal: self.decode_internal,
                    inline_config: Arc::new(InlineConfig::new_parsed(output, &self.config)?),
                    isolation: self.isolation,

                    coverage: Default::default(),
                    debug: Default::default(),
                    odyssey: Default::default(),

                    config: self.config,
                },
            }
        })
    }
}

pub struct CustomMultiContractRunner {
    /// The inner multi-contract runner.
    pub inner: MultiContractRunner,
    /// The symbolic configuration.
    pub symbolic: SymbolicConfig,
}

impl CustomMultiContractRunner {
    pub fn test(
        &mut self,
        filter: &dyn TestFilter,
        tx: mpsc::Sender<(String, SuiteResult)>,
    ) -> Result<()> {
        let tokio_handle = tokio::runtime::Handle::current();
        debug!("running all tests");

        // The DB backend that serves all the data.
        let db = Backend::spawn(self.inner.fork.take())?;

        let find_timer = Instant::now();
        let contracts = self.inner.matching_contracts(filter).collect::<Vec<_>>();
        let find_time = find_timer.elapsed();
        debug!(
            "Found {} test contracts out of {} in {:?}",
            contracts.len(),
            self.inner.contracts.len(),
            find_time,
        );

        contracts.par_iter().try_for_each(|&(id, contract)| {
            let _guard = tokio_handle.enter();
            let result = self.run_test_suite(id, contract, &db, filter, &tokio_handle)?;
            tx.send((id.identifier(), result)).map_err(|e| eyre::eyre!("Failed to send result: {}", e))
        })
    }

    pub fn run_test_suite(&self,
        artifact_id: &ArtifactId,
        contract: &TestContract,
        db: &Backend,
        filter: &dyn TestFilter,
        tokio_handle: &tokio::runtime::Handle,
    ) -> Result<SuiteResult> {
        let identifier = artifact_id.identifier();
        let mut span_name = identifier.as_str();

        if !enabled!(tracing::Level::TRACE) {
            span_name = get_contract_name(&identifier);
        }
        let span = debug_span!("suite", name = %span_name);
        let span_local = span.clone();
        let _guard = span_local.enter();

        debug!("start executing all tests in contract");

        let executor = self.inner.tcfg.executor(self.inner.known_contracts.clone(), artifact_id, db.clone());
        // Instantiate the CustomContractRunner
        let runner = CustomContractRunner::new(
            &identifier,
            contract,
            executor,
            tokio_handle,
            span,
            &self.inner,
            self.symbolic,
        );
        let r = runner.run_tests(filter);

        debug!(duration=?r.duration, "executed all tests in contract");

        Ok(r)
    }
}

pub struct CustomContractRunner<'a> {
    pub inner: ContractRunner<'a>,
    /// The name of the contract.
    pub name: &'a str,
    /// The data of the contract.
    pub contract: &'a TestContract,
    /// The EVM executor.
    pub executor: Executor,
    /// The handle to the tokio runtime.
    pub tokio_handle: &'a tokio::runtime::Handle,
    /// The span of the contract.
    pub span: tracing::Span,
    /// The contract-level configuration.
    pub tcfg: Cow<'a, TestRunnerConfig>,
    /// The parent runner.
    pub mcr: &'a MultiContractRunner,
    /// The symbolic configuration.
    pub symbolic: SymbolicConfig,
}

impl<'a> std::ops::Deref for CustomContractRunner<'a> {
    type Target = Cow<'a, TestRunnerConfig>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.tcfg
    }
}

impl<'a> CustomContractRunner<'a> {
    pub fn new(
        name: &'a str,
        contract: &'a TestContract,
        executor: Executor,
        tokio_handle: &'a tokio::runtime::Handle,
        span: Span,
        mcr: &'a MultiContractRunner,
        symbolic: SymbolicConfig,
    ) -> Self {
        Self {
            inner: ContractRunner::new(
                name,
                contract,
                executor.clone(),
                None,
                tokio_handle,
                span.clone(),
                mcr,
            ),
            name,
            contract,
            executor,
            tokio_handle,
            span,
            tcfg: Cow::Borrowed(&mcr.tcfg),
            mcr,
            symbolic,
        }
    }

    /// Configures this runner with the inline configuration for the contract.
    pub fn apply_contract_inline_config(&mut self) -> Result<()> {
        if self.inline_config.contains_contract(self.name) {
            let new_config = Arc::new(self.inline_config(None)?);
            self.tcfg.to_mut().reconfigure_with(new_config);
            let prev_tracer = self.executor.inspector_mut().tracer.take();
            self.tcfg.configure_executor(&mut self.executor);
            // Don't set tracer here.
            self.executor.inspector_mut().tracer = prev_tracer;
        }
        Ok(())
    }

    /// Returns the configuration for a contract or function.
    pub fn inline_config(&self, func: Option<&Function>) -> Result<Config> {
        let function = func.map(|f| f.name.as_str()).unwrap_or("");
        let config =
            self.mcr.inline_config.merge(self.name, function, &self.config).extract::<Config>()?;
        Ok(config)
    }

    /// Runs all tests for a contract whose names match the provided regular expression
    pub fn run_tests(mut self, filter: &dyn TestFilter) -> SuiteResult {
        let start = Instant::now();
        let mut warnings = Vec::new();

        // Check if `setUp` function with valid signature declared.
        let setup_fns: Vec<_> =
            self.contract.abi.functions().filter(|func| func.name.is_setup()).collect();
        let call_setup = setup_fns.len() == 1 && setup_fns[0].name == "setUp";
        // There is a single miss-cased `setUp` function, so we add a warning
        for &setup_fn in &setup_fns {
            if setup_fn.name != "setUp" {
                warnings.push(format!(
                    "Found invalid setup function \"{}\" did you mean \"setUp()\"?",
                    setup_fn.signature()
                ));
            }
        }

        // There are multiple setUp function, so we return a single test result for `setUp`
        if setup_fns.len() > 1 {
            return SuiteResult::new(
                start.elapsed(),
                [("setUp()".to_string(), TestResult::fail("multiple setUp functions".to_string()))]
                    .into(),
                warnings,
            )
        }

        let prev_tracer = self.executor.inspector_mut().tracer.take();
        if prev_tracer.is_some() {
            self.executor.set_tracing(TraceMode::Call);
        }

        let setup_time = Instant::now();
        let setup = self.inner.setup(call_setup);
        debug!("finished setting up in {:?}", setup_time.elapsed());

        self.executor.inspector_mut().tracer = prev_tracer;

        if setup.reason.is_some() {
            // The setup failed, so we return a single test result for `setUp`
            let fail_msg = if !setup.deployment_failure {
                "setUp()".to_string()
            } else {
                "constructor()".to_string()
            };
            return SuiteResult::new(
                start.elapsed(),
                [(fail_msg, TestResult::setup_result(setup))].into(),
                warnings,
            )
        }

        // Filter out functions sequentially since it's very fast and there is no need to do it
        // in parallel.
        let find_timer = Instant::now();
        let functions = self
            .contract
            .abi
            .functions()
            .filter(|func| is_matching_test(func, filter))
            .collect::<Vec<_>>();
        debug!(
            "Found {} test functions out of {} in {:?}",
            functions.len(),
            self.contract.abi.functions().count(),
            find_timer.elapsed(),
        );

        let test_fail_instances = functions
            .iter()
            .filter_map(|func| {
                TestFunctionKind::classify(&func.name, !func.inputs.is_empty())
                    .is_any_test_fail()
                    .then_some(func.name.clone())
            })
            .collect::<Vec<_>>();

        if !test_fail_instances.is_empty() {
            let instances = format!(
                "Found {} instances: {}",
                test_fail_instances.len(),
                test_fail_instances.join(", ")
            );
            let fail =  TestResult::fail("`testFail*` has been removed. Consider changing to test_Revert[If|When]_Condition and expecting a revert".to_string());
            return SuiteResult::new(start.elapsed(), [(instances, fail)].into(), warnings)
        }

        let test_results = functions
            .par_iter()
            .map(|&func| {
                let start = Instant::now();

                let _guard = self.tokio_handle.enter();

                let _guard;
                let current_span = tracing::Span::current();
                if current_span.is_none() || current_span.id() != self.span.id() {
                    _guard = self.span.enter();
                }

                let sig = func.signature();
                let kind = func.test_function_kind();

                let _guard = debug_span!(
                    "test",
                    %kind,
                    name = %if enabled!(tracing::Level::TRACE) { &sig } else { &func.name },
                )
                .entered();

                let mut res = CustomFunctionRunner::new(&self, &setup).run(
                    func,
                );
                res.duration = start.elapsed();

                (sig, res)
            })
            .collect::<BTreeMap<_, _>>();

        let duration = start.elapsed();
        SuiteResult::new(duration, test_results, warnings)
    }
}

struct CustomFunctionRunner<'a> {
    /// The function-level configuration.
    tcfg: Cow<'a, TestRunnerConfig>,
    /// The EVM executor.
    executor: Cow<'a, Executor>,
    /// The parent runner.
    cr: &'a CustomContractRunner<'a>,
    /// The address of the test contract.
    address: Address,
    /// The test setup result.
    setup: &'a TestSetup,
    /// The test result. Returned after running the test.
    result: TestResult,
}

impl<'a> std::ops::Deref for CustomFunctionRunner<'a> {
    type Target = Cow<'a, TestRunnerConfig>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.tcfg
    }
}

impl<'a> CustomFunctionRunner<'a> {
    fn new(cr: &'a CustomContractRunner<'a>, setup: &'a TestSetup) -> Self {
        Self {
            tcfg: match &cr.tcfg {
                Cow::Borrowed(tcfg) => Cow::Borrowed(tcfg),
                Cow::Owned(tcfg) => Cow::Owned(tcfg.clone()),
            },
            executor: Cow::Borrowed(&cr.executor),
            cr,
            address: setup.address,
            setup,
            result: TestResult::new(setup),
        }
    }

    fn revert_decoder(&self) -> &'a RevertDecoder {
        &self.cr.mcr.revert_decoder
    }

    /// Configures this runner with the inline configuration for the contract.
    fn apply_function_inline_config(&mut self, func: &Function) -> Result<()> {
        if self.inline_config.contains_function(self.cr.name, &func.name) {
            let new_config = Arc::new(self.cr.inline_config(Some(func))?);
            self.tcfg.to_mut().reconfigure_with(new_config);
            self.tcfg.configure_executor(self.executor.to_mut());
        }
        Ok(())
    }

    fn run(
        mut self,
        func: &Function,
    ) -> TestResult {
        if let Err(e) = self.apply_function_inline_config(func) {
            self.result.single_fail(Some(e.to_string()));
            return self.result;
        }

        if is_symbolic_test(func) {
            self.run_symbolic_exec_test(func)
        } else {
            self.result.single_skip(SkipReason(Some("No symbolic execution test found".to_string())));
            return self.result;
        }
    }

    fn run_symbolic_exec_test(
        &mut self,
        func: &Function,
    ) -> TestResult {
        // Prepare unit test execution.
        if self.prepare_test(func).is_err() {
            return self.result.clone();
        }

        // Run current unit test.
        // TODO: This is where the symbolic execution happens.

        // Return the result.
        // TODO: This is a stub - needs to be replaced.
        let mut res = TestResult::new(self.setup);
        res
    }

    /// Prepares single unit test and fuzz test execution:
    /// - set up the test result and executor
    /// - check if before test txes are configured and apply them in order
    ///
    /// Before test txes are arrays of arbitrary calldata obtained by calling the `beforeTest`
    /// function with test selector as a parameter.
    ///
    /// Unit tests within same contract (or even current test) are valid options for before test tx
    /// configuration. Test execution stops if any of before test txes fails.
    fn prepare_test(&mut self, func: &Function) -> Result<(), ()> {
        let address = self.setup.address;

        // Apply before test configured functions (if any).
        if self.cr.contract.abi.functions().filter(|func| func.name.is_before_test_setup()).count() ==
            1
        {
            for calldata in self.executor.call_sol_default(
                address,
                &ITest::beforeTestSetupCall { testSelector: func.selector() },
            ) {
                // Apply before test configured calldata.
                match self.executor.to_mut().transact_raw(
                    self.tcfg.sender,
                    address,
                    calldata,
                    U256::ZERO,
                ) {
                    Ok(call_result) => {
                        let reverted = call_result.reverted;

                        // Merge tx result traces in unit test result.
                        self.result.extend(call_result);

                        // To continue unit test execution the call should not revert.
                        if reverted {
                            self.result.single_fail(None);
                            return Err(());
                        }
                    }
                    Err(_) => {
                        self.result.single_fail(None);
                        return Err(());
                    }
                }
            }
        }
        Ok(())
    }
}

fn is_matching_test(func: &Function, filter: &dyn TestFilter) -> bool {
    func.is_any_test() && filter.matches_test(&func.signature())
}

fn is_symbolic_test(func: &Function) -> bool {
    func.is_any_test() && func.name.starts_with("prove")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolicCase {
    /// The calldata to be executed
    pub calldata: Bytes,
}
