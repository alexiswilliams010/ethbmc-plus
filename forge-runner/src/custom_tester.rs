use crate::custom_runner::{CustomMultiContractBuilder, CustomMultiContractRunner};
use crate::filter::{FilterArgs, ProjectPathsAwareFilter};

use forge::{
    cmd::{
        install::install_missing_dependencies,
        test::TestArgs,
    },
    decode::decode_console_logs,
    result::{
        SuiteResult,
        TestOutcome,
        TestStatus,
    },
    traces::{
        debug::{ContractSources, DebugTraceIdentifier},
        decode_trace_arena,
        render_trace_arena_inner,
        CallTraceDecoderBuilder,
        InternalTraceMode,
        TraceKind,
    },
};
use foundry_config::Config;
use foundry_cli::utils::LoadConfig;
use foundry_common::{
    sh_println,
    sh_warn,
    compile::ProjectCompiler,
    shell,
};
use foundry_compilers::{
    compilers::{multi::MultiCompiler},
    ProjectCompileOutput,
};
use foundry_evm::{
    traces::identifier::TraceIdentifiers,
};

use std::{
    sync::Arc,
    time::Instant,
    sync::{mpsc::channel},
};
use eyre::{bail, Result};
use tracing::debug;
use clap::Parser;

/// CLI arguments for custom test runner
#[derive(Clone, Debug, Parser)]
#[command(next_help_heading = "Symbolic Execution Testing Options")]
pub struct CustomTestArgs {
    #[command(flatten)]
    pub test: TestArgs,

    #[command(flatten)]
    pub filter: FilterArgs,

    // TODO: add custom options for propagating symbolic execution args
}

impl CustomTestArgs {
    pub async fn run(self) -> Result<TestOutcome> {
        debug!(target: "forge::test", "executing custom test command");
        self.execute_tests().await
    }

    /// Returns the flattened [`FilterArgs`] arguments merged with [`Config`].
    /// Loads and applies filter from file if only last test run failures performed.
    pub fn filter(&self, config: &Config) -> Result<ProjectPathsAwareFilter> {
        let mut filter = self.filter.clone();
        if filter.path_pattern.is_some() {
            if self.test.path.is_some() {
                bail!("Can not supply both --match-path and |path|");
            }
        } else {
            filter.path_pattern = self.test.path.clone();
        }
        Ok(filter.merge_with_config(config))
    }

    /// Executes all the tests in the project.
    ///
    /// This will trigger the build process first. On success all test contracts that match the
    /// configured filter will be executed
    ///
    /// Returns the test results for all matching tests.
    pub async fn execute_tests(self) -> Result<TestOutcome> {
        // Merge all configs.
        let (mut config, evm_opts) = self.test.load_config_and_evm_opts()?;

        // Install missing dependencies.
        if install_missing_dependencies(&mut config) && config.auto_detect_remappings {
            // need to re-configure here to also catch additional remappings
            config = self.test.load_config()?;
        }

        // Set up the project.
        let project = config.project()?;

        let internal_filter = self.test.filter(&config)?;
        debug!(target: "forge::test", ?internal_filter, "using filter");

        let sources_to_compile = self.test.get_sources_to_compile(&config, &internal_filter)?;

        let compiler = ProjectCompiler::new()
            .dynamic_test_linking(config.dynamic_test_linking)
            .quiet(shell::is_json())
            .files(sources_to_compile);

        let output = compiler.compile(&project)?;

        // Create test options from general project settings and compiler output.
        let project_root = &project.paths.root;

        // Determine print verbosity and executor verbosity.
        let verbosity = evm_opts.verbosity;
        let env = evm_opts.evm_env().await?;

        // Default to simple internal tracing.
        let decode_internal = InternalTraceMode::Simple;

        // Prepare the test builder.
        let config = Arc::new(config);
        let runner: CustomMultiContractRunner = CustomMultiContractBuilder::new(config.clone())
            .set_decode_internal(decode_internal)
            .initial_balance(evm_opts.initial_balance)
            .evm_spec(config.evm_spec_id())
            .sender(evm_opts.sender)
            .with_fork(evm_opts.get_fork(&config, env.clone()))
            .enable_isolation(evm_opts.isolate)
            .build::<MultiCompiler>(project_root, &output, env, evm_opts)?;

        let pub_filter = self.filter(&config)?;
        let outcome = self.run_tests(runner, config, verbosity, &pub_filter, &output).await?;

        Ok(outcome)
    }

    /// Run all tests that matches the filter predicate from a test runner
    pub async fn run_tests(
        &self,
        mut runner: CustomMultiContractRunner,
        config: Arc<Config>,
        verbosity: u8,
        filter: &ProjectPathsAwareFilter,
        output: &ProjectCompileOutput,
    ) -> eyre::Result<TestOutcome> {
        debug!(target: "forge::test", "running all tests");

        // If we need to render to a serialized format, we should not print anything else to stdout.
        let silent = shell::is_json() || self.test.summary && shell::is_json();

        let num_filtered = runner.inner.matching_test_functions(filter).count();

        // If exactly one test matched, we enable full tracing.
        let decode_internal = if num_filtered == 1 {
            runner.inner.decode_internal = InternalTraceMode::Full;
            true
        } else {
            false
        };

        let remote_chain_id = runner.inner.evm_opts.get_remote_chain_id().await;
        let known_contracts = runner.inner.known_contracts.clone();

        let libraries = runner.inner.libraries.clone();

        // Run tests in a streaming fashion.
        let (tx, rx) = channel::<(String, SuiteResult)>();
        let timer = Instant::now();
        let handle = tokio::task::spawn_blocking({
            let filter = filter.clone();
            move || runner.test(&filter, tx)
        });

        // Set up trace identifiers.
        let mut identifier = TraceIdentifiers::new().with_local(&known_contracts);
        identifier = identifier.with_etherscan(&config, remote_chain_id)?;

        // Build the trace decoder.
        let mut builder = CallTraceDecoderBuilder::new()
            .with_known_contracts(&known_contracts)
            .with_verbosity(verbosity);

        if decode_internal {
            let sources =
                ContractSources::from_project_output(output, &config.root, Some(&libraries))?;
            builder = builder.with_debug_identifier(DebugTraceIdentifier::new(sources));
        }
        let mut decoder = builder.build();

        let mut outcome = TestOutcome::empty(true);

        let mut any_test_failed = false;
        for (contract_name, suite_result) in rx {
            let tests = &suite_result.test_results;

            // Clear the addresses and labels from previous test.
            decoder.clear_addresses();

            // We identify addresses if we're going to print *any* trace or gas report.
            let identify_addresses = verbosity >= 3;

            // Print suite header.
            if !silent {
                sh_println!()?;
                for warning in &suite_result.warnings {
                    sh_warn!("{warning}")?;
                }
                if !tests.is_empty() {
                    let len = tests.len();
                    let tests = if len > 1 { "tests" } else { "test" };
                    sh_println!("Ran {len} {tests} for {contract_name}")?;
                }
            }

            // Process individual test results, printing logs and traces when necessary.
            for (name, result) in tests {
                let show_traces = result.status == TestStatus::Failure;
                if !silent {
                    sh_println!("{}", result.short_result(name))?;

                    // We only display logs at level 2 and above
                    if verbosity >= 2 && show_traces {
                        // We only decode logs from Hardhat and DS-style console events
                        let console_logs = decode_console_logs(&result.logs);
                        if !console_logs.is_empty() {
                            sh_println!("Logs:")?;
                            for log in console_logs {
                                sh_println!("  {log}")?;
                            }
                            sh_println!()?;
                        }
                    }
                }

                // We shouldn't break out of the outer loop directly here so that we finish
                // processing the remaining tests and print the suite summary.
                any_test_failed |= result.status == TestStatus::Failure;

                // Clear the addresses and labels from previous runs.
                decoder.clear_addresses();
                decoder
                    .labels
                    .extend(result.labeled_addresses.iter().map(|(k, v)| (*k, v.clone())));

                // Identify addresses and decode traces.
                let mut decoded_traces = Vec::with_capacity(result.traces.len());
                for (kind, arena) in &mut result.traces.clone() {
                    if identify_addresses {
                        decoder.identify(arena, &mut identifier);
                    }

                    // verbosity:
                    // - 0..3: nothing
                    // - 3: only display traces for failed tests
                    // - 4: also display the setup trace for failed tests
                    // - 5..: display all traces for all tests, including storage changes
                    let should_include = match kind {
                        TraceKind::Execution => {
                            (verbosity == 3 && result.status.is_failure()) || verbosity >= 4
                        }
                        TraceKind::Setup => {
                            (verbosity == 4 && result.status.is_failure()) || verbosity >= 5
                        }
                        TraceKind::Deployment => false,
                    };

                    if should_include {
                        decode_trace_arena(arena, &decoder).await;
                        decoded_traces.push(render_trace_arena_inner(arena, false, verbosity > 4));
                    }
                }

                if !silent && show_traces && !decoded_traces.is_empty() {
                    sh_println!("Traces:")?;
                    for trace in &decoded_traces {
                        sh_println!("{trace}")?;
                    }
                }
            }

            // Print suite summary.
            if !silent {
                sh_println!("{}", suite_result.summary())?;
            }

            // Add the suite result to the outcome.
            outcome.results.insert(contract_name, suite_result);

            // Stop processing the remaining suites if any test failed and `fail_fast` is set.
            if self.test.fail_fast && any_test_failed {
                break;
            }
        }
        outcome.last_run_decoder = Some(decoder);
        let duration = timer.elapsed();

        debug!(target: "forge::test", len=outcome.results.len(), %any_test_failed, "done with results");

        if !self.test.summary && !shell::is_json() {
            sh_println!("{}", outcome.summary(duration))?;
        }

        // Reattach the task.
        if let Err(e) = handle.await {
            match e.try_into_panic() {
                Ok(payload) => std::panic::resume_unwind(payload),
                Err(e) => return Err(e.into()),
            }
        }

        Ok(outcome)
    }
}
