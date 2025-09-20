# EthBMC-Plus: A Bounded Model Checker for Smart Contracts

### Background

EthBMC-Plus is a fork of [EthBMC](https://github.com/RUB-SysSec/EthBMC), which has not seen any updates in recent years. In addition to updating outdated software versions, EthBMC-Plus provides several new features from the original, including integrations with Rust-native EVM implementation [Revm](https://github.com/bluealloy/revm/tree/main) and [Foundry](https://github.com/foundry-rs/foundry).

## Requirements

To compile EthBMC-Plus you will need the latest Rust nightly.

### SMT Solvers

- EthBMC-Plus currently supports three SMT solvers:
    - [Yices2](https://github.com/SRI-CSL/yices2) [default solver used]
	- [Z3](https://github.com/Z3Prover/z3)
	- [Boolector](https://github.com/Boolector/boolector)

### Building

EthBMC-Plus uses `cargo` for compilation. External SMT solvers must be downloaded or compiled separately.

Note when analyzing big contracts you might have to increase Rusts stack size, see [here](https://stackoverflow.com/questions/29937697/how-to-set-the-thread-stack-size-during-compile-time).

## Usage
EthBMC-Plus can be used directly, or used as part of the integration with Foundry.

### Directly
```
EthBMC-Plus 1.0.0
EthBMC-Plus: A Bounded Model Checker for Smart Contracts

USAGE:
    ethbmc-plus [FLAGS] [OPTIONS] <INPUT>

FLAGS:
        --concrete-copy       Use concrete calldatacopy
    -d, --debug-grap          Dump debug graph after analysis
        --no-optimizations    Disable all optimizations
        --dump-solver         Dump all solver queries to ./queries
    -h, --help                Prints help information
        --json                Output json without logging
        --no-verify           Skip verification phase
        --symbolic-storage    Use symbolic storage mode

    -V, --version             Prints version information

OPTIONS:
    -c, --call-bound <call_bound>            Set bound for calls
        --cores <cores>                      Set the amount of cores the se can use
    -b, --loop-bound <loop_bound>            Set bound for loops
    -m, --message-bound <message_bound>      Set bound for message iteration
        --solver <solver>                    The SMT solver to use: z3, boolector, yices2 [yices2]
        --solver-timeout <solver-timeout>    Set solver timeout in milliseconds

ARGS:
    <INPUT>    Set input file
```

To invoke EthBMC-Plus directly, you will need to create an input yaml file (see [examples/](./examples/) folder). Once the yaml file exists, you can run:
```
./target/release/ethbmc-plus examples/rubixi/rubixi.yml
```

Note when executing the parity example (examples/parity) you should limit the loop execution to 1 and use concrete-copy. The bug can still be found without these restrictions, but it takes a long time.

```
./target/release/ethbmc-plus -b1 --concrete-copy examples/parity/parity.yml
```

#### YAML Format 

The yaml format allows you to easily initialize a multi-account environment offline. Under state, you list all the accounts which should be present in the environment. Each account gets its address as a key. Additionally you can set the balance of the accounts, the nonce and the code field. Optionally you can supply storage. These are key-value pairs which get loaded as the initial storage of an account, otherwise it is assumed empty. Additionally you must supply a victim address. This is the account from which the analysis is started. See for example the example for analysing the parity hack:

```
state: 
    # Wallet
    0xad62f08b3b9f0ecc7251befbeff80c9bb488fe9:
        balance: 0x8AC7230489E80000
        nonce: 0x0
        code: 606060...
        storage:
            0x0: 0xcafecafecafecafecafecafecafecafecafecafe # "owner"

    # Receiver
    0xcafecafecafecafecafecafecafecafecafecafe:
        balance: 0x0
        nonce: 0x0
        code: 60606...

victim: 0xad62f08b3b9f0ecc7251befbeff80c9bb488fe9
```

Two accounts are initialized, the wallet account, which holds the stub for forwarding all requests to the library, and the Receiver account, the parity library. Funds are supplied to the account, to simulate a hack of the wallet, as well as setting the first storage variable (0x0) (the variable holding the address of the library contract) to the second account in the environment.

### Foundry

EthBMC-Plus has also been integrated with Foundry to make it easier to generate tests that can be solved and decode counter-examples. This is accomplished using the logic in [forge-runner/](./forge-runner/) to create a custom test runner and tester that integrates with EthBMC-Plus. Any test with the word "prove" will be run with the custom tester that creates, invokes EthBMC-Plus, and decodes the results.

#### Example

Using a trivial example of a contract backdoor, a test can be generated to prove a counterexample exists:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

contract Backdoor {
    // adapted from https://github.com/foundry-rs/foundry/issues/2851
    function backdoor(uint256 x) external pure returns(uint256 number) {
        number = 99;
        unchecked {
            uint256 z = x - 1;
            if (z == 6912213124124531) {
                number = 0;
            } else {
                number = 1;
            }
        }
    }
}

contract BackdoorTest is Test {
    Backdoor public temp;

    function setUp() public {
        temp = new Backdoor();
    }

    function test_proveBackdoor(uint256 x) public view {
        uint256 number = temp.backdoor(x);
        assert(number != 0);
    }
}
```

forge-runner is invoked just like forge, but has additional arguments for symbolic execution:

```bash
$ ./target/release/forge-runner -h

CLI arguments for custom test runner

Usage: forge-runner [OPTIONS] [PATH]

Options:
  -h, --help  Print help (see more with '--help')

Display options:
...standard forge test options...

      --symbolic-storage                 The flag indicating whether to assume that default storage values are symbolic
      --concrete-validation              The flag indicating whether to perform concrete counterexample validation
      --solver <SOLVER>                  The SMT solver to be used during symbolic analysis {0: z3, 1: boolector, 2: yices2} [default: 0]
      --solver-timeout <SOLVER_TIMEOUT>  The timeout (ms) for the solver [default: 100000]
      --loop-bound <LOOP_BOUND>          The number of loops to be unrolled in a single execution [default: 5]
      --call-bound <CALL_BOUND>          The number of calls symbolically analyzed in a sequence [default: 1]
```

When invoking forge-runner on the above test, a decoded counterexample should be created:

```bash
$ ./target/release/forge-runner

Ran 1 test for test/BackdoorTest.t.sol:BackdoorTest
[FAIL; counterexample:          vm.prank(0x0DFA72de72F96Cf5B127b070e90d68eC9710797C);
                BackdoorTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496).test_proveBackdoor(6912213124124532);] test_proveBackdoor(uint256) (gas: 0)
Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 49.09s (49.09s CPU time)
```

## Tests

- Test can only be run one at a time at the moment: `cargo test -- --test-threads=1`
- Integration tests take a long time and should allways be run with optimizations: `cargo test integra --release -- --ignored`

## Acknowledgements

- SaferMaker / baolean's [work](https://hackmd.io/@SaferMaker/EVM-Sym-Test) to improve EthBMC and integrate it with Foundry.
- The original authors of [EthBMC](https://www.usenix.org/system/files/sec20-frank.pdf) for creating the tool. BibTex entry:
```
@inproceedings {frank2020ethbmc,
	title={ETHBMC: A Bounded Model Checker for Smart Contracts},
  	author={Frank, Joel and Aschermann, Cornelius and Holz, Thorsten},
	booktitle = {USENIX Security Symposium (USENIX Security)},
	year = {2020},
}
```
