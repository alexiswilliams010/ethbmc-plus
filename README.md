# EthBMC-Plus: A Bounded Model Checker for Smart Contracts

## Background

EthBMC-Plus is a fork of [EthBMC](https://github.com/RUB-SysSec/EthBMC), which has not seen any updates in recent years. In addition to updating outdated software versions, EthBMC-Plus provides several new features from the original, including integrations with Rust-native EVM implementation [Revm](https://github.com/bluealloy/revm/tree/main).

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

### Usage
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

Currently, the primary way to use EthBMC-Plus is to create an input yml file (see examples):
```
./target/release/ethbmc-plus examples/rubixi/rubixi.yml
```

Note when executing the parity example (examples/parity) we recommend limiting the loop execution to 1 and use concrete-copy. The bug can still be found without these restrictions, but it takes a long time.

```
./target/release/ethbmc-plus -b1 --concrete-copy examples/parity/parity.yml
```

#### YAML Format 

The yaml format allows to easily initialise a multi-account environment offline. Under state you list all the accounts which should be present in the environment. Each account gets its address as a key. Additionally you can set the balance of the accounts, the nonce and the code field. Optionally you can supply storage. These are key-value pairs which get loaded as the initial storage of an account, otherwise it is assumed empty. Additionally you must supply a victim address. This is the account from which the analysis is started. See for example the example for analysing the parity hack:

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

We initialise two accounts, the wallet account, which holds the stub for forwarding all requests to the library, and the Receiver account, the parity library. We additionally supply some funds to it, to simulate a hack of the wallet, as well as setting the first storage variable (0x0) (the variable holding the address of the library contract) to the second account in the environment.

## Tests

- Test can only be run one at a time at the moment (cargo test -- --test-threads=1)
- Integration tests take a long time and should allways be run with optimizations (cargo test integra --release -- --ignored)

## EthBMC BibTeX

[EthBMC](https://www.usenix.org/system/files/sec20-frank.pdf) paper BibTex entry:
```
@inproceedings {frank2020ethbmc,
	title={ETHBMC: A Bounded Model Checker for Smart Contracts},
  	author={Frank, Joel and Aschermann, Cornelius and Holz, Thorsten},
	booktitle = {USENIX Security Symposium (USENIX Security)},
	year = {2020},
}
```
