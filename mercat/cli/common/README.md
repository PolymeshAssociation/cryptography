# MERCAT test harness

The goal of the test harness is to provide an easy to use configuration for defining various
scenarios that users can interact with the MERCAT library and ensure that the library produces
the correct output in those scenarios. The test harness tests both happy paths and the scenarios
where a party tries to cheat by sending incorrect data. Moreover, using the test harness, one
can configure whether to run a test on WASM or a powerful node hardware. Finally, when running the tests,
you can choose the verbosity of logging. If you pass "info" to the `RUST_LOG` environment variable,
the test harness will print the CLI commands for the operations it performs along with some
performance metrics, such as the time it took for each operation.


The starting point of the test harness is the configuration files inside the [scenarios/unittest][scenario].
In this directory, you can have two subdirectories:
- node: Indicates that the configurations inside it will be run on a powerful node hardware.
- wasm: Indicates that the configurations inside it will be run on a WASM.

Regardless of which hardware type you choose, the yaml configuration file will the be same, for example,
[scenarios/unittest/node/multiple_pending_sequence.yml][sample].

## Happy path config

The structure of the configuration file in the happy path is as follows.

```yaml
--- 
title: "Human readable title of the test case."

tickers: # List of all the valid ticker names
  - ACME
  - AAPL

accounts: # List of all the accounts that each user has. A user will have exactly
          # one account per ticker name.
          # These accounts are initially empty.
  - alice:
    - ACME
    - AAPL
  - bob:
    - ACME

mediators: # List of all the known mediators. For each of these mediators, a set of
           # keypairs is generated.
  - Mike
    
auditors: # List of all the known auditors. For each of these mediators, a set of
          # keypairs is generated.
  - Ava
  - Aubrey
    
transactions: # List of all transactions. This config must have exactly one
              # child, either a `sequence` or a `concurrent`.
  - sequence: # Runs its children sequentially.
    - validate # This validates the account creation steps.
    - issue Alice 100 ACME Mike approve # An asset issuance transaction.
    - issue Alice 100 ACME Mike approve auditors Ava,Aubrey tx_name AliceIssue # Optionally, asset issue transactions can be auditted by multiple auditors.
    - validate # without this, the account is not deposited at the time of the
               # next transaction
    - concurrent: # Runs its children concurrently.
      - transfer Alice 10 ACME Bob approve Mike approve # An asset transfer transaction.
      - transfer Alice 20 ACME Bob approve Mike approve
      - transfer Alice 30 ACME Bob approve Mike approve
      - transfer Alice 30 ACME Bob approve Mike approve auditors Ava,Aubrey tx_name AliceToBob # Optionally, asset transfer transactions can be auditted by multiple auditors.
    - validate
    - audit AliceIssue Ava # Auditors can audit a transaction by name at any point.
    - audit AliceToBob Aubrey

outcome: # Defines the expected value of each account after running all the transactions.
  - alice: 
      - ACME: 40
  - bob: 
      - ACME: 60

audit_outcome: # Defines the expected outcome of an audit.
  - ava:
    - AliceIssue: passed_audit
  - aubrey:
    - AliceToBob: failed_audit
```

## Cheating config

The structure of the configuration file in case of cheating parties.

1. Cheating in account creation.

```yaml
--- 
title: "Cheating in creating an account"

tickers: 
  - ACME
  - CHEAT # Reserved ticker name. A cheating party will use this.

accounts:
  - alice(cheat): # name(cheat) indicates that the party will
                  # cheat in this step.
    - ACME

transactions:
  - validate

outcome: 
  - alice:
    - NONE: 0 # Reserved keyword NONE, indicates that a party
              # does not have any validated public account.
```

2. Cheating in token issuance or token transfer.

```yaml
--- 
title: "Cheat in issuing tokens to a single account"

tickers: 
  - ACME

accounts:
  - alice:
    - ACME

mediators:
  - Mike
    
transactions:
  - sequence:
    - validate
    - issue Alice(cheat) 10 ACME Mike approve # name(cheat) indicates that the party will cheat.
    - validate

outcome: 
  - alice:
    - ACME: 0 # Account creation has been successful, but token issuance has failed,
              # hence the value of 0.

```

[scenario]: cli/mercat/common/scenarios/unittest
[sample]: cli/mercat/common/scenarios/unittest/node/multiple_pending_sequence.yml
