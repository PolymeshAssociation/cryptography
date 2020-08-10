# MERCAT CLI

This directory contains the cli and the test harness for [Ploymesh cryptography library][cryptography].

The following describes how to run the MERCAT clis, for a description of the MERCAT test harness, refer
to [common][harness] directory.

To use these clis, it is best to follow the following sequence of operations. First, decide on a directory
that will serve as your blockchain storage. The path of this directory will be passed to the following CLIs.

1. Setup the chain by specifying the list of valid ticker names.
   ```bash
   $ mercat-chain-setup --ticker-names ACME AAPL # args [refer to the cli's help for the most up to date list of arguments]
   ```

2. Use account cli to create an empty account for two users by running
   ```bash
   $ mercat-account create # args
   ```

   This will simulate the "account create transaction" on a blockchain.

3. Use the mediator cli to create the keypairs for the mediator's account by running
   ```bash
   $ mercat-mediator create # args
   ```

4. Next, you need to simulate what the network validators would do by running the validator cli,
   ```bash
   $ mercat-validator
   ```

5. After this point, you can run the following to decrypt the account balance at any time.
   ```bash
   $ mercat-chain-setup # args
   ```

6. Now, you need to issue some tokens to the account by running
   ```bash
   $ mercat-account issue # args
   ```

7. In contrast to the previous account creation transaction, issuing tokens requires mediator's approval.
   To simulate this step, run
   ```bash
   mercat-mediator justify-issuance-transaction # args
   ```

8. Similar to the previous case, you need to verify this transaction by running
   ```bash
   $ mercat-validator
   ```

9. Now that you have created three accounts and have issued some tokens to one of them,
   you can initiate a confidential transaction using the account cli by running
   ```bash
   $ mercat-account create-transaction # args
   ```

10. After initiating a confidential transaction, you need to simulate what the receiver of a confidential transaction
   does, by running
   ```bash
   $ mercat-account finalize-transaction # args
   ```

11. Similar to the token issuance, the confidential transfer also requires the approval of the mediator.
   To simulate it, run
   ```bash
   mercat-mediator justify-transfer-transaction # args
   ```

12. Finally, validate the transaction using
   ```bash
   $ mercat-validator
   ```


[cryptography]: https://github.com/PolymathNetwork/cryptography
[harness]: https://github.com/PolymathNetwork/crypto-framework/tree/master/mercat/common