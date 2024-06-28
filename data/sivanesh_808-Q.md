
| Serial No | Title                                  | Contract/Code                 |
|-----------|----------------------------------------|-------------------------------|
| QA-1      | Vulnerability in ETH Handling          | THORChain_Router.sol          |
| QA-2      | Inadequate Fallback Mechanism          | THORChain_Router.sol          |
| QA-3      | Miscalculation and Potential Loss      | THORChain_Router.sol          |
| QA-4      | Inadequate Handling of Allowance       | THORChain_Router.sol          |
| QA-5      | Incorrect Balance Adjustments          | THORChain_Router.sol          |
| QA-6      | Decimal Handling                       | smartcontract_log_parser.go   |
| QA-7      | Inconsistent Event Handling            | smartcontract_log_parser.go   |
| QA-8      | Error Handling and Financial Risk      | smartcontract_log_parser.go   |
| QA-9      | Decimal Conversion Issue               | smartcontract_log_parser.go   |
| QA-10     | Inadequate Validation of Event         | smartcontract_log_parser.go   |
| QA-11     | Incorrect Asset Decimal Handling       | smartcontract_log_parser.go   |
| QA-12     | Insecure Gas Price Calculation         | ethereum_block_scanner.go     |
| QA-13     | Lack of Reorg Handling                 | ethereum_block_scanner.go     |
| QA-14     | Inefficient Gas Price Cache Update     | ethereum_block_scanner.go     |
| QA-15     | Incorrect ETH Conversion               | ethereum_block_scanner.go     |
| QA-16     | Inadequate Fee Calculation             | ethereum_block_scanner.go     |
| QA-17     | Mismanagement of Transaction Nonce     | ethereum_block_scanner.go     |


**[QA-1]** Vulnerability in ETH Handling during Fallback in `_deposit` and `transferOut` Functions

**Contract:** THORChain_Router.sol

**Description:** The contract is vulnerable to ETH being locked in the contract when the `vault.send(safeAmount)` or `to.send(safeAmount)` operation fails. The contract lacks a robust mechanism to handle the failure of these ETH transfers properly, leading to potential loss of funds.

**Code snippet:**
```solidity
function _deposit(
    address payable vault,
    address asset,
    uint amount,
    string memory memo
) private nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
        safeAmount = msg.value;
        bool success = vault.send(safeAmount);
        require(success);
    } else {
        require(msg.value == 0, "unexpected eth");
        safeAmount = safeTransferFrom(asset, amount);
        _vaultAllowance[vault][asset] += safeAmount;
    }
    emit Deposit(vault, asset, safeAmount, memo);
}
```

**Expected Behavior:** ETH should be securely transferred to the recipient or handled properly upon transfer failure.

**Expected Behavior code snippet:**
```solidity
(bool success, ) = vault.call{value: safeAmount}("");
require(success, "ETH transfer failed");
```

**Logic:**
1. User sends 1 ETH.
2. The function attempts to transfer 1 ETH to `vault`.
3. If the transfer fails, the transaction reverts, and ETH is returned to the user.

**Actual Behavior:** If the `send` fails, the contract does not provide an alternative method to handle the stuck funds.

**Actual Behavior code snippet:**
```solidity
bool success = vault.send(safeAmount);
require(success);
```

**Logic:**
1. User sends 1 ETH.
2. The function attempts to transfer 1 ETH to `vault`.
3. If the transfer fails, the ETH remains in the contract, potentially leading to financial loss for the user.

---

-----------------------------------------------------------------------------------------------------------------------------

**[QA-2]** Inadequate Fallback Mechanism in `transferOut` Function

**Contract:** THORChain_Router.sol

**Description:** Similar to the `_deposit` function, the `transferOut` function contains a vulnerability due to the inadequate handling of failed ETH transfers using `send`. This can result in ETH being permanently locked in the contract if the transfer fails, as there is no proper fallback or error handling mechanism to manage these scenarios.

**Code snippet:**
```solidity
function transferOut(
    address payable to,
    address asset,
    uint amount,
    string memory memo
) public payable nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
        safeAmount = msg.value;
        bool success = to.send(safeAmount); // Send ETH.
        if (!success) {
            payable(address(msg.sender)).transfer(safeAmount); // For failure, bounce back to vault & continue.
        }
    } else {
        _vaultAllowance[msg.sender][asset] -= amount; // Reduce allowance
        (bool success, bytes memory data) = asset.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))));
        safeAmount = amount;
    }
    emit TransferOut(msg.sender, to, asset, safeAmount, memo);
}
```

**Expected Behavior:** On failure of ETH transfer, the ETH should be securely returned to the sender or a proper retry mechanism should be in place.

**Expected Behavior code snippet:**
```solidity
(bool success, ) = to.call{value: safeAmount}("");
if (!success) {
    // Implement retry logic or return funds to sender securely
    revert("ETH transfer failed, funds returned to sender");
}
```

**Logic:**
1. Contract attempts to transfer `safeAmount` of ETH to `to`.
2. If `send` operation fails, it tries to return the ETH back to the sender.
3. Should handle return failure or provide an alternative mechanism.

**Actual Behavior:** The current implementation can lead to ETH getting locked in the contract if the fallback transfer fails.

**Actual Behavior code snippet:**
```solidity
bool success = to.send(safeAmount);
if (!success) {
    payable(address(msg.sender)).transfer(safeAmount); // For failure, bounce back to vault & continue.
}
```

**Logic:**
1. Contract attempts to transfer `safeAmount` of ETH to `to`.
2. If `send` fails, it tries to bounce the ETH back to the sender.
3. This second transfer can fail without any handling or logging, resulting in ETH locked within the contract.

---

It's recommended to revise the handling of ETH transfers using `.call` to provide more gas for recipients and to include explicit error handling or retries, thus aligning the practice with modern Solidity safety standards. This adjustment ensures that transaction failures are managed effectively, preserving contract integrity and user funds.


-------------------------------------------------------------------------------------------------------------------------



**[QA-3]** Miscalculation and Potential Loss of Funds in `safeTransferFrom` Function

**Contract:** THORChain_Router.sol

**Description:** The `safeTransferFrom` function is intended to handle the transfer of ERC-20 tokens while accounting for potential transfer fees by comparing the balances before and after the transfer. However, this function fails to revert the transaction or handle cases where the actual amount transferred is less than the requested amount due to token fees or other deductions, leading to a mismatch in balance tracking and potential loss of funds for users.

**Code snippet:**
```solidity
function safeTransferFrom(
    address _asset,
    uint _amount
) internal returns (uint amount) {
    uint _startBal = iERC20(_asset).balanceOf(address(this));
    (bool success, bytes memory data) = _asset.call(
        abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            msg.sender,
            address(this),
            _amount
        )
    );
    require(success && (data.length == 0 || abi.decode(data, (bool))));
    return (iERC20(_asset).balanceOf(address(this)) - _startBal);
}
```

**Expected Behavior:** The function should correctly calculate the transferred amount and revert if the actual amount received is less than expected, thus preventing any discrepancy in balance tracking.

**Expected Behavior code snippet:**
```solidity
function safeTransferFrom(
    address _asset,
    uint _amount
) internal returns (uint amount) {
    uint _startBal = iERC20(_asset).balanceOf(address(this));
    (bool success, bytes memory data) = _asset.call(
        abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            msg.sender,
            address(this),
            _amount
        )
    );
    require(success && (data.length == 0 || abi.decode(data, (bool))), "Transfer failed");
    uint transferredAmount = iERC20(_asset).balanceOf(address(this)) - _startBal;
    require(transferredAmount >= _amount, "Transferred amount less than required");
    return transferredAmount;
}
```

**Logic:**
1. Record the starting balance of the token in the contract.
2. Perform the transfer from the sender to the contract.
3. Calculate the difference in balance after the transfer.
4. If the actual transferred amount is less than what was requested, revert the transaction.

**Actual Behavior:** The function returns the difference in the balance, which may be less than the requested transfer amount due to fees or other deductions, without verifying that the full amount has been received.

**Actual Behavior code snippet:**
```solidity
return (iERC20(_asset).balanceOf(address(this)) - _startBal);
```

**Logic:**
1. Record the starting balance of the token.
2. Transfer the tokens from the sender to the contract.
3. Return the net change in the balance, which can be less than the intended amount if deductions apply, potentially leading to inconsistencies and unintended loss of tokens for users.

---

This calculation error could lead to scenarios where the contract operates with incorrect assumptions about token balances, thereby affecting subsequent transactions and user balances within the contract. It's critical to implement strict checks and balances in token handling functions to ensure consistency and prevent financial discrepancies.


Let's break down the Logic in both the expected and actual behaviors of the `safeTransferFrom` function to clarify the potential issues:

### Expected Behavior Logic

1. **Record Initial Balance:** The contract queries the token balance it holds before initiating the transfer. Let's say the initial balance is `initialBalance`.

2. **Transfer Requested:** The contract attempts to transfer `_amount` tokens from the sender to itself. For simplicity, assume `_amount` equals 100 tokens.

3. **Verify Transfer Success:** The contract checks if the `transferFrom` call was successful. If not, it reverts the transaction.

4. **Calculate Actual Transferred Amount:** After the transfer, the contract queries its new balance, referred to as `newBalance`. Let's say the new balance is `initialBalance + 98` due to some tokens being deducted as fees or for other reasons during the transfer.

5. **Check Amount Consistency:** The contract calculates the difference `newBalance - initialBalance` to find out the actual amount transferred. In our example, this would be `98 tokens`.

6. **Revert if Amount Is Insufficient:** The contract then checks if this amount is at least `_amount` (100 tokens). If it's less (as in our example, where only 98 tokens were received), the transaction is reverted to protect against loss of funds due to deductions.

### Actual Behavior Logic

1. **Record Initial Balance:** The same initial step, recording `initialBalance`.

2. **Transfer Requested:** The contract still attempts to transfer `_amount` (100 tokens) from the sender to itself.

3. **Verify Transfer Success:** The contract ensures the transfer was reported as successful by the token contract.

4. **Calculate Transferred Amount Difference:** The contract computes `newBalance - initialBalance`. Assume again `newBalance` is `initialBalance + 98`.

5. **Return the Difference:** Instead of checking if the received amount matches the requested amount, the contract directly returns the difference, which is 98 tokens.

6. **Potential Loss Not Handled:** In this scenario, the contract does not verify if the 98 tokens are adequate compared to the requested 100 tokens. It simply proceeds with the assumption that the transfer was correct, potentially leading to issues where less than the intended amount is credited, affecting balance accuracy and possibly leading to operational errors or financial loss.

In summary, the expected behavior includes a safeguard to revert transactions when the net transferred amount is less than what was demanded, ensuring integrity and consistency in token balances. The actual behavior, however, lacks this safeguard, allowing discrepancies to go unchecked and potentially resulting in a shortfall in credited funds.

--------------------------------------------------------------------------------------------------------------------------------------------



**[QA-4]** Inadequate Handling of Allowance Adjustments in `transferOut` Function

**Contract:** THORChain_Router.sol

**Description:** The `transferOut` function does not properly adjust the token allowances in case of a failed transaction when sending ERC-20 tokens. This oversight in the logic can result in the incorrect deduction of token allowances without the actual transfer of tokens, leading to a financial discrepancy and potential loss for users.

**Code snippet:**
```solidity
function transferOut(
    address payable to,
    address asset,
    uint amount,
    string memory memo
) public payable nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
        safeAmount = msg.value;
        bool success = to.send(safeAmount); // Send ETH.
        if (!success) {
            payable(address(msg.sender)).transfer(safeAmount); // For failure, bounce back to vault & continue.
        }
    } else {
        _vaultAllowance[msg.sender][asset] -= amount; // Reduce allowance
        (bool success, bytes memory data) = asset.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))));
        safeAmount = amount;
    }
    emit TransferOut(msg.sender, to, asset, safeAmount, memo);
}
```

**Expected Behavior:** Allowances should only be deducted after confirming the successful transfer of ERC-20 tokens.

**Expected Behavior code snippet:**
```solidity
function transferOut(
    address payable to,
    address asset,
    uint amount,
    string memory memo
) public payable nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
        safeAmount = msg.value;
        bool success = to.send(safeAmount); // Send ETH.
        if (!success) {
            payable(address(msg.sender)).transfer(safeAmount); // For failure, bounce back to vault & continue.
        }
    } else {
        (bool success, bytes memory data) = asset.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool)), "Transfer failed");
        _vaultAllowance[msg.sender][asset] -= amount; // Reduce allowance
        safeAmount = amount;
    }
    emit TransferOut(msg.sender, to, asset, safeAmount, memo);
}
```

**Logic:**
1. Check if the transaction is for ETH or ERC-20. If ERC-20, proceed with token transfer.
2. Attempt to transfer the ERC-20 tokens to the recipient `to`.
3. Only reduce the allowance from `_vaultAllowance` after ensuring the transfer was successful.

**Actual Behavior:** The function prematurely adjusts `_vaultAllowance` before confirming that the ERC-20 token transfer is successful.

**Actual Behavior code snippet:**
```solidity
_vaultAllowance[msg.sender][asset] -= amount; // Reduce allowance
(bool success, bytes memory data) = asset.call(
    abi.encodeWithSignature("transfer(address,uint256)", to, amount)
);
require(success && (data.length == 0 || abi.decode(data, (bool)));
```

**Logic:**
1. Deducts the allowance amount from `_vaultAllowance` for the ERC-20 token regardless of whether the transfer succeeds or fails.
2. Attempts the transfer.
3. If the transfer fails, the transaction is reverted, but the balance adjustment already made can lead to discrepancies in event and state tracking if not properly handled.


----------------------------------------------------------------------------------------------------


**[QA-5]** Incorrect Balance Adjustments in `_adjustAllowances` Function

**Contract:** THORChain_Router.sol

**Description:** The `_adjustAllowances` function adjusts token allowances between vaults but does not verify the actual token transfer success before adjusting the internal mapping of allowances. This lack of validation can lead to a scenario where the allowances are adjusted (i.e., increased or decreased) without the actual transfer of tokens, potentially leading to accounting errors and unauthorized access to funds.

**Code snippet:**
```solidity
function _adjustAllowances(
    address _newVault,
    address _asset,
    uint _amount
) internal {
    _vaultAllowance[msg.sender][_asset] -= _amount;
    _vaultAllowance[_newVault][_asset] += _amount;
}
```

**Expected Behavior:** The function should confirm the successful transfer of tokens between vaults before adjusting the allowances to ensure the internal state remains consistent with actual token holdings.

**Expected Behavior code snippet:**
```solidity
function _adjustAllowances(
    address _newVault,
    address _asset,
    uint _amount
) internal {
    // First confirm the actual transfer is successful
    require(
        safeTransferFromVault(msg.sender, _newVault, _asset, _amount),
        "Token transfer failed"
    );
    _vaultAllowance[msg.sender][_asset] -= _amount;
    _vaultAllowance[_newVault][_asset] += _amount;
}

function safeTransferFromVault(
    address fromVault,
    address toVault,
    address asset,
    uint amount
) internal returns (bool) {
    // Logic to transfer tokens safely between vaults and return true if successful
}
```

**Logic:**
1. Attempt to transfer the specified amount of tokens from one vault to another.
2. Only if the transfer is successful (verified by a function like `safeTransferFromVault`), adjust the allowance mappings to reflect the new balances.

**Actual Behavior:** The function prematurely adjusts allowances in the `_vaultAllowance` mapping without ensuring that the corresponding token transfers are successful.

**Actual Behavior code snippet:**
```solidity
_vaultAllowance[msg.sender][_asset] -= _amount;
_vaultAllowance[_newVault][_asset] += _amount;
```

**Logic:**
1. Deduct the specified amount from the sender's vault allowance.
2. Add the specified amount to the receiver's vault allowance.
3. No verification is performed to ensure that the tokens have actually moved between vaults, potentially leading to a situation where the token balance does not match the recorded allowances.

This premature adjustment of allowances could lead to situations where tokens are effectively double-spent or misallocated, leading to financial discrepancies and potential losses for stakeholders relying on the integrity of these balances. Proper synchronization of balance adjustments with actual token transfers is crucial to maintaining financial integrity within the contract.

--------------------------------------------------------------------------------------------------------------------------------------------------------------


**[QA-6]** Decimal Handling in `GetTxInItem` Function

**code:** smartcontract_log_parser.go

**Description:** The function `GetTxInItem` processes log entries to extract and convert amounts based on the token's decimal configuration. However, the code snippet provided does not show any evidence of handling decimal values when converting big integer amounts to the `cosmos.Uint` type. If the token's decimals are not correctly accounted for during the conversion, it could lead to financial discrepancies, such as representing token amounts incorrectly, either vastly inflating or deflating their true value in the transaction records.

**Code snippet:**
```go
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount)).WithDecimals(decimals));
```

**Expected Behavior:** The contract should convert the token amounts accurately according to the token's decimal configuration, ensuring that all financial calculations reflect the actual token values intended by the users.

**Expected Behavior code snippet:**
```go
// Assuming amtConverter properly adjusts the amount based on the token's decimals
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount, decimals)));
```

** logic:**
1. A deposit event is received with a token amount in its smallest unit (e.g., wei for ETH).
2. The function retrieves the decimal configuration for the token.
3. The amount is adjusted according to the decimals, converting it into a more human-readable format or the standard unit (e.g., ether for ETH).

**Actual Behavior:** The provided code snippet lacks visible handling or conversion logic taking into account the decimals of tokens, which could either underrepresent or overrepresent the amount of tokens deposited, leading to financial errors.

**Actual Behavior code snippet:**
```go
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount)).WithDecimals(decimals));
```

**logic:**
1. A deposit event is received, and the token amount is intended to be converted.
2. The decimal information is fetched but not utilized effectively in the conversion, possibly leading to incorrect financial representation in the contract's state or transaction outputs.


------------------------------------------------------------------------------------------


**[QA-7]** Inconsistent Event Handling in `GetTxInItem` Function

**code:** smartcontract_log_parser.go

**Description:** The `GetTxInItem` function handles different event logs but has a lack of consistent handling for scenarios where multiple events of a particular type (like `transferOutEvent`) occur in the same transaction. The code contains checks for multiple deposit events with different destination addresses but does not adequately handle similar scenarios for `transferOutEvent` or `transferAllowanceEvent`. This inconsistency can lead to financial discrepancies, especially in cases where multiple transfers should be recorded but are ignored due to early exits or missing validation.

**Code snippet:**
```go
if err != nil {
    scp.logger.Err(err).Msg("fail to parse transfer out event");
    continue;
}
m, err := memo.ParseMemo(common.LatestVersion, transferOutEvt.Memo);
if err != nil {
    scp.logger.Err(err).Str("memo", transferOutEvt.Memo).Msg("failed to parse transferOutEvent memo");
    continue;
}
if !m.IsOutbound() && !m.IsType(memo.TxMigrate) {
    scp.logger.Error().Str("memo", transferOutEvt.Memo).Msg("incorrect memo for transferOutEvent");
    continue;
}
```

**Expected Behavior:** The function should handle multiple transfer events consistently, ensuring all valid transfers are recorded and processed. Proper checks and balances should be implemented to handle multiple event scenarios without data loss.

**Expected Behavior code snippet:**
```go
if len(txInItem.Coins) > 0 && !txInItem.SameAssetAndAddress(transferOutEvt.Asset, transferOutEvt.To) {
    return false, fmt.Errorf("multiple transfer events with different assets or destinations detected");
}
```

**Logic:**
1. A `transferOutEvent` is processed, and its validity is checked.
2. If multiple transfer events with different destinations or assets occur, they are all processed without ignoring any unless explicitly invalid.
3. All valid transactions are logged, and no financial data is lost due to oversight.

**Actual Behavior:** The function may prematurely exit upon encountering a transfer out event, potentially ignoring subsequent valid events within the same transaction log. This behavior can lead to unrecorded transfers, affecting the financial integrity of the contract.

**Actual Behavior code snippet:**
```go
if !m.IsOutbound() && !m.IsType(memo.TxMigrate) {
    scp.logger.Error().Str("memo", transferOutEvt.Memo).Msg("incorrect memo for transferOutEvent");
    continue;
}
```

**Logic:**
1. A `transferOutEvent` is processed.
2. If the event does not meet specific memo criteria, it is ignored, and processing potentially stops for other valid events within the same log.
3. This can lead to discrepancies in recorded transactions, especially if multiple valid transfers are present.


--------------------------------------------------------------------------------------------------------


**[QA-8]** Error Handling and Financial Risk in `parseTransferOutAndCall` Function

**code:** smartcontract_log_parser.go

**Description:** In the `parseTransferOutAndCall` function, the error handling approach could lead to financial inaccuracies, particularly when parsing the `TransferOutAndCall` event. If an error occurs while unpacking the event data, the function immediately returns `nil`, potentially causing subsequent valid logs to be ignored. This premature exit without proper logging or handling of the error might result in missing crucial transaction information, which could directly impact financial operations or lead to misrepresentation of the transaction flow.

**Code snippet:**
```go
if err := scp.unpackVaultLog(event, TransferOutAndCallEventName, log); err != nil {
    return nil, err
}
```

**Expected Behavior:** The contract should robustly handle errors by logging them and continue processing other logs in the transaction to ensure no valid data is omitted due to an error in a single event.

**Expected Behavior code snippet:**
```go
if err := scp.unpackVaultLog(event, TransferOutAndCallEventName, log); err != nil {
    scp.logger.Warn().Err(err).Msg("Failed to unpack TransferOutAndCall event, continuing with other logs.");
    continue // assuming this is within a loop processing multiple logs
}
```

**Logic:**
1. Attempt to parse each log entry for a `TransferOutAndCall` event.
2. If an error occurs, log the error but do not exit the function.
3. Continue processing other log entries in the queue, ensuring complete analysis of the transaction log.

**Actual Behavior:** The function stops processing and returns immediately when an error is encountered in unpacking a single event log.

**Actual Behavior code snippet:**
```go
if err := scp.unpackVaultLog(event, TransferOutAndCallEventName, log); err != nil {
    return nil, err
}
```

**Logic:**
1. When parsing `TransferOutAndCall` encounters an error, the function exits immediately.
2. This could skip processing of subsequent logs in the same transaction, potentially leading to a loss of important financial data or misrepresenting the transaction's effects in the ledger.


-----------------------------------------------------------------------------------------------------------

**[QA-9]** Decimal Conversion Issue in Amount Conversion Logic

**code:** smartcontract_log_parser.go

**Description:** The `GetTxInItem` function uses the `amtConverter` to convert token amounts using Big Integers but does not correctly apply the token's decimal configuration during the conversion. This omission can result in financial inaccuracies when token amounts are represented in the user interface or calculations, leading to either underestimation or overestimation of token values based on the decimals not being accounted for in the conversion process.

**Code snippet:**
```go
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount)).WithDecimals(decimals));
```

**Expected Behavior:** The amount conversion should factor in the token's decimal places, ensuring that all financial operations correctly reflect the value as intended in the broader financial ecosystem of the cryptocurrency involved.

**Expected Behavior code snippet:**
```go
// Correct implementation would consider the decimal places in conversion
cosmos.Uint adjustedAmount = scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount, decimals);
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, adjustedAmount));
```

**Logic:**
1. Retrieve the decimal configuration for the token.
2. Adjust the Big Integer amount according to the token's decimals before converting it to `cosmos.Uint`.
3. Use the adjusted amount in financial transactions to ensure accuracy.

**Actual Behavior:** The function ignores the decimals of the asset during conversion, leading to potential financial errors where the represented value in transactions does not match the actual value of the asset as per its decimal definition.

**Actual Behavior code snippet:**
```go
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount)).WithDecimals(decimals));
```

**Logic:**
1. The Big Integer amount is converted directly to `cosmos.Uint` without adjusting for decimals.
2. The resultant value might significantly misrepresent the true value, leading to transactional inaccuracies and potential financial losses for users interacting with the contract.


-----------------------------------------------------------------------------------------------------------------------


**[QA-10]** Inadequate Validation of Event Unpacking in `parseTransferOutAndCall`

**code:** smartcontract_log_parser.go

**Description:** The function `parseTransferOutAndCall` is designed to unpack and process `TransferOutAndCall` events from the log data. However, the function lacks adequate validation after unpacking the event data. Specifically, if the event data is successfully unpacked but results in a struct (`THORChainRouterTransferOutAndCall`) that contains zero or invalid `Amount`, the function will still consider this as a valid event. This can lead to scenarios where transaction flows, particularly outflows, are not properly accounted for, potentially leading to financial loss if the `Amount` is zero or incorrectly calculated but processed as a valid transfer.

**Code snippet:**
```go
if err := scp.unpackVaultLog(event, TransferOutAndCallEventName, log); err != nil {
    return nil, err
}
// No further validation on event.Amount or other critical fields after unpacking
```

**Expected Behavior:** After unpacking event data, there should be strict validations to ensure that the `Amount` and other critical fields are not only present but also valid (non-zero and correctly formatted). This will prevent incorrect transaction processing and potential fund losses.

**Expected Behavior code snippet:**
```go
if err := scp.unpackVaultLog(event, TransferOutAndCallEventName, log); err != nil {
    return nil, err
}
if event.Amount == nil || event.Amount.Sign() <= 0 {
    return nil, fmt.Errorf("invalid or zero amount in TransferOutAndCall event")
}
```

**Logic:**
1. Unpack event data from the log.
2. Validate that the `Amount` field is non-zero and valid.
3. Only proceed with further processing if the validation passes, ensuring financial integrity.

**Actual Behavior:** The function does not perform post-unpacking validation for critical financial fields such as `Amount`. If these fields are zero or malformed, they may still be processed, leading to incorrect ledger entries and potential financial loss.

**Actual Behavior code snippet:**
```go
if err := scp.unpackVaultLog(event, TransferOutAndCallEventName, log); err != nil {
    return nil, err
}
// Lack of validation on the Amount, potentially leading to processing of invalid transaction data.
```

**Logic:**
1. Event data is unpacked without subsequent validation checks on the `Amount`.
2. Processing continues even if the `Amount` is zero or incorrect, risking incorrect financial transactions and potential losses.

-------------------------------------------------------------------------------------------------------


**[QA-11]** Incorrect Asset Decimal Handling in Transaction Processing

**code:** smartcontract_log_parser.go

**Description:** The function `GetTxInItem` processes transaction logs to extract and record transaction details into `txInItem`. However, there is a critical oversight in how asset decimals are handled during the conversion of transaction amounts. The function retrieves asset decimals and applies them as a label to the coin but fails to use these decimals in the actual amount conversion process. This mismanagement can lead to significant discrepancies in the recorded transaction amounts, potentially inflating or deflating the actual value, resulting in financial losses when tokens are incorrectly accounted for.

**Code snippet:**
```go
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount)).WithDecimals(decimals));
```

**Expected Behavior:** The conversion of token amounts should incorporate the token's decimal configuration to ensure that the recorded transaction values accurately reflect the intended economic activities. The adjusted amount should correctly represent the token's smallest unit to prevent any financial discrepancies.

**Expected Behavior code snippet:**
```go
// Properly apply decimals in amount conversion
cosmos.Uint adjustedAmount = adjustAmountByDecimals(depositEvt.Amount, decimals);
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, adjustedAmount));
```

**Logic:**
1. Retrieve the correct decimal configuration for the asset.
2. Adjust the amount based on the asset's decimals to ensure it reflects the actual value in terms of the asset's smallest unit.
3. Record the adjusted amount in `txInItem`, ensuring financial accuracy.

**Actual Behavior:** The function does not adjust the token amounts based on the asset's decimal configuration during conversion, leading to potential misrepresentation of transaction values. This can result in significant financial errors, such as crediting or debiting incorrect amounts from user accounts.

**Actual Behavior code snippet:**
```go
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount)).WithDecimals(decimals));
```

**Logic:**
1. Decimal information is retrieved but not utilized in converting the amount from its big integer representation.
2. The amount conversion does not adjust for the asset's decimals, potentially resulting in financial entries that do not accurately reflect the intended transaction values, leading to financial losses.


----------------------------------------------------------------------------------



**[QA-12]** Use of Insecure Gas Price Calculation Method

**Code:** ethereum_block_scanner.go

**Description:** The method `updateGasPriceV3` calculates the gas price based on the 25th percentile of priority fees added to the base fee. However, rounding up the calculated gas price before adjusting it with the resolution might lead to predictable gas price fluctuations. This can be potentially exploited by miners or other users to influence transaction inclusion or costs.

**Code snippet:**
```go
func (e *ETHScanner) updateGasPriceV3(baseFee *big.Int, priorityFees []*big.Int) {
    // find the 25th percentile priority fee in the block
    sort.Slice(priorityFees, func(i, j int) bool { return priorityFees[i].Cmp(priorityFees[j]) == -1 })
    priorityFee := priorityFees[len(priorityFees)/4]
    
    // consider gas price as base fee + 25th percentile priority fee
    gasPriceWei := new(big.Int).Add(baseFee, priorityFee)
    
    // round the price up to nearest configured resolution
    resolution := big.NewInt(e.cfg.GasPriceResolution)
    gasPriceWei.Add(gasPriceWei, new(big.Int).Sub(resolution, big.NewInt(1)))
    gasPriceWei = gasPriceWei.Div(gasPriceWei, resolution)
    gasPriceWei = gasPriceWei.Mul(gasPriceWei, resolution)
}
```

**Expected Behavior:** The gas price should be calculated securely and should not allow for potential manipulations. Proper rounding after adjusting to the resolution can help prevent this.

**Expected Behavior code snippet:**
```go
func (e *ETHScanner) updateGasPriceV3(baseFee *big.Int, priorityFees []*big.Int) {
    sort.Slice(priorityFees, func(i, j int) bool { return priorityFees[i].Cmp(priorityFees[j]) == -1 })
    priorityFee := priorityFees[len(priorityFees)/4]
    
    gasPriceWei := new(big.Int).Add(baseFee, priorityFee)
    gasPriceWei = gasPriceWei.Div(gasPriceWei, big.NewInt(e.cfg.GasPriceResolution))
    gasPriceWei = gasPriceWei.Mul(gasPriceWei, big.NewInt(e.cfg.GasPriceResolution))
}
```

**Logic:**
1. Compute the gas price as the sum of the base fee and the 25th percentile priority fee.
2. Divide the result by the resolution to round it down to the nearest unit.
3. Multiply the result by the resolution to adjust it back to the proper scale.

**Actual Behavior:** The rounding logic can be exploited due to premature rounding up of the gas price before adjusting to the resolution.

**Actual Behavior code snippet:**
```go
gasPriceWei.Add(gasPriceWei, new(big.Int).Sub(resolution, big.NewInt(1)))
gasPriceWei = gasPriceWei.Div(gasPriceWei, resolution)
gasPriceWei = gasPriceWei.Mul(gasPriceWei, resolution)
```

**Logic:**
1. Compute the gas price as the sum of the base fee and the 25th percentile priority fee.
2. Add the difference of the resolution minus one to this sum.
3. Divide the result by the resolution, effectively rounding up prematurely.
4. Multiply back by the resolution, which could be used to manipulate the transaction inclusion cost.

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**[QA-13]** Lack of Reorg Handling for Transaction State

**Code:** ethereum_block_scanner.go

**Description:** In the function `processReorg`, there is a mechanism to handle blockchain reorganizations by checking for discrepancies between recorded block hashes and the parent hash of the current block. However, the code lacks a robust mechanism to reassess the state of transactions that were included in orphaned blocks. This can lead to transactions being erroneously considered as finalized, potentially leading to a loss of funds if these transactions were reversed or modified as part of the reorganization.

**Code snippet:**
```go
func (e *ETHScanner) processReorg(block *etypes.Header) ([]stypes.TxIn, error) {
    previousHeight := block.Number.Int64() - 1
    prevBlockMeta, err := e.blockMetaAccessor.GetBlockMeta(previousHeight)
    if err != nil {
        return nil, fmt.Errorf("fail to get block meta of height(%d) : %w", previousHeight, err)
    }
    if prevBlockMeta == nil {
        return nil, nil
    }
    // the block's previous hash need to be the same as the block hash chain client recorded in block meta
    if strings.EqualFold(prevBlockMeta.BlockHash, block.ParentHash.Hex()) {
        return nil, nil
    }
    // If reorg detected, further transaction verification is needed here
}
```

**Expected Behavior:** On detection of a blockchain reorganization, the system should re-validate and re-process transactions from the affected blocks to ensure their current state reflects the consensus blockchain. This should prevent the accidental finalization of transactions that might have been reversed or altered.

**Expected Behavior code snippet:**
```go
func (e *ETHScanner) processReorg(block *etypes.Header) ([]stypes.TxIn, error) {
    previousHeight := block.Number.Int64() - 1
    prevBlockMeta, err := e.blockMetaAccessor.GetBlockMeta(previousHeight)
    if err != nil {
        return nil, fmt.Errorf("fail to get block meta of height(%d) : %w", previousHeight, err)
    }
    if prevBlockMeta == nil {
        return nil, nil
    }
    if !strings.EqualFold(prevBlockMeta.BlockHash, block.ParentHash.Hex()) {
        // Re-fetch and reprocess transactions from the affected block
        return e.reprocessTxsForHeight(previousHeight)
    }
    return nil, nil
}
```

**Logic:**
1. Check if the previous block hash matches the parent hash of the current block.
2. If they do not match, invoke a reprocessing of transactions from the potentially orphaned blocks.

**Actual Behavior:** The function does not fully handle the consequences of a blockchain reorg, potentially leading to inaccurate transaction states and possible financial discrepancies.

**Actual Behavior code snippet:**
```go
if strings.EqualFold(prevBlockMeta.BlockHash, block.ParentHash.Hex()) {
    return nil, nil
}
// Missing implementation to handle reprocessing of transactions in orphaned blocks
```

**Logic:**
1. Only a basic hash comparison is performed to detect a reorg.
2. There is no further action to reassess or confirm the state of transactions post-reorg, potentially leaving transactions incorrectly marked as finalized.




--------------------------------------------------------------------------------------------------------------------------------


**[QA-14]** Inefficient and Potentially Risky Gas Price Cache Update

**Code:** ethereum_block_scanner.go

**Description:** The `updateGasPriceFromCache` method calculates the average gas price based on cached gas prices to update the global gas price used in transaction fees. However, the method incorporates an overly simplistic mean calculation without robust outlier handling or error checks, which could lead to inaccuracies in gas price estimation. An inaccurate gas price can result in either overestimating or underestimating transaction costs, leading to economic losses either by overpaying or by having transactions perpetually stuck due to underpayment.

**Code snippet:**
```go
func (e *ETHScanner) updateGasPriceFromCache() {
    if len(e.gasCache) < e.cfg.GasCacheBlocks {
        return
    }

    // Compute the mean of cache
    sum := new(big.Int)
    for _, fee := range e.gasCache {
        sum.Add(sum, fee)
    }
    mean := new(big.Int).Quo(sum, big.NewInt(int64(len(e.gasCache))))

    e.gasPrice = mean
}
```

**Expected Behavior:** The gas price calculation should be resistant to potential manipulation by ensuring that outlier values do not skew the average significantly. Implementing a more sophisticated method like the median or trimmed mean could mitigate risks associated with outlier values.

**Expected Behavior code snippet:**
```go
func (e *ETHScanner) updateGasPriceFromCache() {
    if len(e.gasCache) < e.cfg.GasCacheBlocks {
        return
    }

    // Use median for a more robust central value
    sortedFees := make([]*big.Int, len(e.gasCache))
    copy(sortedFees, e.gasCache)
    sort.Slice(sortedFees, func(i, j int) bool { return sortedFees[i].Cmp(sortedFees[j]) < 0 })
    median := sortedFees[len(sortedFees)/2]

    e.gasPrice = median
}
```

**Logic:**
1. Ensure the cache has enough entries to perform a calculation.
2. Sort the cached gas prices and select the median, which is less susceptible to extreme values than the mean.
3. Update the global gas price to the calculated median value.

**Actual Behavior:** The function calculates the mean gas price from cached values directly, without handling outliers or ensuring robust statistical practices. This can lead to incorrect gas price estimations during times of volatile gas price movements or manipulative actions.

**Actual Behavior code snippet:**
```go
mean := new(big.Int).Quo(sum, big.NewInt(int64(len(e.gasCache))))

e.gasPrice = mean
```

**Logic:**
1. The sum of all cached gas prices is divided by the number of cache entries to find the average.
2. This average is directly used to update the global gas price, which can be inaccurate if the cached data contains outlier values. This simplistic approach risks either overpaying for gas (if the outliers are high) or underestimating the necessary gas price (if the outliers are low), leading to transactions that may not be processed timely or economically.

--------------------------------------------------------------------------------------------------------------------


**[QA-15]** Incorrect Handling of ETH Conversion for Non-18 Decimal Tokens

**Code:** ethereum_block_scanner.go

**Description:** In the `convertAmount` function within the ETHScanner class, there is a significant risk of miscalculation when handling tokens that do not adhere to the standard 18 decimals, which is common for many ERC-20 tokens on the Ethereum network. The function attempts to normalize all token amounts to 18 decimals, but the logic incorrectly scales up the amount by \(10^{18}\) for all tokens, irrespective of their actual decimal configuration. This could result in a drastic misrepresentation of token amounts, potentially causing substantial financial discrepancies and loss when interacting with contracts expecting correctly scaled values.

**Code snippet:**
```go
func (e *ETHScanner) convertAmount(token string, amt *big.Int) cosmos.Uint {
    decimals := uint64(defaultDecimals)  // defaultDecimals is 18
    tokenMeta, err := e.getTokenMeta(token)
    if err != nil {
        e.logger.Err(err).Msgf("fail to get token meta for token address: %s", token)
    }
    if !tokenMeta.IsEmpty() {
        decimals = tokenMeta.Decimal
    }
    if decimals != defaultDecimals {
        var value big.Int
        amt = amt.Mul(amt, value.Exp(big.NewInt(10), big.NewInt(defaultDecimals), nil))
        amt = amt.Div(amt, value.Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
    }
    return cosmos.NewUintFromBigInt(amt).QuoUint64(common.One * 100)
}
```

**Expected Behavior:** The function should correctly scale token amounts based on the difference between the token's decimals and the standard 18 decimals, adjusting either up or down accordingly. This ensures that all token amounts are represented accurately within the system, preventing any unintended financial outcomes due to decimal errors.

**Expected Behavior code snippet:**
```go
func (e *ETHScanner) convertAmount(token string, amt *big.Int) cosmos.Uint {
    tokenMeta, err := e.getTokenMeta(token)
    if err != nil {
        e.logger.Err(err).Msgf("fail to get token meta for token address: %s", token)
        return cosmos.Uint{}
    }
    var scalingFactor big.Int
    if tokenMeta.Decimal != defaultDecimals {
        scalingFactor.Exp(big.NewInt(10), big.NewInt(int64(defaultDecimals - tokenMeta.Decimal)), nil)
        amt = amt.Mul(amt, &scalingFactor)
    }
    return cosmos.NewUintFromBigInt(amt).QuoUint64(common.One * 100)
}
```

**Logic:**
1. Determine the actual decimal configuration of the token.
2. Calculate the scaling factor as \(10^{(18 - \text{token decimals})}\).
3. Adjust the token amount by multiplying with the scaling factor to normalize it to 18 decimals.
4. Convert the BigInteger amount to a Cosmos SDK Uint while scaling down by a factor of \(10^2\) to match system-specific denominations.

**Actual Behavior:** The function inaccurately scales all non-18 decimal tokens up by \(10^{18}\), then divides by the token's original decimal factor, leading to incorrect calculations, especially evident with tokens having decimals significantly less than 18.

**Actual Behavior code snippet:**
```go
if decimals != defaultDecimals {
    var value big.Int
    amt = amt.Mul(amt, value.Exp(big.NewInt(10), big.NewInt(defaultDecimals), nil))
    amt = amt.Div(amt, value.Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
}
```

**Logic:**
1. The token amount is unnecessarily scaled up by \(10^{18}\) regardless of the token's actual decimals.
2. It is then divided by \(10^{\text{token decimals}}\), which can lead to significant errors if the token's decimals are far from 18, potentially causing large-scale financial inaccuracies in transaction processing.


--------------------------------------------------------------------------------------------------------------------------------


**[QA-16]** Inadequate Fee Calculation in Multi-Token Transactions

**Code:** ethereum_block_scanner.go

**Description:** The `convertAmount` function in the `ETHScanner` class is used to adjust the token amounts based on their respective decimals. However, this function has a significant issue when dealing with transactions involving multiple tokens with different decimal places. The function always normalizes token amounts to a fixed decimal (18 decimals), which may not reflect the true decimals of all tokens involved in the transaction. This one-size-fits-all approach can result in incorrect token amount calculations, potentially leading to significant financial discrepancies and loss when executing transactions that involve multiple tokens with varying decimals.

**Code snippet:**
```go
func (e *ETHScanner) convertAmount(token string, amt *big.Int) cosmos.Uint {
    decimals := uint64(defaultDecimals) // defaultDecimals is assumed to be 18
    tokenMeta, err := e.getTokenMeta(token)
    if err != nil {
        e.logger.Err(err).Msgf("fail to get token meta for token address: %s", token)
    }
    if !tokenMeta.IsEmpty() {
        decimals = tokenMeta.Decimal
    }
    if decimals != defaultDecimals {
        var value big.Int
        amt = amt.Mul(amt, value.Exp(big.NewInt(10), big.NewInt(defaultDecimals), nil))
        amt = amt.Div(amt, value.Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
    }
    return cosmos.NewUintFromBigInt(amt).QuoUint64(common.One * 100)
}
```

**Expected Behavior:** The function should handle token amounts based on the actual decimals of each token involved in a transaction. This requires dynamically adjusting the scaling based on each token's metadata rather than assuming a fixed decimal scale for all tokens. This approach ensures that the token amounts are correctly represented and calculated, preventing errors in transactions that involve tokens with non-standard decimals.

**Expected Behavior code snippet:**
```go
func (e *ETHScanner) convertAmount(token string, amt *big.Int) cosmos.Uint {
    tokenMeta, err := e.getTokenMeta(token)
    if err != nil {
        e.logger.Err(err).Msgf("fail to get token meta for token address: %s", token)
        return cosmos.Uint{}
    }
    actualDecimals := big.NewInt(int64(tokenMeta.Decimal))
    defaultDecimalBigInt := big.NewInt(int64(defaultDecimals))
    
    // Adjust amount based on the token's actual decimals
    if actualDecimals.Cmp(defaultDecimalBigInt) != 0 {
        scaleFactor := new(big.Int).Exp(big.NewInt(10), new(big.Int).Sub(defaultDecimalBigInt, actualDecimals), nil)
        amt.Mul(amt, scaleFactor)
    }

    return cosmos.NewUintFromBigInt(amt).QuoUint64(common.One * 100)
}
```

**Logic:**
1. Retrieve the actual decimals for the token.
2. Calculate the scaling factor based on the difference between the standard decimals (18) and the token's actual decimals.
3. Adjust the token amount using this scaling factor.

**Actual Behavior:** The function currently uses a fixed decimal normalization (18 decimals) for all tokens, which can result in incorrect token amount calculations for tokens with decimals that differ from this standard.

**Actual Behavior code snippet:**
```go
if decimals != defaultDecimals {
    var value big.Int
    amt = amt.Mul(amt, value.Exp(big.NewInt(10), big.NewInt(defaultDecimals), nil))
    amt = amt.Div(amt, value.Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
}
```

**Logic:**
1. The function scales the amount to 18 decimals irrespective of the token's actual decimal configuration.
2. This scaling might not be appropriate for tokens with fewer or more decimals than 18, potentially leading to transaction failures, incorrect fund transfers, or financial losses due to erroneous balance calculations.


-----------------------------------------------------------------------------------------------------------------------------------------


**[QA-17]** Mismanagement of Transaction Nonce in Parallel Processing

**Code:** ethereum_block_scanner.go

**Description:** The `ETHScanner` class handles the processing of Ethereum transactions, including sending new transactions based on block events. However, the class does not adequately manage the nonce—a counter used to ensure each transaction from an account is processed only once—especially in environments where transactions are sent in parallel. This oversight can lead to nonce collisions or the use of incorrect nonce values, causing transactions to fail, be rejected by the network, or replace previously sent transactions unintentionally, leading to potential financial loss.

**Code snippet:**
```go
func (e *ETHScanner) sendTransaction(txData *TxData) error {
    nonce, err := e.client.PendingNonceAt(context.Background(), e.fromAddress)
    if err != nil {
        return fmt.Errorf("fail to get pending nonce: %w", err)
    }

    tx := types.NewTransaction(nonce, e.toAddress, txData.Value, txData.GasLimit, txData.GasPrice, txData.Data)
    signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, e.privateKey)
    if err != nil {
        return fmt.Errorf("fail to sign transaction: %w", err)
    }

    err = e.client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        return fmt.Errorf("fail to send transaction: %w", err)
    }
    return nil
}
```

**Expected Behavior:** Proper management of the transaction nonce should be implemented to handle parallel transaction submissions securely. This involves either locking the account nonce access during transaction preparation or using a nonce management system that accurately predicts the next available nonce, even under concurrent conditions.

**Expected Behavior code snippet:**
```go
func (e *ETHScanner) sendTransaction(txData *TxData) error {
    nonce := e.getSafeNonce()
    tx := types.NewTransaction(nonce, e.toAddress, txData.Value, txData.GasLimit, txData.GasPrice, txData.Data)
    signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, e.privateKey)
    if err != nil {
        return fmt.Errorf("fail to sign transaction: %w", err)
    }

    err = e.client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        return fmt.Errorf("fail to send transaction: %w", err)
    }
    return nil
}

func (e *ETHScanner) getSafeNonce() uint64 {
    e.nonceMutex.Lock()
    defer e.nonceMutex.Unlock()
    nonce, err := e.client.PendingNonceAt(context.Background(), e.fromAddress)
    if err != nil {
        log.Fatalf("fail to get pending nonce: %v", err)
    }
    e.nonce += 1
    return nonce
}
```

**Logic:**
1. A mutex lock is used to synchronize access to the nonce retrieval and incrementation process.
2. The nonce for the account is fetched securely and incremented to ensure it is not reused.

**Actual Behavior:** The original method retrieves the nonce without any synchronization mechanism to prevent the reuse or collision of nonce values, which can occur when multiple transactions are prepared concurrently.

**Actual Behavior code snippet:**
```go
nonce, err := e.client.PendingNonceAt(context.Background(), e.fromAddress)
if err != nil {
    return fmt.Errorf("fail to get pending nonce: %w", err)
}
```

**Logic:**
1. The nonce is retrieved directly from the Ethereum client's view of the pending state, which may not be up-to-date when multiple transactions are being sent in parallel.
2. Without synchronization, multiple transactions could receive the same nonce, leading to conflicts and potential failures in transaction processing.



