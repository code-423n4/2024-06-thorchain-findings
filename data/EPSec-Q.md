## Issue Summary

| Category | No. of Issues |
| -------- | ------------- |
| Low      | 12            |
| Info     | 5             |
# Lows
## Low 01 Use ERC20 openzeppelin
### Summary

Instead of using calls for various operations in `THORChain_Router`, it's recommended to utilize the ERC20 contract provided by OpenZeppelin. This approach offers several advantages, including improved code readability, increased security, and reduced complexity.

### Vulnerability Detail

Executing operations via low-level methods such as `call` can introduce complexity and increase the risk of errors. These methods may lead to unexpected behavior and potential vulnerabilities if not handled properly.

### Impact

The impact of using low-level operations instead of leveraging the OpenZeppelin ERC20 library includes:

- **Readability**: Low-level operations may be harder to understand and maintain compared to using a standardized ERC20 implementation.
- **Security**: Directly interacting with contracts via low-level methods may introduce security vulnerabilities if not implemented correctly.
- **Compatibility**: Utilizing a well-tested ERC20 implementation ensures compatibility with existing standards and tools in the Ethereum ecosystem.

### Tools Used

Manual review

### Recommendation

It's advisable to switch to the ERC20 contract provided by OpenZeppelin to improve code quality, security, and compatibility.

## Low 02 Emit event when transfer is not succesfull

### Summary

In the `THORChain_Router::_transferOutV5` function, an event is emitted even when an Ether transfer fails and the amount is sent back to the original sender. This can lead to misleading event logs and incorrect tracking of successful transfers.
### Vulnerability Details

When the Ether transfer to the `to` address fails, the amount is transferred back to the `msg.sender`. Despite the failure of the original transfer, an event is still emitted, indicating that the transfer was attempted. This can cause confusion and inaccuracies in event-based tracking systems.

### Code Snippet

```solidity
function _transferOutV5(TransferOutData memory transferOutPayload) private {

	if (transferOutPayload.asset == address(0)) {
		bool success = transferOutPayload.to.send(transferOutPayload.amount); // Send ETH.
		if (!success) {
			payable(address(msg.sender)).transfer(transferOutPayload.amount); // For failure, bounce back to vault & continue.
		}
	} else {

		_vaultAllowance[msg.sender][transferOutPayload.asset] -= transferOutPayload.amount; // Reduce allowance

		(bool success, bytes memory data) = transferOutPayload.asset.call(abi.encodeWithSignature("transfer(address,uint256)",transferOutPayload.to,transferOutPayload.amount));

        require(success && (data.length == 0 || abi.decode(data, (bool)))); // ok
    }

	emit TransferOut(msg.sender,transferOutPayload.to,transferOutPayload.asset,
	transferOutPayload.amount,transferOutPayload.memo);
	
}
```
### Impact

- **Incorrect Event Logs**: Users and systems relying on emitted events to track successful transfers may be misled, as events are emitted even when the transfer fails.
- **Operational Confusion**: Incorrect events can lead to confusion about the contract's state and operations, affecting trust and reliability.
- **Misleading Audit Trails**: Event logs are often used for auditing and debugging. Emitting events on failed transfers can complicate these processes and lead to incorrect conclusions.

### Tools Used

Manual review
### Recommendations

- **Conditional Event Emission**: Only emit the `TransferOut` event if the Ether transfer is successful. This ensures that event logs accurately reflect the state of transactions.

## Low 03 Restrict functions to be called only by vault

### Summary

The current implementation of the `THORChain_Router` contract allows any address to call its functions, which is contrary to the intended design where only the vault should have access. Restricting access to these functions to only the vault address is crucial for security.

### Vulnerability Details

The vulnerability arises from the lack of access control mechanisms in the `THORChain_Router` contract, allowing any address to call its functions.

### Impact

**Security Breach**: Allowing unrestricted access to contract functions increases the risk of unauthorized operations, such as unauthorized token transfers or manipulation of critical contract variables, which can compromise the security and integrity of the contract.
### Recommendation

**Implement Access Control**: Restrict access to sensitive contract functions to only the vault address or other authorized entities. This can be achieved using modifiers or access control patterns such as role-based access control (RBAC).

## Low 04 Add zero checks

### Summary
Certain tokens within `THORChain_Router` may cause transactions to revert when attempting to transfer zero amounts, potentially disrupting integrations and operations.

### Vulnerability
The vulnerability lies in the specific behavior of certain tokens, where attempting to transfer zero amounts results in transaction reverting. This could be implemented on multiple places such as: 

`safeTransferFrom` method
`_transferOutV5` method
`_transferOutAndCallV5` method
### Impact 
This vulnerability can disrupt integrations and operations that rely on seamless token transfers. Transactions reverting due to zero amount transfers can lead to failed operations, financial losses, and potential inconsistencies in system behavior.

### Tools Used
Manual review
### Recommendation 
To remediate this issue, ensure that token transfers within THORChain_Router only occur when the amount being transferred is positive. Implementing a check to verify the amount before executing transfers can prevent transactions from reverting and mitigate potential disruptions to integrations and operations. Add check is the amount bigger than zero. 

## Low 05 Blacklisted Tokens

### Summary

The usage of blacklisted tokens within the THORChain_Router presents potential risks and complications. If a token is blacklisted by its issuer while stored in a vault within the THORChain_Router, it could lead to the removal of that vault and the transfer of tokens to a new vault. This vulnerability could disrupt the normal functioning of the protocol and affect the security and stability of asset transfers.

### Vulnerability Details

The vulnerability arises from the reliance on tokens that have the capability to be blacklisted within the THORChain_Router. In the event that a token issuer decides to blacklist a specific vault address, the assets stored within that vault could be frozen or rendered inaccessible. This would necessitate the removal of the affected vault from the THORChain_Router and the transfer of its tokens to a new vault. Such actions could potentially disrupt the protocol's operations and introduce uncertainties regarding asset security and availability.

### Tools Used

Manual review

## Low 06 Read Only Reentrency
### Summary

While the `vaultAllowance` function is designed as a read-only view function to retrieve token allowance for a vault, it may still be vulnerable to reentrancy attacks, more specifcly to read only reentrency.

### Vulnerability Details

Although the `vaultAllowance` function is read-only and doesn't modify contract state, it could still be vulnerable to reentrancy attacks if it interacts with external contracts that have unpredictable behavior or if it's called within a vulnerable context in the contract. In such cases, an attacker could repeatedly call the function, exploiting any state changes that occur within the same transaction. Therefore, careful consideration should be given to the function's usage within the contract and its interaction with external contracts to mitigate this risk.

### Code Snippet

```solidity
function vaultAllowance(
    address vault,
    address token
  ) public view returns (uint amount) {
    return _vaultAllowance[vault][token];
  }
```

### Impact

**Reentrancy Risk:** Despite being read-only, if the function interacts with external contracts that are not trusted, it could be susceptible to reentrancy attacks, potentially compromising the contract's integrity.

### Tools Used

Manual review

### Recommendation 

Add modifier `nonReentrant` to the method signature.

## Low 07 IsVaultTransfer is always false

### Summary

The current implementation of `GetTxInItem` method will always return a false for `isVaultTransfer` variable.

### Impact

If another method is relying on the method `GetTxInItem` and more precisely on the variable `isVaultTransfer` this could lead to a problems. For example in `evm_block_scanner.go` 
`getTxInFromSmartContract` executes a logic based on this variable.

### Tools Used

Manual Review

## Low 08 Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

- Found in src/THORChain_Router.sol [Line: 199](THORChain_Router.sol#L199)

	```solidity
	      _vaultAllowance[msg.sender][asset] -= amount; // Reduce allowance
	```

- Found in src/THORChain_Router.sol [Line: 461](THORChain_Router.sol#L461)

	```solidity
	    _vaultAllowance[msg.sender][_asset] -= _amount;
	```

- Found in src/THORChain_Router.sol [Line: 462](THORChain_Router.sol#L462)

	```solidity
	    _vaultAllowance[_newVault][_asset] += _amount;
	```

- Found in src/THORChain_Router.sol [Line: 473](THORChain_Router.sol#L473)

	```solidity
	    _vaultAllowance[msg.sender][_asset] -= _amount;
	```

### Tools Used

Aderyn

## Low 09 `public` functions not used internally could be marked `external`

Instead of marking a function as `public`, consider marking it as `external` if it is not used internally.

- Found in src/THORChain_Router.sol [Line: 185](THORChain_Router.sol#L185)

	```solidity
	  function transferOut(
	```

- Found in src/THORChain_Router.sol [Line: 240](THORChain_Router.sol#L240)

	```solidity
	  function transferOutV5(
	```

- Found in src/THORChain_Router.sol [Line: 261](THORChain_Router.sol#L261)

	```solidity
	  function transferOutAndCall(
	```

- Found in src/THORChain_Router.sol [Line: 430](THORChain_Router.sol#L430)

	```solidity
	  function vaultAllowance(
	```


### Tools Used

Aderyn

## Low 10 Event is missing `indexed` fields

Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.

- Found in src/THORChain_Router.sol [Line: 61](THORChain_Router.sol#L61)

	```solidity
	  event Deposit(
	```

- Found in src/THORChain_Router.sol [Line: 69](THORChain_Router.sol#L69)

	```solidity
	  event TransferOut(
	```

- Found in src/THORChain_Router.sol [Line: 79](THORChain_Router.sol#L79)

	```solidity
	  event TransferOutAndCall(
	```

- Found in src/THORChain_Router.sol [Line: 90](THORChain_Router.sol#L90)

	```solidity
	  event TransferOutAndCallV5(
	```

- Found in src/THORChain_Router.sol [Line: 103](THORChain_Router.sol#L103)

	```solidity
	  event TransferAllowance(
	```

- Found in src/THORChain_Router.sol [Line: 112](THORChain_Router.sol#L112)

	```solidity
	  event VaultTransfer(
	```

### Tools Used

Aderyn

## Low 11 Empty `require()` / `revert()` statements

Use descriptive reason strings or custom errors for revert paths.

- Found in src/THORChain_Router.sol [Line: 153](THORChain_Router.sol#L153)

	```solidity
	      require(success);
	```

- Found in src/THORChain_Router.sol [Line: 203](THORChain_Router.sol#L203)

	```solidity
	      require(success && (data.length == 0 || abi.decode(data, (bool))));
	```

- Found in src/THORChain_Router.sol [Line: 228](THORChain_Router.sol#L228)

	```solidity
	      require(success && (data.length == 0 || abi.decode(data, (bool))));
	```

- Found in src/THORChain_Router.sol [Line: 425](THORChain_Router.sol#L425)

	```solidity
	    require(success);
	```

- Found in src/THORChain_Router.sol [Line: 451](THORChain_Router.sol#L451)

	```solidity
	    require(success && (data.length == 0 || abi.decode(data, (bool))));
	```

- Found in src/THORChain_Router.sol [Line: 493](THORChain_Router.sol#L493)

	```solidity
	    require(success);
	```

### Tools Used

Aderyn

## Low 12 Internal functions called only once can be inlined

Instead of separating the logic into a separate function, consider inlining the logic into the calling function. This can reduce the number of function calls and improve readability.

- Found in src/THORChain_Router.sol [Line: 438](THORChain_Router.sol#L438)

	```solidity
	  function safeTransferFrom(
	```

- Found in src/THORChain_Router.sol [Line: 485](THORChain_Router.sol#L485)

	```solidity
	  function safeApprove(
	```

### Tools Used
Aderyn

## Low 13 Not correct natspec

### Summary

In the function `THORChain_Router::_transferOutAndCallV5`, if the swap operation fails, the `msg.value` will be transferred to the `aggregationPayload.target`. However, instead of the recipient, the `msg.value` is transferred to `aggregationPayload.target`.

### Proof of Concept

The comment `If can't swap, just send the recipient the gas asset` states that ETH should be sent to the recipient. However, as shown in the code below, the `msg.value` is sent to the contract `aggregationPayload.target`, causing ETH to become stuck in the `aggregationPayload.target` contract. More importantly, this is not the intended recipient, so the recipient will not receive the intended ETH. This function should be reworked to operate similarly to `transferOutAndCall`.

### Impact

Incorrectly transferring ETH to `aggregationPayload.target` instead of the intended recipient can result in funds being stuck in the wrong contract and the recipient not receiving the intended ETH. This can lead to significant operational issues and loss of funds.

### Code Snippet

```solidity
function _transferOutAndCallV5(
    TransferOutAndCallData calldata aggregationPayload
  ) private {
    if (aggregationPayload.fromAsset == address(0)) {
      // call swapOutV5 with ether
      (bool swapOutSuccess, ) = aggregationPayload.target.call{
        value: msg.value
      }(
        abi.encodeWithSignature(
          "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
          aggregationPayload.fromAsset,
          aggregationPayload.fromAmount,
          aggregationPayload.toAsset,
          aggregationPayload.recipient,
          aggregationPayload.amountOutMin,
          aggregationPayload.payload,
          aggregationPayload.originAddress
        )
      );
      if (!swapOutSuccess) {
        bool sendSuccess = payable(aggregationPayload.target).send(msg.value); // If can't swap, just send the recipient the gas asset
        if (!sendSuccess) {
          payable(address(msg.sender)).transfer(msg.value); // For failure, bounce back to vault & continue.
        }
      }
```

### Tools Used
Manual Review

### Recommended Mitigation Steps

```diff
function _transferOutAndCallV5(
    TransferOutAndCallData calldata aggregationPayload
) private {
    if (aggregationPayload.fromAsset == address(0)) {
        // Call swapOutV5 with ether
        (bool swapOutSuccess, ) = aggregationPayload.target.call{
            value: msg.value
        }(
            abi.encodeWithSignature(
                "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
                aggregationPayload.fromAsset,
                aggregationPayload.fromAmount,
                aggregationPayload.toAsset,
                aggregationPayload.recipient,
                aggregationPayload.amountOutMin,
                aggregationPayload.payload,
                aggregationPayload.originAddress
            )
        );
        if (!swapOutSuccess) {
+            bool sendSuccess = payable(aggregationPayload.recipient).send(msg.value); 
-            bool sendSuccess = payable(aggregationPayload.target).send(msg.value); 
            if (!sendSuccess) {
                payable(address(msg.sender)).transfer(msg.value); // For failure, bounce back to vault & continue.
            }
        }
    }
}

```


# Informationals

## Informational 01 Reentrence library

### Summary

OpenZeppelin's `ReentrancyGuard` is a Solidity smart contract module designed to prevent reentrant calls to a function. Instead of implementing your own solution `THORChain_Router::nonReentrant`, please consider using OpenZeppelin’s well-tested `ReentrancyGuard` can provide a robust and reliable solution compared to a custom implementation. 
### Vulnerability Detail

**Proven Security**: OpenZeppelin’s contracts are widely used and thoroughly tested by the community. They undergo extensive security audits to ensure reliability and safety.

**Reduced Development Effort**: Implementing a custom reentrancy guard requires careful handling and testing. Using `ReentrancyGuard` saves development time and effort by providing a pre-built and trusted solution.
### Impact

OpenZeppelin follows Solidity best practices and patterns, ensuring that their implementations are efficient and effective. By using `ReentrancyGuard`, you align your contract with these best practices.

## Informational 02 Use uint256

### Summary

In some parts of ThorChainRouter, `uint` is used instead of `uint256`. It's recommended to use `uint256` for better code readability and consistency.

### Vulnerability Detail

Using `uint` instead of `uint256` may lead to confusion and decrease readability. While both are valid, explicitly specifying `uint256` enhances clarity and ensures consistency in the codebase.

### Tools Used
Manual review

### Impact

The impact of using `uint` instead of `uint256` primarily affects code readability and maintenance:

- **Readability**: Explicitly specifying `uint256` makes the code clearer and easier to understand for developers.
- **Consistency**: Consistently using `uint256` throughout the codebase maintains a standard coding style, reducing confusion and potential errors.

### Recommendation

To improve code readability and maintain consistency, it's recommended to replace occurrences of `uint` with `uint256` in ThorChainRouter.

## Informational 03 Event names as constants
### Summary

 In `smartcontract_log_parser.go` parses various events emitted by a smart contract. To enhance code readability and maintainability, event names are recommended to be extracted as constants. Such event names can be found in `parseDeposit`, `parseTransferOut` etc.

### Impact

**Readability**: By defining event names as constants, the code becomes more self-explanatory, making it easier for developers to understand the purpose of each parsing function.

### Tools Used

Manual Review

### Recommendation

To improve code documentation, readability, and maintainability:

- Define event names as constants at the beginning of the file.
- Reference these constants in parsing functions to enhance code clarity and consistency.

### Informational 04  BSC is centralized

### Summary

The Binance Smart Chain (BSC) EVM is considered more centralized compared to Ethereum due to fewer validator nodes, centralized governance by Binance, and significant control over network operations. This affects trust, security, and regulatory scrutiny. Improving validator diversity and governance transparency could address these centralization concerns.

### Impact

The perception of BSC as more centralized has implications for trust, security, and regulatory scrutiny. It affects user confidence and the long-term viability of projects on the platform. Addressing centralization concerns through increased validator diversity and governance transparency is crucial for enhancing decentralization and mitigating risks on BSC.

## Informational 05 Not correct format of names

### Summary 

Following name problems: 

Contract iERC20 (THORChain_Router.sol#8-12) is not in CapWords
Contract iROUTER (THORChain_Router.sol#15-23) is not in CapWords
Contract THORChain_Router (THORChain_Router.sol#26-496) is not in CapWords
Parameter THORChain_Router.safeTransferFrom(address,uint256)._asset (THORChain_Router.sol#439) is not in mixedCase
Parameter THORChain_Router.safeTransferFrom(address,uint256)._amount (THORChain_Router.sol#440) is not in mixedCase
Parameter THORChain_Router.safeApprove(address,address,uint256)._asset (THORChain_Router.sol#487) is not in mixedCase
Parameter THORChain_Router.safeApprove(address,address,uint256)._address (THORChain_Router.sol#488) is not in mixedCase
Parameter THORChain_Router.safeApprove(address,address,uint256)._amount (THORChain_Router.sol#489) is not in mixedCase
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#conformance-to-solidity-naming-conventions

### Tools Used
Slither