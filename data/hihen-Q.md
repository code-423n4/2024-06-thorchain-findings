# QA Report

## Summary

### Low Issues

Total **29 instances** over **5 issues**:

|ID|Issue|Instances|
|:--:|:---|:--:|
| [[L-01]](#l-01-use-abiencodecall-instead-of-abiencodewithsignatureabiencodewithselector) | Use `abi.encodeCall()` instead of `abi.encodeWithSignature()`/`abi.encodeWithSelector()` | 8 |
| [[L-02]](#l-02-unsafe-solidity-low-level-call-can-cause-gas-grief-attack) | Unsafe solidity low-level call can cause gas grief attack | 8 |
| [[L-03]](#l-03-functions-calling-contractsaddresses-with-transfer-hooks-should-be-protected-by-reentrancy-guard) | Functions calling contracts/addresses with transfer hooks should be protected by reentrancy guard | 2 |
| [[L-04]](#l-04-missing-contract-existence-checks-before-low-level-calls) | Missing contract existence checks before low-level calls | 8 |
| [[L-05]](#l-05-code-does-not-follow-the-best-practice-of-check-effects-interaction) | Code does not follow the best practice of check-effects-interaction | 3 |

### Non Critical Issues

Total **78 instances** over **28 issues**:

|ID|Issue|Instances|
|:--:|:---|:--:|
| [[N-01]](#n-01-names-of-privateinternal-functions-should-be-prefixed-with-an-underscore) | Names of `private`/`internal` functions should be prefixed with an underscore | 2 |
| [[N-02]](#n-02-add-inline-comments-for-unnamed-parameters) | Add inline comments for unnamed parameters | 3 |
| [[N-03]](#n-03-consider-splitting-complex-checks-into-multiple-steps) | Consider splitting complex checks into multiple steps | 4 |
| [[N-04]](#n-04-consider-adding-a-blockdeny-list) | Consider adding a block/deny-list | 1 |
| [[N-05]](#n-05-contracts-should-each-be-defined-in-separate-files) | Contracts should each be defined in separate files | 1 |
| [[N-06]](#n-06-consider-emitting-an-event-at-the-end-of-the-constructor) | Consider emitting an event at the end of the constructor | 1 |
| [[N-07]](#n-07-events-are-emitted-without-the-sender-information) | Events are emitted without the sender information | 1 |
| [[N-08]](#n-08-interfaces-should-be-indicated-with-an-i-prefix-in-the-contract-name) | Interfaces should be indicated with an `I` prefix in the contract name | 2 |
| [[N-09]](#n-09-consider-moving-duplicated-strings-to-constants) | Consider moving duplicated strings to constants | 5 |
| [[N-10]](#n-10-contract-name-does-not-follow-the-solidity-style-guide) | Contract name does not follow the Solidity Style Guide | 3 |
| [[N-11]](#n-11-consider-adding-validation-of-user-inputs) | Consider adding validation of user inputs | 9 |
| [[N-12]](#n-12-constants-should-be-put-on-the-left-side-of-comparisons) | Constants should be put on the left side of comparisons | 10 |
| [[N-13]](#n-13-consider-bounding-input-array-length) | Consider bounding input array length | 4 |
| [[N-14]](#n-14-unnecessary-casting) | Unnecessary casting | 5 |
| [[N-15]](#n-15-unused-local-variables) | Unused local variables | 1 |
| [[N-16]](#n-16-unused-named-return) | Unused named return | 2 |
| [[N-17]](#n-17-use-the-latest-solidity-version) | Use the latest Solidity version | 1 |
| [[N-18]](#n-18-use-a-struct-to-encapsulate-multiple-function-parameters) | Use a struct to encapsulate multiple function parameters | 5 |
| [[N-19]](#n-19-contract-variables-should-have-comments) | Contract variables should have comments | 1 |
| [[N-20]](#n-20-missing-event-when-a-state-variables-is-set-in-constructor) | Missing event when a state variables is set in constructor | 1 |
| [[N-21]](#n-21-consider-adding-emergency-stop-functionality) | Consider adding emergency-stop functionality | 1 |
| [[N-22]](#n-22-avoid-the-use-of-sensitive-terms) | Avoid the use of sensitive terms | 2 |
| [[N-23]](#n-23-missing-checks-for-uint-state-variable-assignments) | Missing checks for uint state variable assignments | 1 |
| [[N-24]](#n-24-use-the-modern-upgradeable-contract-paradigm) | Use the Modern Upgradeable Contract Paradigm | 1 |
| [[N-25]](#n-25-large-or-complicated-code-bases-should-implement-invariant-tests) | Large or complicated code bases should implement invariant tests | 1 |
| [[N-26]](#n-26-the-default-value-is-manually-set-when-it-is-declared) | The default value is manually set when it is declared | 4 |
| [[N-27]](#n-27-contracts-should-have-all-publicexternal-functions-exposed-by-interfaces) | Contracts should have all `public`/`external` functions exposed by `interface`s | 1 |
| [[N-28]](#n-28-top-level-declarations-should-be-separated-by-at-least-two-lines) | Top-level declarations should be separated by at least two lines | 5 |

## Low Issues

### [L-01] Use `abi.encodeCall()` instead of `abi.encodeWithSignature()`/`abi.encodeWithSelector()`

Function `abi.encodeCall()` provides [type-safe encode utility](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3693) comparing with `abi.encodeWithSignature()`/`abi.encodeWithSelector()`.

There are 8 instances:

- *THORChain_Router.sol* ( [201-201](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L201-L201), [221-221](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L221-L221), [270-270](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L270-L270), [312-312](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L312-L312), [350-350](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L350-L350), [365-365](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L365-L365), [444-444](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L444-L444), [491-491](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L491-L491) ):

```solidity
201:         abi.encodeWithSignature("transfer(address,uint256)", to, amount)

221:         abi.encodeWithSignature(

270:       abi.encodeWithSignature(

312:         abi.encodeWithSignature(

350:           abi.encodeWithSignature(

365:         abi.encodeWithSignature(

444:       abi.encodeWithSignature(

491:       abi.encodeWithSignature("approve(address,uint256)", _address, _amount)
```

### [L-02] Unsafe solidity low-level call can cause gas grief attack

Using the low-level calls of a solidity address can leave the contract open to gas grief attacks. These attacks occur when the called contract returns a large amount of data.
So when calling an external contract, it is necessary to check the length of the return data before reading/copying it (using `returndatasize()`).

<details>
<summary>There are 8 instances (click to show):</summary>

- *THORChain_Router.sol* ( [200-202](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L200-L202), [220-226](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L220-L226), [269-276](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L269-L276), [309-322](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L309-L322), [347-355](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L347-L355), [364-375](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L364-L375), [443-450](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L443-L450), [490-492](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L490-L492) ):

```solidity
200:       (bool success, bytes memory data) = asset.call(
201:         abi.encodeWithSignature("transfer(address,uint256)", to, amount)
202:       );

220:       (bool success, bytes memory data) = transferOutPayload.asset.call(
221:         abi.encodeWithSignature(
222:           "transfer(address,uint256)",
223:           transferOutPayload.to,
224:           transferOutPayload.amount
225:         )
226:       );

269:     (bool erc20Success, ) = aggregator.call{value: _safeAmount}(
270:       abi.encodeWithSignature(
271:         "swapOut(address,address,uint256)",
272:         finalToken,
273:         to,
274:         amountOutMin
275:       )
276:     );

309:       (bool swapOutSuccess, ) = aggregationPayload.target.call{
310:         value: msg.value
311:       }(
312:         abi.encodeWithSignature(
313:           "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
314:           aggregationPayload.fromAsset,
315:           aggregationPayload.fromAmount,
316:           aggregationPayload.toAsset,
317:           aggregationPayload.recipient,
318:           aggregationPayload.amountOutMin,
319:           aggregationPayload.payload,
320:           aggregationPayload.originAddress
321:         )
322:       );

347:       (bool transferSuccess, bytes memory data) = aggregationPayload
348:         .fromAsset
349:         .call(
350:           abi.encodeWithSignature(
351:             "transfer(address,uint256)",
352:             aggregationPayload.target,
353:             aggregationPayload.fromAmount
354:           )
355:         );

364:       (bool _dexAggSuccess, ) = aggregationPayload.target.call{value: 0}(
365:         abi.encodeWithSignature(
366:           "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
367:           aggregationPayload.fromAsset,
368:           aggregationPayload.fromAmount,
369:           aggregationPayload.toAsset,
370:           aggregationPayload.recipient,
371:           aggregationPayload.amountOutMin,
372:           aggregationPayload.payload,
373:           aggregationPayload.originAddress
374:         )
375:       );

443:     (bool success, bytes memory data) = _asset.call(
444:       abi.encodeWithSignature(
445:         "transferFrom(address,address,uint256)",
446:         msg.sender,
447:         address(this),
448:         _amount
449:       )
450:     );

490:     (bool success, ) = _asset.call(
491:       abi.encodeWithSignature("approve(address,uint256)", _address, _amount)
492:     ); // Approve to transfer
```

</details>

### [L-03] Functions calling contracts/addresses with transfer hooks should be protected by reentrancy guard

Even if the function follows the best practice of check-effects-interaction, not using a reentrancy guard when there may be transfer hooks opens the users of this protocol up to [read-only reentrancy vulnerability](https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/) with no way to protect them except by block-listing the entire protocol.

There are 2 instances:

- *THORChain_Router.sol* ( [213-213](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L213-L213), [326-326](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L326-L326) ):

```solidity
213:         payable(address(msg.sender)).transfer(transferOutPayload.amount); // For failure, bounce back to vault & continue.

326:           payable(address(msg.sender)).transfer(msg.value); // For failure, bounce back to vault & continue.
```

### [L-04] Missing contract existence checks before low-level calls

Low-level calls return success if there is no code present at the specified address. In addition to the zero-address checks, add a check to verify that `<address>.code.length > 0`.

<details>
<summary>There are 8 instances (click to show):</summary>

- *THORChain_Router.sol* ( [200-202](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L200-L202), [220-226](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L220-L226), [269-276](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L269-L276), [309-322](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L309-L322), [347-355](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L347-L355), [364-375](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L364-L375), [443-450](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L443-L450), [490-492](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L490-L492) ):

```solidity
200:       (bool success, bytes memory data) = asset.call(
201:         abi.encodeWithSignature("transfer(address,uint256)", to, amount)
202:       );

220:       (bool success, bytes memory data) = transferOutPayload.asset.call(
221:         abi.encodeWithSignature(
222:           "transfer(address,uint256)",
223:           transferOutPayload.to,
224:           transferOutPayload.amount
225:         )
226:       );

269:     (bool erc20Success, ) = aggregator.call{value: _safeAmount}(
270:       abi.encodeWithSignature(
271:         "swapOut(address,address,uint256)",
272:         finalToken,
273:         to,
274:         amountOutMin
275:       )
276:     );

309:       (bool swapOutSuccess, ) = aggregationPayload.target.call{
310:         value: msg.value
311:       }(
312:         abi.encodeWithSignature(
313:           "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
314:           aggregationPayload.fromAsset,
315:           aggregationPayload.fromAmount,
316:           aggregationPayload.toAsset,
317:           aggregationPayload.recipient,
318:           aggregationPayload.amountOutMin,
319:           aggregationPayload.payload,
320:           aggregationPayload.originAddress
321:         )
322:       );

347:       (bool transferSuccess, bytes memory data) = aggregationPayload
348:         .fromAsset
349:         .call(
350:           abi.encodeWithSignature(
351:             "transfer(address,uint256)",
352:             aggregationPayload.target,
353:             aggregationPayload.fromAmount
354:           )
355:         );

364:       (bool _dexAggSuccess, ) = aggregationPayload.target.call{value: 0}(
365:         abi.encodeWithSignature(
366:           "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
367:           aggregationPayload.fromAsset,
368:           aggregationPayload.fromAmount,
369:           aggregationPayload.toAsset,
370:           aggregationPayload.recipient,
371:           aggregationPayload.amountOutMin,
372:           aggregationPayload.payload,
373:           aggregationPayload.originAddress
374:         )
375:       );

443:     (bool success, bytes memory data) = _asset.call(
444:       abi.encodeWithSignature(
445:         "transferFrom(address,address,uint256)",
446:         msg.sender,
447:         address(this),
448:         _amount
449:       )
450:     );

490:     (bool success, ) = _asset.call(
491:       abi.encodeWithSignature("approve(address,uint256)", _address, _amount)
492:     ); // Approve to transfer
```

</details>

### [L-05] Code does not follow the best practice of check-effects-interaction

Code should follow the best-practice of [check-effects-interaction](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-11-coding-patterns/topic/checks-effects-interactions/), where state variables are updated before any external calls are made. Doing so prevents a large class of reentrancy bugs.

There are 3 instances:

- *THORChain_Router.sol* ( [156-156](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L156-L156), [157-157](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L157-L157), [204-204](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L204-L204) ):

```solidity
/// @audit `send()` is called on line 152
156:       safeAmount = safeTransferFrom(asset, amount); // Transfer asset

/// @audit `send()` is called on line 152
157:       _vaultAllowance[vault][asset] += safeAmount; // Credit to chosen vault

/// @audit `call()` is called on line 200
204:       safeAmount = amount;
```

## Non Critical Issues

### [N-01] Names of `private`/`internal` functions should be prefixed with an underscore

It is recommended by the [Solidity Style Guide](https://docs.soliditylang.org/en/v0.8.20/style-guide.html#underscore-prefix-for-non-external-functions-and-variables).

There are 2 instances:

- *THORChain_Router.sol* ( [438-441](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L438-L441), [485-489](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L485-L489) ):

```solidity
438:   function safeTransferFrom(
439:     address _asset,
440:     uint _amount
441:   ) internal returns (uint amount) {

485:   function safeApprove(
486:     address _asset,
487:     address _address,
488:     uint _amount
489:   ) internal {
```

### [N-02] Add inline comments for unnamed parameters

`function func(address a, address)` -> `function func(address a, address /* b */)`

There are 3 instances:

- *THORChain_Router.sol* ( [9-9](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L9-L9), [11-11](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L11-L11), [16-22](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L16-L22) ):

```solidity
9:   function balanceOf(address) external view returns (uint256);

11:   function burn(uint) external;

16:   function depositWithExpiry(
17:     address,
18:     address,
19:     uint,
20:     string calldata,
21:     uint
22:   ) external;
```

### [N-03] Consider splitting complex checks into multiple steps

Assign the expression's parts to intermediate local variables, and check against those instead.

There are 4 instances:

- *THORChain_Router.sol* ( [203-203](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L203-L203), [228-228](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L228-L228), [358-358](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L358-L358), [451-451](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L451-L451) ):

```solidity
203:       require(success && (data.length == 0 || abi.decode(data, (bool))));

228:       require(success && (data.length == 0 || abi.decode(data, (bool))));

358:         transferSuccess && (data.length == 0 || abi.decode(data, (bool))),

451:     require(success && (data.length == 0 || abi.decode(data, (bool))));
```

### [N-04] Consider adding a block/deny-list

Doing so will significantly increase centralization, but will help to prevent hackers from using stolen tokens

There is 1 instance:

- *THORChain_Router.sol* ( [26](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L26) ):

```solidity
26: contract THORChain_Router {
```

### [N-05] Contracts should each be defined in separate files

Keeping each contract in a separate file makes it easier to work with multiple people, makes the code easier to maintain, and is a common practice on most projects. The following files each contains more than one contract/library/interface.

There is 1 instance:

- [*THORChain_Router.sol*](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol)

### [N-06] Consider emitting an event at the end of the constructor

This will allow users to easily exactly pinpoint when and by whom a contract was constructed.

There is 1 instance:

- *THORChain_Router.sol* ( [126-126](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L126-L126) ):

```solidity
126:   constructor() {
```

### [N-07] Events are emitted without the sender information

When an action is triggered based on a user's action, not being able to filter based on who triggered the action makes event processing a lot more cumbersome. Including the `msg.sender` the events of these types of action will make events much more useful to end users, especially when `msg.sender` is not `tx.origin`.

There is 1 instance:

- *THORChain_Router.sol* ( [159-159](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L159-L159) ):

```solidity
159:     emit Deposit(vault, asset, safeAmount, memo);
```

### [N-08] Interfaces should be indicated with an `I` prefix in the contract name

Interfaces should be indicated with an `I` prefix in the contract name

There are 2 instances:

- *THORChain_Router.sol* ( [8](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L8), [15](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L15) ):

```solidity
8: interface iERC20 {

15: interface iROUTER {
```

### [N-09] Consider moving duplicated strings to constants

Moving duplicate strings to constants can improve code maintainability and readability.

There are 5 instances:

- *THORChain_Router.sol* ( [201-201](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L201-L201), [222-222](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L222-L222), [313-313](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L313-L313), [351-351](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L351-L351), [366-366](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L366-L366) ):

```solidity
201:         abi.encodeWithSignature("transfer(address,uint256)", to, amount)

222:           "transfer(address,uint256)",

313:           "swapOutV5(address,uint256,address,address,uint256,bytes,string)",

351:             "transfer(address,uint256)",

366:           "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
```

### [N-10] Contract name does not follow the Solidity Style Guide

According to the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html#contract-and-library-names), contracts and libraries should be named using the CapWords style.

There are 3 instances:

- *THORChain_Router.sol* ( [8](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L8), [15](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L15), [26](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L26) ):

```solidity
8: interface iERC20 {

15: interface iROUTER {

26: contract THORChain_Router {
```

### [N-11] Consider adding validation of user inputs

There are no validations done on the arguments below. Consider that the Solidity [documentation](https://docs.soliditylang.org/en/latest/control-structures.html#panic-via-assert-and-error-via-require) states that `Properly functioning code should never create a Panic, not even on invalid external input. If this happens, then there is a bug in your contract which you should fix`. This means that there should be explicit checks for expected ranges of inputs. Underflows/overflows result in panics should not be used as range checks, and allowing funds to be sent to  `0x0`, which is the default value of address variables and has many gotchas, should be avoided.

<details>
<summary>There are 9 instances (click to show):</summary>

- *THORChain_Router.sol* ( [131-137](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L131-L137), [165-171](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L165-L171), [185-190](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L185-L190), [261-267](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L261-L267), [408-413](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L408-L413) ):

```solidity
/// @audit `vault not checked`
/// @audit `asset not checked`
131:   function depositWithExpiry(
132:     address payable vault,
133:     address asset,
134:     uint amount,
135:     string memory memo,
136:     uint expiration
137:   ) external payable {

/// @audit `newVault not checked`
/// @audit `asset not checked`
165:   function transferAllowance(
166:     address router,
167:     address newVault,
168:     address asset,
169:     uint amount,
170:     string memory memo
171:   ) external nonReentrant {

/// @audit `to not checked`
185:   function transferOut(
186:     address payable to,
187:     address asset,
188:     uint amount,
189:     string memory memo
190:   ) public payable nonReentrant {

/// @audit `aggregator not checked`
/// @audit `finalToken not checked`
/// @audit `to not checked`
261:   function transferOutAndCall(
262:     address payable aggregator,
263:     address finalToken,
264:     address to,
265:     uint256 amountOutMin,
266:     string memory memo
267:   ) public payable nonReentrant {

/// @audit `asgard not checked`
408:   function returnVaultAssets(
409:     address router,
410:     address payable asgard,
411:     Coin[] memory coins,
412:     string memory memo
413:   ) external payable nonReentrant {
```

</details>

### [N-12] Constants should be put on the left side of comparisons

Putting constants on the left side of comparison statements is a best practice known as [Yoda conditions](https://en.wikipedia.org/wiki/Yoda_conditions).
Although solidity's static typing system prevents accidental assignments within conditionals, adopting this practice can improve code readability and consistency, especially when working across multiple languages.

<details>
<summary>There are 10 instances (click to show):</summary>

- *THORChain_Router.sol* ( [120](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L120), [150](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L150), [155](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L155), [192](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L192), [203](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L203), [210](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L210), [228](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L228), [307](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L307), [358](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L358), [451](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L451) ):

```solidity
/// @audit put `_ENTERED` on the left
120:     require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

/// @audit put `address(0)` on the left
150:     if (asset == address(0)) {

/// @audit put `0` on the left
155:       require(msg.value == 0, "unexpected eth"); // protect user from accidentally locking up eth

/// @audit put `address(0)` on the left
192:     if (asset == address(0)) {

/// @audit put `0` on the left
203:       require(success && (data.length == 0 || abi.decode(data, (bool))));

/// @audit put `address(0)` on the left
210:     if (transferOutPayload.asset == address(0)) {

/// @audit put `0` on the left
228:       require(success && (data.length == 0 || abi.decode(data, (bool))));

/// @audit put `address(0)` on the left
307:     if (aggregationPayload.fromAsset == address(0)) {

/// @audit put `0` on the left
358:         transferSuccess && (data.length == 0 || abi.decode(data, (bool))),

/// @audit put `0` on the left
451:     require(success && (data.length == 0 || abi.decode(data, (bool))));
```

</details>

### [N-13] Consider bounding input array length

The functions below take in an unbounded array, and make function calls for entries in the array. While the function will revert if it eventually runs out of gas, it may be a nicer user experience to require() that the length of the array is below some reasonable maximum, so that the user doesn't have to use up a full transaction's gas only to see that the transaction reverts.

There are 4 instances:

- *THORChain_Router.sol* ( [250](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L250), [400](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L400), [415](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L415), [420](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L420) ):

```solidity
250:     for (uint i = 0; i < transferOutPayload.length; ++i) {

400:     for (uint i = 0; i < aggregationPayloads.length; ++i) {

415:       for (uint i = 0; i < coins.length; i++) {

420:       for (uint i = 0; i < coins.length; i++) {
```

### [N-14] Unnecessary casting

Unnecessary castings can be removed.

There are 5 instances:

- *THORChain_Router.sol* ( [196-196](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L196-L196), [213-213](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L213-L213), [280-280](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L280-L280), [324-324](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L324-L324), [326-326](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L326-L326) ):

```solidity
/// @audit address(msg.sender)
196:         payable(address(msg.sender)).transfer(safeAmount); // For failure, bounce back to vault & continue.

/// @audit address(msg.sender)
213:         payable(address(msg.sender)).transfer(transferOutPayload.amount); // For failure, bounce back to vault & continue.

/// @audit address(msg.sender)
280:         payable(address(msg.sender)).transfer(_safeAmount); // For failure, bounce back to vault & continue.

/// @audit payable(aggregationPayload.target)
324:         bool sendSuccess = payable(aggregationPayload.target).send(msg.value); // If can't swap, just send the recipient the gas asset

/// @audit address(msg.sender)
326:           payable(address(msg.sender)).transfer(msg.value); // For failure, bounce back to vault & continue.
```

### [N-15] Unused local variables

The following local variables are not used. It is recommended to check the code for logical omissions that cause them not to be used. If it's determined that they are not needed anywhere, it's best to remove them from the codebase to improve code clarity and minimize confusion.

There is 1 instance:

- *THORChain_Router.sol* ( [364-364](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L364-L364) ):

```solidity
364:       (bool _dexAggSuccess, ) = aggregationPayload.target.call{value: 0}(
```

### [N-16] Unused named return

Declaring named returns, but not using them, is confusing to the reader. Consider either completely removing them (by declaring just the type without a name), or remove the return statement and do a variable assignment. This would improve the readability of the code, and it may also help reduce regressions during future code refactors.

There are 2 instances:

- *THORChain_Router.sol* ( [430-433](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L430-L433), [438-441](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L438-L441) ):

```solidity
/// @audit amount
430:   function vaultAllowance(
431:     address vault,
432:     address token
433:   ) public view returns (uint amount) {

/// @audit amount
438:   function safeTransferFrom(
439:     address _asset,
440:     uint _amount
441:   ) internal returns (uint amount) {
```

### [N-17] Use the latest Solidity version

Upgrading to the [latest solidity version](https://github.com/ethereum/solc-js/tags) (0.8.19 for L2s) can optimize gas usage, take advantage of new features and improve overall contract efficiency. Where possible, based on compatibility requirements, it is recommended to use newer/latest solidity version to take advantage of the latest optimizations and features.

There is 1 instance:

- *THORChain_Router.sol* ( [5](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L5) ):

```solidity
5: pragma solidity 0.8.22;
```

### [N-18] Use a struct to encapsulate multiple function parameters

If a function has too many parameters, replacing them with a struct can improve code readability and maintainability, increase reusability, and reduce the likelihood of errors when passing the parameters.

<details>
<summary>There are 5 instances (click to show):</summary>

- *THORChain_Router.sol* ( [16-22](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L16-L22), [131-137](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L131-L137), [165-171](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L165-L171), [261-267](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L261-L267), [466-472](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L466-L472) ):

```solidity
16:   function depositWithExpiry(
17:     address,
18:     address,
19:     uint,
20:     string calldata,
21:     uint
22:   ) external;

131:   function depositWithExpiry(
132:     address payable vault,
133:     address asset,
134:     uint amount,
135:     string memory memo,
136:     uint expiration
137:   ) external payable {

165:   function transferAllowance(
166:     address router,
167:     address newVault,
168:     address asset,
169:     uint amount,
170:     string memory memo
171:   ) external nonReentrant {

261:   function transferOutAndCall(
262:     address payable aggregator,
263:     address finalToken,
264:     address to,
265:     uint256 amountOutMin,
266:     string memory memo
267:   ) public payable nonReentrant {

466:   function _routerDeposit(
467:     address _router,
468:     address _vault,
469:     address _asset,
470:     uint _amount,
471:     string memory _memo
472:   ) internal {
```

</details>

### [N-19] Contract variables should have comments

Consider adding some comments on non-public contract variables to explain what they are supposed to do. This will help for future code reviews.

There is 1 instance:

- *THORChain_Router.sol* ( [58-58](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L58-L58) ):

```solidity
58:   uint256 private _status;
```

### [N-20] Missing event when a state variables is set in constructor

The initial states set in a constructor are important and should be recorded in the event.

There is 1 instance:

- *THORChain_Router.sol* ( [127](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L127) ):

```solidity
127:     _status = _NOT_ENTERED;
```

### [N-21] Consider adding emergency-stop functionality

Adding a way to quickly halt protocol functionality in an emergency, rather than having to pause individual contracts one-by-one, will make in-progress hack mitigation faster and much less stressful.

There is 1 instance:

- *THORChain_Router.sol* ( [26](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L26) ):

```solidity
26: contract THORChain_Router {
```

### [N-22] Avoid the use of sensitive terms

Use [alternative variants](https://www.zdnet.com/article/mysql-drops-master-slave-and-blacklist-whitelist-terminology/), e.g. allowlist/denylist instead of whitelist/blacklist.

There are 2 instances:

- *THORChain_Router.sol* ( [258](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L258), [297](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L297) ):

```solidity
258:   // Aggregator is matched to the last three digits of whitelisted aggregators

297:   // Target is fuzzy-matched to the last three digits of whitelisted aggregators
```

### [N-23] Missing checks for uint state variable assignments

Consider whether reasonable bounds checks for variables would be useful.

There is 1 instance:

- *THORChain_Router.sol* ( [127-127](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L127-L127) ):

```solidity
127:     _status = _NOT_ENTERED;
```

### [N-24] Use the Modern Upgradeable Contract Paradigm

Modern smart contract development often employs upgradeable contract structures, utilizing proxy patterns like OpenZeppelin’s Upgradeable Contracts. This paradigm separates logic and state, allowing developers to amend and enhance the contract's functionality without altering its state or the deployed contract address. Transitioning to this approach enhances long-term maintainability.
Resolution: Adopt a well-established proxy pattern for upgradeability, ensuring proper initialization and employing transparent proxies to mitigate potential risks. Embrace comprehensive testing and audit practices, particularly when updating contract logic, to ensure state consistency and security are preserved across upgrades. This ensures your contract remains robust and adaptable to future requirements.

There is 1 instance:

- *THORChain_Router.sol* ( [26](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L26) ):

```solidity
26: contract THORChain_Router {
```

### [N-25] Large or complicated code bases should implement invariant tests

This includes: large code bases, or code with lots of inline-assembly, complicated math, or complicated interactions between multiple contracts.
Invariant fuzzers such as Echidna require the test writer to come up with invariants which should not be violated under any circumstances, and the fuzzer tests various inputs and function calls to ensure that the invariants always hold.
Even code with 100% code coverage can still have bugs due to the order of the operations a user performs, and invariant fuzzers may help significantly.

There is 1 instance:

- Global finding

### [N-26] The default value is manually set when it is declared

In instances where a new variable is defined, there is no need to set it to it's default value.

There are 4 instances:

- *THORChain_Router.sol* ( [250-250](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L250-L250), [400-400](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L400-L400), [415-415](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L415-L415), [420-420](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L420-L420) ):

```solidity
250:     for (uint i = 0; i < transferOutPayload.length; ++i) {

400:     for (uint i = 0; i < aggregationPayloads.length; ++i) {

415:       for (uint i = 0; i < coins.length; i++) {

420:       for (uint i = 0; i < coins.length; i++) {
```

### [N-27] Contracts should have all `public`/`external` functions exposed by `interface`s

All `external`/`public` functions should extend an `interface`. This is useful to ensure that the whole API is extracted and can be more easily integrated by other projects.

There is 1 instance:

- *THORChain_Router.sol* ( [26](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L26) ):

```solidity
26: contract THORChain_Router {
```

### [N-28] Top-level declarations should be separated by at least two lines

-

There are 5 instances:

- *THORChain_Router.sol* ( [207-209](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L207-L209), [238-240](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L238-L240), [389-391](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L389-L391), [395-397](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L395-L397), [483-485](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/./THORChain_Router.sol#L483-L485) ):

```solidity
207:   }
208: 
209:   function _transferOutV5(TransferOutData memory transferOutPayload) private {

238:   }
239: 
240:   function transferOutV5(

389:   }
390: 
391:   function transferOutAndCallV5(

395:   }
396: 
397:   function batchTransferOutAndCallV5(

483:   }
484: 
485:   function safeApprove(
```
