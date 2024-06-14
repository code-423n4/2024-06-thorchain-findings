## Summary

| |Issue|Instances| 
|-|:-|:-:|
| [[L-01](#l-01)] | Use `call` instead of `transfer/send` on payable addresses | 9| 
| [[L-02](#l-02)] | Consider adding validation of user inputs | 6| 
| [[L-03](#l-03)] | Execution at deadlines should be allowed | 1| 
| [[L-04](#l-04)] | Consider bounding input array length | 4| 
| [[L-05](#l-05)] | Code does not follow the best practice of check-effects-interaction | 1| 
| [[L-06](#l-06)] | Events may be emitted out of order due to reentrancy | 6| 
| [[L-07](#l-07)] | External call recipient can consume all remaining gas | 8| 
| [[L-08](#l-08)] | External calls in an unbounded loop can result in a DoS | 7| 
| [[L-09](#l-09)] | Sending tokens in a loop | 2| 

### Low Risk Issues

### [L-01]<a name="l-01"></a> Use `call` instead of `transfer/send` on payable addresses

In Solidity, when transferring Ether, `.transfer()` and `.send()` are commonly used. However, they have a limitation: they forward only a stipend of 2300 gas, which isn't enough to execute any code in the recipient contract beyond a simple event emission. Thus, if the recipient is a contract, the transfer may fail unexpectedly.

To overcome this, Solidity introduced the `.call{value: _amount}('')` method, which forwards all available gas and can invoke more complex functionality. It's also safer in that it does not revert on failure but instead returns a boolean value to indicate success or failure. Therefore, it is generally a better choice to use `.call` when transferring Ether to a payable address, with the necessary safety checks implemented to handle potential errors.

*There are 10 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

152:       bool success = vault.send(safeAmount);

194:       bool success = to.send(safeAmount); // Send ETH.

196:         payable(address(msg.sender)).transfer(safeAmount); // For failure, bounce back to vault & continue.

211:       bool success = transferOutPayload.to.send(transferOutPayload.amount); // Send ETH.

213:         payable(address(msg.sender)).transfer(transferOutPayload.amount); // For failure, bounce back to vault & continue.

278:       bool ethSuccess = payable(to).send(_safeAmount); // If can't swap, just send the recipient the ETH

280:         payable(address(msg.sender)).transfer(_safeAmount); // For failure, bounce back to vault & continue.

324:         bool sendSuccess = payable(aggregationPayload.target).send(msg.value); // If can't swap, just send the recipient the gas asset

326:           payable(address(msg.sender)).transfer(msg.value); // For failure, bounce back to vault & continue.

```


*GitHub* : [152](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L152-L152), [194](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L194-L194), [196](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L196-L196), [211](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L211-L211), [213](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L213-L213), [278](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L278-L278), [280](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L280-L280), [324](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L324-L324), [326](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L326-L326)

### [L-02]<a name="l-02"></a> Consider adding validation of user inputs

There are no validations done on the arguments below. Consider that the Solidity [documentation](https://docs.soliditylang.org/en/latest/control-structures.html#panic-via-assert-and-error-via-require) states that `Properly functioning code should never create a Panic, not even on invalid external input. If this happens, then there is a bug in your contract which you should fix`. This means that there should be explicit checks for expected ranges of inputs. Underflows/overflows result in panics should not be used as range checks, and allowing funds to be sent to `0x0`, which is the default value of address variables and has many gotchas, should be avoided.

*There are 6 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

// @audit missing checks for -->  vault, asset
131:   function depositWithExpiry(
132:     address payable vault,
133:     address asset,
134:     uint amount,
135:     string memory memo,
136:     uint expiration
137:   ) external payable {

// @audit missing checks for -->  router, newVault, asset
165:   function transferAllowance(
166:     address router,
167:     address newVault,
168:     address asset,
169:     uint amount,
170:     string memory memo
171:   ) external nonReentrant {

// @audit missing checks for -->  to
185:   function transferOut(
186:     address payable to,
187:     address asset,
188:     uint amount,
189:     string memory memo
190:   ) public payable nonReentrant {

// @audit missing checks for -->  aggregator, finalToken, to
261:   function transferOutAndCall(
262:     address payable aggregator,
263:     address finalToken,
264:     address to,
265:     uint256 amountOutMin,
266:     string memory memo
267:   ) public payable nonReentrant {

// @audit missing checks for -->  router, asgard
408:   function returnVaultAssets(
409:     address router,
410:     address payable asgard,
411:     Coin[] memory coins,
412:     string memory memo
413:   ) external payable nonReentrant {

// @audit missing checks for -->  vault, token
430:   function vaultAllowance(
431:     address vault,
432:     address token
433:   ) public view returns (uint amount) {

```


*GitHub* : [131](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L131-L137), [165](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L165-L171), [185](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L185-L190), [261](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L261-L267), [408](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L408-L413), [430](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L430-L433)

### [L-03]<a name="l-03"></a> Execution at deadlines should be allowed

The condition may be wrong in these cases, as when block.timestamp is equal to the compared `>` or `<` variable these blocks will not be executed.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

138:     require(block.timestamp < expiration, "THORChain_Router: expired");

```


*GitHub* : [138](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L138-L138)

### [L-04]<a name="l-04"></a> Consider bounding input array length

Unbounded array inputs in functions can lead to unintentional excessive gas consumption, potentially causing a transaction to revert after expending substantial gas. To enhance user experience and prevent such scenarios, consider implementing a `require()` statement that limits the array length to a defined maximum. This constraint ensures that transactions won't proceed if they're likely to hit gas limits due to array size, saving users from unnecessary gas costs and offering a more predictable interaction with the contract.

*There are 4 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

//@audit transferOutPayload.length not bounded 
250:     for (uint i = 0; i < transferOutPayload.length; ++i) {

//@audit aggregationPayloads.length not bounded 
400:     for (uint i = 0; i < aggregationPayloads.length; ++i) {

//@audit coins.length not bounded 
415:       for (uint i = 0; i < coins.length; i++) {

//@audit coins.length not bounded 
420:       for (uint i = 0; i < coins.length; i++) {

```


*GitHub* : [250](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L250-L250), [400](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L400-L400), [415](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L415-L415), [420](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L420-L420)

### [L-05]<a name="l-05"></a> Code does not follow the best practice of check-effects-interaction

Code should follow the best-practice of [CEI](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-11-coding-patterns/topic/checks-effects-interactions/), where state variables are updated before any external calls are made. Doing so prevents a large class of reentrancy bugs

*There are 1 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

// @audit vault.send() called on line 152 
157:       _vaultAllowance[vault][asset] += safeAmount; // Credit to chosen vault

```


*GitHub* : [157](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L157-L157)

### [L-06]<a name="l-06"></a> Events may be emitted out of order due to reentrancy

If a reentrancy occurs, some events may be emitted in an unexpected order, and this may be a problem if a third party expects a specific order for these events. Ensure that events are emitted before external calls and follow the best practice of CEI.

*There are 6 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

159:     emit Deposit(vault, asset, safeAmount, memo);

206:     emit TransferOut(msg.sender, to, asset, safeAmount, memo);

231:     emit TransferOut(
232:       msg.sender,
233:       transferOutPayload.to,
234:       transferOutPayload.asset,
235:       transferOutPayload.amount,
236:       transferOutPayload.memo
237:     );

284:     emit TransferOutAndCall(
285:       msg.sender,
286:       aggregator,
287:       _safeAmount,
288:       finalToken,
289:       to,
290:       amountOutMin,
291:       memo
292:     );

330:       emit TransferOutAndCallV5(
331:         msg.sender,
332:         aggregationPayload.target,
333:         msg.value,
334:         aggregationPayload.toAsset,
335:         aggregationPayload.recipient,
336:         aggregationPayload.amountOutMin,
337:         aggregationPayload.memo,
338:         aggregationPayload.payload,
339:         aggregationPayload.originAddress
340:       );

377:       emit TransferOutAndCallV5(
378:         msg.sender,
379:         aggregationPayload.target,
380:         aggregationPayload.fromAmount,
381:         aggregationPayload.toAsset,
382:         aggregationPayload.recipient,
383:         aggregationPayload.amountOutMin,
384:         aggregationPayload.memo,
385:         aggregationPayload.payload,
386:         aggregationPayload.originAddress
387:       );

```


*GitHub* : [159](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L159-L159), [206](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L206-L206), [231](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L231-L237), [284](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L284-L292), [330](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L330-L340), [377](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L377-L387)

### [L-07]<a name="l-07"></a> External call recipient can consume all remaining gas

There is no limit specified on the amount of gas used, so the recipient can use up all of the remaining gas(gasleft()), causing it to revert. Therefore, when calling an external contract, it is necessary to specify a limited amount of gas to forward.

*There are 8 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

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


*GitHub* : [200](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L200-L202), [220](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L220-L226), [269](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L269-L276), [309](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L309-L322), [347](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L347-L355), [364](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L364-L375), [443](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L443-L450), [490](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L490-L492)

### [L-08]<a name="l-08"></a> External calls in an unbounded loop can result in a DoS

Consider limiting the number of iterations in loops that make external calls, as just a single one of them failing will result in a revert.

*There are 7 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

220:       (bool success, bytes memory data) = transferOutPayload.asset.call(
221:         abi.encodeWithSignature(
222:           "transfer(address,uint256)",
223:           transferOutPayload.to,
224:           transferOutPayload.amount
225:         )
226:       );

251:       _transferOutV5(transferOutPayload[i]);

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

401:       _transferOutAndCallV5(aggregationPayloads[i]);

421:         _routerDeposit(router, asgard, coins[i].asset, coins[i].amount, memo);

```


*GitHub* : [220](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L220-L226), [251](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L251-L251), [309](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L309-L322), [347](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L347-L355), [364](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L364-L375), [401](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L401-L401), [421](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L421-L421)

### [L-09]<a name="l-09"></a> Sending tokens in a loop

Performing token transfers in a loop in a Solidity contract is generally not recommended due to various reasons. One of these reasons is the 'Fail-Silently' issue.

In a Solidity loop, if one transfer operation fails, it causes the entire transaction to fail. This issue can be particularly troublesome when you're dealing with multiple transfers in one transaction. For instance, if you're looping through an array of recipients to distribute dividends or rewards, a single failed transfer will prevent all the subsequent recipients from receiving their transfers. This could be due to the recipient contract throwing an exception or due to other issues like a gas limit being exceeded.

Moreover, such a design could also inadvertently lead to a situation where a malicious contract intentionally causes a failure when receiving Ether to prevent other participants from getting their rightful transfers. This could open up avenues for griefing attacks in the system.

Resolution: To mitigate this problem, it's typically recommended to follow the 'withdraw pattern' in your contracts instead of pushing payments. In this model, each recipient would be responsible for triggering their own payment. This separates each transfer operation, so a failure in one doesn't impact the others. Additionally, it greatly reduces the chance of malicious interference as the control over fund withdrawal lies with the intended recipient and not with an external loop operation.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: ethereum/contracts/THORChain_Router.sol

251:       _transferOutV5(transferOutPayload[i]);

401:       _transferOutAndCallV5(aggregationPayloads[i]);

```


*GitHub* : [251](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L251-L251), [401](https://github.com/code-423n4/2024-06-thorchain/blob/733dbe7cd7eef0dffc5e8a2d02e36bf74b196eff/ethereum/contracts/THORChain_Router.sol#L401-L401)
