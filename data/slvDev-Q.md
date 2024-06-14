## [01] `_dexAggSuccess` return value of low-level `call()`  not checked.

Unchecked return values will lead to transaction continues without reverting even if call wasn't successful.
`_dexAggSuccess` should be removed or checked for success before proceeding with the transaction.

```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

364: (bool _dexAggSuccess, ) = aggregationPayload.target.call{value: 0}(
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
      )
```
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L364


## [02] Use `call()` rather than `transfer()` to sent ether (For failure, bounce back to vault & continue)

You use transfer to send back eth with comment `For failure, bounce back to vault & continue`
But better to use `.call` to send back eth


```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

196: payable(address(msg.sender)).transfer(safeAmount)
211: transferOutPayload.to.send(transferOutPayload.amount)
213: payable(address(msg.sender)).transfer(transferOutPayload.amount)
280: payable(address(msg.sender)).transfer(_safeAmount)
326: payable(address(msg.sender)).transfer(msg.value)
424: asgard.send(msg.value)
```
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L196
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L211
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L213
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L280
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L326
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L424


## [03] Some `ERC20` can revert on a zero/large value `transfer`

ERC20 token behaviors in scope
`Revert on zero value transfers	- Yes`
`Revert on large approvals and/or transfers -	Yes`

```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

156: safeAmount = safeTransferFrom(asset, amount); // Transfer asset


442: uint _startBal = iERC20(_asset).balanceOf(address(this));
      (bool success, bytes memory data) = _asset.call(
        abi.encodeWithSignature(
@>        "transferFrom(address,address,uint256)",
          msg.sender,
          address(this),
          _amount
        )
      );

```


## [04] Use of `abi.encodeWithSignature`/`abi.encodeWithSelector` instead of `abi.encodeCall`

Consider refactoring the code by using `abi.encodeCall` instead of `abi.encodeWithSignature`/`abi.encodeWithSelector`, as the former keeps the code [typo/type safe](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3693).


```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

201: abi.encodeWithSignature("transfer(address,uint256)", to, amount)
221: abi.encodeWithSignature(
          "transfer(address,uint256)",
          transferOutPayload.to,
          transferOutPayload.amount
        )
270: abi.encodeWithSignature(
        "swapOut(address,address,uint256)",
        finalToken,
        to,
        amountOutMin
      )
312: abi.encodeWithSignature(
          "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
          aggregationPayload.fromAsset,
          aggregationPayload.fromAmount,
          aggregationPayload.toAsset,
          aggregationPayload.recipient,
          aggregationPayload.amountOutMin,
          aggregationPayload.payload,
          aggregationPayload.originAddress
        )
350: abi.encodeWithSignature(
            "transfer(address,uint256)",
            aggregationPayload.target,
            aggregationPayload.fromAmount
          )
365: abi.encodeWithSignature(
          "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
          aggregationPayload.fromAsset,
          aggregationPayload.fromAmount,
          aggregationPayload.toAsset,
          aggregationPayload.recipient,
          aggregationPayload.amountOutMin,
          aggregationPayload.payload,
          aggregationPayload.originAddress
        )
444: abi.encodeWithSignature(
        "transferFrom(address,address,uint256)",
        msg.sender,
        address(this),
        _amount
      )
491: abi.encodeWithSignature("approve(address,uint256)", _address, _amount)
```
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L201
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L221
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L270
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L312
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L350
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L365
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L444
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L491


## [05] `.call` bypasses function existence check, type checking and argument packing

Using the `.call` method in Solidity enables direct communication with an address, bypassing function existence checks, type checking, and argument packing.


```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

200: asset.call(
        abi.encodeWithSignature("transfer(address,uint256)", to, amount)
      )
220: transferOutPayload.asset.call(
        abi.encodeWithSignature(
          "transfer(address,uint256)",
          transferOutPayload.to,
          transferOutPayload.amount
        )
      )
269: aggregator.call{value: _safeAmount}(
      abi.encodeWithSignature(
        "swapOut(address,address,uint256)",
        finalToken,
        to,
        amountOutMin
      )
    )
309: aggregationPayload.target.call{
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
      )
347: aggregationPayload
        .fromAsset
        .call(
          abi.encodeWithSignature(
            "transfer(address,uint256)",
            aggregationPayload.target,
            aggregationPayload.fromAmount
          )
        )
364: aggregationPayload.target.call{value: 0}(
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
      )
443: _asset.call(
      abi.encodeWithSignature(
        "transferFrom(address,address,uint256)",
        msg.sender,
        address(this),
        _amount
      )
    )
490: _asset.call(
      abi.encodeWithSignature("approve(address,uint256)", _address, _amount)
    )
```
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L200
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L220
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L269
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L309
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L347
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L364
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L443
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L490


## [06] Unbounded loop with complex logic may run out of gas

If the loop is unbounded, it may run out of gas and cause the transaction to revert. It is recommended to set a limit on the number of iterations to prevent this from happening.

```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

250: for (uint i = 0; i < transferOutPayload.length; ++i)
400: for (uint i = 0; i < aggregationPayloads.length; ++i)
415: for (uint i = 0; i < coins.length; i++)
420: for (uint i = 0; i < coins.length; i++)
```
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L250
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L400
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L415
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L420


## [07] Lack of index element validation in external/public function

There's no validation to check whether the index element provided as an argument actually exists in the call. This omission could lead to unintended behavior if an element that does not exist in the call is passed to the function.

The function should validate that the provided index element exists in the call before proceeding.

Without this validation, the function could cause unintended behaviour as it will call an non-existing index element. This could lead to inconsistencies in data and potentially affect the integrity of the call structure.


```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

199: _vaultAllowance[msg.sender][asset]
434: _vaultAllowance[vault][token]
434: _vaultAllowance[vault]
```
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L199
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L434
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L434


## [08] Events may be emitted out of order due to reentrancy

It's essential to ensure that events follow the best practice of check-effects-interaction and are emitted before any external calls to prevent out-of-order events due to reentrancy.
Emitting events post external interactions may cause them to be out of order due to reentrancy, which can be misleading or erroneous for event listeners.
[Refer to the Solidity Documentation for best practices.]https://solidity.readthedocs.io/en/latest/security-considerations.html#reentrancy)


```solidity
File: chain/ethereum/contracts/THORChain_Router.sol

/// @audit `send()` before `Deposit` event emit
159: emit Deposit(vault, asset, safeAmount, memo);
/// @audit `send()` before `TransferOut` event emit
206: emit TransferOut(msg.sender, to, asset, safeAmount, memo);
/// @audit `send()` before `TransferOut` event emit
230: emit TransferOut(
      msg.sender,
      transferOutPayload.to,
      transferOutPayload.asset,
      transferOutPayload.amount,
      transferOutPayload.memo
    );
/// @audit `call()` before `TransferOutAndCall` event emit
283: emit TransferOutAndCall(
      msg.sender,
      aggregator,
      _safeAmount,
      finalToken,
      to,
      amountOutMin,
      memo
    );
/// @audit `call()` before `TransferOutAndCallV5` event emit
329: emit TransferOutAndCallV5(
        msg.sender,
        aggregationPayload.target,
        msg.value,
        aggregationPayload.toAsset,
        aggregationPayload.recipient,
        aggregationPayload.amountOutMin,
        aggregationPayload.memo,
        aggregationPayload.payload,
        aggregationPayload.originAddress
      );
/// @audit `call()` before `TransferOutAndCallV5` event emit
376: emit TransferOutAndCallV5(
        msg.sender,
        aggregationPayload.target,
        aggregationPayload.fromAmount,
        aggregationPayload.toAsset,
        aggregationPayload.recipient,
        aggregationPayload.amountOutMin,
        aggregationPayload.memo,
        aggregationPayload.payload,
        aggregationPayload.originAddress
      );
```
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L159
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L206
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L230
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L283
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L329
https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L376
