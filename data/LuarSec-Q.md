## `transferOutPayload.amount` may be greater than `msg.value` in `THORChain_Router._transferOutV5`

### Affected Lines
- [ethereum/contracts/THORChain_Router.sol:211](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L211)

### Impact
The payable external `THORChain_Router.transferOutV5` and `THORChain_Router.batchTransferOutV5` functions use the internal `_transferOutV5` function to fulfill EVM outbounds for native/gas assets or ERC20 assets.
 
When fulfilling native ether transfers, no check exists to ensure `transferOutPayload.amount` is covered by `msg.value`, so the function may be called with a zero `msg.value` amount, and any `transferOutPayload.amount` amount.


```solidity
  //File:ethereum/contracts/THORChain_Router.sol

  function _transferOutV5(TransferOutData memory transferOutPayload) private {
    if (transferOutPayload.asset == address(0)) {
      bool success = transferOutPayload.to.send(transferOutPayload.amount); // Send ETH.
      if (!success) {
        payable(address(msg.sender)).transfer(transferOutPayload.amount); // For failure, bounce back to vault & continue.
      }
    } else {
      _vaultAllowance[msg.sender][
        transferOutPayload.asset
      ] -= transferOutPayload.amount; // Reduce allowance

      (bool success, bytes memory data) = transferOutPayload.asset.call(
        abi.encodeWithSignature(
          "transfer(address,uint256)",
          transferOutPayload.to,
          transferOutPayload.amount
        )
      );

      require(success && (data.length == 0 || abi.decode(data, (bool))));
    }

    emit TransferOut(
      msg.sender,
      transferOutPayload.to,
      transferOutPayload.asset,
      transferOutPayload.amount,
      transferOutPayload.memo
    );
  }

  function transferOutV5(
    TransferOutData calldata transferOutPayload
  ) public payable nonReentrant {
    _transferOutV5(transferOutPayload);
  }

  // bifrost to budget gas limits, no more than 50% than L1 gas limit
  function batchTransferOutV5(
    TransferOutData[] calldata transferOutPayload
  ) external payable nonReentrant {
    for (uint i = 0; i < transferOutPayload.length; ++i) {
      _transferOutV5(transferOutPayload[i]);
    }
  }
```

It is understood that `THORChain_Router.transferOutV5` and `THORChain_Router.batchTransferOutV5` are intended to be called by Bifrost components, and that the `THORChain_Router` is not intended to hold native/gas assets like ether. This lowers the probability of successful exploitation, however it is possible for ether to be stuck in `THORChain_Router`, due to a missing requirement of `msg.value == 0` in the `else` blocks called from the external `transferOutAndCallV5`, `batchTransferOutAndCallV5` or `transferOut` functions.

### Recommended Mitigation Steps
- Ensure that in `batchTransferOutV5`, all `transferOutPayload.amount` values for payloads where `transferOutPayload.asset == address(0)` are less than or equal to `msg.value` prior to the internal `_transferOutV5` call.
- When sending native assets in non-batch `transferOutV5` calls, use a check similar to that in [`THORChain_Router.transferOut`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L193), ensure `transferOutPayload.amount` is less than or equal to `msg.value`.

## Missing unexpected native asset checks when processing non-native assets

### Affected Lines
- [ethereum/contracts/THORChain_Router.sol:L199](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L199)
- [ethereum/contracts/THORChain_Router.sol:L216](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L216)
- [ethereum/contracts/THORChain_Router.sol:L342](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L342)

### Impact
The [`THORChain_Router.depositWithExpiry`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L155) function is the only intended to be called by regular users, and requires that `msg.value == 0`
when processing non-native assets. However, the other payable public/external functions `transferOutV5`, `batchTransferOutV5`, `transferOut`, `transferOutAndCallV5` and `batchTransferOutAndCallV5` do not include this requirement when processing ERC20 operations. As these functions may still be called by any account on EVM chains, this presents a way for native assets to get stuck in the `THORChain_Router` contract. One case is shown below for `transferOut`:

```solidity
  //File:ethereum/contracts/THORChain_Router.sol

  function transferOut(
    address payable to,
    address asset,
    uint amount,
    string memory memo
  ) public payable nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
      ...
    } else {
      ...
    }
    emit TransferOut(msg.sender, to, asset, safeAmount, memo);
  }

```

In combination with a lack of input validation on the `transferOutPayload.amount` argument of `_transferOutV5`, this could enable watering hole/social engineering attacks, where threat actors entice victims to deposit native assets into the router via one of the affected external functions, only to steal the native assets via `transferOutV5` or `batchTransferOutV5`.

### Recommended Mitigation Steps
Implement the following requirement in the `else` blocks in the `_transferOutAndCallV5`, `_transferOutV5`, and `transferOut` functions, similar to [_deposit](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L155). This is shown for `transferOut`:

```solidity
  //File:ethereum/contracts/THORChain_Router.sol

  function transferOut(
    address payable to,
    address asset,
    uint amount,
    string memory memo
  ) public payable nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
    ...
    } else {
      require(msg.value == 0, "unexpected eth"); //added requirement.
      ...
    }
    emit TransferOut(msg.sender, to, asset, safeAmount, memo);
  }

```