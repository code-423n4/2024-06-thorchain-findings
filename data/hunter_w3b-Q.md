## [L-01] If the `scp.maxLogs` is not set any limits in `smartcontract_log_parser::GetTxInItem` Function lead to DOS

If the `scp.maxLogs` is not set any limits in `GetTxInItem` function, allowing transactions with an excessive number of logs to be processed without error, which can result in a DoS.

The function `GetTxInItem` is designed to process logs associated with a transaction. However, if `scp.maxLogs` is set to zero (indicating no limit), the following code segment fails to handle this scenario correctly:

```go
func (scp *SmartContractLogParser) GetTxInItem(logs []*etypes.Log, txInItem *types.TxInItem) (bool, error) {
	if len(logs) == 0 {
		scp.logger.Info().Msg("tx logs are empty return nil")
		return false, nil
	} else if int(scp.maxLogs) > 0 && len(logs) > int(scp.maxLogs) {
		scp.logger.Info().Msgf("tx logs are too many, ignore")
		return false, nil
	}
```

When `scp.maxLogs` is zero, the condition `int(scp.maxLogs) > 0` evaluates to false, and the subsequent check `len(logs) > int(scp.maxLogs)` to be true and the check is not return a error. This allows transactions with a potentially excessive number of logs to bypass the limit check and proceed, leading to a DoS attack.

To mitigate this vulnerability, it is recommended to adjust the conditional check to properly handle the case where `scp.maxLogs` is zero. The modified code should ensure that scp.maxLogs is treated correctly to prevent excessive log processing:

```diff
-   } else if int(scp.maxLogs) > 0 && len(logs) > int(scp.maxLogs) {
+   } else if int(scp.maxLogs) >= 0 && len(logs) > int(scp.maxLogs) {
```

if the maxLogs is zero this must also return an error.

## [L-02] Incomplete Processing of Logs in `GetTxInItem` Function

In the `GetTxInItem` function can lead to incomplete log processing. which does not process all logs in a transaction when the first log is a `transferOutEvent`.

If the first log encountered is a `transferOutEvent`, the function will terminate early, causing subsequent logs to be ignored. This can result in missed events and incomplete transaction data.

The `GetTxInItem` function processes a list of logs to extract transaction details. However, if a transferOutEvent is encountered as the first log, the function exits early due to the earlyExit flag being set to true. This behavior prevents the function from processing any remaining logs, which can lead to issues.

```go
case transferOutEvent:
    // it is not legal to have multiple transferOut event , transferOut event should be final
    transferOutEvt, err := scp.parseTransferOut(*item)
    if err != nil {
        scp.logger.Err(err).Msg("fail to parse transfer out event")
        continue
    }
    m, err := memo.ParseMemo(common.LatestVersion, transferOutEvt.Memo)
    if err != nil {
        scp.logger.Err(err).Str("memo", transferOutEvt.Memo).Msg("failed to parse transferOutEvent memo")
        continue
    }
    if !m.IsOutbound() && !m.IsType(memo.TxMigrate) {
        scp.logger.Error().Str("memo", transferOutEvt.Memo).Msg("incorrect memo for transferOutEvent")
        continue
    }
    asset, err := scp.assetResolver(transferOutEvt.Asset.String())
    if err != nil {
        return false, fmt.Errorf("fail to get asset from token address: %w", err)
    }
    if asset.IsEmpty() {
        return false, nil
    }
    txInItem.To = transferOutEvt.To.String()
    txInItem.Memo = transferOutEvt.Memo
    decimals := scp.decimalResolver(transferOutEvt.Asset.String())
    txInItem.Coins = common.NewCoins(
        common.NewCoin(asset, scp.amtConverter(transferOutEvt.Asset.String(), transferOutEvt.Amount)).WithDecimals(decimals),
    )
    earlyExit = true
    isVaultTransfer = false
```

- A transaction is submitted with multiple logs, including both depositEvent and transferOutEvent logs.

- The GetTxInItem function is called to process the logs and extract relevant information.

- The function encounters the transferOutEvent log first and breaks out of the loop, without processing any further logs.

- As a result, the system only has incomplete or incorrect transaction data, which can lead to issues with the overall functionality of the system.

## [L-03] Inappropriate Use of `strings.EqualFold` for Hash Comparison

Using `strings.EqualFold` for comparing hash values can lead to incorrect comparisons. Cryptographic hashes are case-sensitive and should be treated as binary data, not as strings. Since `strings.EqualFold` performs a case-insensitive comparison, it may produce false positives or negatives when comparing hash values.

In the event of a reorg, this function checks whether the previous block hash in the block metadata matches the parent hash of the current block. If they match, the function returns without taking any further action. However, the hash comparison is performed using the `strings.EqualFold` function, which is not appropriate for comparing cryptographic hashes.

```go
func (e *ETHScanner) processReorg(block *etypes.Header) ([]stypes.TxIn, error) {
	previousHeight := block.Number.Int64() - 1

    ////....

    // the block's previous hash need to be the same as the block hash chain client recorded in block meta
	// blockMetas[PreviousHeight].BlockHash == Block.PreviousHash
@>>	if strings.EqualFold(prevBlockMeta.BlockHash, block.ParentHash.Hex()) {
		return nil, nil
	}
	e.logger.Info().Msgf("re-org detected, current block height:%d ,previous block hash is : %s , however block meta at height: %d, block hash is %s", block.Number.Int64(), block.ParentHash.Hex(), prevBlockMeta.Height, prevBlockMeta.BlockHash)
	heights, err := e.reprocessTxs()
	if err != nil {
		e.logger.Err(err).Msg("fail to reprocess all txs")
	}
	var txIns []stypes.TxIn
	for _, item := range heights {
		e.logger.Info().Msgf("rescan block height: %d", item)
		var block *etypes.Block
		block, err = e.getRPCBlock(item)
		if err != nil {
			e.logger.Err(err).Msgf("fail to get block from RPC endpoint, height:%d", item)
			continue
		}
		if block.Transactions().Len() == 0 {
			continue
		}
    ///...
```

## [L-04] No Deadline protection on `swapOut`

The deadline parameter is hard-coded to the max value of `uint`, so the transaction can be held & executed at a much later & more unfavorable time to the user.

```solidity
  function transferOutAndCall(
    address payable aggregator,
    address finalToken,
    address to,
    uint256 amountOutMin,
    string memory memo
  ) public payable nonReentrant {
    uint256 _safeAmount = msg.value;
    (bool erc20Success, ) = aggregator.call{value: _safeAmount}(
      abi.encodeWithSignature(
        "swapOut(address,address,uint256)",
        finalToken,
        to,
        amountOutMin
      )
```

```solidity
  function swapOut(
    address token,
    address to,
    uint256 amountOutMin
  ) public payable nonReentrant {
    address[] memory path = new address[](2);
    path[0] = WETH;
    path[1] = token;
    swapRouter.swapExactETHForTokens{value: msg.value}(
      amountOutMin,
      path,
      to,
@>>      type(uint).max
    );
  }
```

## [L-05] No Check for Zero Address in `vault` Parameter Leads to Token Loss

The `depositWithExpiry` and `_deposit` functions in the smart contract lack a check to ensure that the vault address is not the zero address (`address(0)`). If users inadvertently send assets to the zero address, the tokens are irretrievably lost.

Tokens sent to the zero address are permanently lost.

```solidity
  // Deposit with Expiry (preferred)
  function depositWithExpiry(
@>>    address payable vault,
    address asset,
    uint amount,
    string memory memo,
    uint expiration
  ) external payable {
    require(block.timestamp < expiration, "THORChain_Router: expired");
    _deposit(vault, asset, amount, memo);
  }

  // Deposit an asset with a memo. ETH is forwarded, ERC-20 stays in ROUTER
  function _deposit(
@>>    address payable vault,
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
      require(msg.value == 0, "unexpected eth"); // protect user from accidentally locking up eth
      safeAmount = safeTransferFrom(asset, amount); // Transfer asset
      _vaultAllowance[vault][asset] += safeAmount; // Credit to chosen vault
    }
    emit Deposit(vault, asset, safeAmount, memo);
  }

```

## [L-06] Inconsistent Error Handling in `getSymbol` and `getDecimals` Functions

When the `e.erc20ABI.Pack(symbolMethod)` call fails, the function returns an empty string and `nil` instead of an error. This behavior differs from the `getDecimals` function, which returns an error when `e.erc20ABI.Pack(decimalMethod)` fails.

```go

func (e *ETHScanner) getSymbol(token string) (string, error) {
	if IsETH(token) {
		return "ETH", nil
	}
	to := ecommon.HexToAddress(token)
	input, err := e.erc20ABI.Pack(symbolMethod)
	if err != nil {
@>>		return "", nil
	}
	ctx, cancel := e.getContext()
	defer cancel()
	res, err := e.client.CallContract(ctx, ethereum.CallMsg{
		To:   &to,
		Data: input,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("fail to call to smart contract and get symbol: %w", err)
	}
	var symbol string
	output, err := e.erc20ABI.Unpack(symbolMethod, res)
	if err != nil {
		symbol = string(res)
		e.logger.Err(err).Msgf("fail to unpack symbol method call,token address: %s , symbol: %s", token, symbol)
		return sanitiseSymbol(symbol), nil
	}
	// nolint
	symbol = *abi.ConvertType(output[0], new(string)).(*string)
	return sanitiseSymbol(symbol), nil
}
```

1. A user calls the `getTokenMeta` function with an invalid token address.
2. In the `getSymbol` function, the `e.erc20ABI.Pack(symbolMethod)` call fails due to the invalid address.
3. The function returns an empty string and `nil` instead of an error, making it difficult to identify the source of the issue.
4. In the `getDecimals` function, the `e.erc20ABI.Pack(decimalMethod)` call also fails due to the invalid address.
5. The function returns an error with a proper error message, making it easier to identify the source of the issue.

## [L-07] Lack of Mechanism to Handle Residual 'Dust' Funds in `THORChain_Router` contract

The `batchTransferOutV5`, `batchTransferOutAndCallV5` function lacks a mechanism to handle residual 'dust' funds. When performing multiple transfers, small amounts (referred to as 'dust') may remain untransferred. This issue arises because the function does not ensure that the last transfer handles all residual funds, potentially leaving small, unusable amounts in the contract.

The function does not account for any residual 'dust' funds that may remain after multiple transfers. This could lead to small, unhandled amounts left in the contract, especially when dealing with fractions of tokens or ETH.

Impact: Funds may be left in the contract, rendering them unusable and causing inefficiencies.

```solidity
  function batchTransferOutV5(
    TransferOutData[] calldata transferOutPayload
  ) external payable nonReentrant {
    for (uint i = 0; i < transferOutPayload.length; ++i) {
      _transferOutV5(transferOutPayload[i]);
    }
  }

    function batchTransferOutAndCallV5(
    TransferOutAndCallData[] calldata aggregationPayloads
  ) external payable nonReentrant {
    for (uint i = 0; i < aggregationPayloads.length; ++i) {
      _transferOutAndCallV5(aggregationPayloads[i]);
    }
  }
```

## [L-08] Missing `transferAllowance` Event Emission

The `transferAllowance` function is designed to handle the transfer of allowances between routers and vaults. If the transfer is happening within the same router, it adjusts allowances and emits a TransferAllowance event. However, if the transfer is between different routers, it calls the `_routerDeposit` function without emitting any event.

This absence of an event emission in `_routerDeposit` results in a lack of logs for such transactions, making it harder to track

```solidity
  // Use for "moving" assets between vaults (asgard<>ygg), as well "churning" to a new Asgard
  function transferAllowance(
    address router,
    address newVault,
    address asset,
    uint amount,
    string memory memo
  ) external nonReentrant {
    if (router == address(this)) {
      _adjustAllowances(newVault, asset, amount);
      emit TransferAllowance(msg.sender, newVault, asset, amount, memo);
    } else {
      _routerDeposit(router, newVault, asset, amount, memo);
    }
  }

  ...////...

    // Adjust allowance and forwards funds to new router, credits allowance to desired vault
  function _routerDeposit(
    address _router,
    address _vault,
    address _asset,
    uint _amount,
    string memory _memo
  ) internal {
    _vaultAllowance[msg.sender][_asset] -= _amount;
    safeApprove(_asset, _router, _amount);

    iROUTER(_router).depositWithExpiry(
      _vault,
      _asset,
      _amount,
      _memo,
      type(uint).max
    ); // Transfer by depositing
  }
```

## [L-09] Revert on Zero Value Transfers

Some tokens (e.g. LEND) revert when transferring a zero value amount.

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
      require(msg.value == 0, "unexpected eth"); // protect user from accidentally locking up eth
      safeAmount = safeTransferFrom(asset, amount); // Transfer asset
      _vaultAllowance[vault][asset] += safeAmount; // Credit to chosen vault
    }
    emit Deposit(vault, asset, safeAmount, memo);
  }
```

## [L-10] Zero Approve First

When transferring USDT, BNT, or KNC between vaults, if the allowance is not zero, the transaction will revert. This issue arises because the approve function requires the current allowance to be zero before setting a new allowance, which is not compatible with the transfer flow used in the contract.

```solidity
    function approve(address usr, uint wad) override public returns (bool) {
        require(allowance[msg.sender][usr] == 0, "unsafe-approve");
        return super.approve(usr, wad);
    }
```

If the current allowance is not zero, the approve function call within safeApprove will revert, causing the entire transfer process to fail.

```solidity
  // Use for "moving" assets between vaults (asgard<>ygg), as well "churning" to a new Asgard
  function transferAllowance(
    address router,
    address newVault,
    address asset,
    uint amount,
    string memory memo
  ) external nonReentrant {
    if (router == address(this)) {
      _adjustAllowances(newVault, asset, amount);
      emit TransferAllowance(msg.sender, newVault, asset, amount, memo);
    } else {
      _routerDeposit(router, newVault, asset, amount, memo);
    }
  }

  // Adjust allowance and forwards funds to new router, credits allowance to desired vault
  function _routerDeposit(
    address _router,
    address _vault,
    address _asset,
    uint _amount,
    string memory _memo
  ) internal {
    _vaultAllowance[msg.sender][_asset] -= _amount;
    safeApprove(_asset, _router, _amount);

    iROUTER(_router).depositWithExpiry(
      _vault,
      _asset,
      _amount,
      _memo,
      type(uint).max
    ); // Transfer by depositing
  }

  function safeApprove(
    address _asset,
    address _address,
    uint _amount
  ) internal {
    (bool success, ) = _asset.call(
      abi.encodeWithSignature("approve(address,uint256)", _address, _amount)
    ); // Approve to transfer
    require(success);
  }
```

Recommendation

To avoid this issue, implement a `safeApprove` function that sets the allowance to zero before setting the new allowance. This approach is compatible with USDT and other tokens that enforce the zero-allowance requirement.

```diff
function safeApprove(
    address _asset,
    address _address,
    uint _amount
) internal {
+    // First set allowance to zero
+    (bool success, ) = _asset.call(
+        abi.encodeWithSignature("approve(address,uint256)", _address, 0)
+    );
+    require(success, "failed to reset allowance");
}
```

## [L-11] Out-of-Gas Error in `batchTransferOutV5` and `batchTransferOutAndCallV5` Function

The `batchTransferOutV5` and `batchTransferOutAndCallV5` functions in the THORChain_Router contract are susceptible to out-of-gas errors due to the loop structure within these functions, which can lead to exceeding the block gas limit, causing transactions to fail.

**1. Out-of-Gas Error**

The `batchTransferOutV5` and `batchTransferOutAndCallV5` functions iterate over an array of payloads, calling external contracts within each iteration. Given the block gas limit, executing a large number of iterations can cause the transaction to exceed the available gas, leading to a failure.

- The loop structure in these functions is unbounded and depends on the length of the input array. Large input arrays can lead to excessive gas consumption.
- External calls within the loop further increase the gas usage, as calling external contracts is an expensive operation.

**Impact:**

- Transactions involving a large number of iterations will fail due to exceeding the block gas limit.
- Potential for DoS attacks where malicious users can intentionally cause transactions to fail by submitting large input arrays.

**2. Zero Transfer Reverts**

As the protocol accepts a lot of ERC20 tokens in its whitelist, transferring zero tokens within these functions may lead to a revert for some tokens if the transfer amount is zero.

**Affected Code:**

```solidity
if (transferOutPayload.asset == address(0)) {
    bool success = transferOutPayload.to.send(transferOutPayload.amount); // Send ETH.
    if (!success) {
        payable(address(msg.sender)).transfer(transferOutPayload.amount); // For failure, bounce back to vault & continue.
    }
} else {
    (bool success, bytes memory data) = transferOutPayload.asset.call(
        abi.encodeWithSignature(
            "transfer(address,uint256)",
            transferOutPayload.to,
            transferOutPayload.amount
        )
    );
    require(success && (data.length == 0 || abi.decode(data, (bool))));
}
```

```solidity
  function batchTransferOutV5(
    TransferOutData[] calldata transferOutPayload
  ) external payable nonReentrant {
    for (uint i = 0; i < transferOutPayload.length; ++i) {
      _transferOutV5(transferOutPayload[i]);
    }
  }



  function batchTransferOutAndCallV5(
    TransferOutAndCallData[] calldata aggregationPayloads
  ) external payable nonReentrant {
    for (uint i = 0; i < aggregationPayloads.length; ++i) {
      _transferOutAndCallV5(aggregationPayloads[i]);
    }
  }
```
