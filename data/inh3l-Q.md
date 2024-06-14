
## 1. Use  of .send instead of .call can lead to token lockup if sender requires more than 2300 gas

Links to affected code *

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L152

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L194

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L211

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L280

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L326

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L426

https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L194-L197

https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L210-L214

https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L278-L281


### Impact

The protocol uses `send` function to transfer ETH which does it with a fixed amount of 2300 gas. This function is not equipped to handle changes in the underlying .send() and .transfer() functions which may supply different amounts of gas in the future. Additionally, if the recipient implements a fallback function containing some sort of logic, this may inevitably revert, meaning the vault and owner of the contract will never be able to call certain sensitive functions.

Also, in a certain number of cases, if the ETH risks being locked forever if sender is requires more that 2300 gas for ETH transfer.

For instance in the `transferOut` function, the sender attempts to router attempts to send ETH to the recipient. If it fails, it attempts to return the tokens back the the sender. If however the sender vault requires more than 2300 gas, this call will also fail, trapping the ETH in the router indefinitely. This same can be observed in the [`transferOutV5`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L210-L214) and [`transferOutAndCall`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L278-L281) functions.

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
      ........
```

### Recommended Mitigation Steps

Consider using .call() instead.
 
***
 

## 2. Wrong token decimals will be used in fallback for tokens without decimal function

Links to affected code *

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/bifrost/pkg/chainclients/ethereum/ethereum_block_scanner.go#L629


### Impact

https://github.com/code-423n4/2024-03-pooltogether-findings/issues/172

The protocol aims to work with all sorts of ERC20 tokens, and some ERC20 tokens do not implement a `decimals` function. This doesn't go against EIP20 which says that OPTIONAL - This method can be used to improve usability, but interfaces and other contracts MUST NOT expect these values to be present. These tokens are treated on etherscan as being 0 decimal tokens, [this](https://etherscan.io/token/0x1da4858ad385cc377165a298cc2ce3fce0c5fd31) as an example.

However, the `getDecimals` function consistently uses the `defaultDecimals` parameter which 18 as fallback if the decimals function fails. This means that a token without the decimals function, which should have 0 decimals will be marked as an 18 decimals token instead which will lead to the wrong data being used in functions where the `getDecimals` method is required.


```solidity
func (e *ETHScanner) getDecimals(token string) (uint64, error) {
	if IsETH(token) {
		return defaultDecimals, nil
	}
	to := ecommon.HexToAddress(token)
	input, err := e.erc20ABI.Pack(decimalMethod)
	if err != nil {
		return defaultDecimals, fmt.Errorf("fail to pack decimal method: %w", err)
	}
	ctx, cancel := e.getContext()
	defer cancel()
	res, err := e.client.CallContract(ctx, ethereum.CallMsg{
		To:   &to,
		Data: input,
	}, nil)
	if err != nil {
		return defaultDecimals, fmt.Errorf("fail to call smart contract get decimals: %w", err)
	}
	output, err := e.erc20ABI.Unpack(decimalMethod, res)
	if err != nil {
		return defaultDecimals, fmt.Errorf("fail to unpack decimal method call result: %w", err)
	}
	switch output[0].(type) {
	case uint8:
		decimals, ok := abi.ConvertType(output[0], new(uint8)).(*uint8)
		if !ok {
			return defaultDecimals, fmt.Errorf("dev error: fail to cast uint8")
		}
		return uint64(*decimals), nil
	case *big.Int:
		decimals, ok := abi.ConvertType(output[0], new(*big.Int)).(*big.Int)
		if !ok {
			return defaultDecimals, fmt.Errorf("dev error: fail to cast big.Int")
		}
		return decimals.Uint64(), nil
	}
	return defaultDecimals, fmt.Errorf("%s is %T fail to parse it", output[0], output[0])
}
}
```

***

## 3. Unspent allowances in tokens that have approval race protection can break router operations, should approve to zero first

Links to affected code *

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L474

### Impact

The protocl aims to support all sorts of token which includes tokens that have the approval race protection like usdt. Tokens like these require approval to be changed from a zero allowance to a non-zero and do not allow chaning allowance from non-zero to another non zero value. The `_routerDeposit` function approves the router before attempting to deposit the tokens without first approving to zero. Any unspent allowance might cause this safeApprove to fail, thereby dossing the `_routerDeposit` function and its dependencies. 

```solidity
    safeApprove(_asset, _router, _amount);

    iROUTER(_router).depositWithExpiry(
```
### Recommended Mitigation Steps

Consider approving to 0 first.

***


## 4. Excessive deadline param in use in `_routerDeposit` and `transferOutAndCall`

Links to affected code *

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L481

https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/ethereum/contracts/THORChain_Router.sol#L270-L276

### Impact

The deadline param used in `depositWithExpiry` in the router function is hardcoded as `type(uint).max` which is extremely large and can leave the transaction for a very long time in the mempool. 

```solidity
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
    );
  }

```
The same can be observed digging a bit deeper into the `transferOutAndCall` function when the `swapOut` function is queried. Here, there's no deadline parameter provided, but looking at the `swapOut` function in any of the aggregators, [THorchain_Aggregator](https://github.com/code-423n4/2024-06-thorchain/blob/e5ae503d0dc2394a82242be6860eb538345152a1/chain/ethereum/contracts/THORChain_Aggregator.sol#L136-L140) for instance, the function interacts with uniswap router passing in `type(uint).max` as the deadline. 

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
    );
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
      type(uint).max
    );
  }
```

Setting the deadlines to this value causes that the deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpectedly executed or risk staying for very long in the mempool. And also allows for sandwich attacks by mev bots which can use this to steal positive slippage.

### Recommended Mitigation Steps

Consider using a smaller, more reasonable value.