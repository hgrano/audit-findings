# Audit Findings – Notional Exponent

**Platform:** Sherlock  
**Contest:** [LEND](https://audits.sherlock.xyz/contests/908)  
**Dates:** July 3, 2025 - July 19, 2025   
**Role:** Independent Security Researcher  
**Findings:** 1 High, 1 Medium

# H-01: User withdrawing through `DineroWithdrawRequestManager` will cause permanent loss of assets for other withdrawing users
### Summary
Lack of tracking of redemption request amounts in `DineroWithdrawRequestManager` will cause permanent loss for some withdrawing users, as non-malicious users may receive too many assets if multiple withdrawals use the same `batchId`.

### Root Cause
In [Dinero.sol:61](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/withdraws/Dinero.sol#L61), the amount of assets (which is what will be returned to the user) is calculated based upon the UpxEth balance of the contract for the batchId. This represents a claim the contract has on a portion of the amount withdrawn for that particular batch. The issue is that when requesting withdrawal, multiple requests may use the same `batchId`. Therefore if two users request withdrawal and happen to use the same `batchId`, the first user to finalize their withdrawal will receive both their share of the assets for that batch and the other user's share.

### Internal Pre-conditions
1. System is deployed such that the withdrawal manager is the `DineroWithdrawalManager`.

### External Pre-conditions
1. After the users request withdrawal the underlying ETH must be un-staked and the PirexETH rewardRecipient needs to call `PirexEth::dissolveValidator`.

### Attack Path
Assume the current [`pendingWithdrawal`](https://github.com/dinero-protocol/pirex-eth-contracts/blob/67dca88f91456725cd823cc61bd0b5f1e080cea5/src/PirexEthValidators.sol#L204) amount of the `PirexEth` contract is `x` and then:

1. User1 calls `initiateWithdraw` on the lending router for a yield token amount, `y`, such that `x + y < 32 ether` (User1's withdrawal is allocated to batch 1).
2. User2 calls `initiateWithdraw` on the lending router for a yield token amount, `z`, such that `x + y + z 32 ether` (Part of User2's withdrawal is allocated to batch 1 and the remainder to batch 2).
3. After some time the underlying eth is un-staked.
4. PirexETH rewardRecipient calls `PirexEth::dissolveValidator` for batch 1.
5. User1 calls `redeemNative` on the yield strategy: minus fees, they receive `y` assets back plus the part of User2's withdrawal assigned to batch 1.
6. After some time, users outside of notional may request withdrawal directly from `PirexEth`, and the remainder of batch 2 is filled and `dissolveValidator` called for it.
7. User2 calls `redeemNative` on the yield strategy: minus fees, they only receive the amount of their withdrawal assigned to batch 2.

### Impact
User1 gains an unfair share of assets causing a direct loss of assets for User2.

### PoC
Add the following test to the `TestDinero_pxETH_WithdrawRequest` contract in TestWithdrawRequestImpl.sol`:

```solidity
function test_PoC() public approveVault {
        emit log_named_decimal_uint("Pending withdrawal", IPirexEthValidators(address(PirexETH)).pendingWithdrawal(), 18);
        // For testing purposes, in the fork block number, the pending withdrawal should be zero
        assertEq(IPirexEthValidators(address(PirexETH)).pendingWithdrawal(), 0);

        ERC20 yieldToken = ERC20(manager.YIELD_TOKEN());
        deal(address(yieldToken), address(this), 100e18);
        yieldToken.approve(address(manager), yieldToken.balanceOf(address(this)));
        uint256 yieldTokenAmount = 17e18;
        uint256 sharesAmount = 50e18;

        // First request can't fill up a full 32 ether unstaking batch
        manager.initiateWithdraw(address(0x10), yieldTokenAmount, sharesAmount, withdrawCallData);
        // Second request fills the remainder of the batch used by the first request, plus a little extra
        manager.initiateWithdraw(address(0x20), yieldTokenAmount, sharesAmount, withdrawCallData);

        address alice = makeAddr("alice");
        deal(address(pxETH), alice, 100e18);
        vm.prank(alice);
        // Third request from user outside of the notional protocol will fill up the second batch
        PirexETH.initiateRedemption(32 ether, alice, false);

        // Dissolve the validators for the two batches which cover the first and second requests
        bytes memory pubKey1 = PirexETH.batchIdToValidator(PirexETH.batchId() - 2);
        bytes memory pubKey2 = PirexETH.batchIdToValidator(PirexETH.batchId() - 1);
        vm.deal(PirexETH.rewardRecipient(), 100 ether);
        vm.startPrank(PirexETH.rewardRecipient());
        PirexETH.dissolveValidator{value: 32 ether}(pubKey1);
        PirexETH.dissolveValidator{value: 32 ether}(pubKey2);
        vm.stopPrank();

        uint256 initialAssetBalance = IERC20(manager.WITHDRAW_TOKEN()).balanceOf(address(this));
        (uint256 tokensWithdrawn1, bool finalized1) = manager.finalizeAndRedeemWithdrawRequest(address(0x10), yieldTokenAmount, sharesAmount);
        (uint256 tokensWithdrawn2, bool finalized2) = manager.finalizeAndRedeemWithdrawRequest(address(0x20), yieldTokenAmount, sharesAmount);
        uint256 finalAssetBalance = IERC20(manager.WITHDRAW_TOKEN()).balanceOf(address(this));

        emit log_named_uint("finalized1", finalized1 ? 1 : 0);
        emit log_named_uint("finalized2", finalized2 ? 1 : 0);

        emit log_named_decimal_uint("tokensWithdrawn1", tokensWithdrawn1, 18);
        emit log_named_decimal_uint("tokensWithdrawn2", tokensWithdrawn2, 18);

        emit log_named_decimal_uint("asset balance increase", finalAssetBalance - initialAssetBalance, 18);
    }
```

Also add the below interface to the same file:

```solidity
interface IPirexEthValidators {
    function pendingWithdrawal() external returns (uint256);

    function dissolveValidator(
        bytes calldata _pubKey
    ) external payable;
}
```

And run using `forge test --match-test test_PoC --match-contract TestDinero_pxETH_WithdrawRequest -vvv`. Test logs:

```
Logs:
  Pending withdrawal: 0.000000000000000000
  finalized1: 1
  finalized2: 1
  tokensWithdrawn1: 32.000000000000000000
  tokensWithdrawn2: 1.989800000000000000
  asset balance increase: 33.989800000000000000
```

Both users requested to withdraw 17 ether but one would have received 32 ether and the 1.9898 ether.

# M-01: User finalizing withdrawal from Ethena sUSDe will receive zero USDe back if `coolDownDuration` is zero
### Summary
Incorrect calculation of `tokensClaimed` within `EthenaCooldownHolder` will cause the withdrawing user to receive zero assets back if `sUSDe.cooldownDuration() == 0`.

### Root Cause
The issue is in [Ethena.sol:20](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/withdraws/Ethena.sol#L20): when a user initiates withdrawal and the cool down duration is zero, the sUSDe is immediately redeemed for USDe, which is transferred back to the `EthenaCooldownHolder`. When it comes time for the user to finalize their withdrawal, on [Ethena.sol:47-48](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/withdraws/Ethena.sol#L47-L48), the amount claimed is determined based on the increase in balance due to un-staking. Due to the fact that the redemption has already occurred, when un-staking the balance increase will be zero. Therefore the user receives zero assets back.

### Internal Pre-conditions
1. User has non-zero native balance on a vault (yield strategy), where the yield token is sUSDe

### External Pre-conditions
1. Ethena admin sets coolDownDuration on sUSDe to zero.

### Attack Path
1. User calls `initiateWithdraw` on the router, causing the USDe to be withdrawn to the cool down handler.
2. User calls `redeemNative` on the yield strategy but receives zero USDe back.

### Impact
The user is unable to withdraw underlying assets from the protocol. The only way to remedy in the situation is for the admin to call `rescueTokens` on the `EthenaWithdrawRequestManager` to send the tokens back to the user.
