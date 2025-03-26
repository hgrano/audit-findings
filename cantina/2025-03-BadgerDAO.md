# Audit Findings – Badger DAO eBTC BSM

**Platform:** Cantina  
**Contest:** [badger-ebtc-bsm](https://cantina.xyz/competitions/f57ffb47-0ded-4f04-bcec-ecd7d47fad58)  
**Dates:** March 6, 2025 - March 13, 2025   
**Role:** Independent Security Researcher  
**Findings accepted:** 2 High, 2 Medium

---

## 🛑 High Severity Findings

### H-01: **`EbtcBSM` contract does not handle asset tokens with decimals other than 18**

#### Description and impact
The `EbtcBSM` contract is intended to work with a variety of BTC-pegged tokens: several of these tokens do not use 18 decimal places but the contract is unable to handle these correctly, leading to direct loss of funds for users. The following are examples which all use 8 decimal places:

- cbBTC
- wBTC
- renBTC

The contract always exchanges these tokens at a 1 to 1 rate with eBTC which has 18 decimal places. Calls to sellAsset will receive a very small value of eBTC, and calls to buyAsset receive huge values of eBTC. As shown in the PoC below is it is possible for an attacker to exploit this to easily drain liquidity from the BSM at a significant profit.

The impact is high because:

1. Liquidity is drained causing DoS to other users.
1. The total supply of eBTC does not decrease much if the attacker executes the exploit, while the amount of the underlying asset decreases significantly. The attacker could potentially sell large amounts of eBTC causing a depeg.

Likelihood is high because it is immediately exploitable by any user.

#### Proof of Concept
Add another Solidity file under the test folder and copy the following into it:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "./BSMTestBase.sol";

contract DecimalsTests is BSMTestBase {
    function testBadDecimalsExploit() public {
        vm.prank(testMinter);
        // 1e8 assets, representing value of a single bitcoin as there are 8 decimal places for this token
        bsmTester.sellAsset(1e8, testMinter, 0);
        // Received 1e8 eBTC, representing value of 1e-10 bitcoin, which is essentially worthless
        assertEq(mockEbtcToken.balanceOf(testMinter), 1e8);

        address attacker = vm.addr(0xBEEF);
        deal(address(mockEbtcToken), attacker, 1e18);
        vm.startPrank(attacker);
        // The attacker spends 1e8 eBTC, representing value of 1e-10 bitcoin
        bsmTester.buyAsset(1e8, attacker, 0);

        // Attacker receives 1e8 assets, representing a value of 1 bitcoin having spent almost nothing
        assertEq(mockAssetToken.balanceOf(attacker), 1e8);
    }
}
```

Then run the test using:

```
forge test -vvv --match-test testBadDecimalsExploit
```

#### Recommended Mitigation Steps 

On EbtcBSM.sol:181, adjust the ebtcAmountOut so it is scaled appropriately:

```solidity
_ebtcAmountOut = (_assetAmountIn - _feeAmount) * 10 ** (18 - ASSET_TOKEN_DECIMALS);
```

`ASSET_TOKEN_DECIMALS` can be an immutable variable set in the constructor.

Also, on EbtcBSM.sol:221, scale amountIn and feeAmount as shown:

```solidity
 uint256 amountInScaled = _ebtcAmountIn / (10 ** (18 - ASSET_TOKEN_DECIMALS));
 uint256 feeAmountScaled = _feeAmount / (10 ** (18 - ASSET_TOKEN_DECIMALS));

 uint256 redeemedAmount = escrow.onWithdraw(amountInScaled);

_assetAmountOut = redeemedAmount - feeAmountScaled;
```

Note: the mitigation assumes no tokens with higher than 18 decimals.

**Submission details:** https://cantina.xyz/code/f57ffb47-0ded-4f04-bcec-ecd7d47fad58/findings/502

### H-02: **Oracle price check is inverted**

#### Description and impact
The oracle price check which occurs when minting eBTC is designed to ensure that if tBTC depegs downwards from BTC too much, then eBTC should not be mintable. The `tBTCChainlinkAdapter` returns the inverse of the required price, so the logic is inverted.

The ratio used to compute the price the price of tBTC relative to BTC has the numerator/denominator the wrong way around on tBTCChainlinkAdapter.sol:64.

Due to this, if the price of tBTC is lower than BTC, then the returned price is actually greater than 1e18. Therefore the Oracle price constraint will return true on OraclePriceConstraint.sol:82.

An attacker may do the following to exploit this:

1. Purchase tBTC at a price lower than BTC or eBTC.
1. Call sellAsset and receive eBTC in return for their tBTC.
1. Sell the eBTC at a profit.

This will put downward pressure on the eBTC price, likely causing it to depeg downwards.

The impact is high: the issue may cause distrust of the eBTC protocol if an eBTC depeg occurs and users may sell their eBTC at a loss.

The issue can only occur if tBTC depegs downwards which is not likely to happen often but is certainly possible.

#### Proof of Concept
Add the following imports to SellAssetTests.t.sol:

```solidity
import {MockAssetOracle} from "./mocks/MockAssetOracle.sol";
import {tBTCChainlinkAdapter, AggregatorV3Interface} from "../src/tBTCChainlinkAdapter.sol";
```

Then also add the following test function `SellAssetTests`:

```solidity
    function testSellAssetsDownardsDepeg() public {
        MockAssetOracle usdtBtcAggregator = new MockAssetOracle(8);
        MockAssetOracle btcUsdAggregator = new MockAssetOracle(8);
        tBTCChainlinkAdapter adapterAggreagator = new tBTCChainlinkAdapter(usdtBtcAggregator, btcUsdAggregator);
        OraclePriceConstraint adapterOraclePriceConstraint = new OraclePriceConstraint(address(adapterAggreagator), address(authority));
        setRoleCapability(
            15,
            address(adapterOraclePriceConstraint),
            adapterOraclePriceConstraint.setMinPrice.selector,
            true
        );

        vm.startPrank(techOpsMultisig);
        bsmTester.setOraclePriceConstraint(address(adapterOraclePriceConstraint));
        adapterOraclePriceConstraint.setMinPrice(9500);
        vm.stopPrank();

        usdtBtcAggregator.setLatestRoundId(111);
        usdtBtcAggregator.setPrice(90_000 * 1e8);
        usdtBtcAggregator.setUpdateTime(block.timestamp);

        btcUsdAggregator.setLatestRoundId(222);
        btcUsdAggregator.setPrice(100_000 * 1e8);
        btcUsdAggregator.setUpdateTime(block.timestamp);

        vm.expectPartialRevert(IMintingConstraint.MintingConstraintCheckFailed.selector);
        vm.prank(testMinter);
        bsmTester.sellAsset(1e18, testMinter, 0);
    }
```
Then run the test using:

```
forge test --match-test testSellAssetsDownardsDepeg -vv
```

This results in test failure as the sellAsset function does not revert.

#### Recommended Mitigation Steps

This issue can be fixed by inverting the ratio computed on tBTCChainlinkAdapter.sol:L64 as shown:

```
(BTC_USD_PRECISION * tBtcUsdPrice * ADAPTER_PRECISION) /
(btcUsdPrice * TBTC_USD_PRECISION);
```

**Submission details:** https://cantina.xyz/code/f57ffb47-0ded-4f04-bcec-ecd7d47fad58/findings/456

## ⚠️ Medium Severity Findings

### M-01: `tBTCChainlinkAdapter` does not account for one price feed lagging behind the other

#### Description and impact
On tBTCChainlinkAdapter.sol:108, the contract assigns the `updatedAt` to be the minimum of the two price feeds but does not consider if there is a significant difference difference in these two times. A difference is likely to occur as the tBTC feed is typically updated less frequently than BTC. These are the current configurations of the chainlink feeds:

tBTC trigger parameters (source: https://data.chain.link/feeds/ethereum/mainnet/tbtc-usd):

- Deviation threshold = 2%
- Heartbeat = 24 hours

BTC trigger parameters (source: https://data.chain.link/feeds/ethereum/mainnet/btc-usd):

- Deviation threshold = 0.5%
- Heartbeat = 1 hour

There is some mitigation for this issue already as OraclePriceConstraint:62 ensures that the minimum of the two `updatedAt` values of the feeds is within the desired limit, however this may not be sufficient in all cases.

These are some possible scenarios:

##### Scenario A

Due to the long heartbeat interval of tBTC it's likely that oracleFreshnessSeconds would need to be set quite high (i.e. close to 24 hours) in order to stop DoS in low volatility conditions (when tBTC feed won't be updated regularly). Although unlikely, it is possible that:

1. tBTC price feed stops getting updated for several hours due to an issue with chainlink.
1. BTC price feed continues to be updated, and the price does not fluctuate significantly.
1. While tBTCprice feed is not updated, a tBTC depeg occurs, causing the system requirement of approximate parity between tBTC and BTC to be broken.

##### Scenario B

There is a rapid market movement, and tBTC price feed continually lags behind. This might lead to situations where the depeg threshold is reached simply due to stale price data of tBTC, rather than an actual depeg (leading to temporary DoS). Additionally, it may be the case that a depeg is beginning to occur but the price difference since the last chainlink update is still less than the tBTC deviation threshold of 2%. There may be temporary periods where the depeg cannot be detected the protocol.

The impact is high because in scenario A above, the stale data and depeg cannot be detected by the contract. This could then lead to a depeg of eBTC itself, due to attackers exploiting the price difference between the 1 to 1 price provided by the BSM contract, and the price of tBTC on other markets.

For scenario B, the impact is low as the effects should be short-lived.

The likelihood is low as in scenario A, it requires an issue with chainlink. However we cannot assume chainlink is always available 100% of the time, and it has suffered issues such as a [6 hour ETH price feed delay in March 2020](https://cryptobriefing.com/chainlink-experiences-6-hour-delay-eth-price-feed/).

Scenario B is only possible in high volatility periods, so fairly unlikely.

#### Proof of Concept

The following test can be added to `SellAssetTests`:

```solidity
    function testSellAssetsPriceLag() public {
        vm.warp(1741737645);

        MockAssetOracle usdtBtcAggregator = new MockAssetOracle(8);
        MockAssetOracle btcUsdAggregator = new MockAssetOracle(8);
        tBTCChainlinkAdapter adapterAggreagator = new tBTCChainlinkAdapter(usdtBtcAggregator, btcUsdAggregator);
        OraclePriceConstraint adapterOraclePriceConstraint = new OraclePriceConstraint(address(adapterAggreagator), address(authority));
        setRoleCapability(
            15,
            address(adapterOraclePriceConstraint),
            adapterOraclePriceConstraint.setMinPrice.selector,
            true
        );

        vm.startPrank(techOpsMultisig);
        bsmTester.setOraclePriceConstraint(address(adapterOraclePriceConstraint));
        adapterOraclePriceConstraint.setMinPrice(9500);
        vm.stopPrank();

        usdtBtcAggregator.setLatestRoundId(111);
        usdtBtcAggregator.setPrice(100_000 * 1e8);
        usdtBtcAggregator.setUpdateTime(block.timestamp - 5 hours);

        btcUsdAggregator.setLatestRoundId(222);
        btcUsdAggregator.setPrice(102_000 * 1e8);
        btcUsdAggregator.setUpdateTime(block.timestamp - 5 minutes);

        vm.prank(testMinter);
        bsmTester.sellAsset(1e18, testMinter, 0);
    }

```

The `sellAsset` function does not revert even though there is a significant difference in updateTime between the two feeds.

#### Recommendation
It is difficult to mitigate the issue completely as fundamentally the updates to the two feeds will naturally occur at different frequencies due to the different deviation thresholds and heartbeats. One option would be to consider using WBTC instead of tBTC as its chainlink feed has a lower deviation threshold, and so should be updated more often. In addition to this, another check within the code could be added to compare the updatedAt times of two feeds and ensure they are not too far apart. The threshold for this would need to be carefully tuned to avoid DoS.

**Submission details:** https://cantina.xyz/code/f57ffb47-0ded-4f04-bcec-ecd7d47fad58/findings/466
