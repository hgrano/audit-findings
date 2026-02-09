# Audit Findings

This repository contains all my currently confirmed smart contract audit findings in both contests and private audits.

## Contest Results

Highlights:
- Ranked 2nd on Code4rena 90-day leaderboard as of Feb 2026.
- Five top 3 finishes on Code4Rena: two 2nd places and three 3rd places.
- 24 confirmed high findings in contests.
- 14 confirmed medium findings in contests.
- Most unique/interesting findings:
  - [Sequence H-01](./code4rena/2025-10-sequence.md#h-01-chained-signature-with-checkpoint-usage-disabled-can-bypass-all-checkpointer-validation) (Solo high)
    - Sponsor feedback on [X](https://x.com/taylanpince/status/1993693265875685651?s=20): "The finding that struck us is H-01 by @0xhgrano. In short, a chained signature with the checkpointer flag disabled could bypass checkpointer validation. That is an elegant, high-impact catch, and it humbled us."
  - [Megapot V2 M-06](https://code4rena.com/reports/2025-11-megapot#m-06-changes-to-pyth-entropy-provider-used-by-scaledentropyprovider-allow-attacker-to-fix-jackpot-result) (Solo medium)
  - [Megapot V2 M-05](https://code4rena.com/reports/2025-11-megapot#m-05-randomness-can-be-exploited-in-some-cases) (found only be one other auditor)
  - [Alchemix V3: H-01](./cantina/2025-05-alchemix-v3.md#h-01-an-initial-dust-deposit-can-be-used-to-decrease-debt-on-other-accounts-leading-to-loss-of-funds) (only reported by two other auditors out of ~200 competitors).

| Platform   | Contest                 | Date        | Findings             | Summary                                        | Comments                                 |
|------------|-------------------------|-------------|----------------------|------------------------------------------------|----------------------------------------- |
| Code4rena  | Megapot V2              | Nov 2025    | 1 Solo Med, 1 Med    | [View](./code4rena/2025-11-megapot.md)         | Placed 3rd and invited by sponsor to complete private, post-contest audit |
| Code4rena  | Sequence                | Oct 2025    | 1 Solo High          | [View](./code4rena/2025-10-sequence.md)                  | Placed 2nd                               |
| Code4rena  | GTE Perps and Launchpad | Sept 2025   | 7 High, 6 Med        | Not available yet        | Placed 2nd. 8 submissions selected as primary (best) submission - to be included in final report. Top "gatherer" (highest number of valid H/M findings). |
| Sherlock   | Notional exponent       | July  2025  | 1 High, 1 Med        | [View](./sherlock/2025-05-notional-exponent.md)|                                          |
| Sherlock   | Chainlink Rewards       | June  2025  | 1 Med                | (Private findings)                             |                                          |
| Sherlock   | LEND                    | May   2025  | 7 High               | [View](./sherlock/2025-05-lend.md)             |                                          |
| Cantina    | Alchemix V3             | May   2025  | 4 High               | [View](./cantina/2025-05-alchemix-v3.md)       | Placed 13th out of ~200 auditors. Highlight: one finding which was almost unique (only reported by two other auditors out of ~200 competitors)  |
| Code4rena  | Upside                  | May   2025  | QA report and 1 Med* | [View](./code4rena/2025-05-upside.md)          | Placed 3rd                               |
| Code4rena  | Nudge.xyz               | March 2025  | 2 Med                | [View](./code4rena/2025-03-nudgexyz.md)        | Placed 3rd out of 58 auditors            |
| Cantina    | BadgerDAO               | March 2025  | 2 High, 1 Med, 2 Low | [View](./cantina/2025-03-BadgerDAO.md)         | Placed 14th out of 80 auditors           |
| Code4rena  | Liquid Ron              | Jan 2025    | 1 Low                | [View](./code4rena/2025-01-liquid-ron.md)      | Limited time with this audit, my single finding was deemed as low severity by the judges |
| Code4rena  | Phi                     | August 2024 | 2 High, 2 Med        | [View](./code4rena/2024-08-phi.md)             | My first try at auditing, placed 13th out of 99 auditors |

\* Includes 1 Medium severity finding which was judged invalid, but respectfully, I believe it is worth raising as a Medium severity issue. Unfortunately for the contestants, the judges did not consider any H/M submissions as valid but I scored well based on my QA report.

## Private audits

| Protocol   | Firm                 | Date        | Findings             | Description                              |
|------------|----------------------|-------------|----------------------|----------------------------------------- |
| Zama Token Auction | Burra Security    | Dec 2025    | (Private)            |  Audit of Zama protocol's confidential token auction system |
| Megapot V2 (post-contest audit)  | Private collaboration in a team of three auditors   | Oct 2025    | [View](./private/Megapot_V2.pdf)       | Final audit of Megapot V2 contracts (post C4 contest) |
