# Audit Findings

This repository contains all my currently confirmed smart contract audit findings.

Highlights:
- One 2nd place and two 3rd place finishes on Code4Rena.
- 23 confirmed high findings.
- 11 confirmed medium findings.
- Most unique/interesting findings:
  - Sequence (solo high awaiting report publication by Code4rena)
  - [Alchemix V3: H-01](./cantina/2025-05-alchemix-v3.md#h-01-an-initial-dust-deposit-can-be-used-to-decrease-debt-on-other-accounts-leading-to-loss-of-funds) (only reported by two other auditors out of ~200 competitors).

| Platform   | Contest                 | Date        | Findings             | Summary                                        | Comments                                 |
|------------|-------------------------|-------------|----------------------|------------------------------------------------|----------------------------------------- |
| Code4rena  | Sequence                | Oct 2025    | 1 Solo High          | (Awaiting report publication)                  | Placed 2nd                               |
| Code4rena  | GTE Perps and Launchpad | Sept 2025   | High: 7 confirmed. Med: 6 confirmed. Several more awaiting escalation. | Not available yet        | Several submissions currently selected as primary (best) submission, pending final judging decision |
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
