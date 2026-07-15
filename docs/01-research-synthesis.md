# Research synthesis

Research snapshot: 2026-07-15. This document records product evidence, not legal advice. Laws, broker procedures, and product capabilities change and must be revalidated.

## What people value

The referenced Reddit review and discussion consistently value:

- a setup that takes minutes rather than days;
- fully automated submission and repeated follow-up;
- both standard broker coverage and custom requests;
- a dashboard with request status, completion dates, broker compliance context, and public/private views;
- recurring checks when information resurfaces;
- visible progress while legal response windows run.

These observations align with Incogni's own description of scanning public brokers, directly requesting private brokers, and supporting custom removals. They also align with independent reviews that highlight automation while noting that proof and reporting depth differentiate competitors.

## What people distrust or dislike

The same discussion surfaces important failure modes:

| Concern | MyCogni response |
| --- | --- |
| Reports do not explain what information was removed | Evidence-backed finding and outcome records; redacted field categories in reports |
| No visible recheck cadence | Per-broker next-check date, reason, and policy |
| Custom requests stall without explanation | State reason, deadline, retry history, and escalation path are first-class |
| “Removed” may only mean the broker replied | Separate `broker_asserted_removed` from `verified_removed` |
| People with the same name may be confused | Attribute-level matching, confidence explanation, and approval for ambiguity |
| Past names and addresses are awkward | Multiple aliases, phones, emails, and address validity ranges |
| Subscription feels endless and expensive | Self-hosted software, no arbitrary request quota, burst-friendly scheduled runs |
| Sending PII can confirm a live identity | Minimum-disclosure plans, risk preview, and no blanket broadcast mode |
| Coverage claims can be inflated | Publish capability levels and recent pass rates, not one undifferentiated count |
| Service effectiveness is hard to measure | Baseline evidence, post-request verification, and resurfacing history |
| A centralized service becomes a breach target | Local encryption, external keys, redacted logs, optional cloud deployment |
| Marketing creates unrealistic spam-reduction expectations | No promise that removal eliminates spam, public records, breaches, or collection |
| Reviews may be promotional or synthetic | Treat community posts as hypotheses; validate with research and observable outcomes |

## Empirical findings that shape the architecture

The 2025 PETS paper *Measuring the Accuracy and Effectiveness of PII Removal Services* evaluated 10 services and 2,024 brokers. It found low overlap between services, only 41.1% average accuracy for retrieved records in its study, and 48.2% average removal success for identified records. It also found that broader coverage tends to require more user PII, increasing the removal service's own privacy risk. This makes match review, evidence semantics, minimum disclosure, and connector quality more important than raw coverage.

California's DROP platform launched for consumer deletion requests in 2026, with brokers required to begin processing through it on 2026-08-01. DROP is a useful official path for eligible California residents, but its consumer interface requires residency/identity verification and prohibits unauthorized submissions for another person. MyCogni should guide eligible users to the official platform and record completion; it must not automate around its identity controls or claim access to the broker-side API.

The Data Rights Protocol provides an Apache-2.0 open standard for signed request/status flows, but its repository describes a closed trust network and evolving identity-verification semantics. MyCogni should map its domain model to DRP states and add a compatible transport only when participation and conformance are real—not market the protocol as universally available.

## Ecosystem and reuse policy

Potential public inputs include government broker registries, the Data Rights Protocol, and open directories such as Optery's broker directory. MyCogni must verify source terms and licenses before copying data. The initial repository intentionally includes only a synthetic connector manifest; it does not scrape, copy, or redistribute another service's broker list.

Existing open-source projects demonstrate demand but also common risks: hard-coded browser flows, broad CAPTCHA-solving integrations, secrets in local configuration, lack of evidence semantics, and abandoned connectors. MyCogni's differentiator should be a governed connector lifecycle and privacy architecture rather than merely a larger script collection.

## Primary sources and references

- Referenced Reddit review and discussion: <https://www.reddit.com/r/CyberAdvice/comments/1l3no4j/incogni_review_my_experience_using_it_for_data/>
- Incogni product review/feature description: <https://blog.incogni.com/review/>
- California Privacy Protection Agency data broker information: <https://cppa.ca.gov/data_brokers/>
- California consumer DROP terms: <https://consumer.drop.privacy.ca.gov/>
- California DROP technical specifications for data brokers: <https://privacy.ca.gov/drop-for-data-brokers/technical-specifications/>
- Data Rights Protocol: <https://github.com/datarightsprotocol/data-rights-protocol>
- European Commission right-to-erasure overview: <https://commission.europa.eu/law/law-topic/data-protection/rules-business-and-organisations/dealing-citizens/do-we-always-have-delete-personal-data-if-person-asks_en>
- He et al., PETS 2025: <https://tysong.github.io/files/PETS25.pdf>
- Optery open data broker directory landing page: <https://www.optery.com/data-brokers/>
