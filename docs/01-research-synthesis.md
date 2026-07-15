# Research synthesis

Research snapshot: 2026-07-15. This is product evidence, not legal advice. Laws, product capabilities, study results, and broker procedures must be revalidated.

## Evidence method

Sources are graded before they influence requirements:

- **A — empirical/primary:** peer-reviewed research, government guidance, official technical documentation, and directly observable repository/product behavior.
- **B — independent field report:** independent transparent testing or relatively neutral community discussion. Useful for concrete failure cases and hypotheses, not population estimates.
- **C — interested/anonymous:** vendor claims, vendor-owned communities, affiliate/SEO reviews, anonymous anecdotes, and promotional threads. Useful for feature discovery and interview language only.

The supplied CyberAdvice Reddit review is Grade C. It contains specific useful feedback, but the thread also has vendor participation, promotion/founder concerns, deleted comments, and people asking whether parts were sponsored or AI-generated. MyCogni does not convert its apparent consensus into an effectiveness or demand claim.

## Strongest empirical warnings

### Independent effectiveness work

The Consumer Reports/Tall Poppy evaluation tested seven services and a manual group over four months against 13 people-search sites. In its small, non-representative sample, only 35% of 332 profiles assigned to removal services were gone at four months; manual opt-outs removed about 70%. EasyOptOuts and Optery performed best among evaluated services. The study notes limitations including four participants per service, limited PII supplied, no dashboard/user intervention, and no reappearance check after an observed removal.

The PETS 2025 paper measured ten services and 2,024 brokers. Participants confirmed only 41.1% of retrieved records as theirs on average, and the services removed 48.2% of identified records on average in the study. It found low overlap and a trade-off between broader search coverage and more PII supplied to the removal service.

These studies do not forecast MyCogni. They establish design obligations: high-precision matching, explicit ambiguity, preserved denominators, minimum disclosure, independent proof, method-specific outcomes, and public limits.

### Official consumer guidance

The FTC explains that people-search information may come from other brokers, social media, and public records; removal may require identity data; information can reappear; relatives' records may still expose the user; and the source public record remains. It advises consumers to ask a service about covered sites, reports, scan cadence, and repeat deletion. These map directly to the support matrix, disclosure preview, evidence report, and visible recheck schedule.

California DROP has accepted eligible consumer requests since 2026, and registered data brokers are required to begin processing through it on 2026-08-01. The consumer flow includes eligibility/identity controls. MyCogni will guide and record the user-completed official flow; it will not automate around verification or claim access to the broker processing API.

## What users appear to value

Triangulated product/community themes:

- setup measured in minutes rather than days;
- automatic repeated work after one understandable authorization;
- exposure discovery before disclosure;
- current/historical names, addresses, emails, and phones;
- specific must-have people-search sites, not a large abstract count;
- custom URL intake for uncovered sources;
- clear per-broker dates, compliance context, manual tasks, and recurring checks;
- evidence or direct verification links showing what was found and what changed;
- affordability and a path that does not require an endless subscription.

Optery's official reports use before/after screenshots when public profiles can be captured, illustrating the trust value of inspectable proof, while also acknowledging private/restricted databases cannot provide public screenshots. Privacy Guides' EasyOptOuts test illustrates how a low-cost recurring service can create value with a small, transparent evaluation. Vendor sources document product mechanics; they do not prove comparative superiority.

## What people distrust or dislike

| Concern | MyCogni product/architecture response |
| --- | --- |
| “Completed” while the record remains | separate receipt, acknowledgement, broker assertion, one absence observation, corroborated verification, and inconclusive states |
| Reports omit what changed | encrypted evidence plus redacted field-category/verification-method report; screenshots only when lawful, safe, and retained minimally |
| No visible recheck cadence | last evidence, next date, method, owner, and reason on every case |
| Custom requests stall without explanation | reason code, dependency, deadline, retry/reconciliation history, and manual escalation path |
| Same-name false matches | attribute-level explanation, high auto threshold, explicit ambiguity, never name-only auto-confirm |
| Past names/addresses are awkward | first-class aliases and validity/provenance ranges |
| Blind outreach may confirm/enrich identity | observe-before-disclose default, no blanket mode, minimum bundle, permanent disclosure ledger |
| Coverage is inflated | generated support matrix by capability/maturity/freshness/evidence rather than one count |
| Subscription creates dependency | self-hosted recurrence, export/pause/uninstall/key deletion, no artificial request quota |
| Spam impact is impossible to attribute | no spam-reduction promise; measure exposure outcomes rather than anecdotes |
| Centralized service is a dossier target | local/single-tenant custody, independent profile keys, external wrapping key, no telemetry by default |
| Reviews feel promotional or synthetic | grade sources, publish study limitations, validate through product experiments |
| Model/AI creates another opaque actor | no model in v1; later local assist has zero authority and no raw PII |

## Product-market implications

The wedge is not “free Incogni.” It is proof-first local custody for a technical U.S. self-hoster. V1 narrows to one adult, a small public preview set, guided flows, and 2–5 trusted automatic connectors. It competes with DIY on recurring burden and with SaaS on trust—not on breadth.

Commercial custom removals often hide human work. A volunteer open-source project cannot promise unlimited arbitrary takedowns. V1 custom intake safely classifies a URL and builds a guided draft; automatic arbitrary-site action is deferred.

## Ecosystem and license policy

Public government registries, Data Rights Protocol, community lists, and open-source removers are research inputs. They are not automatically redistributable facts/code under Apache-2.0.

The Data Rights Protocol defines useful signed request/status vocabulary but documents a closed trust network and evolving identity semantics; MyCogni maps states without claiming participation. The “Big Ass Data Broker Opt-Out List” is a valuable reference whose CC BY-NC-SA license is not silently folded into an Apache-2.0 registry. Bulk-email/CAPTCHA-solving open-source projects demonstrate demand and also show why minimum disclosure, no bypass, evidence semantics, expiry, and artifact isolation matter.

Each imported fact or artifact needs source, access date, reviewer, applicable terms/license, transformation, and revalidation/expiry. The repository begins with synthetic data only.

## Primary references

### Grade A

- Consumer Reports/Tall Poppy, *Data Defense*: <https://innovation.consumerreports.org/Data-Defense_-Evaluating-People-Search-Site-Removal-Services-.pdf>
- He et al., PETS 2025: <https://petsymposium.org/popets/2025/popets-2025-0125.pdf>
- FTC people-search guidance: <https://consumer.ftc.gov/articles/what-know-about-people-search-sites-sell-your-information>
- CPPA data broker/DROP information: <https://cppa.ca.gov/data_brokers/>
- DROP technical specifications: <https://privacy.ca.gov/drop-for-data-brokers/technical-specifications/>
- Data Rights Protocol: <https://github.com/consumer-reports-innovation-lab/data-rights-protocol>
- NIST AI RMF Generative AI Profile: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>

### Grade B

- Privacy Guides removal-service criteria: <https://www.privacyguides.org/en/data-broker-removals/>
- Privacy Guides EasyOptOuts field test: <https://www.privacyguides.org/articles/2025/02/03/easyoptouts-review/>

### Grade C, used as hypotheses/product mechanics

- Supplied Reddit review and discussion: <https://www.reddit.com/r/CyberAdvice/comments/1l3no4j/incogni_review_my_experience_using_it_for_data/>
- Concrete completed-but-present complaint: <https://www.reddit.com/r/Incogni_Official/comments/1n49eiy/incogni_cant_force_your_data_to_be_removed_with/>
- Incogni product description: <https://blog.incogni.com/review/>
- Optery removal-report mechanics: <https://help.optery.com/en/article/what-is-a-removals-report-1ht35vl/>
