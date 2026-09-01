# Reference Audit — all 47 cited entries

Every reference cited in `paper.tex` (v8), with how it was verified.
Verification methods, strongest to weakest:

- **DF** — direct fetch of the primary source page (arXiv abs/html, ACM DL,
  IEEE Xplore, ScienceDirect, MDPI, publisher) during the v6/v8 audits.
- **PS** — primary-source confirmation during the initial collection pass
  (topic agents located the publisher/indexer record and matched
  title/authors/venue/year before the entry was admitted to the .bib).
- **C** — canonical/landmark work, additionally matched against its
  well-known venue record during collection.

No entry is cited on memory alone. One entry was **removed** during the
audits (`wickramasekara2026capabilities`, v6: author attribution could not
be confirmed) and one had its **author list corrected**
(`cheng2025omnisec`, v8). Spot-check anything yourself via the listed locator.

| Key | What it is | Locator | Method |
|---|---|---|---|
| alharthi2025cloud | LLM cloud forensics, IEEE SERVICES/CLOUD 2025 | doi:10.1109/SERVICES62574.2025.11120597 (IEEE Xplore #11120597) | DF (v6) |
| anjum2021darpa | DARPA OpTC dataset analysis, SACMAT 2021 | doi:10.1145/3450569.3463573 | PS |
| arp2022dosdonts | ML-in-security pitfalls, USENIX Security 2022 | usenix.org/conference/usenixsecurity22 | C |
| ban2023breaking | AI-assisted SIEM, Applied Sciences 13(11):6610 | doi:10.3390/app13116610 | DF (collection) |
| bohnet2022attributed | Attributed QA | arXiv:2212.08037 | PS |
| cadet2026rag | RAG for incident analysis | arXiv:2603.18196 | DF (v6) |
| cheng2025omnisec | OMNISEC provenance IDS | arXiv:2503.03108 | DF (v8; authors corrected to v3) |
| cherif2025dfirmetric | DFIR-Metric benchmark, ICONIP 2025 | arXiv:2505.19973; doi:10.1007/978-981-95-4367-0_2 | DF (v6) |
| du2017deeplog | DeepLog, ACM CCS 2017 | doi:10.1145/3133956.3134015 | C |
| dykstra2013frost | FROST OpenStack forensics, DFRWS/Digital Investigation | doi:10.1016/j.diin.2013.06.010 | PS |
| flynt2026orgforge | OrgForge-IT insider-threat LLM benchmark | arXiv:2603.22499 | DF (v6 + v8 reconfirm) |
| gemmateam2024gemma | Gemma model report | arXiv:2403.08295 | DF (v8) |
| geng2023constrained | Grammar-constrained decoding, EMNLP 2023 | doi:10.18653/v1/2023.emnlp-main.674 | PS |
| glasser2013bridging | CERT insider-threat data, IEEE SPW 2013 | doi:10.1109/SPW.2013.37 | C |
| greshake2023not | Indirect prompt injection, AISec 2023 | doi:10.1145/3605764.3623985 | PS (v3 addition) |
| gudjonsson2010log2timeline | Super-timeline, SANS GCFA Gold | sans.org/white-papers/33438 | PS |
| habibzadeh2025survey | LLMs-for-SOC survey | arXiv:2509.10858 | DF (v6) |
| herman2020nistir8006 | NIST cloud forensics challenges | doi:10.6028/NIST.IR.8006 | C |
| huang2025hallucination | Hallucination survey, ACM TOIS 43(2) | doi:10.1145/3703155 | DF (v8) |
| jiang2023mistral | Mistral 7B | arXiv:2310.06825 | C |
| kent2006sp80086 | NIST SP 800-86 forensics/IR guide | doi:10.6028/NIST.SP.800-86 | C |
| kent2015lanl | LANL multi-source cyber events dataset | doi:10.17021/1179829 (csr.lanl.gov/data/cyber1) | PS |
| king2003backtracking | Backtracker, SOSP 2003 | doi:10.1145/945445.945467 | C |
| lewis2020rag | RAG, NeurIPS 2020 | NeurIPS proc. vol 33 | C |
| loumachi2025gendfir | GenDFIR timeline RAG, Computers 14(2):67 | doi:10.3390/computers14020067 | DF (v8) |
| milajerdi2019holmes | HOLMES APT detection, IEEE S&P 2019 | doi:10.1109/SP.2019.00026 | C |
| min2023factscore | FActScore, EMNLP 2023 | doi:10.18653/v1/2023.emnlp-main.741 | PS |
| nadler2019detection | Low-throughput DNS exfiltration, C&S 80 | doi:10.1016/j.cose.2018.09.006 | PS |
| ocsf2022schema | OCSF schema | github.com/ocsf/ocsf-schema | C |
| qi2023loggpt | LogGPT | arXiv:2309.01189 | PS |
| ruan2013cloudforensics | Cloud forensics survey, Digital Investigation 10(1) | doi:10.1016/j.diin.2013.02.004 | PS |
| scanlon2023chatgpt | ChatGPT for DF, FSI:DI 46 | doi:10.1016/j.fsidi.2023.301609 | PS |
| sharma2025forensicllm | ForensicLLM, FSI:DI 52 | doi:10.1016/j.fsidi.2025.301872 | DF (v8) |
| sharma2025ragsurvey | RAG survey (Sharma) | arXiv:2506.00054 | DF (v8) |
| singh2025llmsoc | LLMs in the SOC (45 analysts, 10 months) | arXiv:2508.18947 | DF (v6) |
| sommer2010outside | ML for NIDS critique, IEEE S&P 2010 | doi:10.1109/SP.2010.25 | C |
| strom2018attack | MITRE ATT&CK design & philosophy | attack.mitre.org/resources | C |
| studiawan2025standardized | LLM timeline-analysis methodology, FSI:DI | arXiv:2505.03100; doi:10.1016/j.fsidi.2025.301942 | DF (v6) |
| tariq2025alert | Alert fatigue, ACM CSUR 57(9):224 | doi:10.1145/3723158 | DF (v8) |
| touvron2023llama2 | Llama 2 | arXiv:2307.09288 | C |
| tuor2017deep | Deep insider-threat detection, AAAI AICS 2017 | arXiv:1710.00811 | PS |
| turpin2023language | CoT unfaithfulness, NeurIPS 2023 | NeurIPS proc. vol 36 (arXiv:2305.04388) | PS (v3 addition) |
| wang2023selfconsistency | Self-consistency, ICLR 2023 | openreview (arXiv:2203.11171) | C |
| wei2025cortex | CORTEX multi-agent triage | arXiv:2510.00311 | DF (v6 + v8 reconfirm) |
| wickramasekara2025exploring | LLMs for DF efficiency, FSI:DI 52:301859 | doi:10.1016/j.fsidi.2024.301859 | DF (v6) |
| xu2024hallucination | Hallucination inevitability | arXiv:2401.11817 | DF (v8) |
| yin2025digitalforensics | DF in the age of LLMs | arXiv:2504.02963 | DF (v6) |

**Coverage:** 47/47 cited entries verified; 18 by direct primary-source
fetch in the v6/v8 audits (all of the 2025–2026 entries the reviewer
flagged — OrgForge-IT, CORTEX, OMNISEC, Cadet, Singh, Habibzadeh, DFIR-Metric,
Studiawan, ForensicLLM, Tariq, GenDFIR, Huang, Xu, Gemma, Alharthi,
Wickramasekara, Sharma-RAG, Yin); the remainder are either canonical works
(NIST, CCS, S&P, NeurIPS, USENIX) or were matched to publisher records at
collection time.
