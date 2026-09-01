# MASTER PROMPT: Build the Forensic Investigation System

Copy everything below this line and paste it into a fresh conversation with Claude, ChatGPT, or any capable coding AI.

---

You are building a **research prototype**, not a product.

Your job is to help implement a thesis project titled:

**A Privacy-Preserving LLM-Assisted Framework for Post-Incident Forensic Investigation in Private Cloud Environments**

The real research question is:

> **Does LLM-assisted reasoning improve post-incident forensic understanding from structured private-cloud evidence, compared with rule-based analysis alone, without introducing unacceptable hallucinations?**

Everything you build must serve that question.

**What success looks like:** A filled evaluation table comparing rule-based vs LLM-assisted results across 4 scenarios, with real metrics from actual system runs. Not assumed. Not projected. Actually computed from actual outputs.

---

## 1. Non-Negotiable Build Philosophy

1. **Prefer correctness over breadth.** Do not build extra modules just because they sound impressive. Build the smallest end-to-end system that can answer the research question.
2. **No fake completeness.** Do not claim a feature works unless it was actually executed. Do not say "done" for a module that is only scaffolded.
3. **No fabricated results.** Never invent benchmark outputs. Never invent evaluation scores. Never fill the comparison table with expected values and present them as actual results.
4. **No fabricated testing claims.** Never say tests passed unless they were actually run. Never say integration works unless components were actually exercised together.
5. **Work incrementally.** Build one layer. Verify it. Then move to the next layer. Each phase must run before the next phase is built.
6. **Do not over-engineer.** API, dashboard, Docker polish, and fancy packaging are secondary. The core pipeline matters first.
7. **Be explicit about uncertainty and failure.** If something is incomplete, say exactly what. If something is unverified, label it as unverified.
8. **No placeholders. No TODOs.** Every function must be complete and callable.

---

## 2. Required Output Discipline

When reporting progress, separate items into:

### A. Built and executed
Code exists and was actually run. Output was verified.

### B. Built but not executed
Code exists, but no runtime confirmation yet.

### C. Planned only
Not implemented yet.

Never blur those categories.

---

## 3. Required Failure Reporting

If something fails, report:

- what failed
- where it failed
- likely cause
- what was fixed
- what remains unverified

Do not hide failure under vague phrases like "should work," "likely functional," "production-ready," or "fully integrated" unless genuinely verified.

---

## 4. Working Style

Use this workflow:

1. Inspect repository state (read existing files first)
2. Identify the smallest next step
3. Implement only that step
4. Run it
5. Inspect output
6. Fix if needed
7. Then continue

Do not dump a huge amount of unverified code at once. Prefer iterative, verifiable progress.

---

## 5. Repository Behavior

When working in the repository:

1. Read existing files before modifying them
2. Avoid unnecessary rewrites — preserve working code unless there is a real reason to change it
3. Prefer surgical edits over total rewrites
4. Keep code simple
5. Add comments only where they actually help
6. Keep naming clear and boring
7. Do not create empty module trees just to look complete

---

## 6. Code Quality Guidance

Favor:
- Plain Python
- Small functions
- Deterministic behavior
- Structured outputs (JSON)
- Testable logic

Avoid:
- Over-abstraction
- Premature class hierarchies
- Unnecessary framework complexity
- "Enterprise" patterns without need

---

## 7. Scope Control

### In scope
- scenario design with concrete events
- synthetic log generation
- unified normalization
- timeline reconstruction
- light correlation logic
- rule engine
- structured LLM input/output with hallucination checking
- evaluation harness
- final comparison table

### Out of scope unless the core pipeline already works
- polished frontend
- enterprise auth / RBAC
- production deployment
- complex microservices
- advanced SOAR integration
- elaborate Docker orchestration
- "productized" features unrelated to the thesis evaluation

---

## 8. Verification Protocol

After each phase, run executable checks:

- **Run the code.** Not "it should work." Actually execute it.
- **Diff output against expected.** Compare generated events against ground truth. Count mismatches.
- **Check edge cases.** Does Scenario 4 actually fool the rule engine? If rules catch it fully, the scenario needs to be harder.
- **Print intermediate output.** After normalization, print 5 sample events. After timeline, print the Scenario 4 timeline. After rules, print what was flagged.

If any check fails, fix it before proceeding. Do not move to the next phase with known broken output.

---

## 9. Core Architecture

Use this logical pipeline:

1. **Scenario Definitions** → define exactly what happens
2. **Source-Specific Log Generation** → produce raw logs from scenarios
3. **Normalization to Unified Event Schema** → map all sources to one schema
4. **Timeline Reconstruction** → chronological ordering, session grouping
5. **Rule-Based Analysis** → deterministic detection
6. **LLM-Assisted Analysis** → structured reasoning over correlated evidence
7. **Evaluation Against Ground Truth** → compute metrics from actual outputs
8. **Report / Comparison Output** → the table that IS the paper

Keep the architecture simple and direct.

---

## 10. Project Location and Structure

```
~/projects/cybersecurity/forensic-framework/
```

```
forensic-framework/
├── app/
│   ├── __init__.py
│   ├── config.py              # Settings, env loading
│   ├── database.py            # SQLAlchemy models + connection
│   ├── ingestion/
│   │   ├── __init__.py
│   │   └── parser.py          # Read and parse raw log files
│   ├── normalizer/
│   │   ├── __init__.py
│   │   └── normalizer.py      # Map all sources to unified schema
│   ├── timeline/
│   │   ├── __init__.py
│   │   └── timeline.py        # Reconstruct chronological timeline
│   ├── correlation/
│   │   ├── __init__.py
│   │   └── correlator.py      # Cross-source event linking
│   ├── rules/
│   │   ├── __init__.py
│   │   └── rule_engine.py     # Detection rules
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── client.py          # LLM API client (Modal or mock)
│   │   └── prompts.py         # Prompt templates
│   ├── evaluation/
│   │   ├── __init__.py
│   │   └── evaluator.py       # Metrics computation
│   └── reporting/
│       ├── __init__.py
│       └── reporter.py        # Forensic report generator
├── data/
│   ├── scenarios/             # Scenario definition files
│   ├── raw_logs/              # Source-specific log files
│   ├── normalized/            # Unified events output
│   └── ground_truth/          # Expected results
├── config/
│   └── rules.yaml             # Detection rule definitions
├── tests/
├── requirements.txt
├── .env
├── run_pipeline.py            # Run entire analysis pipeline
└── run_evaluation.py          # Run evaluation + print results table
```

If a simpler structure is enough during early phases, use a simpler structure. Do not create empty files just for show.

---

## 11. Tech Stack

- Python 3.11+
- PostgreSQL 15 (via Docker) — or SQLite / flat JSON files if faster for prototype validation
- LLM: Qwen 3.5 via Modal (HTTP API calls to existing endpoint)
- Minimal dependencies — do not add libraries unless justified

---

## 12. Privacy Honesty (IMPORTANT FOR THE PAPER)

The research claim is privacy-preserving local reasoning. You must keep the architecture wording honest:

- **Fully local** = model runs on the organization's own hardware
- **Privately hosted remote** = model runs on a managed compute service (Modal) — not local, but the organization controls the endpoint and no data goes to a third-party LLM provider
- **External API** = data sent to OpenAI/Anthropic/etc.

In this prototype, inference runs on Modal (privately hosted remote). In the paper, frame it as:
- Development/evaluation uses Modal for convenience
- Production deployment for regulated industries would use the same open-weight model on the organization's own infrastructure
- The architecture supports this — the LLM client is a thin HTTP wrapper that can point to any OpenAI-compatible endpoint (local Ollama, vLLM on-prem, or Modal for development)

Do not describe Modal as "local." Do not conflate these categories.

---

## 13. Unified Event Schema

All source logs normalize into this exact schema:

```json
{
  "event_id": "evt_00001",
  "timestamp": "2026-04-01T09:15:32+06:00",
  "source_type": "auth | file_access | admin | network",
  "user": "user_01",
  "action": "login | logout | file_read | file_download | privilege_change | file_delete | log_delete | config_change",
  "resource": "/data/finance/report_q1.xlsx",
  "source_ip": "192.168.1.100",
  "status": "success | failure",
  "session_id": "sess_abc123",
  "severity": "info | warning | critical",
  "metadata": {}
}
```

All timestamps MUST include timezone offset. The organization is in Dhaka, Bangladesh (UTC+6).

You may extend this minimally if justified, but do not bloat it.

---

## 14. User Baselines

```json
{
  "user_01": {
    "department": "finance",
    "role": "financial_analyst",
    "normal_hours": "08:30-18:00",
    "timezone": "Asia/Dhaka",
    "normal_ips": ["192.168.1.100"],
    "normal_directories": ["/data/finance/"],
    "avg_files_per_day": 4,
    "avg_downloads_per_day": 1
  },
  "user_02": {
    "department": "engineering",
    "role": "senior_developer",
    "normal_hours": "09:00-19:00",
    "timezone": "Asia/Dhaka",
    "normal_ips": ["192.168.1.102"],
    "normal_directories": ["/data/engineering/", "/data/shared/project_alpha/", "/data/shared/project_beta/"],
    "avg_files_per_day": 8,
    "avg_downloads_per_day": 3,
    "travel_note": "Frequently travels internationally. IP varies when traveling.",
    "project_memberships": ["project_alpha", "project_beta"]
  },
  "user_03": {
    "department": "hr",
    "role": "hr_specialist",
    "normal_hours": "09:00-17:30",
    "timezone": "Asia/Dhaka",
    "normal_ips": ["192.168.1.103"],
    "normal_directories": ["/data/hr/"],
    "avg_files_per_day": 5,
    "avg_downloads_per_day": 1
  },
  "user_04": {
    "department": "finance",
    "role": "junior_accountant",
    "normal_hours": "09:00-17:00",
    "timezone": "Asia/Dhaka",
    "normal_ips": ["192.168.1.104"],
    "normal_directories": ["/data/finance/"],
    "avg_files_per_day": 3,
    "avg_downloads_per_day": 0,
    "access_level": "read_only"
  }
}
```

---

## 15. The 4 Scenarios

You must implement exactly these four scenarios. The events below are the ground truth — generate raw logs FROM these events.

### SCENARIO 1: Normal Baseline (Control)

**Label:** BENIGN
**Purpose:** Both systems should produce no alert. Establishes that the pipeline doesn't cry wolf.

**Story:** user_01 (financial analyst) has a normal workday.

**Events:**
1. auth: login, user_01, 2026-04-01T09:15+06:00, IP 192.168.1.100, success
2. file_access: file_read, user_01, 09:45, /data/finance/report_q1.xlsx, success
3. file_access: file_read, user_01, 11:20, /data/finance/budget_2026.xlsx, success
4. file_access: file_read, user_01, 14:00, /data/finance/cashflow_march.pdf, success
5. auth: logout, user_01, 17:30, success

**Expected:** Rule-based: no_alert. LLM: no_alert.

---

### SCENARIO 2: Noisy but Benign

**Label:** BENIGN
**Purpose:** Rules should flag this (false positive). LLM should recognize it as benign. Tests whether the LLM can downgrade suspicious-looking but explainable activity.

**Story:** user_02 (senior developer) is at a conference in Singapore (UTC+8). They log in during Singapore working hours, which appears as unusual from a Dhaka-time perspective. They access many files from their own department plus a few cross-project files they're authorized for.

**Timezone math (GET THIS RIGHT):**
- Singapore is UTC+8. Dhaka is UTC+6. Singapore is 2 hours AHEAD of Dhaka.
- To convert Singapore → Dhaka: subtract 2 hours. To convert Dhaka → Singapore: add 2 hours.
- If user_02 starts working at 10:00 Singapore time, that is 08:00 Dhaka time. (10:00 - 2 = 08:00)
- If user_02 works until 23:00 Singapore time, that is 21:00 Dhaka time. (23:00 - 2 = 21:00)
- The "suspicious" part: they also work a late session from 23:30-01:30 Singapore time (preparing for next day's talk), which is 21:30-23:30 Dhaka time. (23:30 - 2 = 21:30)
- VERIFY: 21:30 Dhaka (UTC+6) = 21:30 + 2 = 23:30 Singapore (UTC+8). Correct.

**Events (all timestamps in Dhaka UTC+6):**
1. auth: login, user_02, 2026-04-01T08:15+06:00, IP 103.28.45.67 (Singapore hotel), success
2. file_access: file_read, user_02, 08:30, /data/engineering/arch_overview.pptx, success
3. file_access: file_download, user_02, 09:00, /data/engineering/system_design_v3.pdf (2.1MB), success
4. file_access: file_read, user_02, 10:15, /data/engineering/api_docs.md, success
5. file_access: file_read, user_02, 11:00, /data/engineering/deployment_guide.docx, success
6. file_access: file_read, user_02, 11:30, /data/shared/project_alpha/requirements.docx, success (cross-project but authorized)
7. file_access: file_download, user_02, 11:45, /data/shared/project_alpha/architecture_decisions.md (380KB), success (cross-project download)
8. auth: logout, user_02, 12:30, success
9. auth: login, user_02, 2026-04-01T21:30+06:00, IP 103.28.45.67, success (late session — 23:30 Singapore)
10. file_access: file_download, user_02, 21:45, /data/engineering/infrastructure_diagram.png (4.5MB), success
11. file_access: file_read, user_02, 22:00, /data/engineering/sprint_backlog.xlsx, success
12. file_access: file_read, user_02, 22:15, /data/shared/project_alpha/timeline.xlsx, success (cross-project)
13. file_access: file_download, user_02, 22:30, /data/engineering/performance_benchmarks.xlsx (1.8MB), success
14. file_access: file_read, user_02, 22:45, /data/shared/project_beta/integration_spec.docx, success (cross-project — different project)
15. file_access: file_download, user_02, 23:00, /data/engineering/roadmap_2026.pptx (3.2MB), success
16. file_access: file_download, user_02, 23:10, /data/engineering/load_test_results.tar.gz (8.7MB), success (larger file — test data archive)
17. auth: logout, user_02, 23:25, success

**Why rules flag it:**
- New IP (103.28.45.67 not in normal_ips)
- Late night session (21:30-23:25 Dhaka time)
- 6 downloads total across the day (double user_02's avg_downloads_per_day of 3)
- 4 cross-project file accesses across 2 different shared projects (/data/shared/project_alpha/ and /data/shared/project_beta/)
- One large file download (8.7MB archive)
- 17 events total — higher than usual activity volume

**Why it's actually benign:**
- All engineering files are in user_02's department
- /data/shared/project_alpha/ and /data/shared/project_beta/ are shared project directories (user_02 is authorized for both as a senior developer)
- The large file (load_test_results.tar.gz) is engineering test data, not sensitive records
- File sizes are normal working documents, not database dumps
- No privilege changes, no log tampering, no access to confidential directories
- user_02 has a travel note in baseline — IP variation is expected
- The late session maps to 23:30 Singapore, which is plausible conference prep
- Download count (6) is elevated but not extreme for a travel day with conference prep

**Why this is a hard false positive (not trivially dismissible):**
- The cross-project access spans TWO different projects, not just one
- The download volume is elevated
- The large archive file could look like data exfiltration to a naive system
- Late-night + foreign IP + high downloads is a classic attack profile superficially
- An LLM must reason about travel context, role authorization, and file types to correctly downgrade

**Expected:** Rule-based: false_positive. LLM: no_alert (should recognize context).

---

### SCENARIO 3: Obvious Attack

**Label:** ATTACK
**Purpose:** Both systems detect. Tests whether LLM gives a better investigation narrative. Sanity check.

**Attacker:** External attacker using compromised credentials of user_04 (junior accountant, read_only access).

**Story:** Credentials stolen via phishing. Attacker logs in from a foreign IP at unusual hours. Escalates privileges. Downloads sensitive financial files. Attempts to clean up.

**Events (Dhaka UTC+6):**
1. auth: login_failed, user_04, 2026-04-01T02:47+06:00, IP 185.220.101.34 (Frankfurt, Germany), failure (wrong password)
2. auth: login_failed, user_04, 02:48, IP 185.220.101.34, failure
3. auth: login, user_04, 02:49, IP 185.220.101.34, success (got password right on 3rd try)
4. admin: privilege_change, user_04, 02:52, role read_only -> read_write, success
5. file_access: file_download, user_04, 02:54, /data/finance/confidential/customer_data_2025.csv (45MB), success
6. file_access: file_download, user_04, 02:55, /data/finance/confidential/transaction_log_q1.csv (38MB), success
7. file_access: file_download, user_04, 02:56, /data/finance/confidential/salary_all_employees.xlsx (12MB), success
8. file_access: file_download, user_04, 02:57, /data/finance/confidential/loan_portfolio.xlsx (28MB), success
9. file_access: file_download, user_04, 02:58, /data/finance/confidential/credit_risk_model.xlsx (15MB), success
10. file_access: file_download, user_04, 02:59, /data/finance/confidential/swift_messages_march.csv (22MB), success
11. file_access: file_download, user_04, 03:00, /data/finance/confidential/audit_trail_2025.csv (31MB), success
12. file_access: file_download, user_04, 03:01, /data/finance/confidential/vendor_contracts.pdf (8MB), success
13. file_access: file_download, user_04, 03:02, /data/finance/confidential/board_minutes_q1.pdf (4MB), success
14. file_access: file_download, user_04, 03:03, /data/finance/confidential/tax_filings_2025.xlsx (19MB), success
15. file_access: file_download, user_04, 03:04, /data/finance/confidential/insurance_claims.csv (7MB), success
16. file_access: file_download, user_04, 03:05, /data/finance/confidential/regulatory_correspondence.pdf (3MB), success
17. admin: log_delete, user_04, 03:08, /var/log/file_access.log, success
18. auth: logout, user_04, 03:10, success

**Attack steps (ground truth):**
1. failed_login_attempts (credential stuffing — 2 failures then success)
2. login_unusual_ip (Frankfurt hosting provider IP — user_04 is Dhaka-based junior)
3. privilege_escalation (read_only -> read_write, 3 minutes after login)
4. bulk_file_download (12 files from /confidential/ in 11 minutes, 232MB total)
5. log_deletion (deleted file access log — incomplete cleanup, attacker mistake)
6. logout

**Why this is realistic, not cartoonish:**
- Hosting provider IP, not Tor exit node
- read_only -> read_write escalation, not straight to admin
- 12 files over 11 minutes — fast but not impossibly fast
- Failed logins show credential stuffing pattern
- Only one log file deleted (incomplete cleanup — attackers make mistakes)
- user_04 is a junior with read_only who suddenly writes and downloads — clear anomaly

**Expected:** Rule-based: full_detection (multiple rules trigger). LLM: full_detection + better narrative.

---

### SCENARIO 4: Subtle Attack (KEY SCENARIO — THE PAPER LIVES HERE)

**Label:** ATTACK
**Purpose:** Rule-based system should miss or partially detect. LLM should detect the aggregate pattern. This is where the thesis contribution is demonstrated.

**Attacker:** user_03 (insider — HR specialist planning to leave, collecting data to take to competitor)

**Story:** user_03 has legitimate HR access. Over 3 days, they gradually expand scope and shift from reading to downloading. No single event is alarming. The pattern only becomes suspicious in aggregate.

**Events (Dhaka UTC+6):**

Day 1 (April 1) — Reconnaissance:
1. auth: login, user_03, 2026-04-01T09:00+06:00, IP 192.168.1.103, success
2. admin: privilege_change, user_03, 09:30, added read access to /data/finance/reports/, success (metadata: {"ticket": "HR-2026-441", "justification": "Annual review preparation"})
3. file_access: file_read, user_03, 10:15, /data/hr/headcount_q1.xlsx, success (normal)
4. file_access: file_read, user_03, 11:00, /data/finance/reports/revenue_q1.xlsx, success (new scope)
5. file_access: file_read, user_03, 14:30, /data/finance/reports/expense_breakdown.xlsx, success (new scope)
6. auth: logout, user_03, 17:45, success

Day 2 (April 2) — Expansion:
7. auth: login, user_03, 2026-04-02T08:45+06:00, IP 192.168.1.103, success
8. file_access: file_read, user_03, 09:30, /data/hr/employee_reviews.xlsx, success (normal)
9. file_access: file_read, user_03, 10:45, /data/finance/reports/budget_forecast.xlsx, success (new scope)
10. file_access: file_download, user_03, 11:30, /data/finance/reports/vendor_payments.xlsx (890KB), success (first download outside HR)
11. file_access: file_read, user_03, 13:00, /data/engineering/hiring/candidate_pipeline.xlsx, success (new department — engineering)
12. file_access: file_download, user_03, 14:15, /data/engineering/hiring/offer_letters_template.docx (240KB), success (engineering download)
13. file_access: file_read, user_03, 15:30, /data/finance/reports/profit_loss_march.xlsx, success (finance)
14. auth: logout, user_03, 17:30, success

Day 3 (April 3) — Collection:
15. auth: login, user_03, 2026-04-03T09:15+06:00, IP 192.168.1.103, success
16. file_access: file_read, user_03, 09:45, /data/hr/salary_bands.xlsx, success (normal)
17. file_access: file_download, user_03, 10:30, /data/hr/salary_bands.xlsx (340KB), success (downloading what they normally only read)
18. file_access: file_download, user_03, 11:15, /data/finance/reports/revenue_q1.xlsx (1.1MB), success (re-accessing + downloading a file they only read on Day 1)
19. file_access: file_download, user_03, 13:00, /data/finance/reports/budget_forecast.xlsx (780KB), success
20. file_access: file_download, user_03, 14:00, /data/engineering/hiring/candidate_pipeline.xlsx (560KB), success
21. file_access: file_download, user_03, 15:00, /data/finance/reports/expense_breakdown.xlsx (920KB), success
22. file_access: file_download, user_03, 16:00, /data/hr/performance_reviews_2025.xlsx (1.3MB), success
23. auth: logout, user_03, 17:15, success

**Why rules should struggle:**
- Normal IP (192.168.1.103 — same office, every day)
- Normal hours (09:00-17:45 — standard workday)
- Low volume (max 8 events/day, spread across 8 hours)
- Small files (240KB-1.3MB — documents, not dumps)
- Privilege change has a ticket and justification
- user_03 IS HR — accessing some HR files is expected
- No log deletion, no cleanup
- No single day has bulk downloads (Day 3 has 6 downloads but spread over 7 hours)

**What makes it suspicious (only visible in aggregate across 3 days):**
- Scope creep: Day 1 = 2 new-scope files, Day 2 = 4 new-scope + first downloads, Day 3 = 6 downloads
- Behavioral shift: reading on Days 1-2, downloading on Day 3
- Re-downloading: files read earlier are downloaded later (read → evaluate → collect pattern)
- Cross-department access: HR person accessing finance AND engineering
- The privilege change + subsequent access suggests premeditation

**Attack steps (ground truth):**
1. login_normal
2. minor_privilege_change (requested finance access with plausible justification)
3. slow_scope_expansion_day1 (2 finance files, reads only)
4. slow_scope_expansion_day2 (finance + engineering, first downloads)
5. systematic_download_day3 (6 downloads across HR + finance + engineering)
6. data_exfiltration_complete (15 files accessed, 8 downloaded over 3 days)

**Expected:** Rule-based: partial (may flag cross-department access or the privilege change, but no single rule catches the full pattern). LLM: full_detection (should recognize the escalating scope + read-then-download pattern).

---

## 16. Ground Truth

```json
{
  "scenarios": [
    {
      "id": "scenario_1",
      "name": "normal_baseline",
      "label": "BENIGN",
      "attacker": null,
      "attack_steps": [],
      "expected_detection": { "rule_based": "no_alert", "llm_assisted": "no_alert" }
    },
    {
      "id": "scenario_2",
      "name": "noisy_benign",
      "label": "BENIGN",
      "attacker": null,
      "attack_steps": [],
      "expected_detection": { "rule_based": "false_positive", "llm_assisted": "no_alert" }
    },
    {
      "id": "scenario_3",
      "name": "obvious_attack",
      "label": "ATTACK",
      "attacker": "user_ext_01 (using user_04 credentials)",
      "attack_steps": [
        "failed_login_attempts",
        "login_unusual_ip",
        "privilege_escalation",
        "bulk_file_download",
        "log_deletion",
        "logout"
      ],
      "expected_detection": { "rule_based": "full_detection", "llm_assisted": "full_detection" }
    },
    {
      "id": "scenario_4",
      "name": "subtle_attack",
      "label": "ATTACK",
      "attacker": "user_03",
      "attack_steps": [
        "login_normal",
        "minor_privilege_change",
        "slow_scope_expansion_day1",
        "slow_scope_expansion_day2",
        "systematic_download_day3",
        "data_exfiltration_complete"
      ],
      "expected_detection": { "rule_based": "partial", "llm_assisted": "full_detection" }
    }
  ]
}
```

---

## 17. Detection Rules

```yaml
rules:
  - id: R001
    name: unusual_login_ip
    severity: warning
    condition: source_ip NOT IN user.normal_ips AND action == login

  - id: R002
    name: off_hours_access
    severity: warning
    condition: timestamp outside user.normal_hours

  - id: R003
    name: privilege_escalation
    severity: critical
    condition: action == privilege_change

  - id: R004
    name: bulk_download
    severity: critical
    condition: count(file_download, window=30min) > 5

  - id: R005
    name: cross_department_access
    severity: warning
    condition: resource directory NOT IN user.normal_directories

  - id: R006
    name: log_deletion
    severity: critical
    condition: action == log_delete

  - id: R007
    name: failed_login_spike
    severity: warning
    condition: count(login failures, window=5min) >= 2

  - id: R008
    name: privilege_then_download
    severity: critical
    condition: privilege_change FOLLOWED BY file_download WITHIN 30min
```

---

## 18. LLM Prompt Template

```
You are a digital forensic analyst investigating a private cloud environment after a suspected security incident. Analyze the structured evidence below.

STRICT RULES:
1. Only reason about events explicitly listed in the CORRELATED TIMELINE.
2. Do NOT assume, invent, or infer events not present.
3. If evidence is insufficient, say "INSUFFICIENT EVIDENCE."
4. Reference specific event_ids for every claim.
5. Assign confidence: HIGH, MEDIUM, or LOW to each claim.

USER BASELINES:
{user_baselines_json}

CORRELATED TIMELINE:
{timeline_json}

TRIGGERED RULES:
{triggered_rules_json}

ANALYSIS TASKS:
1. VERDICT: Is there evidence of a security incident? (YES / NO / INSUFFICIENT)
2. ATTACK CHAIN: If YES, list ordered steps. Each step must cite an event_id.
3. SUSPECT: Most suspicious user. Explain using only the evidence.
4. SUPPORTING EVIDENCE: List event_ids that support your verdict.
5. COUNTER-EVIDENCE: List event_ids that weaken your verdict.
6. GAPS: What evidence is missing that would strengthen the analysis?
7. CONFIDENCE: Overall confidence with explanation.

Respond in JSON:
{
  "verdict": "YES | NO | INSUFFICIENT",
  "confidence": "HIGH | MEDIUM | LOW",
  "confidence_explanation": "...",
  "suspect": "user_id or null",
  "attack_chain": [
    {"step": 1, "event_id": "evt_xxx", "description": "...", "confidence": "HIGH|MEDIUM|LOW"}
  ],
  "evidence_for": ["evt_xxx"],
  "evidence_against": ["evt_zzz"],
  "gaps": ["..."],
  "narrative": "2-3 sentence summary"
}
```

---

## 19. Mandatory Anti-Hallucination Constraints

Every LLM prompt must enforce:
- no invented timestamps
- no invented actors
- no invented network movements
- no invented attack steps
- no claims without evidence references
- explicit acknowledgement of missing evidence

You must also build an evaluation check for:
- claims referencing event_ids not in input
- event references that do not exist in the provided timeline
- sequence claims inconsistent with actual timestamps

---

## 20. LLM Integration

LLM is hosted on Modal (already deployed). Use HTTP API:

```python
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

MODAL_ENDPOINT = os.getenv("MODAL_ENDPOINT")
MODAL_TOKEN = os.getenv("MODAL_TOKEN")

async def call_llm(prompt: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{MODAL_ENDPOINT}/v1/chat/completions",
            json={
                "model": "qwen3.5",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 4096
            },
            headers={"Authorization": f"Bearer {MODAL_TOKEN}"},
            timeout=120.0
        )
        return response.json()
```

Create `.env` with placeholder values. User fills in their own.

If the Modal endpoint is unavailable, create a clearly-labeled mock client that returns realistic structured JSON. Mark all results from mock runs as "MOCK" — do not present them as real.

---

## 21. Evaluation Metrics

### Detection metrics:
- **Verdict Accuracy** = correct BENIGN/ATTACK classification
- **Event Recall** = (correctly identified attack steps) / (total actual attack steps) × 100
- **False Positive Rate** = (benign events flagged) / (total benign events) × 100
- **Missed Suspicious Events** = attack steps not detected

### LLM-specific metrics:
- **Hallucination Count** = claims referencing event_ids not in input OR describing events not in input
- **Unsupported Claims Count** = assertions without evidence references
- **Timeline Correctness** = attack chain steps in correct chronological order? (yes/no)
- **Evidence Grounding** = (claims with valid event_id) / (total claims) × 100
- **Narrative Usefulness** = manual review (mark as manual if cannot be automated)

If a metric cannot be computed automatically, clearly mark it as manual review.

---

## 22. Final Comparison Table (THIS IS THE PAPER)

```
| Scenario       | Ground Truth | Rule Verdict    | LLM Verdict    | Event Recall | Rule Misses | LLM Misses | LLM Hallucinations | Notes |
|----------------|-------------|-----------------|-----------------|--------------|-------------|------------|---------------------|-------|
| Normal         | BENIGN      | ?               | ?               | N/A          | N/A         | N/A        | ?                   |       |
| Noisy Benign   | BENIGN      | ?               | ?               | N/A          | N/A         | N/A        | ?                   |       |
| Obvious Attack | ATTACK      | ?               | ?               | ?%           | ?           | ?          | ?                   |       |
| Subtle Attack  | ATTACK      | ?               | ?               | ?%           | ?           | ?          | ?                   |       |
```

Fill ONLY from actual pipeline runs. Mark any mock results clearly.

### Anti-Fabrication Rules for Evaluation

These rules are non-negotiable:

1. **Never populate the comparison table from expectations.** Only from actual executed pipeline output.
2. **Never claim a metric value unless the evaluation code computed it.** If the evaluator hasn't run, the cell stays "?".
3. **Never backfill "expected" values and present them as "actual."** If a scenario wasn't run, say so.
4. **If the LLM client is mocked, every result in the table must be labeled "MOCK."** Do not present mock-derived metrics alongside real metrics without clear separation.
5. **If evaluation reveals the LLM performs worse than expected (e.g., hallucinates on Scenario 4, misses the subtle attack), report that honestly.** A negative result is still a valid thesis result.

---

## 23. Build Order (Strict — Do Not Skip Ahead)

### Phase 1 — Data Foundation
Build:
- Scenario definitions (4 files)
- Ground truth file
- User baselines file
- Raw log generator (produces auth_logs.json, file_logs.json, admin_logs.json FROM the scenario events above)
- Normalizer (produces unified_events.json)

Verify:
- Generated logs match scenarios exactly
- Timestamps are coherent and sequential
- Print event count per scenario, print 3 sample events
- Ground truth aligns with scenario events

Do not move on until this is solid.

### Phase 2 — Investigation Core
Build:
- Timeline reconstruction (chronological ordering, grouped by user/session)
- Lightweight correlation logic (cross-source linking, temporal matching)
- Rule engine (implements all 8 rules from §14)
- Baseline rule outputs for all 4 scenarios

Verify:
- Scenario 1 = no alerts
- Scenario 2 = some warnings (false positive)
- Scenario 3 = many alerts (full detection)
- Scenario 4 = few/partial alerts (if rules catch everything, the rules or scenario need adjustment)

### Phase 3 — LLM Analysis
Build:
- LLM prompt builder (from template in §15)
- Structured evidence packager (timeline + rules + baselines → prompt)
- LLM inference wrapper (Modal client with mock fallback)
- Output parser (extracts JSON from LLM response)
- Hallucination checker (validates event_id references, timestamps, claims)

Verify:
- LLM responds in required JSON structure
- Evidence references map to real event_ids
- Unsupported claims are counted
- Save raw LLM responses to data/llm_responses/

### Phase 4 — Evaluation
Build:
- Evaluator (computes all metrics from §18)
- run_pipeline.py (runs Phase 1-3 end-to-end)
- run_evaluation.py (runs Phase 4, prints the comparison table)
- Filled comparison table printed to stdout

Verify:
- Table is filled from actual runs, not assumptions
- Any mock results clearly labeled

### Phase 5 — Polish (only after Phase 4 is complete and verified)
Optional:
- Streamlit dashboard
- Report generator
- FastAPI wrapper
- Better visualization

These are optional, not core.

---

## 24. Definition of Success

Success is not: lots of files, a nice dashboard, broad architecture diagrams, or impressive claims.

Success is: a small working prototype, four valid scenarios, a real comparison between rule-based and LLM-assisted analysis, measured hallucination behavior, and an honest evaluation table.

At every step, prioritize: verified over assumed, smaller over larger, evidence over presentation, evaluation over polish, honesty over confidence theater.

---

## 25. Start Now

Begin with Phase 1. Create the project directory. Generate the scenario data. Build the parser and normalizer. Run them. Print output. Verify. Then move to Phase 2.
