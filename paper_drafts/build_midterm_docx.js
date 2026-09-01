// Build a Word version of midterm_paper.tex.
// Mirrors the proposal-style structure of the PDF.
// Run: node build_midterm_docx.js

const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun,
  AlignmentType, LevelFormat, HeadingLevel,
  PageNumber, Footer, Header,
} = require("docx");

// ---------- Helpers ----------
const FONT = "Times New Roman";

function p(text, opts = {}) {
  const runs = Array.isArray(text) ? text : [new TextRun({ text, font: FONT, size: opts.size || 22, italics: opts.italics, bold: opts.bold })];
  return new Paragraph({
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { after: opts.after ?? 120, line: 280 },
    indent: opts.indent,
    children: runs,
  });
}

function rt(text, opts = {}) {
  return new TextRun({ text, font: FONT, size: opts.size || 22, italics: opts.italics, bold: opts.bold });
}

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 320, after: 160 },
    children: [new TextRun({ text, font: FONT, size: 26, bold: true })],
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 200, after: 100 },
    children: [new TextRun({ text, font: FONT, size: 23, bold: true, italics: true })],
  });
}

function bullet(children, ref = "bullets") {
  return new Paragraph({
    numbering: { reference: ref, level: 0 },
    spacing: { after: 100, line: 280 },
    alignment: AlignmentType.JUSTIFIED,
    children,
  });
}

// Citation marker: [n]
function c(n) { return rt(` [${n}]`); }

// ---------- Document content ----------
const titleBlock = [
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 80 },
    children: [new TextRun({ text: "Augmenting Rule-Based Private-Cloud Forensic Investigation with Evidence-Grounded LLM Reasoning", font: FONT, size: 32, bold: true })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 240 },
    children: [new TextRun({ text: "Midterm Progress Report", font: FONT, size: 26, italics: true })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 320 },
    children: [new TextRun({ text: "Md. Nazmul Hasan", font: FONT, size: 24 })],
  }),
];

const abstractBlock = [
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 160, line: 280 },
    children: [
      new TextRun({ text: "Abstract—", font: FONT, size: 22, bold: true, italics: true }),
      rt("Private-cloud incident investigation requires reconstructing activity from fragmented authentication, file-access, administrative, network, database, web-server, and email logs, without a unified audit plane comparable to public-cloud services. Rule-based correlation is auditable but brittle. Large language models can synthesise context across events but hallucinate. We propose a hybrid forensic-triage approach that pairs a transparent rule baseline with a constrained LLM required to cite a specific event identifier for every claim, validated by a deterministic citation check applied to the model’s output. The proposed evaluation reports three orthogonal correctness axes — verdict accuracy, suspect attribution, and citation-grounding integrity — on a controlled corpus of fifteen incident scenarios with known ground truth. This midterm report frames the proposal, surveys thirteen related works across five thematic threads, defines the gap, and reports preliminary indications consistent with the direction. Implementation depth, multi-model comparison, real-world dataset validation, and a small human-analyst study are scoped for the final paper."),
    ],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 280, line: 280 },
    children: [
      new TextRun({ text: "Index Terms—", font: FONT, size: 22, bold: true, italics: true }),
      rt("digital forensics, post-incident triage, private cloud, large language models, evidence grounding, hallucination mitigation, rule-based correlation."),
    ],
  }),
];

// ---------- Sections ----------
const intro = [
  h1("I.  Introduction"),
  p("Banks, government agencies, healthcare providers, and other regulated organisations frequently operate private clouds because compliance or threat-model constraints preclude data from leaving organisational control. Unlike public-cloud services such as AWS CloudTrail or Azure Monitor, a private cloud has no single audit plane: authentication, file-access, administrative, network, database, web-server, and email events live in separate systems. After an incident, evidence reconstruction is manual, slow, and expert-dependent. Rule-based correlation in industrial SIEM and SOAR platforms is transparent and auditable but is widely reported as brittle: it generates large alert volumes on legitimate-but-unusual activity and produces weak verdicts on attacks whose pattern lives only in cross-time-window aggregation. Large language models offer complementary capabilities — synthesis of weak signals across events, contextual interpretation, narrative explanation — but bring failure modes that are unacceptable in forensic settings: hallucinated evidence, causal overclaim, and prompt sensitivity."),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("This work concerns post-incident "),
      rt("triage", { italics: true }),
      rt(", not real-time detection: the proposed system reads already-collected logs and produces an investigative output that a human analyst reviews before any action is taken. The research question is bounded accordingly: "),
      rt("can a constrained LLM, operating only over structured normalised events and required to cite specific event identifiers for every claim, improve post-incident forensic triage over a transparent rule-based baseline while preserving traceability?", { italics: true }),
    ],
  }),
  p("This midterm report is structured as a proposal rather than a results report. Section II reviews background and related work and identifies the gap. Section III describes the proposed approach at a conceptual level. Section IV sets out the proposed evaluation methodology. Section V reports preliminary indications consistent with the proposal. Section VI lists the work that remains for the final paper."),
];

const background = [
  h1("II.  Background and Related Work"),

  h2("A.  Forensic triage versus real-time detection"),
  p("Real-time detection runs continuously on streaming events at low latency and may trigger automated responses. Triage operates on already-collected logs, runs in batches or on demand after an incident or audit trigger, and produces an investigative output for human review. The proposed system is a triage system; this distinction is preserved throughout the work."),

  h2("B.  Rule-based correlation as an auditable but brittle baseline"),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("Rule-based correlation expresses threshold and temporal predicates over normalised event streams. Its strengths — determinism, transparency, auditability — are essential in regulated environments. Its weaknesses are well-documented: alert fatigue is a structural rather than incidental property of SOC operations"),
      c(1),
      rt(", and rule logic does not aggregate across long time windows. Prior work proposes AI-assisted alert suppression"),
      c(2),
      rt("; this is adjacent to our proposal but does not address evidence-grounded reasoning over the underlying timeline."),
    ],
  }),

  h2("C.  LLMs in security operations and forensics"),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("A 2025 survey"),
      c(3),
      rt(" catalogues LLM use in SOC workflows and observes that the field lacks shared evaluation infrastructure. A longitudinal empirical study"),
      c(4),
      rt(" of three thousand analyst queries across forty-five SOC analysts finds that LLMs are used predominantly as cognitive aids rather than as autonomous classifiers; this finding directly motivates the analyst-supervised triage posture defended here."),
    ],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("In digital forensics, Studiawan, Breitinger and Scanlon"),
      c(5),
      rt(" propose a NIST-CFTT-inspired evaluation methodology and show that the same model swings from BLEU 0.15 to 0.95 depending on prompt structure — arguments about LLM forensic capability are often arguments about prompting, not about model capability. Loumachi and Ghanem ("),
      rt("GenDFIR", { italics: true }),
      rt(")"),
      c(6),
      rt(" pair rule-based artefact selection with retrieval-augmented LLM timeline analysis; this is the closest comparator to our proposal, but their evaluation does not separate verdict, suspect attribution, and citation-grounding integrity. Cherif et al. ("),
      rt("DFIR-Metric", { italics: true }),
      rt(")"),
      c(7),
      rt(" provide a broader DFIR benchmark; Yin et al."),
      c(8),
      rt(" articulate the LLM reproducibility tension in forensic science; Wickramasekara, Breitinger and Scanlon"),
      c(9),
      rt(" provide the earlier survey-style framing for the area."),
    ],
  }),

  h2("D.  Retrieval-augmented and evidence-grounded LLMs"),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("Huang et al."),
      c(10),
      rt(" survey hallucination phenomena in LLMs and propose the taxonomy this work adopts. Sharma"),
      c(11),
      rt(" surveys retrieval-augmented architectures and notes the central distinction we lean on: "),
      rt("citation correctness is necessary but not sufficient for output reliability", { italics: true }),
      rt(", because a model can cite real sources and still draw an unsupported conclusion. We argue this distinction is load-bearing in forensic contexts."),
    ],
  }),

  h2("E.  Insider threat and multi-day behaviour"),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("Tuor et al."),
      c(12),
      rt(" provide the foundational deep-learning baseline for insider-threat detection on the CERT dataset. The recent OrgForge-IT benchmark"),
      c(13),
      rt(" independently validates the verifiable-synthetic-benchmark approach we adopt for ground-truth construction."),
    ],
  }),

  h2("F.  The gap"),
  p("Across these five threads — thirteen cited works in total — no published study evaluates deterministic rules and a citation-validated LLM side-by-side over the same normalised forensic event schema, with verdict, suspect, and grounding integrity reported as separate axes and failure cases preserved in the corpus. This is the gap the proposal addresses."),
];

const approach = [
  h1("III.  Proposed Approach"),
  p("We propose a hybrid forensic-triage approach with three conceptual components. None of the three is novel in isolation; the contribution is the combination, evaluated under controlled conditions with the integrity properties described in Section IV."),

  h2("A.  Unified evidence representation"),
  p("Logs from heterogeneous private-cloud sources are mapped into a single unified event schema with explicit event identifiers, timestamps, actors, resources, and metadata. A correlation layer reconstructs a chronologically ordered, session-grouped, cross-source-linked timeline. The two analysers below consume this timeline; neither sees raw logs. The intent is that any improvement attributable to the LLM cannot be explained by the LLM receiving privileged input."),

  h2("B.  Transparent rule baseline"),
  p("We propose to evaluate against a deliberately transparent rule baseline expressed as a small set of threshold-style correlation predicates over the normalised stream. The mapping from rule alerts to a scenario-level verdict is a fixed, three-line severity function. The intent is auditability: any reviewer can read every rule and reproduce every verdict. The baseline is positioned as an explainable point of comparison, not as a tuned operational SIEM; we will state this explicitly in the paper to bound the comparison honestly."),

  h2("C.  Constrained LLM with citation grounding"),
  p("We propose to apply an open-weight LLM to the same correlated timeline under three constraints: (i) the model reasons only over structured normalised events; (ii) every step in the produced attack chain, every supporting reference, and every narrative claim must cite at least one event identifier from the input; (iii) a deterministic post-hoc check inspects the model’s output and rejects any claim whose citation does not resolve to a real event. Together, these constraints aim to convert the LLM’s reasoning capacity into outputs whose evidentiary support is structurally checkable."),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("We adopt the precise definition: "),
      rt("evidence grounding", { italics: true }),
      rt(", in this work, means that each reported step cites event identifiers that exist in the scenario evidence; it does not mean that the interpretation drawn from those events is necessarily correct. This distinction is the central conceptual contribution of the proposal."),
    ],
  }),
];

const method = [
  h1("IV.  Proposed Evaluation Methodology"),
  p("The proposed evaluation is structured to test the bounded research question without overclaiming."),

  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("Controlled scenarios with known ground truth.", { bold: true }),
      rt(" A corpus of fifteen incident scenarios is constructed with predetermined labels (5 BENIGN, 10 ATTACK). Four primary scenarios match the original proposal scope (a normal baseline, a noisy benign conference-travel case, an obvious external attack, and a slow multi-day insider). Eleven extended scenarios probe robustness under disorder, conflicting signals, multi-day exfiltration, and adversarial corner cases. Two scenarios are designed deliberately as failure cases (a decoy-misdirection scenario and a rule-context-amplification scenario) and are retained in the corpus rather than removed."),
    ],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("Three orthogonal correctness axes.", { bold: true }),
      rt(" Results are reported on three axes that the literature commonly conflates. "),
      rt("Verdict accuracy", { italics: true }),
      rt(" is the binary classification of the scenario as BENIGN or ATTACK. "),
      rt("Suspect and attack-chain correctness", { italics: true }),
      rt(" measure whether the LLM identified the right primary actor and assembled an evidence chain consistent with the ground-truth attack steps. "),
      rt("Citation-grounding integrity", { italics: true }),
      rt(" counts violations of the structural-grounding check. Keeping these three separate is essential to the proposal: our central conceptual claim is that they can decouple in practice, and only a multi-axis report makes that visible."),
    ],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("Diagnostic ablation.", { bold: true }),
      rt(" On scenarios where the LLM verdict differs from the rule baseline, we propose a diagnostic ablation that omits the rule-alert artefact from the LLM’s input and reruns the same scenario. Verdict reversals across this ablation localise the source of the disagreement to the rule context rather than to the underlying timeline."),
    ],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("What is deliberately not claimed.", { bold: true }),
      rt(" Verdict accuracy under controlled conditions is a triage metric, not a detection metric. The corpus is synthetic and predetermined; the rule baseline is transparent rather than tuned; the validator covers structural grounding only. These bounds are stated up front and respected throughout."),
    ],
  }),
];

const prelim = [
  h1("V.  Preliminary Indications"),
  p("A first-pass implementation of the proposed approach has been exercised against the corpus to test feasibility. We summarise the indication briefly here; the full evaluation, with statistical reporting and multi-model comparison, is deferred to the final paper."),
  p("The transparent rule baseline produced the correct binary verdict on ten of fifteen scenarios; the constrained LLM produced the correct binary verdict on fourteen of fifteen. The post-hoc citation check recorded no invalid event-identifier citations in thirteen of fifteen scenarios. The improvement was concentrated on multi-day attack patterns no single rule covers, and on benign-but-noisy activity that produced large alert volume without a corresponding incident. These early figures are consistent with the proposal direction; we do not yet claim production-grade detection performance, multi-model generalisation, or statistical significance."),
  p("Two findings already inform the final paper’s framing."),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 120, line: 280 },
    children: [
      rt("Citation grounding is necessary but not sufficient.", { italics: true }),
      rt(" On the decoy-misdirection scenario, the LLM produced the correct binary verdict but identified the decoy actor as the suspect, with every cited event still real and the structural check silent. This is consistent with Sharma’s general observation"),
      c(11),
      rt(": a model can cite real sources and still draw an unsupported conclusion. The forensic-domain instance suggests the structural check needs to be supplemented by interpretive checks (multi-suspect hypothesis tracking, evidence-sufficiency assessment) that the present design does not perform."),
    ],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 160, line: 280 },
    children: [
      rt("Rule-alert context is suggestive, not neutral.", { italics: true }),
      rt(" On the rule-context-amplification scenario, the LLM returned ATTACK with rule alerts in its input; under the diagnostic ablation that removes the rule-alert artefact, the same model on the same timeline returned BENIGN across five repeated runs. This indicates that rule output, when supplied to a downstream LLM, behaves as biased context rather than neutral evidence — a calibration concern for any hybrid SIEM/LLM design."),
    ],
  }),
];

const remaining = [
  h1("VI.  Remaining Work"),
  p("The proposed approach is at the stage of demonstrating feasibility under controlled conditions. The final paper will extend the work along five axes."),
  bullet([rt("Multi-model evaluation.", { bold: true }), rt(" Repeat the corpus evaluation on at least one additional open-weight model. The proposed architecture is endpoint-agnostic; the question is whether the indications above generalise beyond a single model.")]),
  bullet([rt("Statistical reporting.", { bold: true }), rt(" Run all scenarios with N = 5 repeated runs at low temperature and report mean and standard deviation, since the underlying generation is not strictly deterministic.")]),
  bullet([rt("Real-world dataset validation.", { bold: true }), rt(" Apply the proposed pipeline to a public benchmark (LANL authentication, DARPA OpTC) or to anonymised institutional logs. This is the principal step from controlled study to empirical study.")]),
  bullet([rt("Adversarial robustness study.", { bold: true }), rt(" Develop the decoy-misdirection finding into a systematic perturbation experiment: vary the decoy-to-real activity ratio, decoy actor count, and decoy event volume, and report the perturbation level at which suspect identification breaks.")]),
  bullet([rt("Stronger validator.", { bold: true }), rt(" Extend the post-hoc check to address causal overclaim and missing-alternative-explanation, the two hallucination categories the present check does not cover.")]),
  p("A small human-analyst usefulness study is identified as a desirable but optional addition; even three security practitioners rating the LLM’s narrative output against the rule-alert output would close a known construct-validity gap."),
];

const conclusion = [
  h1("VII.  Conclusion"),
  p("We have proposed a hybrid forensic-triage approach for private-cloud environments that pairs a transparent rule baseline with a constrained LLM required to cite a specific event identifier for every claim, evaluated on three orthogonal correctness axes. The proposal addresses a gap in the literature: no published study compares deterministic rules and a citation-validated LLM over the same evidence with verdict, suspect, and grounding integrity reported separately. Preliminary indications across a controlled corpus of fifteen scenarios are consistent with the proposal direction, and two characterised findings — the necessary-but-not-sufficient nature of citation grounding, and the non-neutrality of rule-alert context to a downstream LLM — already shape the final paper’s bounded claim. Implementation depth, statistical rigour, multi-model comparison, real-world data, and an adversarial-robustness study remain for the final term paper."),
];

// ---------- Bibliography ----------
const refs = [
  ["Tariq et al.", "“Alert Fatigue in Security Operations Centres: Research Challenges and Opportunities,” ACM Computing Surveys, 2025. DOI: 10.1145/3723158."],
  ["Ban et al.", "“Breaking Alert Fatigue: AI-Assisted SIEM Framework for Effective Incident Response,” Applied Sciences (MDPI), vol. 13, no. 11, 6610, 2023."],
  ["A. Habibzadeh, F. Feyzi, R. Ebrahimi Atani", "“Large Language Models for Security Operations Centers: A Comprehensive Survey,” arXiv:2509.10858, 2025."],
  ["R. Singh, S. Tariq, F. Jalalvand, M. Baruwal Chhetri, S. Nepal, C. Paris, M. Lochner", "“LLMs in the SOC: An Empirical Study of Human–AI Collaboration in Security Operations Centres,” arXiv:2508.18947, 2025."],
  ["H. Studiawan, F. Breitinger, M. Scanlon", "“Towards a Standardized Methodology and Dataset for Evaluating LLM-Based Digital Forensic Timeline Analysis,” FSI: Digital Investigation, vol. 54, 2025. arXiv:2505.03100."],
  ["F. K. Loumachi, M. C. Ghanem", "“GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval Augmented Generation and Large Language Models,” arXiv:2409.02572, 2024."],
  ["B. Cherif, T. Bisztray, R. A. Dubniczky, A. Aldahmani, S. Alshehhi, N. Tihanyi", "“DFIR-Metric: A Benchmark Dataset for Evaluating Large Language Models in Digital Forensics and Incident Response,” arXiv:2505.19973, 2025."],
  ["Z. Yin, Z. Wang, W. Xu, J. Zhuang, P. Mozumder, A. Smith, W. Zhang", "“Digital Forensics in the Age of Large Language Models,” arXiv:2504.02963, 2025."],
  ["A. Wickramasekara, F. Breitinger, M. Scanlon", "“Exploring the Potential of Large Language Models for Improving Digital Forensic Investigation Efficiency,” FSI: Digital Investigation, vol. 52, 301859, 2025. DOI: 10.1016/j.fsidi.2024.301859."],
  ["Huang et al.", "“A Survey on Hallucination in Large Language Models: Principles, Taxonomy, Challenges, and Open Questions,” ACM Transactions on Information Systems, 2025. DOI: 10.1145/3703155."],
  ["C. Sharma", "“Retrieval-Augmented Generation: A Comprehensive Survey of Architectures, Enhancements, and Robustness Frontiers,” arXiv:2506.00054, 2025."],
  ["A. Tuor, S. Kaplan, B. Hutchinson, N. Nichols, S. Robinson", "“Deep Learning for Unsupervised Insider Threat Detection in Structured Cybersecurity Data Streams,” in Proc. AAAI Workshop on AI for Cyber Security, 2017."],
  ["J. Flynt", "“OrgForge-IT: A Verifiable Synthetic Benchmark for LLM-Based Insider Threat Detection,” arXiv:2603.22499, 2026."],
];

const bib = [
  h1("References"),
  ...refs.map((r, i) => new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { after: 80, line: 260 },
    indent: { left: 360, hanging: 360 },
    children: [
      rt(`[${i + 1}] `, { size: 20 }),
      rt(`${r[0]}, `, { size: 20 }),
      rt(r[1], { size: 20 }),
    ],
  })),
];

// ---------- Document ----------
const doc = new Document({
  creator: "Md. Nazmul Hasan",
  title: "Augmenting Rule-Based Private-Cloud Forensic Investigation with Evidence-Grounded LLM Reasoning",
  styles: {
    default: { document: { run: { font: FONT, size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: FONT },
        paragraph: { spacing: { before: 320, after: 160 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 23, bold: true, italics: true, font: FONT },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 1 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets",
        levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
      },
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [
            rt("", { size: 18 }),
            new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 18 }),
          ],
        })],
      }),
    },
    children: [
      ...titleBlock,
      ...abstractBlock,
      ...intro,
      ...background,
      ...approach,
      ...method,
      ...prelim,
      ...remaining,
      ...conclusion,
      ...bib,
    ],
  }],
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync("midterm_paper.docx", buffer);
  console.log("Wrote midterm_paper.docx");
});
