// Research presentation deck.
// Palette: user-selected Color Hunt + deep teal anchor.
// Output: midterm_presentation.pptx
// Run: node build_midterm_deck.js

const pptxgen = require("pptxgenjs");

// -------- Palette --------
const C = {
  ink:       "0F2A30",
  body:      "2C3E44",
  caption:   "6B7B80",
  surface:   "F5F8F8",
  white:     "FFFFFF",
  teal:      "26CCC2",
  peach:     "FFB76C",
  cyan:      "6AECE1",
  yellow:    "FFF57E",
  tealTint:  "E8F8F7",
  peachTint: "FFF2E2",
  yellowTint:"FFFBE3",
  tealDark:  "0F7A75",
  peachDark: "B5772D",
  yellowDk:  "5C4A0A",
};

const FONT_HEAD = "Calibri";
const FONT_BODY = "Calibri";
const FONT_LIGHT = "Calibri Light";

let pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.author = "Md. Nazmul Hasan";
pres.title  = "Augmenting rule-based private-cloud forensic investigation";

const SLIDE_W = 10.0;
const SLIDE_H = 5.625;
const TOTAL_SLIDES = 18;

// -------- Helpers --------
function leftAccent(s, color = C.teal) {
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.06, h: SLIDE_H,
    fill: { color }, line: { color, width: 0 },
  });
}

function sectionTag(s, text, color = C.teal) {
  s.addText(text, {
    x: 0.55, y: 0.32, w: 9, h: 0.32,
    fontSize: 13, fontFace: FONT_HEAD, color, bold: true, charSpacing: 6, margin: 0,
  });
}

function sectionTitle(s, text, opts = {}) {
  s.addText(text, {
    x: 0.55, y: 0.7, w: 9, h: 0.85,
    fontSize: opts.fontSize || 32, fontFace: FONT_HEAD, color: C.ink, bold: true,
    margin: 0,
  });
}

function pageNumber(s, n) {
  s.addText(`${n} / ${TOTAL_SLIDES}`, {
    x: 9.0, y: 5.32, w: 0.85, h: 0.25,
    fontSize: 11, fontFace: FONT_BODY, color: C.caption, align: "right", margin: 0,
  });
}

function footerBrand(s) {
  s.addText("Augmenting rule-based private-cloud forensic investigation", {
    x: 0.55, y: 5.32, w: 7.5, h: 0.25,
    fontSize: 11, fontFace: FONT_BODY, color: C.caption, margin: 0,
  });
}

function chrome(s, tag, title, n) {
  leftAccent(s);
  sectionTag(s, tag);
  if (title) sectionTitle(s, title);
  pageNumber(s, n);
  footerBrand(s);
}

// =====================================================
// SLIDE 1 — Title
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.22, h: SLIDE_H,
    fill: { color: C.teal }, line: { color: C.teal, width: 0 },
  });

  s.addText("Augmenting rule-based", {
    x: 0.8, y: 1.55, w: 8.7, h: 0.95,
    fontSize: 42, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText("private-cloud forensic investigation", {
    x: 0.8, y: 2.3, w: 8.7, h: 0.95,
    fontSize: 42, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText("with evidence-grounded LLM reasoning", {
    x: 0.8, y: 3.25, w: 8.7, h: 0.65,
    fontSize: 24, fontFace: FONT_LIGHT, color: C.body, margin: 0,
  });

  s.addText("Md. Nazmul Hasan", {
    x: 0.8, y: 4.45, w: 8.7, h: 0.4,
    fontSize: 16, fontFace: FONT_BODY, color: C.caption, margin: 0,
  });

  // palette stripe
  const dy = 5.05;
  [C.teal, C.peach, C.cyan, C.yellow].forEach((col, i) => {
    s.addShape(pres.shapes.RECTANGLE, {
      x: 0.8 + i * 0.7, y: dy, w: 0.55, h: 0.08,
      fill: { color: col }, line: { color: col, width: 0 },
    });
  });
}

// =====================================================
// SLIDE 2 — Why this matters
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "01  ·  WHY THIS MATTERS", "Private-cloud incidents are slow to investigate", 2);

  // Three short statements stacked
  const items = [
    { num: "01", text: "Banks, government, healthcare run their own private clouds." },
    { num: "02", text: "Unlike AWS or Azure, there is no single audit plane to query." },
    { num: "03", text: "After an incident, evidence sits in seven disjoint log surfaces." },
  ];

  items.forEach((it, i) => {
    const y = 1.85 + i * 0.85;
    s.addShape(pres.shapes.RECTANGLE, {
      x: 0.55, y, w: 0.5, h: 0.5,
      fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
    });
    s.addText(it.num, {
      x: 0.55, y, w: 0.5, h: 0.5,
      fontSize: 16, fontFace: FONT_HEAD, color: C.tealDark, bold: true,
      align: "center", valign: "middle", margin: 0,
    });
    s.addText(it.text, {
      x: 1.2, y, w: 8.3, h: 0.5,
      fontSize: 22, fontFace: FONT_BODY, color: C.ink, valign: "middle", margin: 0,
    });
  });

  // Stat strip at bottom
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.55, w: 8.9, h: 0.55,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addText([
    { text: "The cost: ", options: { bold: true, color: C.peachDark } },
    { text: "investigators spend days reconstructing what happened — and rule engines drown them in alerts.", options: { color: C.body } },
  ], {
    x: 0.75, y: 4.55, w: 8.7, h: 0.55,
    fontSize: 16, fontFace: FONT_BODY, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 3 — Today's approach 1: rule-based correlation
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "02  ·  CURRENT APPROACH (1)", "Rule-based correlation: deterministic, but brittle", 3);

  const colY = 1.85;
  const colH = 2.85;

  // Strengths column
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: colY, w: 4.4, h: colH,
    fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
  });
  s.addText("STRENGTHS", {
    x: 0.75, y: colY + 0.2, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT_HEAD, color: C.tealDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText([
    { text: "Deterministic and transparent", options: { bullet: true, breakLine: true } },
    { text: "Auditable: each alert traces to a rule", options: { bullet: true, breakLine: true } },
    { text: "Runs continuously at low cost", options: { bullet: true, breakLine: true } },
    { text: "Fits regulated environments", options: { bullet: true } },
  ], {
    x: 0.75, y: colY + 0.65, w: 4.0, h: colH - 0.85,
    fontSize: 18, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 8,
  });

  // Weaknesses column
  s.addShape(pres.shapes.RECTANGLE, {
    x: 5.05, y: colY, w: 4.4, h: colH,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addText("WEAKNESSES", {
    x: 5.25, y: colY + 0.2, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT_HEAD, color: C.peachDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText([
    { text: "Brittle thresholds, alert fatigue", options: { bullet: true, breakLine: true } },
    { text: "Cries wolf on travel and maintenance", options: { bullet: true, breakLine: true } },
    { text: "Misses subtle multi-day patterns", options: { bullet: true, breakLine: true } },
    { text: "No semantic context", options: { bullet: true } },
  ], {
    x: 5.25, y: colY + 0.65, w: 4.0, h: colH - 0.85,
    fontSize: 18, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 8,
  });
}

// =====================================================
// SLIDE 4 — Today's approach 2: LLM-assisted analysis
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "03  ·  CURRENT APPROACH (2)", "LLM-assisted analysis: powerful, but unconstrained", 4);

  const colY = 1.85;
  const colH = 2.85;

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: colY, w: 4.4, h: colH,
    fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
  });
  s.addText("WHAT IT CAN DO", {
    x: 0.75, y: colY + 0.2, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT_HEAD, color: C.tealDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText([
    { text: "Synthesise weak signals across events", options: { bullet: true, breakLine: true } },
    { text: "Read context: roles, tickets, file types", options: { bullet: true, breakLine: true } },
    { text: "Aggregate across time windows", options: { bullet: true, breakLine: true } },
    { text: "Produce narrative explanations", options: { bullet: true } },
  ], {
    x: 0.75, y: colY + 0.65, w: 4.0, h: colH - 0.85,
    fontSize: 18, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 8,
  });

  s.addShape(pres.shapes.RECTANGLE, {
    x: 5.05, y: colY, w: 4.4, h: colH,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addText("WHY IT IS RISKY", {
    x: 5.25, y: colY + 0.2, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT_HEAD, color: C.peachDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText([
    { text: "Hallucinates events not in evidence", options: { bullet: true, breakLine: true } },
    { text: "Overclaims intent and causality", options: { bullet: true, breakLine: true } },
    { text: "Sensitive to prompt structure", options: { bullet: true, breakLine: true } },
    { text: "Errors are unacceptable in forensics", options: { bullet: true } },
  ], {
    x: 5.25, y: colY + 0.65, w: 4.0, h: colH - 0.85,
    fontSize: 18, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 8,
  });
}

// =====================================================
// SLIDE 5 — Literature review
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "04  ·  LITERATURE REVIEW", "13 papers across 5 threads", 5);

  // 5 thread rows with paper counts and lead names
  const rowY0 = 1.65;
  const rowH = 0.55;
  const rowGap = 0.05;
  const x0 = 0.55;
  const w = 8.9;

  function threadRow(i, label, count, papers) {
    const y = rowY0 + i * (rowH + rowGap);
    s.addShape(pres.shapes.RECTANGLE, {
      x: x0, y, w, h: rowH,
      fill: { color: C.surface }, line: { color: C.surface, width: 0 },
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x: x0, y, w: 0.06, h: rowH, fill: { color: C.teal }, line: { color: C.teal, width: 0 },
    });
    // count badge
    s.addShape(pres.shapes.RECTANGLE, {
      x: x0 + 0.2, y: y + 0.12, w: 0.45, h: rowH - 0.24,
      fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
    });
    s.addText(String(count), {
      x: x0 + 0.2, y: y + 0.12, w: 0.45, h: rowH - 0.24,
      fontSize: 16, fontFace: FONT_HEAD, color: C.tealDark, bold: true,
      align: "center", valign: "middle", margin: 0,
    });
    // label
    s.addText(label, {
      x: x0 + 0.8, y: y + 0.05, w: 2.7, h: rowH - 0.1,
      fontSize: 14, fontFace: FONT_HEAD, color: C.ink, bold: true,
      valign: "middle", margin: 0,
    });
    // papers / takeaway
    s.addText(papers, {
      x: x0 + 3.6, y: y + 0.05, w: w - 3.8, h: rowH - 0.1,
      fontSize: 12, fontFace: FONT_BODY, color: C.body,
      valign: "middle", margin: 0,
    });
  }

  threadRow(0, "SIEM correlation",      2, "Tariq et al. 2025 · Ban et al. 2023");
  threadRow(1, "LLMs in SOC",           2, "Habibzadeh 2025 · Singh et al. 2025 (3,090 queries)");
  threadRow(2, "LLMs for forensics",    5, "Studiawan 2025 · GenDFIR 2024 · DFIR-Metric 2025 · Yin 2025 · Wickramasekara 2025");
  threadRow(3, "RAG / grounding",       2, "Huang et al. 2025 (taxonomy) · Sharma 2025");
  threadRow(4, "Insider threat",        2, "Tuor et al. 2017 · OrgForge-IT 2026");

  // Bottom emphasis strip
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.65, w: 8.9, h: 0.55,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addText([
    { text: "Closest comparator: GenDFIR (Loumachi & Ghanem 2024).  ", options: { bold: true, color: C.peachDark } },
    { text: "Nobody has measured rules vs constrained LLMs side-by-side with grounding enforced.", options: { color: C.body } },
  ], {
    x: 0.75, y: 4.65, w: 8.6, h: 0.55,
    fontSize: 13, fontFace: FONT_BODY, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 6 — The gap
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "05  ·  THE GAP", null, 6);

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 1.5, w: 0.1, h: 3.0,
    fill: { color: C.peach }, line: { color: C.peach, width: 0 },
  });

  s.addText("What is missing", {
    x: 0.85, y: 1.5, w: 8.6, h: 0.6,
    fontSize: 24, fontFace: FONT_HEAD, color: C.peachDark, bold: true, margin: 0,
  });

  s.addText("A controlled comparison of rule-based correlation and constrained LLM reasoning over the same evidence — with citation grounding enforced and failure modes preserved.", {
    x: 0.85, y: 2.15, w: 8.6, h: 1.7,
    fontSize: 26, fontFace: FONT_LIGHT, color: C.ink, margin: 0, paraSpaceAfter: 8,
  });

  // Three "what we keep" markers
  s.addText([
    { text: "Same evidence  ·  ", options: { bold: true, color: C.tealDark } },
    { text: "Citations enforced  ·  ", options: { bold: true, color: C.tealDark } },
    { text: "Failures kept in the corpus", options: { bold: true, color: C.tealDark } },
  ], {
    x: 0.85, y: 4.0, w: 8.6, h: 0.4,
    fontSize: 16, fontFace: FONT_BODY, margin: 0,
  });
}

// =====================================================
// SLIDE 7 — Research question
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "06  ·  RESEARCH QUESTION", null, 7);

  // Big, scannable question
  s.addText("Can a constrained LLM improve forensic triage", {
    x: 0.55, y: 1.55, w: 9, h: 0.85,
    fontSize: 34, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText("over a rule-based baseline,", {
    x: 0.55, y: 2.35, w: 9, h: 0.85,
    fontSize: 34, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText([
    { text: "without losing ", options: {} },
    { text: "traceability", options: { color: C.peachDark, bold: true } },
    { text: "?", options: {} },
  ], {
    x: 0.55, y: 3.15, w: 9, h: 0.85,
    fontSize: 34, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });

  // Constraints sub-line
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.3, w: 8.9, h: 0.7,
    fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
  });
  s.addText([
    { text: "Constraints: ", options: { bold: true, color: C.tealDark } },
    { text: "structured events only  ·  every claim cites an event ID  ·  validator checks all citations", options: { color: C.body } },
  ], {
    x: 0.75, y: 4.3, w: 8.6, h: 0.7,
    fontSize: 17, fontFace: FONT_BODY, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 8 — Research methodology
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "07  ·  RESEARCH METHODOLOGY", "How we structured the work", 8);

  const items = [
    { num: "01", title: "Define the question narrowly", body: "Post-incident triage, not real-time detection. No autonomous attribution claim." },
    { num: "02", title: "Survey 13 papers across 5 threads", body: "Identify the gap: rules vs constrained LLMs, side-by-side, with grounding enforced." },
    { num: "03", title: "Design 15 controlled scenarios", body: "5 BENIGN + 10 ATTACK with predetermined ground truth. Two failure cases retained." },
    { num: "04", title: "Run both analysers on same timeline", body: "Same evidence to rule engine and constrained LLM. Validator checks LLM citations after the fact." },
    { num: "05", title: "Score on three orthogonal axes", body: "Verdict accuracy · suspect / attack-chain correctness · citation-grounding integrity." },
  ];

  items.forEach((it, i) => {
    const y = 1.6 + i * 0.65;
    s.addShape(pres.shapes.RECTANGLE, {
      x: 0.55, y, w: 0.65, h: 0.5,
      fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
    });
    s.addText(it.num, {
      x: 0.55, y, w: 0.65, h: 0.5,
      fontSize: 16, fontFace: FONT_HEAD, color: C.tealDark, bold: true,
      align: "center", valign: "middle", margin: 0,
    });
    s.addText(it.title, {
      x: 1.35, y: y + 0.02, w: 8.1, h: 0.3,
      fontSize: 16, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
    });
    s.addText(it.body, {
      x: 1.35, y: y + 0.28, w: 8.1, h: 0.25,
      fontSize: 12.5, fontFace: FONT_BODY, color: C.body, margin: 0,
    });
  });

  s.addText("Failure modes documented openly: S14 (suspect-level) and S15 (rule-context amplification).", {
    x: 0.55, y: 5.0, w: 8.9, h: 0.3,
    fontSize: 12, fontFace: FONT_BODY, color: C.caption, italic: true, margin: 0,
  });
}

// =====================================================
// SLIDE 9 — System pipeline
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "08  ·  PROPOSED PIPELINE", "Same evidence, two analysers, one validator", 9);

  const rowY = 1.6;
  const blockH = 0.46;
  const arrowH = 0.20;
  const stride = blockH + arrowH;

  function block(x, y, w, h, label, fill, txt) {
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w, h, fill: { color: fill }, line: { color: fill, width: 0 },
    });
    s.addText(label, {
      x: x + 0.08, y, w: w - 0.16, h, fontSize: 14, fontFace: FONT_HEAD,
      color: txt, bold: true, valign: "middle", align: "center", margin: 0,
    });
  }
  function arrow(y) {
    s.addText("↓", { x: 4.7, y, w: 0.6, h: arrowH, fontSize: 16, color: C.caption, align: "center", valign: "middle", margin: 0 });
  }

  block(0.55, rowY, 8.9, blockH, "Logs from 7 source types  ·  auth · file · admin · network · db · web · email", C.tealTint, C.tealDark);

  arrow(rowY + blockH);

  const r2y = rowY + stride;
  block(0.55, r2y, 4.30, blockH, "Normaliser  ·  unified event schema", C.surface, C.body);
  block(5.15, r2y, 4.30, blockH, "Timeline + correlation", C.surface, C.body);
  arrow(r2y + blockH);

  const r3y = r2y + stride;
  block(0.55, r3y, 4.30, blockH, "Transparent rule engine", C.tealTint, C.tealDark);
  block(5.15, r3y, 4.30, blockH, "Constrained, citation-bound LLM", C.peachTint, C.peachDark);
  arrow(r3y + blockH);

  const r4y = r3y + stride;
  block(0.55, r4y, 8.9, blockH, "Deterministic citation validator  →  Evaluation", C.cyan, C.ink);

  s.addText("Both analysers consume the same timeline. Only the LLM is validated.", {
    x: 0.55, y: r4y + blockH + 0.18, w: 8.9, h: 0.4,
    fontSize: 14, fontFace: FONT_BODY, color: C.caption, italic: true, margin: 0,
  });
}

// =====================================================
// SLIDE 9 — Methodology (rule + LLM)
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "09  ·  PROPOSED APPROACH", "What we are proposing, at a conceptual level", 10);

  const colY = 1.85;
  const colH = 2.85;

  // Rule baseline
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: colY, w: 4.4, h: colH,
    fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
  });
  s.addText("RULE BASELINE", {
    x: 0.75, y: colY + 0.2, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT_HEAD, color: C.tealDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText("Transparent and auditable", {
    x: 0.75, y: colY + 0.55, w: 4.0, h: 0.5,
    fontSize: 22, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText([
    { text: "Threshold predicates (bulk download)", options: { bullet: true, breakLine: true } },
    { text: "Sequence predicates (privilege then download)", options: { bullet: true, breakLine: true } },
    { text: "Cross-source predicates (lateral movement)", options: { bullet: true, breakLine: true } },
    { text: "Each verdict traces back to a rule", options: { bullet: true } },
  ], {
    x: 0.75, y: colY + 1.15, w: 4.0, h: colH - 1.3,
    fontSize: 16, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 6,
  });

  // LLM with grounding
  s.addShape(pres.shapes.RECTANGLE, {
    x: 5.05, y: colY, w: 4.4, h: colH,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addText("CONSTRAINED LLM", {
    x: 5.25, y: colY + 0.2, w: 4.0, h: 0.35,
    fontSize: 14, fontFace: FONT_HEAD, color: C.peachDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText("Required to cite evidence", {
    x: 5.25, y: colY + 0.55, w: 4.0, h: 0.5,
    fontSize: 22, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText([
    { text: "Every claim must cite an event identifier", options: { bullet: true, breakLine: true } },
    { text: "Validator checks each citation against the timeline", options: { bullet: true, breakLine: true } },
    { text: "Open-weight, deployment-agnostic model", options: { bullet: true, breakLine: true } },
    { text: "Conceptual contract, not a fixed implementation", options: { bullet: true } },
  ], {
    x: 5.25, y: colY + 1.15, w: 4.0, h: colH - 1.3,
    fontSize: 16, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 6,
  });
}

// =====================================================
// SLIDE 10 — Evaluation design
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "10  ·  PROPOSED EVALUATION", "15 controlled scenarios with known ground truth", 11);

  // Scenario tier visual: 4 primary + 11 extended
  const cardY = 1.85;
  const cardH = 2.5;
  const cardW = 4.4;

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: cardY, w: cardW, h: cardH,
    fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
  });
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: cardY, w: cardW, h: 0.06, fill: { color: C.teal }, line: { color: C.teal, width: 0 },
  });
  s.addText("PRIMARY  ·  4 SCENARIOS", {
    x: 0.75, y: cardY + 0.22, w: cardW - 0.4, h: 0.35,
    fontSize: 13, fontFace: FONT_HEAD, color: C.tealDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText("Original proposal scope", {
    x: 0.75, y: cardY + 0.6, w: cardW - 0.4, h: 0.45,
    fontSize: 19, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText([
    { text: "S1  ·  normal baseline (BENIGN)", options: { breakLine: true } },
    { text: "S2  ·  noisy travel (BENIGN)", options: { breakLine: true } },
    { text: "S3  ·  obvious external attack", options: { breakLine: true } },
    { text: "S4  ·  slow multi-day insider", options: {} },
  ], {
    x: 0.75, y: cardY + 1.2, w: cardW - 0.4, h: 1.2,
    fontSize: 16, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 6,
  });

  s.addShape(pres.shapes.RECTANGLE, {
    x: 5.05, y: cardY, w: cardW, h: cardH,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addShape(pres.shapes.RECTANGLE, {
    x: 5.05, y: cardY, w: cardW, h: 0.06, fill: { color: C.peach }, line: { color: C.peach, width: 0 },
  });
  s.addText("EXTENDED  ·  11 SCENARIOS", {
    x: 5.25, y: cardY + 0.22, w: cardW - 0.4, h: 0.35,
    fontSize: 13, fontFace: FONT_HEAD, color: C.peachDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText("Robustness + failure cases", {
    x: 5.25, y: cardY + 0.6, w: cardW - 0.4, h: 0.45,
    fontSize: 19, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
  });
  s.addText([
    { text: "S5–S13  ·  hijack, maintenance, slow exfil", options: { breakLine: true } },
    { text: "S14  ·  decoy misdirection (failure)", options: { breakLine: true } },
    { text: "S15  ·  rule-context amplification (failure)", options: {} },
  ], {
    x: 5.25, y: cardY + 1.2, w: cardW - 0.4, h: 1.2,
    fontSize: 16, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 6,
  });

  // Bottom strip: total + framing
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.5, w: 8.9, h: 0.55,
    fill: { color: C.surface }, line: { color: C.surface, width: 0 },
  });
  s.addText([
    { text: "Total: 5 BENIGN + 10 ATTACK.  ", options: { bold: true, color: C.tealDark } },
    { text: "Failure cases are kept in the corpus — findings, not embarrassments.", options: { color: C.body, italic: true } },
  ], {
    x: 0.75, y: 4.5, w: 8.6, h: 0.55,
    fontSize: 14, fontFace: FONT_BODY, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 12 — Scenario list (NEW, transparency)
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "11  ·  SCENARIO LIST", "All 15 scenarios with one-line descriptions", 12);

  const scenarios = [
    [1,  "BENIGN", "Normal daily activity by a financial analyst"],
    [2,  "BENIGN", "Developer travelling from Singapore hotel; high but authorised"],
    [3,  "ATTACK", "External brute-force at 02:47 AM, escalation, bulk download"],
    [4,  "ATTACK", "Slow 3-day insider exfiltration by an HR specialist"],
    [5,  "ATTACK", "Session hijack via mid-session source-IP change"],
    [6,  "BENIGN", "Scheduled late-night server maintenance over home VPN"],
    [7,  "BENIGN", "Botnet credential stuffing — all attempts fail"],
    [8,  "ATTACK", "SQLi, credential dump, lateral movement across systems"],
    [9,  "ATTACK", "Auth server crashed; downloads with no login event"],
    [10, "ATTACK", "Network logs delayed 2 hours; cross-department access"],
    [11, "ATTACK", "6 hours legitimate, then account compromised from new IP"],
    [12, "ATTACK", "VPN log timestamped after the access it should authorise"],
    [13, "ATTACK", "7-day ultra-slow exfil — one file per day across departments"],
    [14, "ATTACK", "Decoy: loud fake attacker hides the quiet real one"],
    [15, "BENIGN", "End-of-quarter reporting; bulk legitimate finance access"],
  ];

  const rowH = 0.40;
  const colW = 4.40;
  const gap  = 0.10;
  const y0   = 1.55;
  const splitAt = 8;  // first 8 in left column, last 7 in right

  scenarios.forEach((sc, i) => {
    const colIdx = i < splitAt ? 0 : 1;
    const rowIdx = i < splitAt ? i : i - splitAt;
    const x = 0.55 + colIdx * (colW + gap);
    const y = y0 + rowIdx * rowH;
    const isBenign = sc[1] === "BENIGN";
    const tint   = isBenign ? C.tealTint : C.peachTint;
    const stripe = isBenign ? C.teal     : C.peach;
    const labCol = isBenign ? C.tealDark : C.peachDark;

    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: colW, h: rowH - 0.06,
      fill: { color: tint }, line: { color: tint, width: 0 },
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 0.06, h: rowH - 0.06,
      fill: { color: stripe }, line: { color: stripe, width: 0 },
    });
    s.addText(`S${sc[0]}`, {
      x: x + 0.18, y, w: 0.50, h: rowH - 0.06,
      fontSize: 13, fontFace: FONT_HEAD, color: labCol, bold: true,
      valign: "middle", margin: 0,
    });
    s.addText(sc[2], {
      x: x + 0.72, y, w: colW - 0.82, h: rowH - 0.06,
      fontSize: 10.5, fontFace: FONT_BODY, color: C.body,
      valign: "middle", margin: 0,
    });
  });

  // Legend strip at bottom
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 5.00, w: 8.90, h: 0.30,
    fill: { color: C.surface }, line: { color: C.surface, width: 0 },
  });
  s.addText([
    { text: "5 BENIGN", options: { bold: true, color: C.tealDark } },
    { text: "   +   ", options: { color: C.caption } },
    { text: "10 ATTACK", options: { bold: true, color: C.peachDark } },
    { text: "      ·      ", options: { color: C.caption } },
    { text: "S1–S4 primary  ·  S5–S13 extended  ·  S14 & S15 are the observed limitations", options: { color: C.body, italic: true } },
  ], {
    x: 0.75, y: 5.00, w: 8.50, h: 0.30,
    fontSize: 11, fontFace: FONT_BODY, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 13 — Preliminary indications
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "12  ·  PRELIMINARY INDICATIONS", "Early signal from a feasibility test", 13);

  const cardY = 1.85;
  const cardH = 2.4;
  const cardW = 2.95;
  const gap = 0.10;
  const x0 = 0.55;

  function statCard(x, label, labelColor, value, valueColor, bg, sub) {
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: cardY, w: cardW, h: cardH, fill: { color: bg }, line: { color: bg, width: 0 },
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: cardY, w: cardW, h: 0.06,
      fill: { color: labelColor }, line: { color: labelColor, width: 0 },
    });
    s.addText(label, {
      x: x + 0.2, y: cardY + 0.22, w: cardW - 0.4, h: 0.4,
      fontSize: 14, fontFace: FONT_HEAD, color: labelColor, bold: true, charSpacing: 5, margin: 0,
    });
    s.addText(value, {
      x: x + 0.2, y: cardY + 0.7, w: cardW - 0.4, h: 1.2,
      fontSize: 64, fontFace: FONT_HEAD, color: valueColor, bold: true, margin: 0,
    });
    s.addText(sub, {
      x: x + 0.2, y: cardY + 1.85, w: cardW - 0.4, h: 0.5,
      fontSize: 14, fontFace: FONT_BODY, color: C.caption, margin: 0,
    });
  }

  statCard(x0,                       "RULE BASELINE", C.tealDark, "66.7%", C.ink, C.surface,
    "10 of 15 verdicts correct");
  statCard(x0 + cardW + gap,         "LLM",           C.peachDark, "93.3%", C.peachDark, C.peachTint,
    "14 of 15 verdicts correct");
  statCard(x0 + (cardW + gap) * 2,   "VALIDATOR",     C.tealDark, "13/15", C.ink, C.surface,
    "scenarios with no invalid event-ID citations");

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.55, w: 8.9, h: 0.55,
    fill: { color: C.surface }, line: { color: C.surface, width: 0 },
  });
  s.addText("Preliminary +27 pp gap on synthetic data. Two observed limitations still bound the proposal.", {
    x: 0.75, y: 4.55, w: 8.6, h: 0.55,
    fontSize: 15, fontFace: FONT_BODY, color: C.body, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 12 — What the LLM adds
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "13  ·  EARLY INDICATIONS", "Three forms of synthesis observed in the feasibility test", 14);

  const cardY = 1.85;
  const cardH = 3.0;
  const cardW = 2.95;
  const gap = 0.10;
  const x0 = 0.55;

  function synth(x, num, title, body, scenarios) {
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: cardY, w: cardW, h: cardH,
      fill: { color: C.surface }, line: { color: C.surface, width: 0 },
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: cardY, w: cardW, h: 0.06,
      fill: { color: C.teal }, line: { color: C.teal, width: 0 },
    });
    s.addText(num, {
      x: x + 0.2, y: cardY + 0.22, w: 0.5, h: 0.4,
      fontSize: 22, fontFace: FONT_HEAD, color: C.tealDark, bold: true, margin: 0,
    });
    s.addText(title, {
      x: x + 0.2, y: cardY + 0.7, w: cardW - 0.4, h: 0.7,
      fontSize: 17, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
    });
    s.addText(body, {
      x: x + 0.2, y: cardY + 1.5, w: cardW - 0.4, h: 1.0,
      fontSize: 14, fontFace: FONT_BODY, color: C.body, margin: 0,
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x: x + 0.2, y: cardY + cardH - 0.5, w: cardW - 0.4, h: 0.36,
      fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
    });
    s.addText(scenarios, {
      x: x + 0.2, y: cardY + cardH - 0.5, w: cardW - 0.4, h: 0.36,
      fontSize: 13, fontFace: FONT_HEAD, color: C.tealDark, bold: true, valign: "middle", align: "center", margin: 0,
    });
  }

  synth(x0,
    "01",
    "Cross-time aggregation",
    "Multi-day patterns no single rule covers.",
    "S4  ·  S13");
  synth(x0 + cardW + gap,
    "02",
    "Contextual downgrading",
    "Reads role and metadata; recognises explainable activity.",
    "S2  ·  S6");
  synth(x0 + (cardW + gap) * 2,
    "03",
    "Cross-source pattern",
    "Mid-session source-IP change as hijack signal.",
    "S5");
}

// =====================================================
// SLIDE 13 — S14 decoy
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "14  ·  OBSERVED LIMITATION 1", "S14: decoy misdirection", 15);

  const colY = 1.7;
  const colH = 2.4;
  const colW = 4.4;
  const x0 = 0.55;

  s.addShape(pres.shapes.RECTANGLE, {
    x: x0, y: colY, w: colW, h: colH,
    fill: { color: C.surface }, line: { color: C.surface, width: 0 },
  });
  s.addShape(pres.shapes.RECTANGLE, {
    x: x0, y: colY, w: 0.06, h: colH, fill: { color: C.teal }, line: { color: C.teal, width: 0 },
  });
  s.addText("SCENARIO", {
    x: x0 + 0.2, y: colY + 0.2, w: colW - 0.4, h: 0.32,
    fontSize: 13, fontFace: FONT_HEAD, color: C.tealDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText([
    { text: "Two simultaneous attacks.", options: { bold: true, breakLine: true } },
    { text: "Decoy: user_04 generates 21 alerts.", options: { breakLine: true } },
    { text: "Real attack: user_02 quietly exfiltrates.", options: { breakLine: true } },
    { text: "Ground truth: real attacker is user_02.", options: { italic: true } },
  ], {
    x: x0 + 0.2, y: colY + 0.62, w: colW - 0.4, h: colH - 0.75,
    fontSize: 17, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 6,
  });

  const x1 = x0 + colW + 0.2;
  s.addShape(pres.shapes.RECTANGLE, {
    x: x1, y: colY, w: colW, h: colH,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addShape(pres.shapes.RECTANGLE, {
    x: x1, y: colY, w: 0.06, h: colH, fill: { color: C.peach }, line: { color: C.peach, width: 0 },
  });
  s.addText("PRELIMINARY OBSERVATION", {
    x: x1 + 0.2, y: colY + 0.2, w: colW - 0.4, h: 0.32,
    fontSize: 13, fontFace: FONT_HEAD, color: C.peachDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText([
    { text: "Verdict: YES — correct.", options: { bold: true, breakLine: true } },
    { text: "Suspect: user_04 — wrong actor.", options: { bold: true, breakLine: true } },
    { text: "Attack chain built from decoy events.", options: { breakLine: true } },
    { text: "Validator silent: every cited event is real.", options: { italic: true } },
  ], {
    x: x1 + 0.2, y: colY + 0.62, w: colW - 0.4, h: colH - 0.75,
    fontSize: 17, fontFace: FONT_BODY, color: C.body, margin: 0, paraSpaceAfter: 6,
  });

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.3, w: 8.9, h: 0.7,
    fill: { color: C.yellowTint }, line: { color: C.yellowTint, width: 0 },
  });
  s.addText([
    { text: "Lesson: ", options: { bold: true, color: C.yellowDk } },
    { text: "citation grounding is necessary but not sufficient.", options: { bold: true } },
  ], {
    x: 0.75, y: 4.3, w: 8.6, h: 0.7,
    fontSize: 18, fontFace: FONT_BODY, color: C.ink, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 14 — S15 ablation
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "15  ·  OBSERVED LIMITATION 2", "S15: rule-context amplification", 16);

  s.addText("Legitimate end-of-quarter activity. 10 rule alerts on a BENIGN scenario.", {
    x: 0.55, y: 1.55, w: 8.9, h: 0.4,
    fontSize: 16, fontFace: FONT_BODY, color: C.body, italic: true, margin: 0,
  });

  const cardY = 2.05;
  const cardH = 2.05;
  const cardW = 4.4;
  const x0 = 0.55;

  // With rule context — wrong
  s.addShape(pres.shapes.RECTANGLE, {
    x: x0, y: cardY, w: cardW, h: cardH,
    fill: { color: C.peachTint }, line: { color: C.peachTint, width: 0 },
  });
  s.addShape(pres.shapes.RECTANGLE, {
    x: x0, y: cardY, w: cardW, h: 0.06, fill: { color: C.peach }, line: { color: C.peach, width: 0 },
  });
  s.addText("WITH RULE-ALERT CONTEXT", {
    x: x0 + 0.2, y: cardY + 0.22, w: cardW - 0.4, h: 0.32,
    fontSize: 13, fontFace: FONT_HEAD, color: C.peachDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText("YES", {
    x: x0 + 0.2, y: cardY + 0.6, w: cardW - 0.4, h: 0.95,
    fontSize: 60, fontFace: FONT_HEAD, color: C.peachDark, bold: true, margin: 0,
  });
  s.addText("Incorrect attack verdict on benign activity.", {
    x: x0 + 0.2, y: cardY + 1.55, w: cardW - 0.4, h: 0.45,
    fontSize: 14, fontFace: FONT_BODY, color: C.body, margin: 0,
  });

  // Without rule context — correct (measured)
  const x1 = x0 + cardW + 0.2;
  s.addShape(pres.shapes.RECTANGLE, {
    x: x1, y: cardY, w: cardW, h: cardH,
    fill: { color: C.tealTint }, line: { color: C.tealTint, width: 0 },
  });
  s.addShape(pres.shapes.RECTANGLE, {
    x: x1, y: cardY, w: cardW, h: 0.06, fill: { color: C.teal }, line: { color: C.teal, width: 0 },
  });
  s.addText("WITHOUT RULE CONTEXT  ·  N=5", {
    x: x1 + 0.2, y: cardY + 0.22, w: cardW - 0.4, h: 0.32,
    fontSize: 13, fontFace: FONT_HEAD, color: C.tealDark, bold: true, charSpacing: 5, margin: 0,
  });
  s.addText("NO  ·  5 / 5", {
    x: x1 + 0.2, y: cardY + 0.6, w: cardW - 0.4, h: 0.95,
    fontSize: 48, fontFace: FONT_HEAD, color: C.tealDark, bold: true, margin: 0,
  });
  s.addText("Same model, same timeline, alerts removed.", {
    x: x1 + 0.2, y: cardY + 1.55, w: cardW - 0.4, h: 0.45,
    fontSize: 14, fontFace: FONT_BODY, color: C.body, margin: 0,
  });

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.3, w: 8.9, h: 0.7,
    fill: { color: C.yellowTint }, line: { color: C.yellowTint, width: 0 },
  });
  s.addText([
    { text: "Lesson: ", options: { bold: true, color: C.yellowDk } },
    { text: "rule output is not neutral context.", options: { bold: true } },
  ], {
    x: 0.75, y: 4.3, w: 8.6, h: 0.7,
    fontSize: 18, fontFace: FONT_BODY, color: C.ink, valign: "middle", margin: 0,
  });
}

// =====================================================
// SLIDE 15 — Threats to validity
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "16  ·  THREATS TO VALIDITY", "What we are not claiming", 17);

  const cellW = 4.4;
  const cellH = 1.55;
  const gap = 0.15;
  const x0 = 0.55;
  const y0 = 1.85;

  function cell(x, y, label, body) {
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: cellW, h: cellH,
      fill: { color: C.surface }, line: { color: C.surface, width: 0 },
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x, y, w: 0.06, h: cellH, fill: { color: C.peach }, line: { color: C.peach, width: 0 },
    });
    s.addText(label, {
      x: x + 0.2, y: y + 0.18, w: cellW - 0.4, h: 0.36,
      fontSize: 16, fontFace: FONT_HEAD, color: C.ink, bold: true, margin: 0,
    });
    s.addText(body, {
      x: x + 0.2, y: y + 0.6, w: cellW - 0.4, h: cellH - 0.7,
      fontSize: 14, fontFace: FONT_BODY, color: C.body, margin: 0,
    });
  }

  cell(x0,                   y0,                 "Synthetic data",
    "15 author-designed scenarios. Real enterprise logs are noisier.");
  cell(x0 + cellW + gap,     y0,                 "Single model",
    "One open-weight model only. Cross-model behaviour unknown.");
  cell(x0,                   y0 + cellH + gap,   "Transparent baseline",
    "+27 pp vs explainable rules; tuned SIEM would close part of it.");
  cell(x0 + cellW + gap,     y0 + cellH + gap,   "Validator scope",
    "Catches structural grounding only; not causal overclaim.");
}

// =====================================================
// SLIDE 16 — Conclusion + Q&A
// =====================================================
{
  const s = pres.addSlide();
  s.background = { color: C.white };
  chrome(s, "17  ·  CONCLUSION", "Where the proposal stands", 18);

  // Key conclusions
  const items = [
    { tag: "PROPOSE",  color: C.tealDark,  bg: C.tealTint,   text: "Pair a transparent rule baseline with a citation-bound LLM, evaluated on three orthogonal axes." },
    { tag: "EARLY",    color: C.tealDark,  bg: C.tealTint,   text: "Feasibility test on synthetic data is consistent with the proposal direction." },
    { tag: "BOUND",    color: C.peachDark, bg: C.peachTint,  text: "Citation grounding is necessary but not sufficient (S14)." },
    { tag: "BOUND",    color: C.peachDark, bg: C.peachTint,  text: "Rule context is not neutral — amplifies false positives (S15)." },
    { tag: "NEXT",     color: C.yellowDk,  bg: C.yellowTint, text: "Real-world data, multi-model, human-analyst study, deployment." },
  ];

  items.forEach((it, i) => {
    const y = 1.65 + i * 0.55;
    s.addShape(pres.shapes.RECTANGLE, {
      x: 0.55, y, w: 1.4, h: 0.45,
      fill: { color: it.bg }, line: { color: it.bg, width: 0 },
    });
    s.addText(it.tag, {
      x: 0.55, y, w: 1.4, h: 0.45,
      fontSize: 12, fontFace: FONT_HEAD, color: it.color, bold: true, charSpacing: 4,
      align: "center", valign: "middle", margin: 0,
    });
    s.addText(it.text, {
      x: 2.05, y, w: 7.4, h: 0.45,
      fontSize: 16, fontFace: FONT_BODY, color: C.ink, valign: "middle", margin: 0,
    });
  });

  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.55, y: 4.55, w: 8.9, h: 0.55,
    fill: { color: C.ink }, line: { color: C.ink, width: 0 },
  });
  s.addText("Questions?", {
    x: 0.75, y: 4.55, w: 8.6, h: 0.55,
    fontSize: 22, fontFace: FONT_HEAD, color: C.cyan, bold: true, valign: "middle", margin: 0,
  });
}

// -------- Save --------
pres.writeFile({ fileName: "midterm_presentation.pptx" })
  .then(name => console.log(`Wrote ${name}`));
