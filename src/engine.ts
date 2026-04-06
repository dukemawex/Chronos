/**
 * Chronos — Threat-Hunting & Incident Response Engine (TypeScript)
 *
 * Implements the core Chronos analysis pipeline:
 *   1. Ingest normalised CloudTrail `LogEvent` objects.
 *   2. Run a suite of threat hunters against those events.
 *   3. Score the findings and classify a Threat Tier.
 *   4. Emit a Markdown Security Brief or Threat Intelligence Report.
 *
 * Design mirrors the Python reference implementation in `chronos/` while
 * using TypeScript idioms (interfaces, typed generics, optional chaining).
 */

import { parseCloudTrail, LogEvent } from "./parsers/cloudtrail";

// ---------------------------------------------------------------------------
// Re-export the parser so callers only need to import from engine.ts
// ---------------------------------------------------------------------------
export { parseCloudTrail, LogEvent };

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Severity levels for a Finding, ordered highest → lowest. */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

/** A single threat-hunting result. */
export interface Finding {
  title: string;
  severity: Severity;
  /** Short attack-vector hypothesis. */
  hypothesis: string;
  /** Raw log lines that support this finding. */
  evidence: string[];
  /** Ordered list of (timestamp, description) tuples. */
  timeline: Array<[Date, string]>;
  /** Recommended remediation actions. */
  mitigations: string[];
  /** Confidence score 0–100.  Assigned by the scorer if absent. */
  confidence?: number;
}

/** Full result returned by `analyse()`. */
export interface AnalysisResult {
  events: LogEvent[];
  findings: Finding[];
  logSources: string[];
  analysisTime: Date;
  threatScore: number;
  threatTierLabel: string;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const SEVERITY_DEFAULT_CONFIDENCE: Record<Severity, number> = {
  CRITICAL: 75,
  HIGH: 55,
  MEDIUM: 35,
  LOW: 15,
  INFO: 5,
};

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

/** Return the confidence score for a single finding. */
function findingConfidence(f: Finding): number {
  if (f.confidence !== undefined) return f.confidence;
  return SEVERITY_DEFAULT_CONFIDENCE[f.severity] ?? 5;
}

/**
 * Compute an overall Threat Score (0–100) from a list of findings.
 *
 * Algorithm: weighted average of the top-5 individual confidence values,
 * with the highest-confidence finding carrying double weight.
 */
export function scoreFindings(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  const scores = findings
    .map(findingConfidence)
    .sort((a, b) => b - a)
    .slice(0, 5);

  const weightedSum = scores[0] * 2 + scores.slice(1).reduce((s, v) => s + v, 0);
  const weightTotal = 1 + scores.length; // 2 for top + 1 each for rest
  const raw = weightedSum / weightTotal;

  return Math.min(100, Math.round(raw));
}

/**
 * Map a numeric threat score to a human-readable tier label.
 *
 * | Score  | Tier                   |
 * |--------|------------------------|
 * | 90–100 | CONFIRMED COMPROMISE   |
 * | 75–89  | HIGHLY LIKELY THREAT   |
 * | 55–74  | PROBABLE THREAT        |
 * | 35–54  | SUSPICIOUS ACTIVITY    |
 * | 0–34   | INFORMATIONAL          |
 */
export function threatTier(score: number): string {
  if (score >= 90) return "🔴 CONFIRMED COMPROMISE";
  if (score >= 75) return "🟠 HIGHLY LIKELY THREAT";
  if (score >= 55) return "🟡 PROBABLE THREAT";
  if (score >= 35) return "🟡 SUSPICIOUS ACTIVITY";
  return "⚪ INFORMATIONAL";
}

// ---------------------------------------------------------------------------
// Hunters
// ---------------------------------------------------------------------------

// ---- Helper utilities ----

/** Group events by an arbitrary string key. */
function groupBy<T>(items: T[], key: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (!map.has(k)) map.set(k, []);
    map.get(k)!.push(item);
  }
  return map;
}

/**
 * Return inter-event gap sizes in seconds for a list of events
 * sorted by timestamp.
 */
function gapsBetween(events: LogEvent[]): number[] {
  const sorted = [...events].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  const gaps: number[] = [];
  for (let i = 1; i < sorted.length; i++) {
    gaps.push((sorted[i].timestamp.getTime() - sorted[i - 1].timestamp.getTime()) / 1000);
  }
  return gaps;
}

/**
 * Return `{ periodic: true, period }` when all gaps are within `tolerance`
 * fraction of their mean — a signal of automation.
 */
function isPeriodic(
  gaps: number[],
  tolerance = 0.15
): { periodic: boolean; period: number } {
  if (gaps.length < 3) return { periodic: false, period: 0 };
  const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length;
  if (mean === 0) return { periodic: false, period: 0 };
  const allClose = gaps.every((g) => Math.abs(g - mean) / mean < tolerance);
  return { periodic: allClose, period: mean };
}

// ---- 1. Low-and-Slow / Periodic Activity Hunter ----

const PERIODIC_MIN_EVENTS = 4;
const PERIODIC_MIN_INTERVAL_SECONDS = 1800; // 30 minutes

/**
 * Detect regularly spaced CloudTrail API calls from the same source IP —
 * a classic "low-and-slow" reconnaissance or exfiltration signature.
 *
 * Groups events by `srcIp` and tests whether the inter-event gaps are
 * approximately equal.  Only intervals ≥ 30 minutes are flagged to avoid
 * noise from legitimate polling.
 */
export function huntPeriodicActivity(events: LogEvent[]): Finding[] {
  const findings: Finding[] = [];

  const byIp = groupBy(events, (e) => e.srcIp || "unknown");

  for (const [ip, ipEvents] of byIp) {
    if (ipEvents.length < PERIODIC_MIN_EVENTS) continue;

    const sorted = [...ipEvents].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );
    const gaps = gapsBetween(sorted);
    const { periodic, period } = isPeriodic(gaps);

    if (!periodic || period < PERIODIC_MIN_INTERVAL_SECONDS) continue;

    const periodHours = period / 3600;
    const eventTypes = [...new Set(sorted.map((e) => e.eventType))];

    findings.push({
      title: `Low-and-Slow Reconnaissance from ${ip}`,
      severity: "MEDIUM",
      hypothesis: (
        `Source IP ${ip} issued ${sorted.length} CloudTrail API call(s) ` +
        `(${eventTypes.join(", ")}) at regular ~${periodHours.toFixed(1)}-hour intervals ` +
        `over ${((period * (sorted.length - 1)) / 86400).toFixed(1)} day(s). ` +
        `Highly periodic activity suggests an automated tool designed to evade ` +
        `rate-limiting and threshold-based detection.`
      ),
      evidence: sorted.map((e) => e.raw),
      timeline: sorted.map((e) => [
        e.timestamp,
        `${e.eventType} from ${ip} by '${e.user}'`,
      ]),
      mitigations: [
        `Block or rate-limit source IP ${ip} at the WAF / security group.`,
        "Enable GuardDuty to correlate low-frequency API anomalies across days.",
        "Tune SIEM rules to detect long-interval periodic patterns (>30 min).",
        "Review CloudTrail Insights for unusual API call volume from this identity.",
      ],
    });
  }

  return findings;
}

// ---- 2. IAM Privilege Escalation Hunter ----

const IAM_SENSITIVE_EVENTS = new Set([
  "CreateUser",
  "AttachUserPolicy",
  "PutUserPolicy",
  "CreateAccessKey",
  "AddUserToGroup",
  "UpdateAssumeRolePolicy",
  "AttachRolePolicy",
  "PutRolePolicy",
  "CreateLoginProfile",
  "CreateRole",
]);

/**
 * Flag sensitive IAM mutations that may indicate privilege escalation or
 * persistence establishment.
 */
export function huntIamChanges(events: LogEvent[]): Finding[] {
  const findings: Finding[] = [];

  const iamEvents = events.filter(
    (e) => e.source === "cloudtrail" && IAM_SENSITIVE_EVENTS.has(e.eventType)
  );

  if (iamEvents.length === 0) return findings;

  // Group consecutive IAM events by the acting user to detect escalation chains
  const byUser = groupBy(iamEvents, (e) => e.user || "unknown");

  for (const [user, userEvents] of byUser) {
    const sorted = [...userEvents].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );
    const types = sorted.map((e) => e.eventType);
    const isEscalation =
      types.includes("CreateUser") &&
      (types.includes("AttachUserPolicy") || types.includes("PutUserPolicy"));

    findings.push({
      title: `IAM Privilege Change by '${user}' — ${sorted.map((e) => e.eventType).join(" → ")}`,
      severity: isEscalation ? "CRITICAL" : "HIGH",
      confidence: isEscalation ? 80 : 55,
      hypothesis: (
        `User '${user}' performed ${sorted.length} sensitive IAM operation(s): ` +
        `${types.join(", ")}. ` +
        (isEscalation
          ? "The CreateUser → AttachUserPolicy sequence is consistent with " +
            "Persistence via New Account followed by Privilege Escalation (T1136, T1078)."
          : "These changes may indicate an attempt to expand access or establish a backdoor.")
      ),
      evidence: sorted.map((e) => e.raw),
      timeline: sorted.map((e) => [
        e.timestamp,
        `${e.eventType} by '${user}' from ${e.srcIp}`,
      ]),
      mitigations: [
        `Immediately audit all permissions granted by '${user}' in this window.`,
        "Remove any newly created users or role bindings not approved via change management.",
        "Enable IAM Access Analyzer to detect over-permissive policies.",
        "Require MFA and approval workflows for all sensitive IAM mutations.",
        "Review CloudTrail Insights for abnormal IAM API call rates.",
      ],
    });
  }

  return findings;
}

// ---- 3. S3 Bucket Policy Change Hunter ----

const S3_SENSITIVE_EVENTS = new Set([
  "PutBucketPolicy",
  "DeleteBucketPolicy",
  "PutBucketAcl",
  "PutBucketPublicAccessBlock",
  "DeletePublicAccessBlock",
]);

/**
 * Flag any modifications to S3 bucket policies, ACLs, or public-access
 * settings — common precursors to data exfiltration.
 */
export function huntS3PolicyChanges(events: LogEvent[]): Finding[] {
  const findings: Finding[] = [];

  const s3Events = events.filter(
    (e) => e.source === "cloudtrail" && S3_SENSITIVE_EVENTS.has(e.eventType)
  );

  for (const e of s3Events) {
    const bucket = String(
      (e.requestParameters as Record<string, unknown>)?.bucketName ?? "unknown"
    );
    findings.push({
      title: `S3 Bucket Policy Change — ${e.eventType} on '${bucket}'`,
      severity: "HIGH",
      hypothesis: (
        `The S3 bucket '${bucket}' had its policy or ACL modified ` +
        `(${e.eventType}) by '${e.user}' from ${e.srcIp}. ` +
        `This may indicate Data Exfiltration Preparation or Lateral Movement (T1530).`
      ),
      evidence: [e.raw],
      timeline: [
        [e.timestamp, `${e.eventType} on '${bucket}' by '${e.user}'`],
      ],
      mitigations: [
        `Immediately review the policy change on bucket '${bucket}'.`,
        "Check whether the bucket became publicly accessible.",
        "Enable S3 Block Public Access at the account level.",
        "Ensure all sensitive buckets have versioning and access logging enabled.",
        "Alert on all future PutBucketPolicy / DeletePublicAccessBlock calls.",
      ],
    });
  }

  return findings;
}

// ---- 4. Brute-Force / Credential Stuffing Hunter ----

const BRUTE_FORCE_THRESHOLD = 5;
const BRUTE_FORCE_WINDOW_SECONDS = 3600;

/**
 * Detect repeated failed `ConsoleLogin` or `AssumeRole` attempts from the
 * same source IP within a sliding one-hour window.
 */
export function huntBruteForce(events: LogEvent[]): Finding[] {
  const findings: Finding[] = [];

  const failedEvents = events.filter(
    (e) =>
      e.source === "cloudtrail" &&
      (e.eventType === "ConsoleLogin" || e.eventType === "AssumeRole") &&
      e.errorCode !== ""
  );

  const byIp = groupBy(failedEvents, (e) => e.srcIp || "unknown");

  for (const [ip, ipEvents] of byIp) {
    const sorted = [...ipEvents].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );

    let windowStart = 0;
    for (let windowEnd = 0; windowEnd < sorted.length; windowEnd++) {
      while (
        (sorted[windowEnd].timestamp.getTime() -
          sorted[windowStart].timestamp.getTime()) /
          1000 >
        BRUTE_FORCE_WINDOW_SECONDS
      ) {
        windowStart++;
      }
      const window = sorted.slice(windowStart, windowEnd + 1);
      if (window.length >= BRUTE_FORCE_THRESHOLD) {
        const users = [...new Set(window.map((e) => e.user))];
        const multiUser = users.length > 1;
        findings.push({
          title: `${multiUser ? "Credential Stuffing" : "Brute-Force"} from ${ip}`,
          severity: "HIGH",
          hypothesis: (
            `IP ${ip} made ${window.length} failed authentication attempt(s) ` +
            `against ${users.length} account(s) (${users.join(", ")}) ` +
            `within a one-hour window.`
          ),
          evidence: window.map((e) => e.raw),
          timeline: window.map((e) => [
            e.timestamp,
            `Failed ${e.eventType} for '${e.user}' from ${ip} (${e.errorCode})`,
          ]),
          mitigations: [
            `Block source IP ${ip} at the WAF / security group.`,
            "Enable AWS Account-level MFA policy.",
            "Configure GuardDuty to alert on brute-force patterns.",
            "Enforce CAPTCHA or adaptive throttling on the AWS console.",
          ],
        });
        break; // one finding per IP
      }
    }
  }

  return findings;
}

// ---- 5. New-IP → IAM Change Correlation (APT) ----

const NEW_IP_IAM_WINDOW_SECONDS = 86400; // 24 hours

/**
 * Detect the APT pattern: a user logs in from a **new** source IP, then
 * makes sensitive IAM changes within 24 hours — a strong indicator of
 * account take-over followed by privilege escalation.
 */
export function huntNewIpIamChain(events: LogEvent[]): Finding[] {
  const findings: Finding[] = [];

  // Build per-user IP history from successful console logins
  const loginEvents = events.filter(
    (e) =>
      e.source === "cloudtrail" &&
      e.eventType === "ConsoleLogin" &&
      e.errorCode === ""
  );

  const byUser = groupBy(loginEvents, (e) => e.user || "unknown");

  for (const [user, userLogins] of byUser) {
    const sorted = [...userLogins].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );
    if (sorted.length < 2) continue;

    // Collect "known" IPs from all but the last login
    const knownIps = new Set(sorted.slice(0, -1).map((e) => e.srcIp));
    const latestLogin = sorted[sorted.length - 1];
    if (knownIps.has(latestLogin.srcIp)) continue;

    // Look for IAM changes within the window after the new-IP login
    const loginTime = latestLogin.timestamp.getTime();
    const iamFollowups = events.filter(
      (e) =>
        e.source === "cloudtrail" &&
        IAM_SENSITIVE_EVENTS.has(e.eventType) &&
        e.user === user &&
        e.timestamp.getTime() >= loginTime &&
        (e.timestamp.getTime() - loginTime) / 1000 <= NEW_IP_IAM_WINDOW_SECONDS
    );

    if (iamFollowups.length === 0) continue;

    const evidence = [latestLogin, ...iamFollowups].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );

    findings.push({
      title: `APT — New-IP Login → IAM Change by '${user}'`,
      severity: "CRITICAL",
      confidence: 85,
      hypothesis: (
        `User '${user}' logged in from a new IP ${latestLogin.srcIp} ` +
        `(previously seen: ${[...knownIps].join(", ")}) and then performed ` +
        `${iamFollowups.length} IAM change(s) within ${NEW_IP_IAM_WINDOW_SECONDS / 3600} hour(s). ` +
        `This two-stage pattern is strongly associated with Account Take-Over ` +
        `followed by Privilege Escalation (MITRE T1078 → T1136/T1098).`
      ),
      evidence: evidence.map((e) => e.raw),
      timeline: evidence.map((e) => [
        e.timestamp,
        e.eventType === "ConsoleLogin"
          ? `New-IP login for '${user}' from ${e.srcIp}`
          : `${e.eventType} by '${user}' from ${e.srcIp}`,
      ]),
      mitigations: [
        `Revoke all active sessions for '${user}' immediately.`,
        "Force password reset and re-enrol MFA.",
        `Investigate source IP ${latestLogin.srcIp} for threat intelligence.`,
        "Audit and roll back any IAM changes made in this window.",
        "Enable GuardDuty UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B.",
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Registry of all hunters (order matters for report presentation)
// ---------------------------------------------------------------------------

const ALL_HUNTERS: Array<(events: LogEvent[]) => Finding[]> = [
  huntPeriodicActivity,
  huntBruteForce,
  huntIamChanges,
  huntS3PolicyChanges,
  huntNewIpIamChain,
];

// ---------------------------------------------------------------------------
// Main Analysis Pipeline
// ---------------------------------------------------------------------------

/**
 * Run the full Chronos threat-hunting pipeline on a set of CloudTrail log
 * files / strings.
 *
 * @param inputs  Array of raw CloudTrail log contents (strings).
 * @param sources Optional display names for each input (e.g. file names).
 */
export function analyse(inputs: string[], sources?: string[]): AnalysisResult {
  const allEvents: LogEvent[] = [];

  for (const raw of inputs) {
    allEvents.push(...parseCloudTrail(raw));
  }

  // Sort chronologically
  allEvents.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  // Run all hunters
  const findings: Finding[] = [];
  for (const hunter of ALL_HUNTERS) {
    findings.push(...hunter(allEvents));
  }

  // Sort findings by severity
  findings.sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  );

  // Annotate confidence
  for (const f of findings) {
    if (f.confidence === undefined) {
      f.confidence = SEVERITY_DEFAULT_CONFIDENCE[f.severity] ?? 5;
    }
  }

  const score = scoreFindings(findings);

  return {
    events: allEvents,
    findings,
    logSources: sources ?? inputs.map((_, i) => `input-${i + 1}`),
    analysisTime: new Date(),
    threatScore: score,
    threatTierLabel: threatTier(score),
  };
}

// ---------------------------------------------------------------------------
// Report Generators
// ---------------------------------------------------------------------------

function fmtDate(d: Date): string {
  return d.toISOString().replace("T", " ").replace("Z", " UTC");
}

function severityEmoji(s: Severity): string {
  return { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵", INFO: "⚪" }[s] ?? "";
}

/**
 * Generate a **Security Brief** targeted at Tier 3 SOC analysts.
 *
 * Sections:
 *   1. Executive Summary
 *   2. Timeline of Activity
 *   3. Evidence Blocks
 *   4. Recommended Mitigations
 */
export function generateSecurityBrief(result: AnalysisResult): string {
  const { events, findings, logSources, analysisTime, threatScore, threatTierLabel } =
    result;

  const lines: string[] = [];
  lines.push("# Chronos Security Brief");
  lines.push("");
  lines.push(`**Generated:** ${fmtDate(analysisTime)}`);
  lines.push(`**Log Sources:** ${logSources.join(", ")}`);
  lines.push(`**Events Analysed:** ${events.length}`);
  lines.push(`**Findings:** ${findings.length}`);
  lines.push("");

  // Executive Summary
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(`**Threat Score: ${threatScore}/100 — ${threatTierLabel}**`);
  lines.push("");
  if (findings.length === 0) {
    lines.push("No threat indicators detected in the supplied log set.");
  } else {
    for (const f of findings) {
      lines.push(
        `- ${severityEmoji(f.severity)} **${f.title}** (confidence: ${f.confidence ?? "—"})`
      );
    }
  }
  lines.push("");

  // Timeline
  lines.push("## Timeline of Activity");
  lines.push("");
  const allTimeline: Array<[Date, string, string]> = findings.flatMap((f) =>
    f.timeline.map(([ts, desc]) => [ts, desc, f.title] as [Date, string, string])
  );
  allTimeline.sort((a, b) => a[0].getTime() - b[0].getTime());
  for (const [ts, desc, title] of allTimeline) {
    lines.push(`- \`${fmtDate(ts)}\` — ${desc} *(${title})*`);
  }
  lines.push("");

  // Evidence
  lines.push("## Evidence Blocks");
  lines.push("");
  for (const f of findings) {
    lines.push(`### ${severityEmoji(f.severity)} ${f.title}`);
    lines.push("");
    lines.push(`> ${f.hypothesis}`);
    lines.push("");
    lines.push("```");
    lines.push(...f.evidence.slice(0, 5));
    lines.push("```");
    lines.push("");
  }

  // Mitigations
  lines.push("## Recommended Mitigations");
  lines.push("");
  const seen = new Set<string>();
  for (const f of findings) {
    for (const m of f.mitigations) {
      if (!seen.has(m)) {
        lines.push(`- ${m}`);
        seen.add(m);
      }
    }
  }

  return lines.join("\n");
}

/**
 * Generate a **Threat Intelligence Report** targeted at L3 Incident
 * Responders.
 *
 * Sections:
 *   1. Threat Score Dashboard
 *   2. Critical & High Findings (with MITRE ATT&CK mapping)
 *   3. Supporting Findings
 *   4. Unified Attack Timeline
 *   5. Remediation Plan
 */
export function generateThreatIntelReport(result: AnalysisResult): string {
  const { events, findings, logSources, analysisTime, threatScore, threatTierLabel } =
    result;

  const lines: string[] = [];
  lines.push("# Chronos Threat Intelligence Report");
  lines.push("**TLP:AMBER — Handle in accordance with information security policy**");
  lines.push("");
  lines.push(`**Generated:** ${fmtDate(analysisTime)}`);
  lines.push(`**Log Sources:** ${logSources.join(", ")}`);
  lines.push(`**Events Analysed:** ${events.length}`);
  lines.push("");

  // Section 1: Threat Score Dashboard
  lines.push("## 1. Threat Score Dashboard");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Overall Threat Score | **${threatScore}/100** |`);
  lines.push(`| Threat Tier | **${threatTierLabel}** |`);
  lines.push(
    `| Critical Findings | ${findings.filter((f) => f.severity === "CRITICAL").length} |`
  );
  lines.push(
    `| High Findings | ${findings.filter((f) => f.severity === "HIGH").length} |`
  );
  lines.push(`| Total Findings | ${findings.length} |`);
  lines.push(`| Unique Source IPs | ${new Set(events.map((e) => e.srcIp).filter(Boolean)).size} |`);
  lines.push("");

  // Section 2: Critical & High Findings
  const critHighFindings = findings.filter((f) =>
    ["CRITICAL", "HIGH"].includes(f.severity)
  );
  lines.push("## 2. Critical & High Severity Findings");
  lines.push("");
  if (critHighFindings.length === 0) {
    lines.push("_No critical or high findings._");
  }
  for (const f of critHighFindings) {
    lines.push(`### ${severityEmoji(f.severity)} ${f.title}`);
    lines.push("");
    lines.push(`**Confidence:** ${f.confidence ?? "—"}/100`);
    lines.push("");
    lines.push(`**Hypothesis:** ${f.hypothesis}`);
    lines.push("");
    lines.push("**Attack Timeline:**");
    lines.push("");
    for (const [ts, desc] of f.timeline) {
      lines.push(`- \`${fmtDate(ts)}\` ${desc}`);
    }
    lines.push("");
    lines.push("**Raw Evidence (first 5 records):**");
    lines.push("```json");
    lines.push(...f.evidence.slice(0, 5));
    lines.push("```");
    lines.push("");
  }

  // Section 3: Supporting Findings
  const supportingFindings = findings.filter(
    (f) => !["CRITICAL", "HIGH"].includes(f.severity)
  );
  lines.push("## 3. Supporting Findings");
  lines.push("");
  if (supportingFindings.length === 0) {
    lines.push("_No additional supporting findings._");
  }
  for (const f of supportingFindings) {
    lines.push(
      `- ${severityEmoji(f.severity)} **${f.title}** — ${f.hypothesis.slice(0, 120)}…`
    );
  }
  lines.push("");

  // Section 4: Unified Attack Timeline
  lines.push("## 4. Unified Attack Timeline");
  lines.push("");
  const allTimeline: Array<[Date, string, Severity]> = findings.flatMap((f) =>
    f.timeline.map(([ts, desc]) => [ts, desc, f.severity] as [Date, string, Severity])
  );
  allTimeline.sort((a, b) => a[0].getTime() - b[0].getTime());
  for (const [ts, desc, sev] of allTimeline) {
    lines.push(`- ${severityEmoji(sev)} \`${fmtDate(ts)}\` ${desc}`);
  }
  lines.push("");

  // Section 5: Remediation Plan
  lines.push("## 5. Remediation Plan");
  lines.push("");
  const critical = findings.filter((f) => f.severity === "CRITICAL");
  const high = findings.filter((f) => f.severity === "HIGH");
  const other = findings.filter((f) => !["CRITICAL", "HIGH"].includes(f.severity));

  lines.push("### 🔴 Immediate (0–4 hours)");
  lines.push("");
  for (const f of critical) {
    for (const m of f.mitigations.slice(0, 2)) lines.push(`- ${m}`);
  }
  lines.push("");
  lines.push("### 🟠 Urgent (4–24 hours)");
  lines.push("");
  for (const f of high) {
    for (const m of f.mitigations.slice(0, 2)) lines.push(`- ${m}`);
  }
  lines.push("");
  lines.push("### 🟡 Short-term (1–7 days)");
  lines.push("");
  for (const f of [...critical, ...high]) {
    for (const m of f.mitigations.slice(2)) lines.push(`- ${m}`);
  }
  lines.push("");
  lines.push("### ⚪ Long-term (ongoing)");
  lines.push("");
  for (const f of other) {
    for (const m of f.mitigations) lines.push(`- ${m}`);
  }

  return lines.join("\n");
}
