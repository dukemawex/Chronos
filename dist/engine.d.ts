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
import { LogEvent } from "./parsers/cloudtrail";
export type { LogEvent };
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
/**
 * Compute an overall Threat Score (0–100) from a list of findings.
 *
 * Algorithm: weighted average of the top-5 individual confidence values,
 * with the highest-confidence finding carrying double weight.
 */
export declare function scoreFindings(findings: Finding[]): number;
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
export declare function threatTier(score: number): string;
/**
 * Detect regularly spaced CloudTrail API calls from the same source IP —
 * a classic "low-and-slow" reconnaissance or exfiltration signature.
 *
 * Groups events by `srcIp` and tests whether the inter-event gaps are
 * approximately equal.  Only intervals ≥ 30 minutes are flagged to avoid
 * noise from legitimate polling.
 */
export declare function huntPeriodicActivity(events: LogEvent[]): Finding[];
/**
 * Flag sensitive IAM mutations that may indicate privilege escalation or
 * persistence establishment.
 */
export declare function huntIamChanges(events: LogEvent[]): Finding[];
/**
 * Flag any modifications to S3 bucket policies, ACLs, or public-access
 * settings — common precursors to data exfiltration.
 */
export declare function huntS3PolicyChanges(events: LogEvent[]): Finding[];
/**
 * Detect repeated failed `ConsoleLogin` or `AssumeRole` attempts from the
 * same source IP within a sliding one-hour window.
 */
export declare function huntBruteForce(events: LogEvent[]): Finding[];
/**
 * Detect the APT pattern: a user logs in from a **new** source IP, then
 * makes sensitive IAM changes within 24 hours — a strong indicator of
 * account take-over followed by privilege escalation.
 */
export declare function huntNewIpIamChain(events: LogEvent[]): Finding[];
/**
 * Run the full Chronos threat-hunting pipeline on a set of CloudTrail log
 * files / strings.
 *
 * @param inputs  Array of raw CloudTrail log contents (strings).
 * @param sources Optional display names for each input (e.g. file names).
 */
export declare function analyse(inputs: string[], sources?: string[]): AnalysisResult;
/**
 * Generate a **Security Brief** targeted at Tier 3 SOC analysts.
 *
 * Sections:
 *   1. Executive Summary
 *   2. Timeline of Activity
 *   3. Evidence Blocks
 *   4. Recommended Mitigations
 */
export declare function generateSecurityBrief(result: AnalysisResult): string;
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
export declare function generateThreatIntelReport(result: AnalysisResult): string;
//# sourceMappingURL=engine.d.ts.map