/**
 * Chronos — public package entry point.
 *
 * Re-exports every symbol that consumers of the `chronos` npm package need.
 */
export { parseCloudTrail } from "./parsers/cloudtrail";
export type { CloudTrailRecord, LogEvent } from "./parsers/cloudtrail";
export { analyse, scoreFindings, threatTier, huntPeriodicActivity, huntBruteForce, huntIamChanges, huntS3PolicyChanges, huntNewIpIamChain, generateSecurityBrief, generateThreatIntelReport, } from "./engine";
export type { Severity, Finding, AnalysisResult } from "./engine";
//# sourceMappingURL=index.d.ts.map