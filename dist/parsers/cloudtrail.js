"use strict";
/**
 * Chronos — AWS CloudTrail JSON log parser.
 *
 * Accepts either of the two formats emitted by CloudTrail:
 *   1. A JSON object with a top-level `Records` array (S3 export format).
 *   2. JSON-Lines (one JSON object per line), each being a single record or an
 *      object with a `Records` key.
 *
 * Each parsed record is returned as a normalised `LogEvent`.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCloudTrail = parseCloudTrail;
// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
/**
 * Extract a display name for the calling principal from the `userIdentity`
 * block.  Preference order: userName → session-issuer userName → ARN → "".
 */
function extractUser(identity) {
    if (!identity)
        return "";
    if (identity.userName)
        return identity.userName;
    const issuer = identity.sessionContext?.sessionIssuer;
    if (issuer?.userName)
        return issuer.userName;
    if (issuer?.arn)
        return issuer.arn;
    return identity.arn ?? "";
}
/**
 * Parse an ISO-8601 string such as `"2026-04-01T06:00:00Z"` into a `Date`.
 * Returns `null` for invalid / missing values.
 */
function parseTimestamp(ts) {
    if (typeof ts !== "string" || !ts)
        return null;
    const d = new Date(ts);
    return isNaN(d.getTime()) ? null : d;
}
/** Convert a single raw record object into a `LogEvent`, or `null` on error. */
function recordToEvent(rec) {
    const ts = parseTimestamp(rec.eventTime);
    if (!ts)
        return null;
    return {
        source: "cloudtrail",
        timestamp: ts,
        raw: JSON.stringify(rec),
        eventType: rec.eventName ?? "unknown",
        user: extractUser(rec.userIdentity),
        srcIp: rec.sourceIPAddress ?? "",
        awsRegion: rec.awsRegion ?? "",
        eventSource: rec.eventSource ?? "",
        requestParameters: rec.requestParameters ?? {},
        responseElements: rec.responseElements ?? {},
        errorCode: rec.errorCode ?? "",
    };
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
/**
 * Parse AWS CloudTrail logs into an array of normalised `LogEvent` objects.
 *
 * @param input  Raw log content — either the full file as a single string, or
 *               an array of lines (strings).
 */
function parseCloudTrail(input) {
    const lines = Array.isArray(input)
        ? input
        : input.split("\n");
    const rawRecords = [];
    // ---- Pass 1: try to parse each non-empty line as JSON ----
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed)
            continue;
        try {
            const obj = JSON.parse(trimmed);
            if (Array.isArray(obj)) {
                rawRecords.push(...obj);
            }
            else if ("Records" in obj && Array.isArray(obj.Records)) {
                rawRecords.push(...obj.Records);
            }
            else if ("eventName" in obj) {
                rawRecords.push(obj);
            }
        }
        catch {
            // Non-JSON line — ignore and continue
        }
    }
    // ---- Pass 2: fallback — treat entire input as one JSON document ----
    if (rawRecords.length === 0) {
        const fullText = Array.isArray(input) ? input.join("\n") : input;
        try {
            const obj = JSON.parse(fullText);
            if (Array.isArray(obj)) {
                rawRecords.push(...obj);
            }
            else if ("Records" in obj && Array.isArray(obj.Records)) {
                rawRecords.push(...obj.Records);
            }
        }
        catch {
            // Unparseable — return empty
        }
    }
    // ---- Convert records to LogEvents, dropping those without a valid timestamp ----
    return rawRecords
        .map(recordToEvent)
        .filter((e) => e !== null);
}
//# sourceMappingURL=cloudtrail.js.map