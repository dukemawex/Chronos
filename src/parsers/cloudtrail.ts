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

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Raw shape of a single CloudTrail record (only the fields Chronos uses). */
export interface CloudTrailRecord {
  eventVersion?: string;
  userIdentity?: {
    type?: string;
    userName?: string;
    arn?: string;
    accountId?: string;
    sessionContext?: {
      sessionIssuer?: { userName?: string; arn?: string };
    };
  };
  eventTime: string;
  eventSource?: string;
  eventName: string;
  awsRegion?: string;
  sourceIPAddress?: string;
  userAgent?: string;
  requestParameters?: Record<string, unknown>;
  responseElements?: Record<string, unknown>;
  errorCode?: string;
}

/** Normalised event produced by any Chronos parser. */
export interface LogEvent {
  /** Log type identifier. Always `"cloudtrail"` from this parser. */
  source: "cloudtrail";
  /** UTC timestamp of the event. */
  timestamp: Date;
  /** Original record serialised to JSON. */
  raw: string;
  /** CloudTrail `eventName` (e.g. `"GetObject"`, `"ConsoleLogin"`). */
  eventType: string;
  /** IAM user name or role ARN extracted from `userIdentity`. */
  user: string;
  /** `sourceIPAddress` field from the record. */
  srcIp: string;
  /** AWS region where the API call was made. */
  awsRegion: string;
  /** AWS service endpoint (e.g. `"iam.amazonaws.com"`). */
  eventSource: string;
  /** `requestParameters` map (may be empty). */
  requestParameters: Record<string, unknown>;
  /** `responseElements` map (may be empty). */
  responseElements: Record<string, unknown>;
  /** Non-empty when the API call resulted in an error. */
  errorCode: string;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract a display name for the calling principal from the `userIdentity`
 * block.  Preference order: userName → session-issuer userName → ARN → "".
 */
function extractUser(identity?: CloudTrailRecord["userIdentity"]): string {
  if (!identity) return "";
  if (identity.userName) return identity.userName;
  const issuer = identity.sessionContext?.sessionIssuer;
  if (issuer?.userName) return issuer.userName;
  if (issuer?.arn) return issuer.arn;
  return identity.arn ?? "";
}

/**
 * Parse an ISO-8601 string such as `"2026-04-01T06:00:00Z"` into a `Date`.
 * Returns `null` for invalid / missing values.
 */
function parseTimestamp(ts: unknown): Date | null {
  if (typeof ts !== "string" || !ts) return null;
  const d = new Date(ts);
  return isNaN(d.getTime()) ? null : d;
}

/** Convert a single raw record object into a `LogEvent`, or `null` on error. */
function recordToEvent(rec: CloudTrailRecord): LogEvent | null {
  const ts = parseTimestamp(rec.eventTime);
  if (!ts) return null;

  return {
    source: "cloudtrail",
    timestamp: ts,
    raw: JSON.stringify(rec),
    eventType: rec.eventName ?? "unknown",
    user: extractUser(rec.userIdentity),
    srcIp: rec.sourceIPAddress ?? "",
    awsRegion: rec.awsRegion ?? "",
    eventSource: rec.eventSource ?? "",
    requestParameters: (rec.requestParameters as Record<string, unknown>) ?? {},
    responseElements: (rec.responseElements as Record<string, unknown>) ?? {},
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
export function parseCloudTrail(input: string | string[]): LogEvent[] {
  const lines: string[] = Array.isArray(input)
    ? input
    : input.split("\n");

  const rawRecords: CloudTrailRecord[] = [];

  // ---- Pass 1: try to parse each non-empty line as JSON ----
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed) as
        | { Records?: CloudTrailRecord[] }
        | CloudTrailRecord[]
        | CloudTrailRecord;
      if (Array.isArray(obj)) {
        rawRecords.push(...obj);
      } else if ("Records" in obj && Array.isArray(obj.Records)) {
        rawRecords.push(...obj.Records);
      } else if ("eventName" in obj) {
        rawRecords.push(obj as CloudTrailRecord);
      }
    } catch {
      // Non-JSON line — ignore and continue
    }
  }

  // ---- Pass 2: fallback — treat entire input as one JSON document ----
  if (rawRecords.length === 0) {
    const fullText = Array.isArray(input) ? input.join("\n") : input;
    try {
      const obj = JSON.parse(fullText) as
        | { Records?: CloudTrailRecord[] }
        | CloudTrailRecord[];
      if (Array.isArray(obj)) {
        rawRecords.push(...obj);
      } else if ("Records" in obj && Array.isArray(obj.Records)) {
        rawRecords.push(...obj.Records);
      }
    } catch {
      // Unparseable — return empty
    }
  }

  // ---- Convert records to LogEvents, dropping those without a valid timestamp ----
  return rawRecords
    .map(recordToEvent)
    .filter((e): e is LogEvent => e !== null);
}
