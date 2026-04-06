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
/** Raw shape of a single CloudTrail record (only the fields Chronos uses). */
export interface CloudTrailRecord {
    eventVersion?: string;
    userIdentity?: {
        type?: string;
        userName?: string;
        arn?: string;
        accountId?: string;
        sessionContext?: {
            sessionIssuer?: {
                userName?: string;
                arn?: string;
            };
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
/**
 * Parse AWS CloudTrail logs into an array of normalised `LogEvent` objects.
 *
 * @param input  Raw log content — either the full file as a single string, or
 *               an array of lines (strings).
 */
export declare function parseCloudTrail(input: string | string[]): LogEvent[];
//# sourceMappingURL=cloudtrail.d.ts.map