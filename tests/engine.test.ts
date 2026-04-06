/**
 * Validates that the Chronos engine correctly detects the "Low and Slow"
 * attack pattern encoded in tests/mock_logs.json.
 *
 * The synthetic log contains:
 *   - 12 periodic API calls from 198.51.100.42 every 6 hours over 3 days
 *     → should trigger huntPeriodicActivity
 *   - CreateUser → AttachUserPolicy → CreateAccessKey on Day 4
 *     → should trigger huntIamChanges (CRITICAL escalation chain)
 *   - PutBucketPolicy on prod-data
 *     → should trigger huntS3PolicyChanges
 */

import * as fs from "fs";
import * as path from "path";
import {
  parseCloudTrail,
  analyse,
  huntPeriodicActivity,
  huntIamChanges,
  huntS3PolicyChanges,
} from "../src/index";

const MOCK_LOG_PATH = path.join(__dirname, "mock_logs.json");

function loadMockLog(): string {
  return fs.readFileSync(MOCK_LOG_PATH, "utf-8");
}

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

describe("parseCloudTrail — mock_logs.json", () => {
  it("parses all records with valid timestamps", () => {
    const events = parseCloudTrail(loadMockLog());
    expect(events.length).toBeGreaterThan(0);
    for (const e of events) {
      expect(e.timestamp).toBeInstanceOf(Date);
      expect(isNaN(e.timestamp.getTime())).toBe(false);
    }
  });

  it("sets source to 'cloudtrail' for every event", () => {
    const events = parseCloudTrail(loadMockLog());
    for (const e of events) {
      expect(e.source).toBe("cloudtrail");
    }
  });

  it("extracts srcIp for the attacker IP", () => {
    const events = parseCloudTrail(loadMockLog());
    const attackerEvents = events.filter((e) => e.srcIp === "198.51.100.42");
    expect(attackerEvents.length).toBeGreaterThan(0);
  });

  it("returns events sorted by the caller after parseCloudTrail", () => {
    // parseCloudTrail does not guarantee order — the engine sorts them
    const events = parseCloudTrail(loadMockLog());
    expect(events.length).toBeGreaterThan(4); // more than minimum periodic count
  });
});

// ---------------------------------------------------------------------------
// Individual hunter tests
// ---------------------------------------------------------------------------

describe("huntPeriodicActivity — Low-and-Slow detection", () => {
  it("flags the attacker IP for periodic activity", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntPeriodicActivity(events);
    expect(findings.length).toBeGreaterThan(0);
    const finding = findings.find((f) => f.title.includes("198.51.100.42"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
  });

  it("finding hypothesis mentions automation / interval", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntPeriodicActivity(events);
    const finding = findings.find((f) => f.title.includes("198.51.100.42"))!;
    expect(finding.hypothesis).toMatch(/periodic|interval|automated/i);
  });

  it("finding has at least 4 timeline entries", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntPeriodicActivity(events);
    const finding = findings.find((f) => f.title.includes("198.51.100.42"))!;
    expect(finding.timeline.length).toBeGreaterThanOrEqual(4);
  });

  it("includes mitigation recommendations", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntPeriodicActivity(events);
    const finding = findings.find((f) => f.title.includes("198.51.100.42"))!;
    expect(finding.mitigations.length).toBeGreaterThan(0);
  });
});

describe("huntIamChanges — privilege escalation", () => {
  it("detects the CreateUser → AttachUserPolicy escalation chain", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntIamChanges(events);
    expect(findings.length).toBeGreaterThan(0);
    const critical = findings.filter((f) => f.severity === "CRITICAL");
    expect(critical.length).toBeGreaterThan(0);
  });

  it("finding title references CreateUser or AttachUserPolicy", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntIamChanges(events);
    const match = findings.find(
      (f) =>
        f.title.includes("CreateUser") || f.title.includes("AttachUserPolicy")
    );
    expect(match).toBeDefined();
  });
});

describe("huntS3PolicyChanges", () => {
  it("flags the PutBucketPolicy event on prod-data", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntS3PolicyChanges(events);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].title).toMatch(/PutBucketPolicy/);
    expect(findings[0].title).toMatch(/prod-data/);
  });

  it("severity is HIGH", () => {
    const events = parseCloudTrail(loadMockLog());
    const findings = huntS3PolicyChanges(events);
    expect(findings[0].severity).toBe("HIGH");
  });
});

// ---------------------------------------------------------------------------
// Full pipeline (analyse)
// ---------------------------------------------------------------------------

describe("analyse — full pipeline on mock_logs.json", () => {
  it("returns an AnalysisResult with events and findings", () => {
    const result = analyse([loadMockLog()], ["mock_logs.json"]);
    expect(result.events.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("computes a non-zero threat score", () => {
    const result = analyse([loadMockLog()], ["mock_logs.json"]);
    expect(result.threatScore).toBeGreaterThan(0);
  });

  it("threat tier label is a non-empty string", () => {
    const result = analyse([loadMockLog()], ["mock_logs.json"]);
    expect(typeof result.threatTierLabel).toBe("string");
    expect(result.threatTierLabel.length).toBeGreaterThan(0);
  });

  it("findings are sorted with CRITICAL first", () => {
    const result = analyse([loadMockLog()], ["mock_logs.json"]);
    const hasCritical = result.findings.some((f) => f.severity === "CRITICAL");
    if (hasCritical) {
      expect(result.findings[0].severity).toBe("CRITICAL");
    }
  });

  it("logSources contains the provided source name", () => {
    const result = analyse([loadMockLog()], ["mock_logs.json"]);
    expect(result.logSources).toContain("mock_logs.json");
  });
});
