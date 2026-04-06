"use strict";
/**
 * Chronos — public package entry point.
 *
 * Re-exports every symbol that consumers of the `chronos` npm package need.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateThreatIntelReport = exports.generateSecurityBrief = exports.huntNewIpIamChain = exports.huntS3PolicyChanges = exports.huntIamChanges = exports.huntBruteForce = exports.huntPeriodicActivity = exports.threatTier = exports.scoreFindings = exports.analyse = exports.parseCloudTrail = void 0;
// Parser
var cloudtrail_1 = require("./parsers/cloudtrail");
Object.defineProperty(exports, "parseCloudTrail", { enumerable: true, get: function () { return cloudtrail_1.parseCloudTrail; } });
// Engine (analysis pipeline + hunters + scoring + reports)
var engine_1 = require("./engine");
Object.defineProperty(exports, "analyse", { enumerable: true, get: function () { return engine_1.analyse; } });
Object.defineProperty(exports, "scoreFindings", { enumerable: true, get: function () { return engine_1.scoreFindings; } });
Object.defineProperty(exports, "threatTier", { enumerable: true, get: function () { return engine_1.threatTier; } });
Object.defineProperty(exports, "huntPeriodicActivity", { enumerable: true, get: function () { return engine_1.huntPeriodicActivity; } });
Object.defineProperty(exports, "huntBruteForce", { enumerable: true, get: function () { return engine_1.huntBruteForce; } });
Object.defineProperty(exports, "huntIamChanges", { enumerable: true, get: function () { return engine_1.huntIamChanges; } });
Object.defineProperty(exports, "huntS3PolicyChanges", { enumerable: true, get: function () { return engine_1.huntS3PolicyChanges; } });
Object.defineProperty(exports, "huntNewIpIamChain", { enumerable: true, get: function () { return engine_1.huntNewIpIamChain; } });
Object.defineProperty(exports, "generateSecurityBrief", { enumerable: true, get: function () { return engine_1.generateSecurityBrief; } });
Object.defineProperty(exports, "generateThreatIntelReport", { enumerable: true, get: function () { return engine_1.generateThreatIntelReport; } });
//# sourceMappingURL=index.js.map