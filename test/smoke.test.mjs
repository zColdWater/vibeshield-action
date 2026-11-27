import assert from "node:assert/strict";
import { buildMarkdownReport, normalizeTargetUrl, runScan, COMMENT_MARKER } from "../src/index.mjs";

// 1. Unit tests
assert.equal(normalizeTargetUrl("supabase.com"), "https://supabase.com/");
assert.throws(() => normalizeTargetUrl("javascript:alert(1)"));

const mock = buildMarkdownReport(
  {
    hostname: "demo.vercel.app",
    tlsHttps: true,
    tls: { protocol: "TLSv1.3", daysRemaining: 75 },
    assessment: { score: 86, grade: "A", criticalCount: 0, highCount: 0, mediumCount: 1, lowCount: 1 },
    bundles: { secretsFoundCount: 0 },
    headers: { passed: 8, total: 10 },
    probes: { exposedCount: 0, totalChecked: 28 },
    supabase: { detected: true, serviceRoleLeaked: false, exposedTables: [] },
    findings: [{ severity: "medium", title: "Missing Permissions-Policy header" }],
  },
  { failBelow: 75 }
);
assert.equal(mock.gatePassed, true);
assert.ok(mock.markdown.includes(COMMENT_MARKER));
assert.ok(mock.markdown.includes("Full Cursor Fix & 24/7 Monitor ->** https://shipbastion.com/?url=demo.vercel.app"));
assert.ok(mock.markdown.includes("https://shipbastion.com/trust/demo.vercel.app"));
assert.equal(buildMarkdownReport({ hostname: "a.dev", assessment: { score: 60 } }, { failBelow: 75 }).gatePassed, false);
console.log("1. UNIT_TESTS_OK");

// 2. Live API E2E test against production https://shipbastion.com/api/free-scan
const live = await runScan("https://supabase.com", "https://shipbastion.com");
const liveRep = buildMarkdownReport(live, { apiBase: "https://shipbastion.com", failBelow: 0 });
assert.ok(liveRep.score >= 0 && liveRep.score <= 100, "score in range");
assert.ok(liveRep.markdown.includes("supabase.com"), "hostname present");
console.log("2. LIVE_API_E2E_OK:", JSON.stringify({ host: liveRep.host, score: liveRep.score, grade: liveRep.grade, crit: liveRep.crit, high: liveRep.high }));
