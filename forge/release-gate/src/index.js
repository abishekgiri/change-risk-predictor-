import { storage, asApp, route } from "@forge/api";
import Resolver from "@forge/resolver";
import crypto from 'crypto';

// --- Constants ---
const KEY_POLICY_ACTIVE = "policy:active";
const KEY_POLICY_PREFIX = "policy:";
const AUDIT_KEY_PREFIX = "audit:";
const CONFIG_AUDIT_OLD = "audit:RG";
const OVERRIDE_KEY_PREFIX = "override:";
const APPROVAL_KEY_PREFIX = "approvals:";
const METADATA_KEY_PREFIX = "ext_meta:";

const resolverInstance = new Resolver();

// --- Resolvers ---

resolverInstance.define("getPolicy", async (req) => {
  const activeVersionId = (await storage.get(KEY_POLICY_ACTIVE));
  let activePolicy = null;
  if (activeVersionId) {
    activePolicy = await storage.get(`${KEY_POLICY_PREFIX}${activeVersionId}`);
  }
  if (!activePolicy) {
    const legacyConfig = (await storage.get("policy:RG")) || { enabled: true, riskThreshold: 70, requiredRole: "Release Manager" };
    activePolicy = {
      versionId: "legacy",
      rules: {
        mode: "ALL",
        rules: [
          { type: "risk_threshold", value: legacyConfig.riskThreshold || 70 },
          { type: "requires_approval", requiredRole: legacyConfig.requiredRole || "Release Manager" }
        ]
      },
      enabled: legacyConfig.enabled !== false
    };
  }
  return { policy: activePolicy };
});

resolverInstance.define("savePolicy", async (req) => {
  const { rules, enabled } = req.payload;
  const accountId = req.context.accountId;
  const versionId = crypto.randomUUID();
  const newPolicy = {
    versionId,
    rules,
    enabled,
    createdAt: new Date().toISOString(),
    createdBy: accountId,
  };
  await storage.set(`${KEY_POLICY_PREFIX}${versionId}`, newPolicy);
  await storage.set(KEY_POLICY_ACTIVE, versionId);
  return newPolicy;
});

resolverInstance.define("getIssuePanelData", async (req) => {
  const { issueKey } = req.context.extension;

  // Policy
  const activeVersionId = (await storage.get(KEY_POLICY_ACTIVE));
  let policy = null;
  if (activeVersionId) {
    policy = await storage.get(`${KEY_POLICY_PREFIX}${activeVersionId}`);
  } else {
    const legacy = (await storage.get("policy:RG")) || { requiredRole: "Release Manager" };
    policy = { rules: { rules: [{ type: "requires_approval", requiredRole: legacy.requiredRole }] }, enabled: legacy.enabled !== false };
  }

  const approvalRule = policy.rules?.rules?.find(r => r.type === "requires_approval");
  const requiredRole = approvalRule ? approvalRule.requiredRole : null;

  // Approvals
  const approvalKey = `${APPROVAL_KEY_PREFIX}${issueKey}`;
  const approvals = (await storage.get(approvalKey)) || [];

  // Override Status
  const overrideChain = (await storage.get(`${OVERRIDE_KEY_PREFIX}${issueKey}`)) || [];
  const lastOverride = overrideChain.length > 0 ? overrideChain[overrideChain.length - 1] : null;
  const activeOverride = (lastOverride && lastOverride.status === "APPROVED") ? lastOverride : null;

  // External Metadata
  const metadata = (await storage.get(`${METADATA_KEY_PREFIX}${issueKey}`)) || null;

  return {
    policy: { enabled: policy.enabled, requiredRole },
    approvals,
    override: {
      status: lastOverride ? lastOverride.status : "NONE",
      active: !!activeOverride,
      history: overrideChain
    },
    metadata,
    currentUser: req.context.accountId,
    issueKey: issueKey
  };
});

resolverInstance.define("approveIssue", async (req) => {
  const { issueKey } = req.context.extension;
  const accountId = req.context.accountId;

  const activeVersionId = (await storage.get(KEY_POLICY_ACTIVE));
  let requiredRole = "Release Manager";
  if (activeVersionId) {
    const policy = await storage.get(`${KEY_POLICY_PREFIX}${activeVersionId}`);
    const rule = policy.rules?.rules?.find(r => r.type === "requires_approval");
    if (rule) requiredRole = rule.requiredRole;
  }

  const record = {
    issueKey,
    approverAccountId: accountId,
    timestamp: new Date().toISOString(),
    roleOrGroup: requiredRole,
    comment: req.payload.comment || ""
  };

  const approvalKey = `${APPROVAL_KEY_PREFIX}${issueKey}`;
  const existing = (await storage.get(approvalKey)) || [];
  existing.push(record);
  await storage.set(approvalKey, existing);

  return record;
});

// Override Resolvers
resolverInstance.define("requestOverride", async (req) => {
  const { issueKey } = req.context.extension;
  const { reason } = req.payload;
  await appendOverrideEvent(issueKey, req.context.accountId, "REQUESTED", reason);
});

resolverInstance.define("approveOverride", async (req) => {
  const { issueKey } = req.context.extension;
  await appendOverrideEvent(issueKey, req.context.accountId, "APPROVED", "Override Approved via Panel");
});

resolverInstance.define("verifyAuditChain", async (req) => {
  const { issueKey } = req.payload;
  if (!issueKey) return { valid: false, error: "Missing issueKey" };
  const logs = (await storage.get(`${AUDIT_KEY_PREFIX}${issueKey}`)) || [];
  let prevHash = null;
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];
    const payload = { ...log };
    delete payload.hash;
    delete payload.prevHash;
    const canonical = JSON.stringify(payload, Object.keys(payload).sort());
    const expectedHash = sha256(canonical + (prevHash || ""));
    if (log.hash !== expectedHash) return { valid: false, brokenIndex: i, log: log };
    if (log.prevHash !== prevHash) return { valid: false, brokenIndex: i, reason: "Chain Link Broken", log: log };
    prevHash = log.hash;
  }
  return { valid: true, count: logs.length };
});

resolverInstance.define("exportAuditData", async (req) => {
  const policies = [];
  let cursor = null;
  do {
    const res = await storage.query().where('key', 'startsWith', KEY_POLICY_PREFIX).cursor(cursor).getMany();
    for (const result of res.results) policies.push(result.value);
    cursor = res.nextCursor;
  } while (cursor);

  const decisions = {};
  cursor = null;
  do {
    const res = await storage.query().where('key', 'startsWith', AUDIT_KEY_PREFIX).cursor(cursor).getMany();
    for (const result of res.results) decisions[result.key] = result.value;
    cursor = res.nextCursor;
  } while (cursor);

  const approvals = {};
  cursor = null;
  do {
    const res = await storage.query().where('key', 'startsWith', APPROVAL_KEY_PREFIX).cursor(cursor).getMany();
    for (const result of res.results) approvals[result.key] = result.value;
    cursor = res.nextCursor;
  } while (cursor);

  const overrides = {};
  cursor = null;
  do {
    const res = await storage.query().where('key', 'startsWith', OVERRIDE_KEY_PREFIX).cursor(cursor).getMany();
    for (const result of res.results) overrides[result.key] = result.value;
    cursor = res.nextCursor;
  } while (cursor);

  return {
    timestamp: new Date().toISOString(),
    exportedBy: req.context.accountId,
    policies,
    decisions,
    approvals,
    overrides
  };
});

// External Metadata Resolver
resolverInstance.define("setExternalMetadata", async (req) => {
  const { issueKey, data } = req.payload;
  await storage.set(`${METADATA_KEY_PREFIX}${issueKey}`, data);
  return { success: true };
});

export const resolver = resolverInstance.getDefinitions();

// --- Validator V2 (Rule Engine) ---

export const run = async (event) => {
  // 1. Log Payload for Debugging
  console.log("VALIDATOR PAYLOAD:", JSON.stringify(event, null, 2));

  // 2. Identify Issue ID/Key (handling 'issue' vs 'workItem')
  const issueIdOrKey = event.issue?.key || event.issue?.id || event.workItem?.key || event.workItem?.id;

  // 3. Ensure Issue Object Structure
  if (!event.issue) event.issue = event.workItem || { key: issueIdOrKey || "UNKNOWN" };
  if (!event.issue.fields) event.issue.fields = {};

  // 4. Fetch Details if Summary is missing
  if (issueIdOrKey && !event.issue.fields.summary) {
    try {
      console.log(`Fetching details for issue: ${issueIdOrKey}`);
      const response = await asApp().requestJira(route`/rest/api/3/issue/${issueIdOrKey}?fields=summary`);
      if (response.status === 200) {
        const issueData = await response.json();
        event.issue.fields.summary = issueData.fields.summary;
        event.issue.key = issueData.key; // Ensure key is set
        console.log("Fetched Summary:", event.issue.fields.summary);
      } else {
        console.error("Failed to fetch issue details. Status:", response.status);
      }
    } catch (e) {
      console.error("Error fetching issue details:", e);
    }
  }

  const activeVersionId = (await storage.get(KEY_POLICY_ACTIVE));
  let policy = null;
  if (activeVersionId) {
    policy = await storage.get(`${KEY_POLICY_PREFIX}${activeVersionId}`);
  }
  if (!policy) {
    const legacyConfig = (await storage.get("policy:RG")) || { enabled: true, riskThreshold: 70, requiredRole: "Release Manager" };
    policy = {
      enabled: legacyConfig.enabled !== false,
      rules: {
        mode: "ALL",
        rules: [
          { type: "risk_threshold", value: legacyConfig.riskThreshold || 70 },
          { type: "requires_approval", requiredRole: legacyConfig.requiredRole || "Release Manager" }
        ]
      }
    };
  }

  const overrideChain = (await storage.get(`${OVERRIDE_KEY_PREFIX}${event.issue.key}`)) || [];
  const lastOverride = overrideChain.length > 0 ? overrideChain[overrideChain.length - 1] : null;
  const isOverrideActive = (lastOverride && lastOverride.status === "APPROVED");

  if (isOverrideActive) {
    await logDecision(event, "ALLOW", ["Active Override Applied"]);
    return { result: true };
  }

  if (!policy.enabled) {
    await logDecision(event, "ALLOW", ["Policy disabled"]);
    return { result: true };
  }

  const evaluation = await evaluateRules(policy.rules, event);
  const finalDecision = evaluation.allowed ? "ALLOW" : "BLOCK";
  await logDecision(event, finalDecision, evaluation.reasons);

  if (!evaluation.allowed) {
    return {
      result: false,
      errorMessage: `🚫 ReleaseGate: ${evaluation.reasons.join(". ")}`
    };
  }
  return { result: true };
};

// --- Rule Evaluator ---

async function evaluateRules(ruleSet, event) {
  const mode = ruleSet.mode || "ALL";
  const results = [];
  // Safe Access with Fallback
  const summary = event.issue?.fields?.summary || event.workItem?.fields?.summary || "";
  const riskScore = summary.toUpperCase().includes("HIGH") ? 90 : 20;

  for (const rule of ruleSet.rules || []) {
    let result = { allowed: true, reason: "" };
    switch (rule.type) {
      case "risk_threshold":
        if (riskScore > rule.value) result = { allowed: false, reason: `Risk Score ${riskScore} > Threshold ${rule.value}` };
        break;
      case "requires_approval":
        const hasApproval = await checkApproval(event.issue.key, rule.requiredRole);
        if (!hasApproval) result = { allowed: false, reason: `Missing approval from ${rule.requiredRole}` };
        break;
    }
    results.push(result);
  }
  if (mode === "ALL") {
    const failure = results.find(r => !r.allowed);
    if (failure) return { allowed: false, reasons: [failure.reason] };
    return { allowed: true, reasons: ["All checks passed"] };
  }
  return { allowed: true, reasons: ["Default Allow"] };
}

// --- Helpers ---

async function checkApproval(issueKey, requiredRole) {
  if (!issueKey) return false;
  const key = `${APPROVAL_KEY_PREFIX}${issueKey}`;
  const approvals = (await storage.get(key)) || [];
  if (approvals.length === 0) return false;
  for (const app of approvals) {
    if (await userMatchesRequiredApprover(app.approverAccountId, requiredRole, issueKey)) return true;
  }
  return false;
}

async function userMatchesRequiredApprover(accountId, requiredRole, issueKey) {
  try {
    const groupRes = await asApp().requestJira(route`/rest/api/3/group/member?groupname=${requiredRole}&accountId=${accountId}`);
    if (groupRes.status === 200) {
      const isMember = await groupRes.json();
      if (isMember.self) return true;
    }
    return false;
  } catch { return false; }
}

function sha256(content) { return crypto.createHash('sha256').update(content).digest('hex'); }

async function logDecision(event, decision, reasons) {
  try {
    const issueKey = event.issue.key || "UNKNOWN";
    const key = `${AUDIT_KEY_PREFIX}${issueKey}`;
    const chain = (await storage.get(key)) || [];
    const prevLog = chain.length > 0 ? chain[chain.length - 1] : null;

    const payload = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      issueKey,
      userAccountId: event.user ? event.user.accountId : "unknown",
      decision,
      reasons,
    };
    const canonical = JSON.stringify(payload, Object.keys(payload).sort());
    const hash = sha256(canonical + (prevLog ? prevLog.hash : ""));
    chain.push({ ...payload, prevHash: prevLog ? prevLog.hash : null, hash });
    await storage.set(key, chain);
  } catch (e) { console.error("Audit fail", e); }
}

async function appendOverrideEvent(issueKey, accountId, status, reason) {
  const key = `${OVERRIDE_KEY_PREFIX}${issueKey}`;
  const chain = (await storage.get(key)) || [];
  const prevEvent = chain.length > 0 ? chain[chain.length - 1] : null;

  const payload = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    issueKey,
    requestedBy: accountId,
    status,
    reason
  };
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const hash = sha256(canonical + (prevEvent ? prevEvent.hash : ""));
  chain.push({ ...payload, prevHash: prevEvent ? prevEvent.hash : null, hash });
  await storage.set(key, chain);
}
