import api, { route } from "@forge/api";
import crypto from "crypto";

const _env = (name) => {
  const raw = process.env[name];
  if (!raw) return null;
  const v = String(raw).trim();
  return v ? v : null;
};

const _baseUrl = () => {
  const configured =
    _env("RELEASEGATE_GATE_URL") ||
    _env("RELEASEGATE_API_BASE_URL") ||
    _env("RELEASEGATE_BASE_URL");
  const fallback = "https://releasegate.dev";
  const base = (configured || fallback).replace(/\/+$/, "");
  return base;
};

const _tenantId = () => _env("RELEASEGATE_TENANT_ID") || "default";

const _environment = () =>
  (_env("RELEASEGATE_ENVIRONMENT") || "PRODUCTION").toUpperCase();

const _debugLogEvent = () =>
  ["1", "true", "yes", "on"].includes(
    (_env("RELEASEGATE_DEBUG_LOG_EVENT") || "").toLowerCase()
  );

const _asString = (value, fallback = "unknown") => {
  const s = String(value || "").trim();
  return s ? s : fallback;
};

const _issueKeyFromEvent = (event) => {
  const key = event?.issue?.key || event?.issueKey || event?.issue_key;
  return _asString(key, "");
};

const _transitionFromEvent = (event) => {
  const transition = event?.transition || {};
  const transitionId =
    transition?.id ||
    transition?.transitionId ||
    transition?.transition_id ||
    event?.transitionId ||
    event?.transition_id ||
    event?.context?.transitionId ||
    event?.context?.transition_id ||
    event?.context?.transition?.id ||
    event?.context?.transition?.transitionId ||
    event?.context?.transition?.transition_id;
  const transitionName =
    transition?.name ||
    transition?.transitionName ||
    transition?.transition_name ||
    event?.transitionName ||
    event?.transition_name ||
    event?.context?.transitionName ||
    event?.context?.transition_name ||
    event?.context?.transition?.name ||
    event?.context?.transition?.transitionName ||
    event?.context?.transition?.transition_name;
  const fromStatusId = transition?.from?.id || transition?.from?.statusId || transition?.from?.status_id;
  const toStatusId = transition?.to?.id || transition?.to?.statusId || transition?.to?.status_id;
  return {
    transition_id: _asString(transitionId, ""),
    transition_name: transitionName ? _asString(transitionName, "") : undefined,
    from_status_id: fromStatusId ? _asString(fromStatusId, "") : undefined,
    to_status_id: toStatusId ? _asString(toStatusId, "") : undefined,
  };
};

const _actorFromEvent = (event) => {
  const user = event?.user || event?.actor || {};
  const accountId = user?.accountId || user?.account_id || user?.id;
  const email = user?.email || user?.emailAddress;
  return {
    actor_account_id: _asString(accountId, ""),
    actor_email: email ? _asString(email, "") : undefined,
  };
};

const _fetchIssueMeta = async (issueKey) => {
  const fields = ["project", "issuetype", "status"].join(",");
  const res = await api
    .asApp()
    .requestJira(
      route`/rest/api/3/issue/${issueKey}?fields=${fields}`
    );
  if (res.status !== 200) {
    throw new Error(`jira issue fetch failed (status=${res.status})`);
  }
  const data = await res.json();
  const projectKey = data?.fields?.project?.key;
  const issueType = data?.fields?.issuetype?.name;
  const statusName = data?.fields?.status?.name;
  return {
    project_key: _asString(projectKey, ""),
    issue_type: _asString(issueType, ""),
    source_status: _asString(statusName, ""),
  };
};

const _fetchTransitions = async (issueKey) => {
  const res = await api.asApp().requestJira(
    route`/rest/api/3/issue/${issueKey}/transitions`
  );
  if (res.status !== 200) {
    throw new Error(`jira transitions fetch failed (status=${res.status})`);
  }
  const data = await res.json();
  return Array.isArray(data?.transitions) ? data.transitions : [];
};

const _resolveTransition = async (issueKey, transition) => {
  const transitions = await _fetchTransitions(issueKey);
  if (_debugLogEvent()) {
    const summary = transitions.map((t) => ({
      id: _asString(t?.id, ""),
      name: _asString(t?.name, ""),
      to: _asString(t?.to?.id, ""),
      toName: _asString(t?.to?.name, ""),
    }));
    console.log(
      "WORKFLOW_TRANSITION_RESOLUTION:",
      JSON.stringify({
        issueKey,
        requestedTransitionId: _asString(transition?.transition_id, ""),
        requestedTransitionName: _asString(transition?.transition_name, ""),
        requestedFromStatusId: _asString(transition?.from_status_id, ""),
        requestedToStatusId: _asString(transition?.to_status_id, ""),
        availableTransitions: summary,
      })
    );
  }
  const idCandidate = _asString(transition?.transition_id, "");
  if (idCandidate) {
    const match = transitions.find(
      (t) => _asString(t?.id, "") === _asString(idCandidate, "")
    );
    return {
      transition_id: idCandidate,
      transition_name:
        transition?.transition_name || (match ? _asString(match?.name, "") : undefined),
      target_status: match ? _asString(match?.to?.name, "unknown") : "unknown",
    };
  }

  const toStatusId = _asString(transition?.to_status_id, "");
  if (toStatusId) {
    const matches = transitions.filter(
      (t) => _asString(t?.to?.id, "") === _asString(toStatusId, "")
    );
    if (matches.length === 1) {
      const match = matches[0];
      return {
        transition_id: _asString(match?.id, ""),
        transition_name: transition?.transition_name || _asString(match?.name, ""),
        target_status: _asString(match?.to?.name, "unknown"),
      };
    }
    if (matches.length > 1) {
      // Prefer name disambiguation when available.
      const nameCandidate = _asString(transition?.transition_name, "");
      if (nameCandidate) {
        const normalized = nameCandidate.toLowerCase();
        const named = matches.find(
          (t) => _asString(t?.name, "").toLowerCase() === normalized
        );
        if (named) {
          return {
            transition_id: _asString(named?.id, ""),
            transition_name: _asString(named?.name, ""),
            target_status: _asString(named?.to?.name, "unknown"),
          };
        }
      }
      // Deterministic fallback: choose smallest transition id.
      const ordered = [...matches].sort((a, b) =>
        _asString(a?.id, "").localeCompare(_asString(b?.id, ""), "en")
      );
      const chosen = ordered[0];
      return {
        transition_id: _asString(chosen?.id, ""),
        transition_name: _asString(chosen?.name, ""),
        target_status: _asString(chosen?.to?.name, "unknown"),
      };
    }
  }

  const nameCandidate = _asString(transition?.transition_name, "");
  if (nameCandidate) {
    const normalized = nameCandidate.toLowerCase();
    const match = transitions.find(
      (t) => _asString(t?.name, "").toLowerCase() === normalized
    );
    if (match) {
      return {
        transition_id: _asString(match?.id, ""),
        transition_name: _asString(match?.name, ""),
        target_status: _asString(match?.to?.name, "unknown"),
      };
    }
  }

  // Last-resort deterministic fallback for workflows with a single outgoing transition.
  if (transitions.length === 1) {
    const only = transitions[0];
    return {
      transition_id: _asString(only?.id, ""),
      transition_name: _asString(only?.name, ""),
      target_status: _asString(only?.to?.name, "unknown"),
    };
  }

  return {
    transition_id: "",
    transition_name: transition?.transition_name,
    target_status: "unknown",
  };
};

const _signatureHeaders = (method, path, bodyText) => {
  const keyId =
    _env("RELEASEGATE_WEBHOOK_KEY_ID") ||
    _env("RELEASEGATE_SIGNATURE_KEY_ID") ||
    null;
  const secret =
    _env("RELEASEGATE_WEBHOOK_SECRET") ||
    _env("RELEASEGATE_SIGNATURE_SECRET") ||
    null;
  if (!keyId || !secret) return null;

  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(16).toString("hex");
  const canonical = Buffer.concat([
    Buffer.from(timestamp, "utf-8"),
    Buffer.from("\n", "utf-8"),
    Buffer.from(nonce, "utf-8"),
    Buffer.from("\n", "utf-8"),
    Buffer.from(String(method || "POST").toUpperCase(), "utf-8"),
    Buffer.from("\n", "utf-8"),
    Buffer.from(String(path || "/"), "utf-8"),
    Buffer.from("\n", "utf-8"),
    Buffer.from(bodyText || "", "utf-8"),
  ]);
  const sigHex = crypto.createHmac("sha256", secret).update(canonical).digest("hex");
  return {
    "X-Signature": `sha256=${sigHex}`,
    "X-Key-Id": keyId,
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
  };
};

const _apiKeyHeaders = () => {
  const key = _env("RELEASEGATE_GATE_API_KEY") || _env("RELEASEGATE_API_KEY") || null;
  if (!key) return null;
  return { "X-API-Key": key };
};

const _authHeaders = (method, path, bodyText) => {
  const signature = _signatureHeaders(method, path, bodyText);
  if (signature) return signature;
  const apiKey = _apiKeyHeaders();
  if (apiKey) return apiKey;
  throw new Error("missing ReleaseGate auth (set signature or api key env vars)");
};

const _postGate = async (payload) => {
  const baseUrl = _baseUrl();
  const urlPath = "/integrations/jira/transition/check";
  const url = `${baseUrl}${urlPath}`;

  const body = JSON.stringify(payload);
  const headers = {
    "Content-Type": "application/json",
    ..._authHeaders("POST", urlPath, body),
  };
  const res = await api.fetch(url, {
    method: "POST",
    headers,
    body,
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`gate request failed (status=${res.status}) body=${text.slice(0, 256)}`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`gate response not valid json: ${String(e)}`);
  }
};

export const run = async (event, _context) => {
  // Fail-closed: any exception blocks the transition.
  try {
    if (_debugLogEvent()) {
      console.log("WORKFLOW_VALIDATOR_EVENT:", JSON.stringify(event));
    }

    const issueKey = _issueKeyFromEvent(event);
    if (!issueKey) {
      return { result: false, errorMessage: "ReleaseGate: missing issue key (fail-closed)." };
    }

    const actor = _actorFromEvent(event);
    if (!actor.actor_account_id) {
      return { result: false, errorMessage: "ReleaseGate: missing actor id (fail-closed)." };
    }

    const transitionRaw = _transitionFromEvent(event);
    const issueMeta = await _fetchIssueMeta(issueKey);
    const transition = await _resolveTransition(issueKey, transitionRaw);

    if (!transition.transition_id) {
      return {
        result: false,
        errorMessage: "ReleaseGate: missing transition id (fail-closed).",
      };
    }
    if (!transition.target_status || transition.target_status === "unknown") {
      return {
        result: false,
        errorMessage: "ReleaseGate: could not resolve target status (fail-closed).",
      };
    }

    const payload = {
      tenant_id: _tenantId(),
      issue_key: issueKey,
      transition_id: transition.transition_id,
      transition_name: transition.transition_name,
      source_status: issueMeta.source_status,
      target_status: transition.target_status,
      actor_account_id: actor.actor_account_id,
      actor_email: actor.actor_email,
      environment: _environment(),
      project_key: issueMeta.project_key,
      issue_type: issueMeta.issue_type,
      context_overrides: {
        repo: "abishekgiri/change-risk-predictor-",
        pr_number: 27,
      },
    };

    const decision = await _postGate(payload);
    if (!decision?.allow) {
      const reason = _asString(decision?.reason, "Blocked by ReleaseGate.");
      const decisionId = _asString(decision?.decision_id, "");
      return {
        result: false,
        errorMessage: decisionId ? `${reason} Decision: ${decisionId}` : reason,
      };
    }
    return { result: true };
  } catch (e) {
    console.error("ReleaseGate validator error:", String(e));
    return {
      result: false,
      errorMessage: "ReleaseGate validation failure (fail-closed).",
    };
  }
};
