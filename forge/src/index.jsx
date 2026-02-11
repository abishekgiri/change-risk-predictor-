import { api } from '@forge/api';
import crypto from 'crypto';
import policiesData from './policies.json';

const POLICIES = policiesData?.policies || [];
const POLICY_HASH = crypto
    .createHash('sha256')
    .update(JSON.stringify(POLICIES))
    .digest('hex');

const getIssueProperty = async (issueKey, propKey) => {
    try {
        const res = await api.asApp().requestJira(`/rest/api/3/issue/${issueKey}/properties/${propKey}`);
        if (res.status === 200) {
            const data = await res.json();
            return data?.value || {};
        }
    } catch (e) {
        console.log(`ReleaseGate: property ${propKey} fetch failed`, e);
    }
    return null;
};

const checkCondition = (actual, operator, expected) => {
    if (actual === undefined || actual === null) return false;
    if (operator === '==') return actual === expected;
    if (operator === '!=') return actual !== expected;
    if (operator === '>') return Number(actual) > Number(expected);
    if (operator === '>=') return Number(actual) >= Number(expected);
    if (operator === '<') return Number(actual) < Number(expected);
    if (operator === '<=') return Number(actual) <= Number(expected);
    if (operator === 'in') {
        if (Array.isArray(actual)) return actual.some(a => expected.includes(a));
        return expected.includes(actual);
    }
    if (operator === 'not in') {
        if (Array.isArray(actual)) return actual.every(a => !expected.includes(a));
        return !expected.includes(actual);
    }
    return false;
};

const evaluatePolicies = (signals) => {
    let decision = 'ALLOWED';
    let messages = [];

    for (const p of POLICIES) {
        const controls = p.controls || [];
        const matches = controls.every(c => checkCondition(signals[c.signal], c.operator, c.value));
        if (!matches) continue;
        const result = p.enforcement?.result || 'COMPLIANT';
        const message = p.enforcement?.message || `Policy ${p.policy_id} triggered`;
        messages.push(message);
        if (result === 'BLOCK') {
            decision = 'BLOCKED';
        } else if (result === 'WARN' && decision !== 'BLOCKED') {
            decision = 'CONDITIONAL';
        }
    }

    return { decision, message: messages[0] };
};

export const run = async (event, context) => {
    try {
        const { issue, transition } = event || {};
        const issueKey = issue?.key;
        const transitionName = transition?.name || 'unknown';
        const decisionSeed = `${issueKey}:${transitionName}:${POLICY_HASH}`;
        const decisionId = crypto.createHash('sha256').update(decisionSeed).digest('hex').slice(0, 20);

        console.log(`ReleaseGate: Validator invoked issue=${issueKey} transition=${transitionName} decision_id=${decisionId} policy_hash=${POLICY_HASH}`);

        // Override check (issue property)
        const override = await getIssueProperty(issueKey, 'releasegate_override');
        if (override?.enabled) {
            console.log(`ReleaseGate: decision=ALLOWED reason=OVERRIDE_APPLIED decision_id=${decisionId} policy_hash=${POLICY_HASH}`);
            return { result: true };
        }

        // Risk data from GitHub integration
        const risk = await getIssueProperty(issueKey, 'releasegate_risk');
        if (!risk) {
            // Explicit fail-open for missing metadata.
            console.log(`ReleaseGate: decision=ALLOWED reason=MISSING_RISK_METADATA decision_id=${decisionId} policy_hash=${POLICY_HASH}`);
            return { result: true };
        }

        const signals = {
            'core_risk.severity_level': risk.risk_level || risk.severity_level,
            'core_risk.violation_severity': risk.risk_score || risk.severity,
            'risk.level': risk.risk_level || risk.severity_level,
            'risk.score': risk.risk_score || risk.severity
        };

        // Optional approvals property
        const approvals = await getIssueProperty(issueKey, 'releasegate_approvals');
        if (approvals) {
            if (approvals.count !== undefined) signals['approvals.count'] = approvals.count;
            if (approvals.required_count !== undefined) {
                signals['approvals.required'] = true;
                signals['approvals.satisfied'] = approvals.count >= approvals.required_count;
            }
            if (approvals.role_counts) {
                for (const [k, v] of Object.entries(approvals.role_counts)) {
                    signals[`approvals.${k}`] = v;
                }
            }
        }

        const result = evaluatePolicies(signals);

        if (result.decision === 'BLOCKED') {
            console.log(`ReleaseGate: decision=BLOCKED decision_id=${decisionId} policy_hash=${POLICY_HASH}`);
            return {
                result: false,
                errorMessage: result.message || `ReleaseGate blocked this transition. Decision ID: ${decisionId}`
            };
        }

        console.log(`ReleaseGate: decision=ALLOWED decision_id=${decisionId} policy_hash=${POLICY_HASH}`);
        return { result: true };
    } catch (e) {
        console.log(`ReleaseGate: decision=ERROR policy_hash=${POLICY_HASH}`, e);
        return {
            result: false,
            errorMessage: 'ReleaseGate validator error. Please retry or contact admin.'
        };
    }
};
