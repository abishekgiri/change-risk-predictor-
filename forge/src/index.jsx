import { api } from '@forge/api';
import policiesData from './policies.json';

const POLICIES = policiesData?.policies || [];

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
    const { issue, transition } = event;
    const issueKey = issue?.key;
    const transitionName = transition?.name || 'unknown';

    console.log(`ReleaseGate: Validator invoked for ${issueKey} (${transitionName})`);

    // Override check (issue property)
    const override = await getIssueProperty(issueKey, 'releasegate_override');
    if (override?.enabled) {
        return { result: true };
    }

    // Risk data from GitHub integration
    const risk = await getIssueProperty(issueKey, 'releasegate_risk');
    if (!risk) {
        // Fail open if we don't have risk data
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
        return {
            result: false,
            errorMessage: result.message || 'ReleaseGate: transition blocked'
        };
    }

    return { result: true };
};
