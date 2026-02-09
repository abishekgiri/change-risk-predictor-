import { fetch } from '@forge/api';

/**
 * ReleaseGate Validator
 * 
 * Enforces policies on Jira transitions.
 * MVP Logic: Always ALLOW (Fail Open).
 */
export const run = async (event, context) => {
    console.log("ReleaseGate: Validator invoked for issue", event.issue.key);

    // 1. Context Extraction
    const { issue, transition } = event;
    const { id: transitionId, name: transitionName } = transition;

    console.log(`Transition: ${transitionName} (${transitionId})`);

    // 2. Logic Stub
    // TODO: Call internal policy engine or check issue properties

    // 3. Decision
    // Return result: true to allow, false to block.
    // If blocking, provide an errorMessage.

    return {
        result: true
    };
};
