# ReleaseGate Migration Walkthrough

**Audience**: Engineering Lead, Jira Admin, Security / Compliance Reviewer
**Environment**: Forge Development Environment

We have successfully migrated the ReleaseGate Jira Validator from the deprecated **UI Kit 1** to the modern **UI Kit 2 (Custom UI / React)**.

## 1. What Changed?
*   **Frontend**: Rewrote `src/admin.jsx` (UI Kit 1) into a full React application in `static/admin/App.jsx`.
*   **Build System**: Added `vite` to build the React app into `dist/admin`.
*   **Backend**: Updated `src/index.js` to use `@forge/resolver` for handling frontend requests (`getPolicy`, `savePolicy`).
*   **Manifest**: Changed `jira:projectSettingsPage` to use the `resource: main` type instead of a `function`.

## 2. Verification Steps

### A. Admin UI (Project Settings)
1.  Navigate to a Jira Project -> **Project Settings**.
2.  Click **ReleaseGate Policy** in the sidebar.
3.  **Verify**: The page renders with a modern look (white background, standard inputs).
4.  **Test**: Change "Risk Threshold" to `80`.
5.  **Action**: Click **Save Policy**.
6.  **Verify UI**: Button changes to "Saving..." then "Policy Saved!".
7.  **Verify Persistence**: Refresh the page. The value should explicitly stay at `80`.

### C. Role-Aware Approvals (Phase 11.2)
1.  **Configure**: Set "Required Approver" -> "Release Manager" in Policy Admin.
2.  **View**: Open an Issue. You should see the **ReleaseGate** panel.
3.  **Check**: Panel says "Required: Release Manager".
4.  **Action**: Click **Approve as Release Manager**.
5.  **Verify**:
    *   Button changes to "You Approved".
    *   List adds your name + timestamp.
    *   Transition is now **Allowed**.
6.  **Negative Test**:
    *   Clear approvals (hard to do without backend tool, or just create new issue).
    *   Try to transition BEFORE approving -> Should **BLOCK**.

### D. Immutable Decision History (Phase 11.2)
1.  **Generate Logs**: Perform some Blocks and Allows on an issue.
2.  **Verify**: Open Developer Console (or use Postman/CLI) to invoke `verifyAuditChain`.
    *   *Note*: Since we haven't built a UI for this yet, you can trust the backend logs or use `forge logs` to see the "Log Decision" output which includes the hash.
3.  **Concept**: Every decision now includes `prevHash` + `hash` (SHA256).

## 3. Maintenance Commands
*   **Login**: `forge login` (if token expires).
*   **Build**: `cd forge/release-gate && npm install && ./node_modules/.bin/vite build`
*   **Deploy**: `forge deploy`

### E. Policy Engine V2 (Phase 11.2)
1.  **View Admin**: Note that the UI now shows a JSON Editor.
2.  **Verify Version**: "Active Version" should be visible (or "Legacy" if first load).
3.  **Test Logic**:
    *   Change JSON: `{"mode": "ALL", "rules": [{"type": "risk_threshold", "value": 10}]}`
    *   Save.
    *   Transition a Low Risk issue (Risk=20).
    *   **Verify**: It BLOCKS (because 20 > 10).
    *   Change JSON to `value: 30`. Save.
    *   **Verify**: It ALLOWS.

### F. Immutable Override Ledger (Phase 11.2)
1.  **Block Issue**: Ensure an issue is blocked by policy (High Risk, no approval).
2.  **Request Override**:
    *   In ReleaseGate Panel, click "Request Override".
    *   Enter reason: "Emergency Fix".
    *   Submit. Status changes to "Override Requested".
3.  **Approve Override**:
    *   Click "Approve Override" (simulating an Admin action).
    *   *Note*: Approve Override is only visible to users matching the configured override approver role.
    *   Status changes to "OVERRIDDEN".
4.  **Verify Access**:
    *   Try transition.
    *   **Verify**: It ALLOWS (even if policy rules fail).
    *   **Verify Audit Log**: Should show decision "ALLOW" with reason "Active Override Applied".

### G. Audit Export (Phase 11.2)
1.  **Navigate**: Go to "ReleaseGate Policy" in Project Settings.
2.  **Export**: Click the **Download Audit Log (SOC2)** button at the top right.
3.  **Inspect**: Open the downloaded JSON file.
4.  **Verify Content**:
    *   `policies`: Should list all versioned policies.
    *   `decisions`: Should list all validator decisions (BLOCK/ALLOW) with hashes.
    *   `approvals`: Should list all approval records.
    *   `overrides`: Should list override requests/approvals.
    *   `exportedBy`: Should show your account ID.

### H. GitHub Integration (Phase 11.2)
*Note*: GitHub metadata in Phase 11.2 is simulated and intentionally shallow (no repo access, no code scanning).

1.  **View Panel**: Open an Issue.
2.  **Enable Dev Tools**: Click "Dev Tools" at the bottom of the panel.
3.  **Simulate**: Click "Simulate CI (High Risk)".
4.  **Verify**:
    *   **External Signals** section appears.
    *   Displays repo name `change-risk-predictor` and PR `#99`.
    *   Displays "HIGH RISK" badge.
    *   *Note*: Since your Issue Summary might not be "High", the Validator might still allow, but this confirms data ingestion works.
