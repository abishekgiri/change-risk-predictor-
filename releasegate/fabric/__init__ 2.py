"""ReleaseGate Fabric — Phase 8 Cross-System Governance.

The fabric module owns the ChangeRecord: a lifecycle object that ties together
every system a change touches (Jira → PR → Deploy → Incident → Hotfix).

Unlike the event-level cross_system_correlations table, a ChangeRecord has
explicit lifecycle state and enforces that every required link is present
before a transition is allowed.
"""
