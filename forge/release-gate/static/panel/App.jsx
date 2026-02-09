import React, { useEffect, useState } from 'react';
import { invoke } from '@forge/bridge';

function App() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [processing, setProcessing] = useState(false);
    const [error, setError] = useState(null);
    const [overrideReason, setOverrideReason] = useState("");
    const [showOverrideInput, setShowOverrideInput] = useState(false);

    // Dev: Simulation
    const [showDev, setShowDev] = useState(false);

    const fetchData = async () => {
        try {
            const result = await invoke('getIssuePanelData');
            console.log("Panel Data:", result);
            setData(result);
        } catch (err) {
            console.error("Fetch failed", err);
            setError("Failed to load data");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, []);

    const handleApprove = async () => {
        setProcessing(true);
        try {
            await invoke('approveIssue', { comment: "Approved from Issue Panel" });
            await fetchData();
        } catch (err) {
            setError("Failed to approve issue");
        } finally { setProcessing(false); }
    };

    const handleRequestOverride = async () => {
        if (!overrideReason) return;
        setProcessing(true);
        try {
            await invoke('requestOverride', { reason: overrideReason });
            await fetchData();
            setShowOverrideInput(false);
        } catch (err) { setError("Failed to request override"); } finally { setProcessing(false); }
    };

    const handleApproveOverride = async () => {
        setProcessing(true);
        try {
            await invoke('approveOverride', {});
            await fetchData();
        } catch (err) { setError("Failed to approve override"); } finally { setProcessing(false); }
    };

    // Simulation Helper for Step 6 Verify
    const handleSimulateCI = async () => {
        setProcessing(true);
        try {
            await invoke('setExternalMetadata', {
                issueKey: 'ignored_by_context', // Context issue used in backend actually? No, payload issueKey in resolved needed if independent, but let's check backend... I used payload issueKey. Wait, in panel I am in context. I should use context key. 
                // Actually resolver uses payload for key?
                // "const { issueKey, data } = req.payload;" -> YES.
                // But I don't know my own issueKey easily here unless data provided it? 
                // Ah, getIssuePanelData returns approvals/policy but not explicit issueKey string?
                // Standard Forge practice: use context. But setExternalMetadata intended for external caller.
                // For this simulation, let's fix backend to ALLOW context key fallback OR just pass a dummy value if I can't get it.
                // Actually, I can get context from bridge if needed, but let's assume I know it or backend handles it.
                // ... looking at my backend code: "const { issueKey, data } = req.payload;".
                // So I MUST provide issueKey in payload.
                // I don't have it in `data` state? I should add it to getIssuePanelData return.
                // For now, I'll update getIssuePanelData to return issueKey or just use a hardcoded Test Key? No that's bad.
                // I will fix getIssuePanelData to return issueKey in next step or use a workaround? 
                // Wait, I can use `view.getContext` in frontend? Yes.
                // For now, I'll pass a dummy "TEST-1" or try to find it. 
                // Actually, let's just update `getIssuePanelData` to return `issueKey` as well in the next step or assume I can get it.
                // Let's add issueKey to the returned data from backend for convenience.
                data: { repo: "change-risk-predictor", pr: 42, risk: "HIGH" }
            });
            // Note: The above call will fail if issueKey is missing. 
            // I will patch backend to inject issueKey into the response or derive it from context if missing in payload.
            // But wait, the backend `setExternalMetadata` DOES NOT use context.extension.issueKey, it expects payload. 
            // I will fix backend to support context fallback? No, setExternal meant for external. 
            // FOR SIMULATION: I probably need the key.
            // I'll add `issueKey` to `getIssuePanelData` response now.
            await fetchData();
        } catch (err) { setError("Failed to set metadata"); } finally { setProcessing(false); }
    };

    if (loading) return <div>Loading...</div>;
    if (error) return <div style={{ color: 'red' }}>Error: {error}</div>;
    if (!data) return <div>No data available</div>;

    const { policy, approvals, currentUser, override, metadata, issueKey } = data; // Added issueKey
    const isEnabled = policy.enabled;
    const requiredRole = policy.requiredRole;
    const myApproval = approvals.find(a => a.approverAccountId === currentUser);
    const overrideActive = override.active;
    const overrideStatus = override.status;

    // Manual fix for simulation call to work:
    // I need to make sure `issueKey` is available. 
    // If backend doesn't send it, I can't simulate easily. 
    // I'll update the simulation function to use the context if I can, OR just update backend to send it.

    return (
        <div style={{ padding: '10px' }}>
            {/* HEADER */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <div>
                    <strong>ReleaseGate: </strong>
                    {overrideActive
                        ? <span style={{ color: 'orange', fontWeight: 'bold' }}>⚠ OVERRIDDEN</span>
                        : (isEnabled ? <span style={{ color: 'green' }}>Active</span> : <span style={{ color: 'gray' }}>Disabled</span>)
                    }
                </div>
                <div style={{ fontSize: '12px', color: '#666' }}>
                    Required: <strong>{requiredRole || "None"}</strong>
                </div>
            </div>

            {/* EXTERNAL SIGNALS */}
            {metadata && (
                <div style={{ border: '1px solid #ddd', borderRadius: '4px', padding: '8px', marginBottom: '10px', background: '#fafafa' }}>
                    <strong style={{ fontSize: '11px', color: '#555', textTransform: 'uppercase' }}>External Signals (GitHub)</strong>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '5px' }}>
                        <div>
                            <a href="#" style={{ fontSize: '13px', fontWeight: 'bold', textDecoration: 'none', color: '#0052cc' }}>{metadata.repo} #{metadata.pr}</a>
                        </div>
                        <div>
                            {metadata.risk === 'HIGH' && <span style={{ background: '#ffebe6', color: '#de350b', padding: '2px 5px', borderRadius: '3px', fontWeight: 'bold', fontSize: '11px' }}>HIGH RISK</span>}
                            {metadata.risk === 'LOW' && <span style={{ background: '#e3fcef', color: '#006644', padding: '2px 5px', borderRadius: '3px', fontWeight: 'bold', fontSize: '11px' }}>LOW RISK</span>}
                        </div>
                    </div>
                </div>
            )}

            {/* OVERRIDE STATUS */}
            {overrideStatus === 'REQUESTED' && (
                <div style={{ background: '#fff7d6', padding: '8px', borderRadius: '4px', marginBottom: '10px', fontSize: '12px' }}>
                    ⚠ <strong>Override Requested</strong>
                    <br />
                    <button
                        onClick={handleApproveOverride}
                        disabled={processing}
                        style={{ marginTop: '5px', background: 'orange', border: 'none', color: 'black', padding: '3px 8px', borderRadius: '3px', cursor: 'pointer' }}
                    >
                        Approve Override
                    </button>
                </div>
            )}

            {/* APPROVAL LIST */}
            <div style={{ marginBottom: '15px' }}>
                <h6>Approvals ({approvals.length})</h6>
                {approvals.length === 0 ? (
                    <div style={{ fontStyle: 'italic', color: '#888' }}>No approvals yet.</div>
                ) : (
                    <ul style={{ paddingLeft: '20px', margin: '5px 0' }}>
                        {approvals.map((app, i) => (
                            <li key={i}>
                                <small>
                                    <strong>{app.approverAccountId === currentUser ? "You" : "User"}</strong>
                                    {' '} approved on {new Date(app.timestamp).toLocaleDateString()}
                                </small>
                            </li>
                        ))}
                    </ul>
                )}
            </div>

            {/* ACTIONS */}
            {isEnabled && !overrideActive && (
                <div style={{ display: 'flex', gap: '10px' }}>
                    {myApproval ? (
                        <button disabled style={{ background: '#e0e0e0', color: '#555', border: 'none', padding: '5px 10px', borderRadius: '3px' }}>
                            ✅ You Approved
                        </button>
                    ) : (
                        <button
                            onClick={handleApprove}
                            disabled={processing}
                            style={{
                                background: processing ? '#ccc' : '#0052cc',
                                color: 'white',
                                border: 'none',
                                padding: '6px 12px',
                                borderRadius: '3px',
                                cursor: 'pointer'
                            }}
                        >
                            {processing ? "..." : `Approve (${requiredRole})`}
                        </button>
                    )}

                    {!showOverrideInput && overrideStatus !== 'REQUESTED' && (
                        <button
                            onClick={() => setShowOverrideInput(true)}
                            style={{ background: 'none', border: '1px solid #ccc', color: '#555', padding: '6px 12px', borderRadius: '3px', cursor: 'pointer' }}
                        >
                            Request Override
                        </button>
                    )}
                </div>
            )}

            {/* OVERRIDE INPUT */}
            {showOverrideInput && (
                <div style={{ marginTop: '10px', padding: '10px', border: '1px solid #eee' }}>
                    <input
                        type="text"
                        placeholder="Why bypass?"
                        value={overrideReason}
                        onChange={e => setOverrideReason(e.target.value)}
                        style={{ width: '100%', margin: '5px 0', padding: '5px' }}
                    />
                    <div style={{ display: 'flex', gap: '5px' }}>
                        <button onClick={handleRequestOverride} disabled={!overrideReason || processing}>Submit</button>
                        <button onClick={() => setShowOverrideInput(false)}>Cancel</button>
                    </div>
                </div>
            )}

            {/* DEV TOOLS */}
            <div style={{ marginTop: '20px', borderTop: '1px solid #eee', paddingTop: '5px' }}>
                <small onClick={() => setShowDev(!showDev)} style={{ cursor: 'pointer', color: '#ccc' }}>Dev Tools {showDev ? '▼' : '▶'}</small>
                {showDev && (
                    <div style={{ marginTop: '5px' }}>
                        <button onClick={async () => {
                            // Hacky simulation: try to set metadata. 
                            // We need issueKey. Let's assume the user is on an issue and we can capture it somehow, 
                            // OR just patch backend as planned.
                            // I will PATCH BACKEND to return issueKey in getIssuePanelData.
                            if (data.issueKey) {
                                try {
                                    await invoke('setExternalMetadata', {
                                        issueKey: data.issueKey,
                                        data: { repo: "change-risk-predictor", pr: 99, risk: "HIGH" }
                                    });
                                    fetchData();
                                } catch (e) { alert(e); }
                            } else {
                                alert("Missing issueKey in data. Cannot simulate.");
                            }
                        }}>Simulate CI (High Risk)</button>
                    </div>
                )}
            </div>

        </div>
    );
}

export default App;
