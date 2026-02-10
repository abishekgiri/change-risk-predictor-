import React, { useEffect, useState } from 'react';
import { invoke } from '@forge/bridge';

function App() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [saveStatus, setSaveStatus] = useState("");
    const [isSaving, setIsSaving] = useState(false);
    const [isExporting, setIsExporting] = useState(false);
    const [jsonInput, setJsonInput] = useState("");

    useEffect(() => {
        (async () => {
            try {
                const result = await invoke('getPolicy');
                setData(result);
                if (result.policy) {
                    setJsonInput(JSON.stringify(result.policy.rules, null, 2));
                } else {
                    setJsonInput(JSON.stringify({
                        mode: "ALL",
                        rules: [
                            { type: "risk_threshold", value: 70 },
                            { type: "requires_approval", requiredRole: "Release Manager" }
                        ]
                    }, null, 2));
                }
            } catch (err) {
                console.error("Failed to load policy", err);
            } finally {
                setLoading(false);
            }
        })();
    }, []);

    const handleSave = async () => {
        console.log("Saving Policy...", jsonInput); // Debug Log
        setIsSaving(true);
        setSaveStatus("");
        try {
            const parsedRules = JSON.parse(jsonInput);
            const payload = {
                rules: parsedRules,
                enabled: data?.policy?.enabled !== false
            };
            const newPolicy = await invoke('savePolicy', payload);
            setData(prev => ({ ...prev, policy: newPolicy }));
            setSaveStatus("✅ Policy Saved! (v" + newPolicy.versionId.substring(0, 8) + ")");
            setTimeout(() => setSaveStatus(""), 3000);
        } catch (err) {
            console.error("Save Error", err);
            setSaveStatus("❌ Error: Invalid JSON or Save Failed");
        } finally {
            setIsSaving(false);
        }
    };

    const handleExport = async () => {
        setIsExporting(true);
        try {
            const exportData = await invoke('exportAuditData');

            // Trigger Download
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `release-gate-audit-${new Date().toISOString()}.json`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);

        } catch (err) {
            console.error("Export Failed", err);
            alert("Failed to export audit logs. See console.");
        } finally {
            setIsExporting(false);
        }
    };

    if (loading) return <div>Loading...</div>;

    return (
        <div style={{ padding: '20px', fontFamily: 'sans-serif' }}>
            <h1>ReleaseGate Policy Config (V2)</h1>

            {data?.policy && (
                <div style={{ marginBottom: '15px', padding: '10px', background: '#f4f5f7', borderRadius: '4px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                        <strong>Active Version:</strong> {data.policy.versionId || "Legacy"}
                        <br />
                        <strong>Status:</strong> {data.policy.enabled ? "Active" : "Disabled"}
                    </div>
                    <button
                        onClick={handleExport}
                        disabled={true} // Disabled to prevent sandbox error (Phase 11.2)
                        style={{ background: '#888', color: 'white', border: 'none', padding: '8px 12px', borderRadius: '3px', cursor: 'not-allowed' }}
                    >
                        Export (Coming Soon)
                    </button>
                </div>
            )}

            <h3>Policy Rules (JSON)</h3>
            <p style={{ fontSize: '0.9em', color: '#666' }}>
                Define rules for risk calculation and gates.
            </p>

            <textarea
                value={jsonInput}
                onChange={(e) => setJsonInput(e.target.value)}
                rows={15}
                style={{ width: '100%', fontFamily: 'monospace', padding: '10px' }}
            />

            <div style={{ marginTop: '10px' }}>
                <button
                    onClick={handleSave}
                    disabled={isSaving}
                    style={{ padding: '10px 20px', background: '#0052cc', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                >
                    {isSaving ? "Saving..." : "Save New Version"}
                </button>

                {saveStatus && <span style={{ marginLeft: '10px', fontWeight: 'bold' }}>{saveStatus}</span>}
            </div>

        </div>
    );
}

export default App;
