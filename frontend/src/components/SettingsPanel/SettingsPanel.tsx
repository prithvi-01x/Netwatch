import React, { useState, useEffect, useCallback } from 'react'
import './SettingsPanel.css'

interface Config {
    confidence_threshold: number
    port_scan_min_ports: number
    syn_flood_min_packets: number
    brute_force_min_attempts: number
    flow_expiry_seconds: number
}

interface OllamaModel {
    name: string
    size: number
    modified_at: string
}

interface Props {
    currentModel: string
    onModelChange: (model: string) => void
    soundEnabled: boolean
    onSoundToggle: () => void
    notificationsEnabled: boolean
    onNotificationsToggle: () => void
    theme: 'dark' | 'light'
    onThemeToggle: () => void
}

export const SettingsPanel: React.FC<Props> = ({
    currentModel, onModelChange,
    soundEnabled, onSoundToggle,
    notificationsEnabled, onNotificationsToggle,
    theme, onThemeToggle,
}) => {
    const [config, setConfig] = useState<Config | null>(null)
    const [draft, setDraft] = useState<Config | null>(null)
    const [saving, setSaving] = useState(false)
    const [saveMsg, setSaveMsg] = useState<string | null>(null)
    const [ollamaModels, setOllamaModels] = useState<OllamaModel[]>([])
    const [loadingModels, setLoadingModels] = useState(false)
    const [whitelist, setWhitelist] = useState<string[]>([])
    const [newWlIp, setNewWlIp] = useState('')

    // Load config from backend
    useEffect(() => {
        fetch('/api/config')
            .then(r => r.json())
            .then(data => { setConfig(data); setDraft(data) })
            .catch(() => { })
    }, [])

    // Load Ollama models
    useEffect(() => {
        setLoadingModels(true)
        fetch('http://localhost:11434/api/tags')
            .then(r => r.json())
            .then(data => setOllamaModels(data.models ?? []))
            .catch(() => { })
            .finally(() => setLoadingModels(false))
    }, [])

    // Load whitelist from localStorage
    useEffect(() => {
        const stored = localStorage.getItem('netwatch_whitelist')
        if (stored) setWhitelist(JSON.parse(stored))
    }, [])

    const saveWhitelist = (list: string[]) => {
        setWhitelist(list)
        localStorage.setItem('netwatch_whitelist', JSON.stringify(list))
    }

    const handleSaveConfig = useCallback(async () => {
        if (!draft) return
        setSaving(true)
        try {
            const res = await fetch('/api/config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(draft),
            })
            const updated = await res.json()
            setConfig(updated)
            setDraft(updated)
            setSaveMsg('✓ Saved — takes effect on next detection window')
            setTimeout(() => setSaveMsg(null), 3000)
        } catch {
            setSaveMsg('✗ Failed to save')
            setTimeout(() => setSaveMsg(null), 3000)
        } finally {
            setSaving(false)
        }
    }, [draft])

    const formatBytes = (b: number) => {
        if (b > 1e9) return `${(b / 1e9).toFixed(1)} GB`
        if (b > 1e6) return `${(b / 1e6).toFixed(0)} MB`
        return `${b} B`
    }

    return (
        <div className="settings">
            <div className="settings__title">⚙ Settings</div>

            {/* ── Detection Thresholds ── */}
            <div className="settings__section">
                <div className="settings__section-title">Detection Thresholds</div>
                <div className="settings__description">Changes take effect on the next aggregation window</div>
                {draft && (
                    <div className="settings__grid">
                        <div className="settings__field">
                            <label className="settings__label">
                                Confidence Threshold
                                <span className="settings__hint">Alerts below this are suppressed</span>
                            </label>
                            <div className="settings__slider-wrap">
                                <input
                                    type="range" min="0" max="1" step="0.05"
                                    value={draft.confidence_threshold}
                                    onChange={e => setDraft({ ...draft, confidence_threshold: parseFloat(e.target.value) })}
                                    className="settings__slider"
                                />
                                <span className="settings__slider-val mono">{draft.confidence_threshold.toFixed(2)}</span>
                            </div>
                        </div>

                        <div className="settings__field">
                            <label className="settings__label">
                                Port Scan Min Ports
                                <span className="settings__hint">Minimum distinct ports to trigger port scan alert</span>
                            </label>
                            <input
                                type="number" min="5" max="1000"
                                value={draft.port_scan_min_ports}
                                onChange={e => setDraft({ ...draft, port_scan_min_ports: parseInt(e.target.value) })}
                                className="settings__input"
                            />
                        </div>

                        <div className="settings__field">
                            <label className="settings__label">
                                SYN Flood Min Packets
                                <span className="settings__hint">Packets per window to trigger SYN flood</span>
                            </label>
                            <input
                                type="number" min="10" max="10000"
                                value={draft.syn_flood_min_packets}
                                onChange={e => setDraft({ ...draft, syn_flood_min_packets: parseInt(e.target.value) })}
                                className="settings__input"
                            />
                        </div>

                        <div className="settings__field">
                            <label className="settings__label">
                                Brute Force Min Attempts
                                <span className="settings__hint">Attempts per window to trigger brute force</span>
                            </label>
                            <input
                                type="number" min="5" max="5000"
                                value={draft.brute_force_min_attempts}
                                onChange={e => setDraft({ ...draft, brute_force_min_attempts: parseInt(e.target.value) })}
                                className="settings__input"
                            />
                        </div>

                        <div className="settings__field">
                            <label className="settings__label">
                                Flow Expiry Seconds
                                <span className="settings__hint">How long an inactive flow is kept alive</span>
                            </label>
                            <input
                                type="number" min="10" max="600"
                                value={draft.flow_expiry_seconds}
                                onChange={e => setDraft({ ...draft, flow_expiry_seconds: parseInt(e.target.value) })}
                                className="settings__input"
                            />
                        </div>
                    </div>
                )}

                <div className="settings__save-row">
                    <button
                        className="settings__save-btn"
                        onClick={handleSaveConfig}
                        disabled={saving || !draft}
                    >
                        {saving ? 'Saving...' : 'Save Thresholds'}
                    </button>
                    {saveMsg && (
                        <span className={`settings__save-msg ${saveMsg.startsWith('✓') ? 'settings__save-msg--ok' : 'settings__save-msg--err'}`}>
                            {saveMsg}
                        </span>
                    )}
                </div>
            </div>

            {/* ── AI Model ── */}
            <div className="settings__section">
                <div className="settings__section-title">AI Model (Ollama)</div>
                <div className="settings__description">Switch the model used in the Ask AI tab</div>
                <div className="settings__field">
                    <label className="settings__label">Active Model</label>
                    {loadingModels ? (
                        <span className="settings__loading">Loading models from Ollama...</span>
                    ) : ollamaModels.length > 0 ? (
                        <select
                            className="settings__select"
                            value={currentModel}
                            onChange={e => onModelChange(e.target.value)}
                        >
                            {ollamaModels.map(m => (
                                <option key={m.name} value={m.name}>
                                    {m.name} ({formatBytes(m.size)})
                                </option>
                            ))}
                        </select>
                    ) : (
                        <div className="settings__no-models">
                            <span>No models found — make sure Ollama is running</span>
                            <code className="settings__code">ollama serve</code>
                        </div>
                    )}
                </div>
            </div>

            {/* ── Notifications & Sound ── */}
            <div className="settings__section">
                <div className="settings__section-title">Alerts & Notifications</div>
                <div className="settings__toggles">
                    <div className="settings__toggle-row">
                        <div className="settings__toggle-info">
                            <span className="settings__toggle-label">Browser Notifications</span>
                            <span className="settings__toggle-desc">Desktop popup on new CRITICAL alert</span>
                        </div>
                        <button
                            className={`settings__toggle ${notificationsEnabled ? 'settings__toggle--on' : ''}`}
                            onClick={onNotificationsToggle}
                        >
                            <span className="settings__toggle-knob" />
                        </button>
                    </div>

                    <div className="settings__toggle-row">
                        <div className="settings__toggle-info">
                            <span className="settings__toggle-label">Sound Alerts</span>
                            <span className="settings__toggle-desc">Beep on new CRITICAL alert</span>
                        </div>
                        <button
                            className={`settings__toggle ${soundEnabled ? 'settings__toggle--on' : ''}`}
                            onClick={onSoundToggle}
                        >
                            <span className="settings__toggle-knob" />
                        </button>
                    </div>

                    <div className="settings__toggle-row">
                        <div className="settings__toggle-info">
                            <span className="settings__toggle-label">Light Theme</span>
                            <span className="settings__toggle-desc">Switch between dark and light mode</span>
                        </div>
                        <button
                            className={`settings__toggle ${theme === 'light' ? 'settings__toggle--on' : ''}`}
                            onClick={onThemeToggle}
                        >
                            <span className="settings__toggle-knob" />
                        </button>
                    </div>
                </div>
            </div>

            {/* ── Whitelist ── */}
            <div className="settings__section">
                <div className="settings__section-title">IP Whitelist</div>
                <div className="settings__description">IPs that will never trigger alerts (stored locally)</div>
                <div className="settings__whitelist">
                    {whitelist.length === 0 && (
                        <div className="settings__empty">No whitelisted IPs</div>
                    )}
                    {whitelist.map(ip => (
                        <div key={ip} className="settings__wl-item">
                            <span className="settings__wl-ip mono">{ip}</span>
                            <button
                                className="settings__wl-remove"
                                onClick={() => saveWhitelist(whitelist.filter(w => w !== ip))}
                            >✕</button>
                        </div>
                    ))}
                    <div className="settings__wl-add">
                        <input
                            type="text"
                            className="settings__input"
                            placeholder="Add IP to whitelist..."
                            value={newWlIp}
                            onChange={e => setNewWlIp(e.target.value)}
                            onKeyDown={e => {
                                if (e.key === 'Enter' && newWlIp.trim()) {
                                    saveWhitelist([...whitelist, newWlIp.trim()])
                                    setNewWlIp('')
                                }
                            }}
                        />
                        <button
                            className="settings__save-btn"
                            onClick={() => {
                                if (newWlIp.trim()) {
                                    saveWhitelist([...whitelist, newWlIp.trim()])
                                    setNewWlIp('')
                                }
                            }}
                        >Add</button>
                    </div>
                </div>
            </div>
        </div>
    )
}