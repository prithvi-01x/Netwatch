import React, { useCallback, useState, useMemo } from 'react'
import { format } from 'date-fns'
import { SeverityBadge } from '../shared/SeverityBadge'
import type { Alert, Severity, AttackPhase, LLMExplanation } from '../../types'

interface Props {
    alert: Alert
    style: React.CSSProperties
    acknowledged?: boolean
    onAcknowledge?: (id: string) => void
}

const SEVERITY_FILL: Record<Severity, string> = {
    CRITICAL: 'var(--severity-critical)',
    HIGH: 'var(--severity-high)',
    MEDIUM: 'var(--severity-medium)',
    LOW: 'var(--severity-low)',
}

const PHASE_COLORS: Record<AttackPhase, string> = {
    'reconnaissance': '#a371f7',
    'initial-access': '#ff8c00',
    'lateral-movement': '#ff2d2d',
    'exfiltration': '#ffd700',
    'c2': '#ff2d2d',
    'unknown': '#484f58',
}

const CONFIDENCE_COLORS: Record<string, string> = {
    HIGH: '#3fb950',
    MEDIUM: '#ffd700',
    LOW: '#8b949e',
    UNCERTAIN: '#484f58',
}

export const AlertCard: React.FC<Props> = React.memo(({ alert, style, acknowledged, onAcknowledge }) => {
    const [expanded, setExpanded] = useState(false)
    const [liveAnalysis, setLiveAnalysis] = useState<LLMExplanation | null>(null)
    const [analyzing, setAnalyzing] = useState(false)
    const [analyzeError, setAnalyzeError] = useState<string | null>(null)

    const time = useMemo(() => format(new Date(alert.timestamp * 1000), 'HH:mm:ss'), [alert.timestamp])
    const confPct = Math.round(alert.confidence * 100)
    const evidenceEntries = useMemo(() => Object.entries(alert.evidence), [alert.evidence])

    // Use live analysis if available, otherwise fall back to alert's stored analysis
    const llm = liveAnalysis ?? alert.llm_explanation
    const isStale = !liveAnalysis && (alert.llm_explanation?.fallback_used || !alert.llm_explanation)

    const fetchLiveAnalysis = useCallback(async () => {
        if (liveAnalysis || analyzing) return // already fetched or in progress
        setAnalyzing(true)
        setAnalyzeError(null)
        try {
            const res = await fetch(`/api/llm/explain/${alert.alert_id}`, { method: 'POST' })
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            const data = await res.json()
            setLiveAnalysis(data)
        } catch (err: any) {
            setAnalyzeError(err?.message ?? 'Failed to reach Ollama')
        } finally {
            setAnalyzing(false)
        }
    }, [alert.alert_id, liveAnalysis, analyzing])

    const toggle = useCallback(() => {
        const opening = !expanded
        setExpanded(opening)
        // Auto-trigger real-time analysis when expanding if analysis is static/missing
        if (opening && isStale) {
            fetchLiveAnalysis()
        }
    }, [expanded, isStale, fetchLiveAnalysis])

    return (
        <div style={style}>
            <div
                className={`alert-card ${acknowledged ? 'alert-card--acknowledged' : ''}`}
                data-severity={alert.severity}
                onClick={toggle}
            >
                <SeverityBadge severity={alert.severity} size="sm" />
                <span className="alert-card__time">{time}</span>
                <span className="alert-card__rule">{alert.rule_name}</span>
                <span className="alert-card__ips">
                    {alert.src_ip} <span className="arrow">→</span> {alert.dst_ip}
                </span>
                <span className="alert-card__confidence">
                    <span className="alert-card__confidence-bar">
                        <span
                            className="alert-card__confidence-fill"
                            style={{ width: `${confPct}%`, background: SEVERITY_FILL[alert.severity] }}
                        />
                    </span>
                    <span className="alert-card__confidence-text">{confPct}%</span>
                </span>

                {/* AI status dot */}
                <span
                    className="alert-card__ai-dot"
                    title={
                        analyzing ? 'Analyzing with Ollama...'
                            : liveAnalysis ? 'Live AI analysis'
                                : llm && !llm.fallback_used ? 'AI enriched'
                                    : 'Static fallback — click to get live analysis'
                    }
                    style={{
                        color: analyzing ? 'var(--severity-medium)'
                            : liveAnalysis ? 'var(--live-green)'
                                : llm && !llm.fallback_used ? 'var(--live-green)'
                                    : 'var(--text-muted)'
                    }}
                >
                    {analyzing ? '◌' : liveAnalysis ? '✦' : llm && !llm.fallback_used ? '✦' : '◦'}
                </span>

                {onAcknowledge && (
                    <span
                        className={`alert-card__ack ${acknowledged ? 'alert-card__ack--done' : ''}`}
                        title={acknowledged ? 'Acknowledged' : 'Acknowledge'}
                        onClick={e => { e.stopPropagation(); onAcknowledge(alert.alert_id) }}
                    >
                        {acknowledged ? '✓' : '○'}
                    </span>
                )}
                <span className={`alert-card__expand ${expanded ? 'alert-card__expand--open' : ''}`}>
                    ▶
                </span>
            </div>

            {expanded && (
                <div className="alert-card__detail">
                    <p className="alert-card__detail-desc">{alert.description}</p>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.73rem' }}>
                        Window: {alert.window_size_seconds}s &nbsp;·&nbsp; ID: {alert.alert_id.slice(0, 8)}
                    </p>

                    {/* Evidence */}
                    {evidenceEntries.length > 0 && (
                        <dl className="alert-card__evidence">
                            {evidenceEntries.map(([k, v]) => (
                                <React.Fragment key={k}>
                                    <dt>{k}</dt>
                                    <dd>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</dd>
                                </React.Fragment>
                            ))}
                        </dl>
                    )}

                    {/* Live AI Analysis block */}
                    {analyzing && (
                        <div className="alert-card__llm alert-card__llm--loading">
                            <span className="alert-card__llm-spinner" />
                            <div>
                                <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', fontWeight: 600 }}>
                                    ◌ Analyzing with Ollama...
                                </span>
                                <p style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginTop: 4 }}>
                                    Running real-time analysis on this specific alert
                                </p>
                            </div>
                        </div>
                    )}

                    {!analyzing && analyzeError && (
                        <div className="alert-card__llm alert-card__llm--error">
                            <span style={{ color: 'var(--severity-high)', fontSize: '0.78rem' }}>
                                ⚠ Could not reach Ollama: {analyzeError}
                            </span>
                            <button
                                className="alert-card__llm-retry"
                                onClick={e => { e.stopPropagation(); fetchLiveAnalysis() }}
                            >
                                Retry
                            </button>
                        </div>
                    )}

                    {!analyzing && !analyzeError && llm && (
                        <div className="alert-card__llm">
                            <div className="alert-card__llm-header">
                                <span className="alert-card__llm-title">
                                    {liveAnalysis ? '✦ Live AI Analysis' : llm.fallback_used ? '◦ AI Analysis (static)' : '✦ AI Analysis'}
                                </span>
                                <span
                                    className="alert-card__llm-phase"
                                    style={{
                                        background: PHASE_COLORS[llm.attack_phase] + '22',
                                        color: PHASE_COLORS[llm.attack_phase],
                                        borderColor: PHASE_COLORS[llm.attack_phase] + '44'
                                    }}
                                >
                                    {llm.attack_phase}
                                </span>
                                <span
                                    className="alert-card__llm-conf"
                                    style={{ color: CONFIDENCE_COLORS[llm.llm_confidence] }}
                                >
                                    {llm.llm_confidence}
                                </span>
                                {llm.fallback_used && !liveAnalysis && (
                                    <span className="alert-card__llm-fallback-badge">static</span>
                                )}
                                {liveAnalysis && (
                                    <span className="alert-card__llm-live-badge">live</span>
                                )}
                                {/* Manual refresh button */}
                                <button
                                    className="alert-card__llm-refresh"
                                    title="Re-analyze with Ollama"
                                    onClick={e => {
                                        e.stopPropagation()
                                        setLiveAnalysis(null)
                                        setTimeout(() => fetchLiveAnalysis(), 0)
                                    }}
                                >
                                    ↺
                                </button>
                            </div>

                            <p className="alert-card__llm-summary">{llm.summary}</p>

                            <div className="alert-card__llm-section">
                                <span className="alert-card__llm-label">Severity reasoning</span>
                                <p className="alert-card__llm-text">{llm.severity_reasoning}</p>
                            </div>

                            <div className="alert-card__llm-section">
                                <span className="alert-card__llm-label">Recommended action</span>
                                <p className="alert-card__llm-text alert-card__llm-action">{llm.recommended_action}</p>
                            </div>

                            {llm.ioc_tags.length > 0 && (
                                <div className="alert-card__llm-tags">
                                    {llm.ioc_tags.map(tag => (
                                        <span key={tag} className="alert-card__llm-tag">{tag}</span>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {!analyzing && !analyzeError && !llm && (
                        <div className="alert-card__llm alert-card__llm--pending">
                            <span className="alert-card__llm-spinner" />
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                                Awaiting AI analysis…
                            </span>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
})