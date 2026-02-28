import React, { useCallback, useState, useMemo } from 'react'
import { format } from 'date-fns'
import { SeverityBadge } from '../shared/SeverityBadge'
import type { Alert, Severity, AttackPhase } from '../../types'

interface Props {
    alert: Alert
    style: React.CSSProperties
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

export const AlertCard: React.FC<Props> = React.memo(({ alert, style }) => {
    const [expanded, setExpanded] = useState(false)
    const toggle = useCallback(() => setExpanded((e) => !e), [])

    const time = useMemo(() => format(new Date(alert.timestamp * 1000), 'HH:mm:ss'), [alert.timestamp])
    const confPct = Math.round(alert.confidence * 100)
    const evidenceEntries = useMemo(() => Object.entries(alert.evidence), [alert.evidence])
    const llm = alert.llm_explanation

    return (
        <div style={style}>
            <div className="alert-card" data-severity={alert.severity} onClick={toggle}>
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
                            style={{
                                width: `${confPct}%`,
                                background: SEVERITY_FILL[alert.severity],
                            }}
                        />
                    </span>
                    <span className="alert-card__confidence-text">{confPct}%</span>
                </span>
                {/* AI enrichment indicator */}
                <span
                    className="alert-card__ai-dot"
                    title={llm ? (llm.fallback_used ? 'Static fallback (Ollama unavailable)' : 'AI enriched') : 'Awaiting AI analysis'}
                    style={{ color: llm ? (llm.fallback_used ? 'var(--text-muted)' : 'var(--live-green)') : 'var(--text-muted)' }}
                >
                    {llm && !llm.fallback_used ? '✦' : '◦'}
                </span>
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

                    {/* LLM Explanation block */}
                    {llm ? (
                        <div className="alert-card__llm">
                            <div className="alert-card__llm-header">
                                <span className="alert-card__llm-title">
                                    {llm.fallback_used ? '◦ AI Analysis (static)' : '✦ AI Analysis'}
                                </span>
                                <span
                                    className="alert-card__llm-phase"
                                    style={{ background: PHASE_COLORS[llm.attack_phase] + '22', color: PHASE_COLORS[llm.attack_phase], borderColor: PHASE_COLORS[llm.attack_phase] + '44' }}
                                >
                                    {llm.attack_phase}
                                </span>
                                <span
                                    className="alert-card__llm-conf"
                                    style={{ color: CONFIDENCE_COLORS[llm.llm_confidence] }}
                                >
                                    {llm.llm_confidence}
                                </span>
                                {llm.fallback_used && (
                                    <span className="alert-card__llm-fallback-badge">fallback</span>
                                )}
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
                    ) : (
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