import React, { useMemo, useState } from 'react'
import { format } from 'date-fns'
import type { Alert } from '../../types'
import './IncidentTimeline.css'

interface Props {
    alerts: Alert[]
}

interface Incident {
    id: string
    title: string
    startTime: number
    endTime: number
    alerts: Alert[]
    severity: string
    srcIps: string[]
    dstIps: string[]
    phase: string
    status: 'active' | 'resolved'
}

function groupIntoIncidents(alerts: Alert[]): Incident[] {
    if (!alerts.length) return []

    // Group alerts by dst_ip (attack target) within 10-minute windows
    const groups = new Map<string, Alert[]>()

    alerts.forEach(alert => {
        const key = alert.dst_ip
        if (!groups.has(key)) groups.set(key, [])
        groups.get(key)!.push(alert)
    })

    const incidents: Incident[] = []
    let idx = 0
    groups.forEach((grpAlerts, dstIp) => {
        if (grpAlerts.length < 1) return
        const sorted = [...grpAlerts].sort((a, b) => a.timestamp - b.timestamp)
        const hasCritical = sorted.some(a => a.severity === 'CRITICAL')
        const phases = [...new Set(sorted.map(a => a.llm_explanation?.attack_phase).filter(Boolean))]
        const srcIps = [...new Set(sorted.map(a => a.src_ip))]

        incidents.push({
            id: `INC-${String(++idx).padStart(4, '0')}`,
            title: hasCritical ? `C2 Beaconing Campaign → ${dstIp}` : `Suspicious Activity → ${dstIp}`,
            startTime: sorted[0].timestamp,
            endTime: sorted[sorted.length - 1].timestamp,
            alerts: sorted,
            severity: hasCritical ? 'CRITICAL' : 'HIGH',
            srcIps,
            dstIps: [dstIp],
            phase: phases[0] ?? 'unknown',
            status: Date.now() / 1000 - sorted[sorted.length - 1].timestamp < 300 ? 'active' : 'resolved',
        })
    })

    return incidents.sort((a, b) => b.startTime - a.startTime)
}

export const IncidentTimeline: React.FC<Props> = ({ alerts }) => {
    const [expandedId, setExpandedId] = useState<string | null>(null)

    const incidents = useMemo(() => groupIntoIncidents(alerts), [alerts])

    const toggleIncident = (id: string) => {
        setExpandedId(prev => prev === id ? null : id)
    }

    if (!incidents.length) {
        return (
            <div className="incident-timeline">
                <div className="incident-timeline__empty">
                    <span>🛡️</span>
                    <span>No incidents detected</span>
                </div>
            </div>
        )
    }

    return (
        <div className="incident-timeline">
            <div className="incident-timeline__header">
                <span className="incident-timeline__title">⚡ Incident Timeline</span>
                <span className="incident-timeline__count">{incidents.length} incident{incidents.length !== 1 ? 's' : ''}</span>
            </div>

            <div className="incident-timeline__list">
                {incidents.map(inc => {
                    const expanded = expandedId === inc.id
                    const duration = inc.endTime - inc.startTime
                    const durationStr = duration < 60
                        ? `${Math.round(duration)}s`
                        : `${Math.round(duration / 60)}m`

                    return (
                        <div
                            key={inc.id}
                            className={`incident-card incident-card--${inc.severity.toLowerCase()} ${expanded ? 'incident-card--expanded' : ''}`}
                        >
                            <div className="incident-card__header" onClick={() => toggleIncident(inc.id)}>
                                <div className="incident-card__left">
                                    <span className="incident-card__id mono">{inc.id}</span>
                                    <span className={`incident-card__sev incident-card__sev--${inc.severity.toLowerCase()}`}>
                                        {inc.severity}
                                    </span>
                                    {inc.status === 'active' && (
                                        <span className="incident-card__active">
                                            <span className="incident-card__pulse" />
                                            ACTIVE
                                        </span>
                                    )}
                                </div>

                                <div className="incident-card__center">
                                    <span className="incident-card__title">{inc.title}</span>
                                    <div className="incident-card__meta">
                                        <span>{format(new Date(inc.startTime * 1000), 'HH:mm:ss')}</span>
                                        <span className="incident-card__meta-sep">→</span>
                                        <span>{format(new Date(inc.endTime * 1000), 'HH:mm:ss')}</span>
                                        <span className="incident-card__meta-sep">·</span>
                                        <span>{durationStr}</span>
                                        <span className="incident-card__meta-sep">·</span>
                                        <span>{inc.alerts.length} alerts</span>
                                        <span className="incident-card__meta-sep">·</span>
                                        <span>{inc.srcIps.length} source IP{inc.srcIps.length !== 1 ? 's' : ''}</span>
                                    </div>
                                </div>

                                <div className="incident-card__right">
                                    <span className="incident-card__phase">{inc.phase}</span>
                                    <span className={`incident-card__chevron ${expanded ? 'incident-card__chevron--open' : ''}`}>▶</span>
                                </div>
                            </div>

                            {expanded && (
                                <div className="incident-card__detail">
                                    <div className="incident-card__ips">
                                        <div>
                                            <span className="incident-card__ip-label">Source IPs</span>
                                            <div className="incident-card__ip-list">
                                                {inc.srcIps.map(ip => (
                                                    <span key={ip} className="incident-card__ip-badge incident-card__ip-badge--src mono">{ip}</span>
                                                ))}
                                            </div>
                                        </div>
                                        <div>
                                            <span className="incident-card__ip-label">Target IPs</span>
                                            <div className="incident-card__ip-list">
                                                {inc.dstIps.map(ip => (
                                                    <span key={ip} className="incident-card__ip-badge incident-card__ip-badge--dst mono">{ip}</span>
                                                ))}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Mini timeline of individual alerts */}
                                    <div className="incident-card__timeline">
                                        {inc.alerts.slice(0, 8).map((alert) => (
                                            <div key={alert.alert_id} className="incident-card__event">
                                                <span className={`incident-card__event-dot incident-card__event-dot--${alert.severity.toLowerCase()}`} />
                                                <span className="incident-card__event-time mono">
                                                    {format(new Date(alert.timestamp * 1000), 'HH:mm:ss')}
                                                </span>
                                                <span className="incident-card__event-src mono">{alert.src_ip}</span>
                                                <span className="incident-card__event-desc">{alert.description.slice(0, 80)}</span>
                                            </div>
                                        ))}
                                        {inc.alerts.length > 8 && (
                                            <div className="incident-card__event-more">
                                                + {inc.alerts.length - 8} more alerts
                                            </div>
                                        )}
                                    </div>

                                    <div className="incident-card__actions">
                                        <button className="incident-card__action-btn">Acknowledge</button>
                                        <button className="incident-card__action-btn">Escalate</button>
                                        <button className="incident-card__action-btn incident-card__action-btn--danger">Block All Sources</button>
                                    </div>
                                </div>
                            )}
                        </div>
                    )
                })}
            </div>
        </div>
    )
}
