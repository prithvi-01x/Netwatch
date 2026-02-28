/**
 * NodeInfoPanel.tsx
 *
 * Slide-in panel shown when a graph node is clicked.
 * Shows IP details, alert breakdown, active rules, and a filter shortcut.
 */

import React from 'react'
import type { GraphNode, GraphEdge, Severity } from '../../types'

const SEV_COLOR: Record<Severity, string> = {
    CRITICAL: '#ff2d2d',
    HIGH:     '#ff8c00',
    MEDIUM:   '#ffd700',
    LOW:      '#4a9eff',
}

interface Props {
    node: GraphNode
    edges: GraphEdge[]
    onClose: () => void
    onFilterAlerts?: (ip: string) => void
}

function resolveId(n: GraphNode | string): string {
    return typeof n === 'string' ? n : n.id
}

const NodeInfoPanel: React.FC<Props> = ({ node, edges, onClose, onFilterAlerts }) => {
    // Edges involving this node
    const outgoing = edges.filter(e => resolveId(e.source as GraphNode) === node.id)
    const incoming = edges.filter(e => resolveId(e.target as GraphNode) === node.id)

    const ruleBreakdown: Record<string, number> = {}
    ;[...outgoing, ...incoming].forEach(e => {
        ruleBreakdown[e.rule_name] = (ruleBreakdown[e.rule_name] ?? 0) + e.count
    })

    const sevBreakdown: Record<string, number> = {}
    ;[...outgoing, ...incoming].forEach(e => {
        sevBreakdown[e.severity] = (sevBreakdown[e.severity] ?? 0) + e.count
    })

    const ago = (ts: number) => {
        const s = Math.round(Date.now() / 1000 - ts)
        if (s < 60)   return `${s}s ago`
        if (s < 3600) return `${Math.round(s/60)}m ago`
        return `${Math.round(s/3600)}h ago`
    }

    return (
        <div style={{
            position: 'absolute',
            top: 0, right: 0,
            width: 280,
            height: '100%',
            background: '#0f1420',
            borderLeft: '1px solid #1e2d40',
            display: 'flex',
            flexDirection: 'column',
            zIndex: 10,
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.75rem',
            color: '#c8d8e8',
            overflowY: 'auto',
        }}>
            {/* Header */}
            <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '12px 16px',
                borderBottom: '1px solid #1e2d40',
                background: '#0a0e14',
            }}>
                <div>
                    <div style={{ fontWeight: 700, fontSize: '0.8rem', color: SEV_COLOR[node.max_severity as Severity] }}>
                        {node.id}
                    </div>
                    <div style={{ color: '#4a6070', fontSize: '0.65rem', marginTop: 2 }}>
                        {node.type.toUpperCase()} · {node.alert_count} alert{node.alert_count !== 1 ? 's' : ''}
                    </div>
                </div>
                <button onClick={onClose} style={{
                    background: 'none', border: 'none', color: '#4a6070',
                    cursor: 'pointer', fontSize: '1rem', lineHeight: 1,
                }}>✕</button>
            </div>

            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* Status row */}
                <div style={{ display: 'flex', gap: 12 }}>
                    <div style={{
                        flex: 1, background: '#1a2030', borderRadius: 6, padding: '8px 12px',
                        border: `1px solid ${SEV_COLOR[node.max_severity as Severity]}33`,
                    }}>
                        <div style={{ color: '#4a6070', fontSize: '0.6rem', marginBottom: 4 }}>MAX SEVERITY</div>
                        <div style={{ color: SEV_COLOR[node.max_severity as Severity], fontWeight: 700 }}>
                            {node.max_severity}
                        </div>
                    </div>
                    <div style={{
                        flex: 1, background: '#1a2030', borderRadius: 6, padding: '8px 12px',
                        border: '1px solid #1e2d40',
                    }}>
                        <div style={{ color: '#4a6070', fontSize: '0.6rem', marginBottom: 4 }}>LAST SEEN</div>
                        <div style={{ color: '#c8d8e8' }}>{ago(node.last_seen)}</div>
                    </div>
                </div>

                {/* Rules breakdown */}
                {Object.keys(ruleBreakdown).length > 0 && (
                    <div>
                        <div style={{ color: '#4a6070', fontSize: '0.6rem', letterSpacing: '0.1em', marginBottom: 8 }}>
                            DETECTION RULES
                        </div>
                        {Object.entries(ruleBreakdown).sort((a, b) => b[1] - a[1]).map(([rule, count]) => (
                            <div key={rule} style={{
                                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                padding: '4px 0', borderBottom: '1px solid #1e2d40',
                            }}>
                                <span style={{ color: '#8b949e', fontFamily: 'monospace' }}>{rule}</span>
                                <span style={{
                                    background: '#1e2d40', borderRadius: 4,
                                    padding: '1px 6px', color: '#4a9eff', fontSize: '0.7rem',
                                }}>{count}</span>
                            </div>
                        ))}
                    </div>
                )}

                {/* Severity breakdown */}
                {Object.keys(sevBreakdown).length > 0 && (
                    <div>
                        <div style={{ color: '#4a6070', fontSize: '0.6rem', letterSpacing: '0.1em', marginBottom: 8 }}>
                            SEVERITY BREAKDOWN
                        </div>
                        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[])
                            .filter(s => sevBreakdown[s])
                            .map(sev => (
                            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                <div style={{
                                    width: 8, height: 8, borderRadius: '50%',
                                    background: SEV_COLOR[sev], flexShrink: 0,
                                }} />
                                <div style={{ flex: 1, fontSize: '0.7rem', color: '#8b949e' }}>{sev}</div>
                                <div style={{
                                    height: 6, borderRadius: 3,
                                    background: SEV_COLOR[sev] + '55',
                                    border: `1px solid ${SEV_COLOR[sev]}88`,
                                    width: Math.max(20, (sevBreakdown[sev] / node.alert_count) * 100),
                                }} />
                                <div style={{ color: SEV_COLOR[sev], minWidth: 24, textAlign: 'right' }}>
                                    {sevBreakdown[sev]}
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Connections */}
                {(outgoing.length > 0 || incoming.length > 0) && (
                    <div>
                        <div style={{ color: '#4a6070', fontSize: '0.6rem', letterSpacing: '0.1em', marginBottom: 8 }}>
                            CONNECTIONS
                        </div>
                        {outgoing.slice(0, 5).map((e, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, fontSize: '0.7rem' }}>
                                <span style={{ color: '#ff2d2d' }}>→</span>
                                <span style={{ color: '#8b949e' }}>{resolveId(e.target as GraphNode)}</span>
                                <span style={{ marginLeft: 'auto', color: SEV_COLOR[e.severity as Severity] }}>{e.severity}</span>
                            </div>
                        ))}
                        {incoming.slice(0, 3).map((e, i) => (
                            <div key={`in-${i}`} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, fontSize: '0.7rem' }}>
                                <span style={{ color: '#4a9eff' }}>←</span>
                                <span style={{ color: '#8b949e' }}>{resolveId(e.source as GraphNode)}</span>
                                <span style={{ marginLeft: 'auto', color: '#4a6070' }}>victim</span>
                            </div>
                        ))}
                    </div>
                )}

                {/* Filter shortcut */}
                {onFilterAlerts && node.type === 'attacker' && (
                    <button
                        onClick={() => onFilterAlerts(node.id)}
                        style={{
                            background: 'none',
                            border: '1px solid #4a9eff',
                            borderRadius: 6,
                            color: '#4a9eff',
                            padding: '8px 12px',
                            cursor: 'pointer',
                            fontFamily: 'monospace',
                            fontSize: '0.72rem',
                            width: '100%',
                            textAlign: 'center',
                        }}
                    >
                        Filter alerts → {node.id}
                    </button>
                )}
            </div>
        </div>
    )
}

export default NodeInfoPanel
