/**
 * AttackGraphView.tsx
 *
 * Top-level container for the Phase 7 attack graph.
 * Renders controls (time window, pause, reset), the D3 canvas,
 * legend, and the node info panel.
 */

import React, { useState, useCallback, useRef } from 'react'
import AttackGraph from './AttackGraph'
import NodeInfoPanel from './NodeInfoPanel'
import { useGraph, type TimeWindow } from '../../hooks/useGraph'
import type { GraphNode } from '../../types'
import './AttackGraphView.css'

interface Props {
    onFilterAlerts?: (ip: string) => void
}

const TIME_WINDOWS: { label: string; value: TimeWindow }[] = [
    { label: '15m',  value: '15m'  },
    { label: '1h',   value: '1h'   },
    { label: '6h',   value: '6h'   },
    { label: '24h',  value: '24h'  },
    { label: 'All',  value: 'all'  },
]

const AttackGraphView: React.FC<Props> = ({ onFilterAlerts }) => {
    const [timeWindow, setTimeWindow] = useState<TimeWindow>('1h')
    const [paused, setPaused] = useState(false)
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
    const [resetKey, setResetKey] = useState(0)

    const { data, isLoading, error, lastFetch, refresh } = useGraph(timeWindow)

    const handleNodeClick = useCallback((node: GraphNode | null) => {
        setSelectedNode(node)
    }, [])

    const handleReset = useCallback(() => {
        setResetKey(k => k + 1)
        setSelectedNode(null)
    }, [])

    const handleFilterAlerts = useCallback((ip: string) => {
        onFilterAlerts?.(ip)
    }, [onFilterAlerts])

    const ago = lastFetch > 0
        ? `${Math.round(Date.now() / 1000 - lastFetch)}s ago`
        : 'never'

    return (
        <div className="agv">
            {/* ── Toolbar ── */}
            <div className="agv__toolbar">
                <div className="agv__toolbar-left">
                    <span className="agv__title">ATTACK GRAPH</span>
                    <div className="agv__time-picker">
                        {TIME_WINDOWS.map(tw => (
                            <button
                                key={tw.value}
                                className={`agv__time-btn ${timeWindow === tw.value ? 'agv__time-btn--active' : ''}`}
                                onClick={() => setTimeWindow(tw.value)}
                            >
                                {tw.label}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="agv__toolbar-right">
                    <span className="agv__stat">
                        <span className="agv__stat-val">{data.nodes.length}</span> nodes
                    </span>
                    <span className="agv__stat">
                        <span className="agv__stat-val">{data.edges.length}</span> edges
                    </span>
                    {isLoading && <span className="agv__loading">syncing…</span>}
                    {!isLoading && <span className="agv__updated">updated {ago}</span>}

                    <button className="agv__btn" onClick={() => setPaused(p => !p)}>
                        {paused ? '▶ Resume' : '⏸ Pause'}
                    </button>
                    <button className="agv__btn" onClick={handleReset}>
                        ↺ Reset
                    </button>
                    <button className="agv__btn" onClick={refresh}>
                        ⟳ Refresh
                    </button>
                </div>
            </div>

            {/* ── Main canvas area ── */}
            <div className="agv__body">
                {error ? (
                    <div className="agv__error">
                        <span>⚠ Failed to load graph data</span>
                        <span style={{ color: '#484f58', fontSize: '0.75rem' }}>{error}</span>
                    </div>
                ) : (
                    <div className="agv__canvas-wrap">
                        <AttackGraph
                            key={resetKey}
                            nodes={data.nodes}
                            edges={data.edges}
                            onNodeClick={handleNodeClick}
                            selectedNodeId={selectedNode?.id ?? null}
                            paused={paused}
                        />

                        {/* Node info panel */}
                        {selectedNode && (
                            <NodeInfoPanel
                                node={selectedNode}
                                edges={data.edges}
                                onClose={() => setSelectedNode(null)}
                                onFilterAlerts={handleFilterAlerts}
                            />
                        )}
                    </div>
                )}
            </div>

            {/* ── Legend ── */}
            <div className="agv__legend">
                <span className="agv__legend-title">LEGEND</span>
                <span className="agv__legend-item">
                    <span className="agv__legend-dot" style={{ background: '#ff2d2d' }} /> Attacker (CRITICAL)
                </span>
                <span className="agv__legend-item">
                    <span className="agv__legend-dot" style={{ background: '#ff8c00' }} /> Attacker (HIGH)
                </span>
                <span className="agv__legend-item">
                    <span className="agv__legend-dot" style={{ background: '#ffd700' }} /> Attacker (MEDIUM)
                </span>
                <span className="agv__legend-item">
                    <span className="agv__legend-dot" style={{ background: '#1a4a7a', border: '1px solid #4a9eff' }} /> Victim
                </span>
                <span className="agv__legend-item">
                    <span className="agv__legend-dot" style={{ background: '#484f58' }} /> Stale (&gt;5m)
                </span>
                <span className="agv__legend-sep" />
                <span className="agv__legend-item" style={{ color: '#484f58' }}>
                    Click node for details · Drag to pin
                </span>
            </div>
        </div>
    )
}

export default AttackGraphView
