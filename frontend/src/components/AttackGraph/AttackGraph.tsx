/**
 * AttackGraph.tsx
 *
 * D3 force-directed graph on an HTML5 Canvas.
 * Canvas (not SVG) for performance — handles 200+ nodes without frame drops.
 *
 * Visual language:
 *   - Attacker nodes: red/orange circles, sized by alert count
 *   - Victim nodes: blue circles
 *   - Edges: colored by severity, thickness by count
 *   - CRITICAL/HIGH nodes pulse with a glow ring
 *   - Nodes fade when stale (>5 min since last alert)
 */

import React, {
    useRef, useEffect, useCallback, useState, useMemo,
} from 'react'
import * as d3 from 'd3'
import type { GraphNode, GraphEdge, Severity } from '../../types'

// ─── Constants ───────────────────────────────────────────────────────────────

const SEV_COLOR: Record<Severity, string> = {
    CRITICAL: '#ff2d2d',
    HIGH:     '#ff8c00',
    MEDIUM:   '#ffd700',
    LOW:      '#4a9eff',
}

const SEV_RANK: Record<Severity, number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
}

const ATTACKER_BASE  = 10
const VICTIM_BASE    = 8
const MAX_NODE_R     = 28
const STALE_AFTER_S  = 300   // 5 min

// ─── Helpers ─────────────────────────────────────────────────────────────────

function nodeRadius(n: GraphNode): number {
    const base = n.type === 'attacker' ? ATTACKER_BASE : VICTIM_BASE
    return Math.min(base + Math.sqrt(n.alert_count) * 1.8, MAX_NODE_R)
}

function nodeColor(n: GraphNode): string {
    if (n.type === 'victim') return '#1a4a7a'
    return SEV_COLOR[n.max_severity] ?? '#ff8c00'
}

function nodeBorder(n: GraphNode): string {
    if (n.type === 'victim') return '#4a9eff'
    return SEV_COLOR[n.max_severity] ?? '#ff8c00'
}

function edgeColor(sev: Severity): string {
    return SEV_COLOR[sev] ?? '#4a9eff'
}

function edgeWidth(count: number): number {
    return Math.min(1 + Math.log1p(count) * 0.8, 5)
}

function isStale(n: GraphNode, now: number): boolean {
    return now - n.last_seen > STALE_AFTER_S
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AttackGraphProps {
    nodes: GraphNode[]
    edges: GraphEdge[]
    onNodeClick?: (node: GraphNode | null) => void
    selectedNodeId?: string | null
    paused?: boolean
}

// ─── Component ───────────────────────────────────────────────────────────────

const AttackGraph: React.FC<AttackGraphProps> = ({
    nodes,
    edges,
    onNodeClick,
    selectedNodeId,
    paused = false,
}) => {
    const canvasRef  = useRef<HTMLCanvasElement>(null)
    const wrapRef    = useRef<HTMLDivElement>(null)
    const simRef     = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null)
    const rafRef     = useRef<number>(0)
    const pausedRef  = useRef(paused)
    pausedRef.current = paused

    const nodesRef   = useRef<GraphNode[]>([])
    const edgesRef   = useRef<GraphEdge[]>([])

    // ── Sync incoming props into refs without restarting simulation ──────────
    useEffect(() => {
        const sim = simRef.current
        if (!sim) return

        const now = Date.now() / 1000
        const existingById = new Map(nodesRef.current.map(n => [n.id, n]))

        // Merge new nodes — preserve x/y/vx/vy for continuity
        const merged = nodes.map(incoming => {
            const existing = existingById.get(incoming.id)
            if (existing) {
                // Update data fields, keep simulation position
                return Object.assign(existing, {
                    alert_count:  incoming.alert_count,
                    max_severity: incoming.max_severity,
                    rules:        incoming.rules,
                    last_seen:    incoming.last_seen,
                    type:         incoming.type,
                })
            }
            return { ...incoming }
        })

        nodesRef.current = merged
        edgesRef.current = edges.map(e => ({ ...e }))

        sim.nodes(merged)
        sim.force<d3.ForceLink<GraphNode, GraphEdge>>('link')?.links(edgesRef.current)
        sim.alpha(0.3).restart()
    }, [nodes, edges])

    // ── Canvas draw loop ─────────────────────────────────────────────────────
    const draw = useCallback(() => {
        const canvas = canvasRef.current
        if (!canvas) return
        const ctx = canvas.getContext('2d')
        if (!ctx) return

        const w = canvas.width
        const h = canvas.height
        const now = Date.now() / 1000
        const pulse = (Math.sin(now * 3) + 1) / 2   // 0..1 oscillator

        ctx.clearRect(0, 0, w, h)

        // Background
        ctx.fillStyle = '#0a0e14'
        ctx.fillRect(0, 0, w, h)

        // Draw edges first (below nodes)
        edgesRef.current.forEach(edge => {
            const src = edge.source as GraphNode
            const tgt = edge.target as GraphNode
            if (src.x == null || tgt.x == null) return

            const stale = isStale(src, now)
            ctx.globalAlpha = stale ? 0.2 : 0.55
            ctx.strokeStyle = edgeColor(edge.severity as Severity)
            ctx.lineWidth   = edgeWidth(edge.count)
            ctx.setLineDash([])

            ctx.beginPath()
            ctx.moveTo(src.x!, src.y!)
            ctx.lineTo(tgt.x!, tgt.y!)
            ctx.stroke()

            // Arrow head
            const dx = tgt.x! - src.x!
            const dy = tgt.y! - src.y!
            const len = Math.sqrt(dx * dx + dy * dy) || 1
            const ux = dx / len; const uy = dy / len
            const tgtR = nodeRadius(tgt)
            const ax = tgt.x! - ux * (tgtR + 4)
            const ay = tgt.y! - uy * (tgtR + 4)
            const perpX = -uy * 4; const perpY = ux * 4

            ctx.beginPath()
            ctx.moveTo(ax + perpX, ay + perpY)
            ctx.lineTo(ax - perpX, ay - perpY)
            ctx.lineTo(ax + ux * 8, ay + uy * 8)
            ctx.closePath()
            ctx.fillStyle = edgeColor(edge.severity as Severity)
            ctx.fill()
        })

        ctx.globalAlpha = 1

        // Draw nodes
        nodesRef.current.forEach(node => {
            if (node.x == null) return
            const r     = nodeRadius(node)
            const color = nodeColor(node)
            const border = nodeBorder(node)
            const stale  = isStale(node, now)
            const isSel  = node.id === selectedNodeId
            const isCrit = SEV_RANK[node.max_severity as Severity] >= 3

            ctx.globalAlpha = stale ? 0.35 : 1

            // Pulse glow for critical/high attackers
            if (isCrit && !stale && node.type === 'attacker') {
                const glowR = r + 6 + pulse * 8
                const grad  = ctx.createRadialGradient(node.x!, node.y!, r, node.x!, node.y!, glowR)
                grad.addColorStop(0, border + '66')
                grad.addColorStop(1, border + '00')
                ctx.beginPath()
                ctx.arc(node.x!, node.y!, glowR, 0, Math.PI * 2)
                ctx.fillStyle = grad
                ctx.fill()
            }

            // Selection ring
            if (isSel) {
                ctx.beginPath()
                ctx.arc(node.x!, node.y!, r + 5, 0, Math.PI * 2)
                ctx.strokeStyle = '#ffffff'
                ctx.lineWidth = 2
                ctx.stroke()
            }

            // Node fill
            const grad = ctx.createRadialGradient(node.x! - r * 0.3, node.y! - r * 0.3, r * 0.1, node.x!, node.y!, r)
            grad.addColorStop(0, color + 'ee')
            grad.addColorStop(1, color + '88')
            ctx.beginPath()
            ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2)
            ctx.fillStyle = grad
            ctx.fill()

            // Border
            ctx.beginPath()
            ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2)
            ctx.strokeStyle = border
            ctx.lineWidth   = isSel ? 2.5 : 1.5
            ctx.stroke()

            // Label
            ctx.globalAlpha = stale ? 0.4 : 1
            ctx.fillStyle   = '#e6edf3'
            ctx.font        = `${Math.max(9, r * 0.55)}px 'JetBrains Mono', monospace`
            ctx.textAlign   = 'center'
            ctx.textBaseline = 'middle'

            // Show last octet for space efficiency on small nodes
            const label = r < 14 ? node.id.split('.').slice(-2).join('.') : node.id
            ctx.fillText(label, node.x!, node.y!)

            // Alert count badge for attackers
            if (node.type === 'attacker' && node.alert_count > 1) {
                const bx = node.x! + r * 0.7
                const by = node.y! - r * 0.7
                ctx.beginPath()
                ctx.arc(bx, by, 8, 0, Math.PI * 2)
                ctx.fillStyle = '#ff2d2d'
                ctx.globalAlpha = 1
                ctx.fill()
                ctx.fillStyle = '#fff'
                ctx.font      = '8px monospace'
                ctx.fillText(String(Math.min(node.alert_count, 99)), bx, by)
            }

            ctx.globalAlpha = 1
        })

        // Empty state
        if (nodesRef.current.length === 0) {
            ctx.fillStyle    = '#484f58'
            ctx.font         = '14px monospace'
            ctx.textAlign    = 'center'
            ctx.textBaseline = 'middle'
            ctx.fillText('No alerts in selected time window', w / 2, h / 2)
        }
    }, [selectedNodeId])

    // ── Render loop ──────────────────────────────────────────────────────────
    useEffect(() => {
        const loop = () => {
            draw()
            rafRef.current = requestAnimationFrame(loop)
        }
        rafRef.current = requestAnimationFrame(loop)
        return () => cancelAnimationFrame(rafRef.current)
    }, [draw])

    // ── Build D3 simulation ──────────────────────────────────────────────────
    useEffect(() => {
        const canvas = canvasRef.current
        const wrap   = wrapRef.current
        if (!canvas || !wrap) return

        const w = wrap.clientWidth  || 800
        const h = wrap.clientHeight || 500
        canvas.width  = w
        canvas.height = h

        const sim = d3.forceSimulation<GraphNode>()
            .force('link', d3.forceLink<GraphNode, GraphEdge>()
                .id(d => d.id)
                .distance(120)
                .strength(0.4))
            .force('charge', d3.forceManyBody().strength(-300).distanceMax(400))
            .force('center', d3.forceCenter(w / 2, h / 2).strength(0.05))
            .force('collision', d3.forceCollide<GraphNode>().radius(d => nodeRadius(d) + 8))
            .alphaDecay(0.02)
            .velocityDecay(0.4)

        sim.on('tick', () => {
            if (!pausedRef.current) return  // simulation still runs, just skip draw (handled by RAF)
        })

        simRef.current = sim
        return () => { sim.stop() }
    }, [])

    // ── Canvas resize ────────────────────────────────────────────────────────
    useEffect(() => {
        const wrap = wrapRef.current
        if (!wrap) return
        const obs = new ResizeObserver(() => {
            const canvas = canvasRef.current
            if (!canvas) return
            canvas.width  = wrap.clientWidth
            canvas.height = wrap.clientHeight
            simRef.current?.force('center', d3.forceCenter(wrap.clientWidth / 2, wrap.clientHeight / 2).strength(0.05))
            simRef.current?.alpha(0.2).restart()
        })
        obs.observe(wrap)
        return () => obs.disconnect()
    }, [])

    // ── Pause / resume simulation ────────────────────────────────────────────
    useEffect(() => {
        if (!simRef.current) return
        if (paused) simRef.current.stop()
        else simRef.current.alpha(0.1).restart()
    }, [paused])

    // ── Mouse interaction ────────────────────────────────────────────────────
    const getNodeAt = useCallback((cx: number, cy: number): GraphNode | null => {
        for (const n of nodesRef.current) {
            if (n.x == null || n.y == null) continue
            const dx = n.x - cx; const dy = n.y - cy
            if (Math.sqrt(dx * dx + dy * dy) <= nodeRadius(n) + 4) return n
        }
        return null
    }, [])

    const [tooltip, setTooltip] = useState<{ x: number; y: number; node: GraphNode } | null>(null)
    const dragRef = useRef<GraphNode | null>(null)

    const onMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
        const rect = canvasRef.current!.getBoundingClientRect()
        const mx = e.clientX - rect.left
        const my = e.clientY - rect.top
        const node = getNodeAt(mx, my)

        if (dragRef.current) {
            dragRef.current.fx = mx
            dragRef.current.fy = my
            simRef.current?.alpha(0.1).restart()
            return
        }
        canvasRef.current!.style.cursor = node ? 'pointer' : 'default'
        setTooltip(node ? { x: e.clientX, y: e.clientY, node } : null)
    }, [getNodeAt])

    const onMouseDown = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
        const rect = canvasRef.current!.getBoundingClientRect()
        const node = getNodeAt(e.clientX - rect.left, e.clientY - rect.top)
        if (node) { dragRef.current = node; node.fx = node.x; node.fy = node.y }
    }, [getNodeAt])

    const onMouseUp = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
        const rect = canvasRef.current!.getBoundingClientRect()
        const node = getNodeAt(e.clientX - rect.left, e.clientY - rect.top)
        if (dragRef.current) {
            dragRef.current.fx = null
            dragRef.current.fy = null
            dragRef.current = null
        }
        if (node) onNodeClick?.(node)
        else onNodeClick?.(null)
    }, [getNodeAt, onNodeClick])

    const onMouseLeave = useCallback(() => {
        setTooltip(null)
        if (dragRef.current) {
            dragRef.current.fx = null
            dragRef.current.fy = null
            dragRef.current = null
        }
    }, [])

    return (
        <div ref={wrapRef} style={{ position: 'relative', width: '100%', height: '100%' }}>
            <canvas
                ref={canvasRef}
                style={{ display: 'block', width: '100%', height: '100%' }}
                onMouseMove={onMouseMove}
                onMouseDown={onMouseDown}
                onMouseUp={onMouseUp}
                onMouseLeave={onMouseLeave}
            />

            {/* Hover tooltip */}
            {tooltip && (
                <div style={{
                    position: 'fixed',
                    left: tooltip.x + 12,
                    top:  tooltip.y - 10,
                    background: '#161b22',
                    border: '1px solid #30363d',
                    borderRadius: 6,
                    padding: '8px 12px',
                    fontSize: '0.72rem',
                    fontFamily: 'monospace',
                    color: '#e6edf3',
                    pointerEvents: 'none',
                    zIndex: 999,
                    minWidth: 160,
                }}>
                    <div style={{ fontWeight: 700, marginBottom: 4, color: SEV_COLOR[tooltip.node.max_severity as Severity] }}>
                        {tooltip.node.id}
                    </div>
                    <div style={{ color: '#8b949e' }}>
                        Type: <span style={{ color: '#e6edf3' }}>{tooltip.node.type}</span>
                    </div>
                    <div style={{ color: '#8b949e' }}>
                        Alerts: <span style={{ color: '#e6edf3' }}>{tooltip.node.alert_count}</span>
                    </div>
                    <div style={{ color: '#8b949e' }}>
                        Severity: <span style={{ color: SEV_COLOR[tooltip.node.max_severity as Severity] }}>{tooltip.node.max_severity}</span>
                    </div>
                    {tooltip.node.rules.length > 0 && (
                        <div style={{ color: '#8b949e', marginTop: 2 }}>
                            Rules: <span style={{ color: '#e6edf3' }}>{tooltip.node.rules.join(', ')}</span>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}

export default AttackGraph
