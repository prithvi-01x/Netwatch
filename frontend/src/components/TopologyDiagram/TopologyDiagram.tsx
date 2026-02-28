/**
 * TopologyDiagram.tsx  — pure SVG + HTML, zero extra dependencies
 *
 * Layout:
 *   ISP (top-center)
 *    │  packet pipe
 *   Router
 *    │  packet pipe
 *   Host Machine
 *    ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─┤  (SVG fan-out lines)
 *   [Container] [Container] …
 *
 * The SVG canvas sits behind an absolutely-positioned HTML overlay that
 * renders the node cards exactly where the SVG coordinate system places them.
 * Packet dots use SVG <animateMotion> along real path data so they follow
 * every line precisely.
 */

import React, { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { useFlows } from '../../hooks/useFlows'
import { fetchDockerTopology, fetchHostPorts, fetchHostInfo } from '../../api/client'
import type { TopologyConfig, ContainerInfo, PortInfo } from './types'
import { DEFAULT_CONFIG } from './types'
import DockerNode from './nodes/DockerNode'
import IspNode from './nodes/IspNode'
import RouterNode from './nodes/RouterNode'
import HostNode from './nodes/HostNode'
import './TopologyDiagram.css'

// ─── Layout maths ────────────────────────────────────────────────────────────

const NODE_W = 240   // ISP / Router / Host card width
const ISP_H = 90    // ISP card height
const RTR_H = 90    // Router card height  
const HOST_H = 400  // tall enough for many ports; actual card grows with content
const CON_W = 190   // container card width
const CON_H = 90
const CON_GAP = 20

// Fixed Y positions — generous vertical spacing so pipes are clearly visible
const ISP_Y = 40
const RTR_Y = ISP_Y + ISP_H + 60
const HOST_Y = RTR_Y + RTR_H + 60
const CON_Y = HOST_Y + HOST_H + 80

const NETWATCH_PORTS = new Set([8000, 3000, 11434])

function calcLayout(numContainers: number, canvasW: number) {
    // Total width needed for all containers
    const totalConW = numContainers * CON_W + Math.max(0, numContainers - 1) * CON_GAP
    // Effective canvas centre — expand canvas if containers are wider than viewport
    const effectiveW = Math.max(canvasW, totalConW + 80)
    const cx = effectiveW / 2

    // ISP, Router, Host — centred
    const ispX = cx - NODE_W / 2
    const rtrX = cx - NODE_W / 2
    const hostX = cx - NODE_W / 2

    // Containers — fan out symmetrically from centre
    const conStartX = cx - totalConW / 2

    const conPositions = Array.from({ length: numContainers }, (_, i) => ({
        x: conStartX + i * (CON_W + CON_GAP),
        y: CON_Y,
    }))

    // Pipe anchor points — use per-node heights so anchors sit exactly on card edges
    const ispBottom = { x: cx, y: ISP_Y + ISP_H }
    const rtrTop = { x: cx, y: RTR_Y }
    const rtrBottom = { x: cx, y: RTR_Y + RTR_H }
    const hostTop = { x: cx, y: HOST_Y }
    const hostBottom = { x: cx, y: HOST_Y + HOST_H }

    const conTops = conPositions.map(p => ({
        x: p.x + CON_W / 2,
        y: CON_Y,
    }))

    return { ispX, rtrX, hostX, conPositions, ispBottom, rtrTop, rtrBottom, hostTop, hostBottom, conTops, cx, effectiveW }
}

// ─── SVG packet-pipe component ───────────────────────────────────────────────

interface PipeProps {
    x1: number; y1: number
    x2: number; y2: number
    speed: 'slow' | 'medium' | 'fast'
    color?: string
    label?: string
}

const DURATIONS = { fast: 0.65, medium: 1.3, slow: 2.6 }

const PacketPipe: React.FC<PipeProps> = ({ x1, y1, x2, y2, speed, color = '#4a9eff', label }) => {
    const dur = DURATIONS[speed]
    // SVG path string for animateMotion
    const d = `M ${x1} ${y1} L ${x2} ${y2}`
    const mx = (x1 + x2) / 2 + 8
    const my = (y1 + y2) / 2

    return (
        <g>
            {/* The pipe line */}
            <line
                x1={x1} y1={y1} x2={x2} y2={y2}
                stroke={color}
                strokeWidth={2}
                opacity={0.35}
            />

            {/* 3 staggered dots — only shown when not slow */}
            {speed !== 'slow' ? (
                [0, 0.33, 0.66].map((offset, i) => (
                    <circle key={i} r={3} fill={color} style={{ filter: `drop-shadow(0 0 4px ${color})` }}>
                        <animateMotion
                            dur={`${dur}s`}
                            begin={`${offset * dur}s`}
                            repeatCount="indefinite"
                            path={d}
                        />
                        <animate
                            attributeName="opacity"
                            values="0;1;1;0"
                            keyTimes="0;0.05;0.9;1"
                            dur={`${dur}s`}
                            begin={`${offset * dur}s`}
                            repeatCount="indefinite"
                        />
                    </circle>
                ))
            ) : (
                <circle r={2.5} fill="#2a3a4a" opacity={0.5}>
                    <animateMotion dur={`${dur}s`} repeatCount="indefinite" path={d} />
                </circle>
            )}

            {/* Optional label */}
            {label && (
                <text x={mx} y={my} fill="#4a6070" fontSize={9} fontFamily="monospace" letterSpacing="0.1em" dominantBaseline="middle">
                    {label}
                </text>
            )}
        </g>
    )
}

// ─── Main component ───────────────────────────────────────────────────────────

interface Props {
    config?: TopologyConfig
}

const TopologyDiagram: React.FC<Props> = ({ config = DEFAULT_CONFIG }) => {
    const { flows, lastUpdate, isLive } = useFlows()
    const [containers, setContainers] = useState<ContainerInfo[]>(config.containers)
    const [hostPorts, setHostPorts] = useState<PortInfo[]>(config.host_ports)
    const [hostIp, setHostIp] = useState(config.host_ip)
    const [hostIface, setHostIface] = useState(config.interface_name)
    const [now, setNow] = useState(() => Date.now() / 1000)
    const wrapRef = useRef<HTMLDivElement>(null)
    const [canvasW, setCanvasW] = useState(900)

    // Measure wrapper width so layout is responsive
    useEffect(() => {
        if (!wrapRef.current) return
        const obs = new ResizeObserver(entries => {
            const w = entries[0].contentRect.width
            if (w > 0) setCanvasW(w)
        })
        obs.observe(wrapRef.current)
        return () => obs.disconnect()
    }, [])

    // Clock tick
    useEffect(() => {
        const id = setInterval(() => setNow(Date.now() / 1000), 1000)
        return () => clearInterval(id)
    }, [])

    // Pause animations when tab hidden
    useEffect(() => {
        const el = document.documentElement
        const handler = () => {
            el.style.setProperty('--anim-play-state', document.visibilityState === 'hidden' ? 'paused' : 'running')
        }
        document.addEventListener('visibilitychange', handler)
        return () => document.removeEventListener('visibilitychange', handler)
    }, [])

    // Docker polling every 5s
    useEffect(() => {
        let mounted = true
        const poll = async () => {
            try {
                const res = await fetchDockerTopology()
                if (mounted && res.containers) setContainers(res.containers)
            } catch { /* silent — show stale data */ }
        }
        poll()
        const id = setInterval(poll, 5_000)
        return () => { mounted = false; clearInterval(id) }
    }, [])

    // Host info polling every 10s — auto-detects real IP + interface
    useEffect(() => {
        let mounted = true
        const poll = async () => {
            try {
                const res = await fetchHostInfo()
                if (mounted) {
                    if (res.ip && res.ip !== 'unknown') setHostIp(res.ip)
                    if (res.interface && res.interface !== 'unknown') setHostIface(res.interface)
                }
            } catch { /* keep config defaults */ }
        }
        poll()
        const id = setInterval(poll, 10_000)
        return () => { mounted = false; clearInterval(id) }
    }, [])

    // Host ports polling every 3s — catches nc, python servers, anything on the host
    useEffect(() => {
        let mounted = true
        const poll = async () => {
            try {
                const res = await fetchHostPorts()
                if (mounted && res.ports.length > 0) {
                    // Merge: config static ports + live discovered ports
                    // Live ports win (they reflect actual state)
                    const liveMap = new Map(res.ports.map(p => [`${p.port}:${p.protocol}`, p]))
                    const staticOnly = config.host_ports.filter(
                        p => !liveMap.has(`${p.port}:${p.protocol}`)
                    ).map(p => ({ ...p, state: 'closed' as const }))
                    setHostPorts([...res.ports, ...staticOnly].sort((a, b) => a.port - b.port))
                }
            } catch { /* backend not yet running — keep config defaults */ }
        }
        poll()
        const id = setInterval(poll, 3_000)
        return () => { mounted = false; clearInterval(id) }
    }, [config.host_ports])

    const activePorts = useMemo<Set<number>>(() => {
        const ports = new Set<number>()
        flows.forEach(f => {
            if (NETWATCH_PORTS.has(f.dst_port)) ports.add(f.dst_port)
            if (NETWATCH_PORTS.has(f.src_port)) ports.add(f.src_port)
        })
        return ports
    }, [flows])

    const activeIps = useMemo(() => {
        const ips = new Set<string>()
        flows.forEach(f => { ips.add(f.src_ip); ips.add(f.dst_ip) })
        return ips
    }, [flows])

    const trafficSpeed: 'slow' | 'medium' | 'fast' =
        flows.length > 20 ? 'fast' : flows.length > 5 ? 'medium' : 'slow'

    const layout = useMemo(() => calcLayout(containers.length, canvasW), [containers.length, canvasW])

    // Canvas height: enough room for containers + a bottom margin
    const canvasH = CON_Y + CON_H + 60

    const formatBytes = (b: number) =>
        b > 1024 * 1024 ? `${(b / 1024 / 1024).toFixed(1)}MB`
            : b > 1024 ? `${(b / 1024).toFixed(1)}KB`
                : `${b}B`

    return (
        <div className="topology-diagram">
            {/* ── Header ── */}
            <div className="topology-diagram__header">
                <span className="topology-diagram__title">NETWORK TOPOLOGY</span>
                <span className={`topology-diagram__live ${isLive ? 'topology-diagram__live--on' : ''}`}>
                    {isLive ? '● LIVE' : '○ OFFLINE'}
                </span>
                {lastUpdate > 0 && (
                    <span className="topo-node__ts">updated {Math.round(now - lastUpdate)}s ago</span>
                )}
            </div>

            {/* ── Canvas: SVG pipes behind HTML cards ── */}
            <div ref={wrapRef} style={{ position: 'relative', width: '100%', height: canvasH, overflowX: 'auto' }}>
                <div style={{ position: 'relative', width: layout.effectiveW, height: canvasH, minWidth: '100%' }}>

                    {/* SVG layer — pipes only */}
                    <svg
                        width={layout.effectiveW}
                        height={canvasH}
                        style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none', overflow: 'visible' }}
                    >
                        {/* ISP → Router */}
                        <PacketPipe
                            x1={layout.ispBottom.x} y1={layout.ispBottom.y}
                            x2={layout.rtrTop.x} y2={layout.rtrTop.y}
                            speed={trafficSpeed} color="#4a9eff" label="WAN"
                        />

                        {/* Router → Host */}
                        <PacketPipe
                            x1={layout.rtrBottom.x} y1={layout.rtrBottom.y}
                            x2={layout.hostTop.x} y2={layout.hostTop.y}
                            speed={trafficSpeed} color="#4a9eff" label="LAN"
                        />

                        {/* Host → each container */}
                        {layout.conTops.map((ct, i) => {
                            const c = containers[i]
                            const hasTraffic = c && activeIps.has(c.ip)
                            return (
                                <PacketPipe
                                    key={containers[i]?.name ?? i}
                                    x1={layout.hostBottom.x} y1={layout.hostBottom.y}
                                    x2={ct.x} y2={ct.y}
                                    speed={hasTraffic ? trafficSpeed : 'slow'}
                                    color={hasTraffic ? '#00ff88' : '#1e2d40'}
                                />
                            )
                        })}
                    </svg>

                    {/* HTML layer — node cards, absolutely positioned */}

                    {/* ISP */}
                    <div style={{ position: 'absolute', left: layout.ispX, top: ISP_Y, width: NODE_W }}>
                        <IspNode />
                    </div>

                    {/* Router */}
                    <div style={{ position: 'absolute', left: layout.rtrX, top: RTR_Y, width: NODE_W }}>
                        <RouterNode gatewayIp={config.gateway_ip} />
                    </div>

                    {/* Host */}
                    <div style={{ position: 'absolute', left: layout.hostX, top: HOST_Y, width: NODE_W }}>
                        <HostNode
                            hostIp={hostIp}
                            interfaceName={hostIface}
                            ports={hostPorts}
                            activePorts={activePorts}
                        />
                    </div>

                    {/* Container cards */}
                    {containers.map((c, i) => (
                        <div
                            key={c.name}
                            style={{
                                position: 'absolute',
                                left: layout.conPositions[i]?.x ?? 0,
                                top: CON_Y,
                                width: CON_W,
                            }}
                        >
                            <DockerNode container={c} activePorts={activePorts} />
                        </div>
                    ))}
                </div>
            </div>

            {/* ── Active flows table ── */}
            <div className="topo-node topo-node--flows" style={{ marginTop: 24, maxWidth: canvasW }}>
                <div className="topo-node__header">
                    <span className="topo-node__icon">⟳</span>
                    <span className="topo-node__title">ACTIVE FLOWS</span>
                    <span className={`topo-node__badge ${isLive ? 'topo-node__badge--live' : ''}`}>
                        {flows.length} flows
                    </span>
                </div>
                <div className="flows-table">
                    {flows.length === 0 ? (
                        <div className="flows-table__empty">
                            {isLive ? 'Waiting for traffic…' : 'No backend connection'}
                        </div>
                    ) : (
                        flows.slice(0, 10).map((f, i) => {
                            const isStale = lastUpdate > 0 && now - lastUpdate > 5
                            const isNetwatch = NETWATCH_PORTS.has(f.dst_port) || NETWATCH_PORTS.has(f.src_port)
                            return (
                                <div key={i} className={`flow-row ${isNetwatch ? 'flow-row--highlight' : ''} ${isStale ? 'flow-row--stale' : ''}`}>
                                    <span className="flow-row__src">{f.src_ip}:{f.src_port}</span>
                                    <span className="flow-row__arrow">→</span>
                                    <span className="flow-row__dst">{f.dst_ip}:{f.dst_port}</span>
                                    <span className={`flow-row__proto flow-row__proto--${f.protocol.toLowerCase()}`}>{f.protocol}</span>
                                    <span className="flow-row__pps">{f.pps} pps</span>
                                    <span className="flow-row__bytes">{formatBytes(f.bytes)}</span>
                                </div>
                            )
                        })
                    )}
                </div>
            </div>
        </div>
    )
}

export default TopologyDiagram