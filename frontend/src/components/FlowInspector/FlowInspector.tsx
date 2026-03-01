import React, { useState, useMemo } from 'react'
import { useFlows } from '../../hooks/useFlows'
import { format } from 'date-fns'
import './FlowInspector.css'

type SortKey = 'pps' | 'packets' | 'bytes' | 'src_ip' | 'dst_ip' | 'protocol'

export const FlowInspector: React.FC = () => {
    const { flows, lastUpdate, isLive } = useFlows()
    const [search, setSearch] = useState('')
    const [sortKey, setSortKey] = useState<SortKey>('pps')
    const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
    const [protocolFilter, setProtocolFilter] = useState<string>('ALL')

    const protocols = useMemo(() => {
        const set = new Set(flows.map(f => f.protocol?.toUpperCase() ?? 'UNKNOWN'))
        return ['ALL', ...Array.from(set).sort()]
    }, [flows])

    const filtered = useMemo(() => {
        let list = [...flows]

        if (search) {
            const q = search.toLowerCase()
            list = list.filter(f =>
                f.src_ip?.includes(q) ||
                f.dst_ip?.includes(q) ||
                String(f.src_port).includes(q) ||
                String(f.dst_port).includes(q)
            )
        }

        if (protocolFilter !== 'ALL') {
            list = list.filter(f => f.protocol?.toUpperCase() === protocolFilter)
        }

        list.sort((a, b) => {
            const av = (a as any)[sortKey] ?? 0
            const bv = (b as any)[sortKey] ?? 0
            const cmp = typeof av === 'string' ? av.localeCompare(bv) : av - bv
            return sortDir === 'desc' ? -cmp : cmp
        })

        return list
    }, [flows, search, sortKey, sortDir, protocolFilter])

    const handleSort = (key: SortKey) => {
        if (sortKey === key) {
            setSortDir(d => d === 'desc' ? 'asc' : 'desc')
        } else {
            setSortKey(key)
            setSortDir('desc')
        }
    }

    const formatBytes = (b: number) => {
        if (b > 1e6) return `${(b / 1e6).toFixed(1)}M`
        if (b > 1e3) return `${(b / 1e3).toFixed(1)}K`
        return String(b)
    }

    const getProtoColor = (proto: string) => {
        switch (proto?.toUpperCase()) {
            case 'TCP': return 'var(--protocol-tcp)'
            case 'UDP': return 'var(--protocol-udp)'
            case 'DNS': return 'var(--protocol-dns)'
            case 'ICMP': return 'var(--protocol-icmp)'
            default: return 'var(--protocol-other)'
        }
    }

    const SortIcon = ({ col }: { col: SortKey }) => (
        <span className="flow__sort-icon">
            {sortKey === col ? (sortDir === 'desc' ? ' ↓' : ' ↑') : ' ·'}
        </span>
    )

    return (
        <div className="flow-inspector">
            <div className="flow-inspector__header">
                <div className="flow-inspector__title-row">
                    <span className="flow-inspector__title">⇄ Flow Inspector</span>
                    <span className={`flow-inspector__live ${isLive ? 'flow-inspector__live--on' : ''}`}>
                        {isLive ? '● LIVE' : '○ disconnected'}
                    </span>
                    {lastUpdate > 0 && (
                        <span className="flow-inspector__updated">
                            Updated {format(new Date(lastUpdate * 1000), 'HH:mm:ss')}
                        </span>
                    )}
                </div>
                <div className="flow-inspector__controls">
                    <input
                        type="text"
                        className="flow-inspector__search"
                        placeholder="Filter by IP or port..."
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                    />
                    <select
                        className="flow-inspector__proto-select"
                        value={protocolFilter}
                        onChange={e => setProtocolFilter(e.target.value)}
                    >
                        {protocols.map(p => <option key={p} value={p}>{p}</option>)}
                    </select>
                    <span className="flow-inspector__count mono">
                        {filtered.length} / {flows.length} flows
                    </span>
                </div>
            </div>

            {flows.length === 0 ? (
                <div className="flow-inspector__empty">
                    <span>⇄</span>
                    <span>No active flows — waiting for traffic data</span>
                    {!isLive && <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>WebSocket disconnected</span>}
                </div>
            ) : (
                <div className="flow-inspector__table-wrap">
                    <table className="flow-inspector__table">
                        <thead>
                            <tr>
                                <th onClick={() => handleSort('src_ip')} className="flow-inspector__th--sortable">
                                    Source <SortIcon col="src_ip" />
                                </th>
                                <th onClick={() => handleSort('dst_ip')} className="flow-inspector__th--sortable">
                                    Destination <SortIcon col="dst_ip" />
                                </th>
                                <th onClick={() => handleSort('protocol')} className="flow-inspector__th--sortable">
                                    Proto <SortIcon col="protocol" />
                                </th>
                                <th onClick={() => handleSort('packets')} className="flow-inspector__th--sortable">
                                    Packets <SortIcon col="packets" />
                                </th>
                                <th onClick={() => handleSort('bytes')} className="flow-inspector__th--sortable">
                                    Bytes <SortIcon col="bytes" />
                                </th>
                                <th onClick={() => handleSort('pps')} className="flow-inspector__th--sortable">
                                    PPS <SortIcon col="pps" />
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((f, i) => (
                                <tr key={`${f.src_ip}:${f.src_port}-${f.dst_ip}:${f.dst_port}-${i}`} className="flow-inspector__row">
                                    <td className="flow-inspector__ip mono">
                                        {f.src_ip}<span className="flow-inspector__port">:{f.src_port}</span>
                                    </td>
                                    <td className="flow-inspector__ip mono">
                                        {f.dst_ip}<span className="flow-inspector__port">:{f.dst_port}</span>
                                    </td>
                                    <td>
                                        <span
                                            className="flow-inspector__proto"
                                            style={{ color: getProtoColor(f.protocol), borderColor: getProtoColor(f.protocol) + '44', background: getProtoColor(f.protocol) + '15' }}
                                        >
                                            {f.protocol?.toUpperCase() ?? '?'}
                                        </span>
                                    </td>
                                    <td className="flow-inspector__num mono">{f.packets?.toLocaleString()}</td>
                                    <td className="flow-inspector__num mono">{formatBytes(f.bytes ?? 0)}</td>
                                    <td className="flow-inspector__num mono">
                                        <span
                                            className="flow-inspector__pps"
                                            style={{ color: f.pps > 100 ? 'var(--severity-high)' : f.pps > 50 ? 'var(--severity-medium)' : 'var(--text-secondary)' }}
                                        >
                                            {f.pps?.toFixed(1)}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    )
}