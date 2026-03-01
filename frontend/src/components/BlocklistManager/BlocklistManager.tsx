import React, { useState, useCallback } from 'react'
import type { StatsResponse } from '../../types'
import './BlocklistManager.css'

interface Props {
    stats: StatsResponse | null
}

interface BlockEntry {
    id: string
    ip: string
    reason: string
    addedAt: number
    addedBy: 'manual' | 'auto' | 'threat-intel'
    hits: number
    expires?: number
}

const INITIAL_BLOCKS: BlockEntry[] = [
    { id: '1', ip: '104.20.41.79', reason: 'TOR exit node — high abuse score (78/100)', addedAt: Date.now() - 3600000, addedBy: 'threat-intel', hits: 142 },
    { id: '2', ip: '18.97.36.5',   reason: 'Persistent C2 beaconing activity', addedAt: Date.now() - 7200000, addedBy: 'auto', hits: 95 },
]

export const BlocklistManager: React.FC<Props> = ({ stats }) => {
    const [blocks, setBlocks] = useState<BlockEntry[]>(INITIAL_BLOCKS)
    const [newIp, setNewIp] = useState('')
    const [newReason, setNewReason] = useState('')
    const [showAdd, setShowAdd] = useState(false)
    const [search, setSearch] = useState('')

    const topIps = stats?.top_src_ips ?? []

    const addBlock = useCallback(() => {
        const ip = newIp.trim()
        const reason = newReason.trim() || 'Manually blocked'
        if (!ip) return
        if (blocks.some(b => b.ip === ip)) return

        setBlocks(prev => [{
            id: String(Date.now()),
            ip,
            reason,
            addedAt: Date.now(),
            addedBy: 'manual',
            hits: 0,
        }, ...prev])
        setNewIp('')
        setNewReason('')
        setShowAdd(false)
    }, [newIp, newReason, blocks])

    const removeBlock = useCallback((id: string) => {
        setBlocks(prev => prev.filter(b => b.id !== id))
    }, [])

    const quickBlock = useCallback((ip: string) => {
        if (blocks.some(b => b.ip === ip)) return
        setBlocks(prev => [{
            id: String(Date.now()),
            ip,
            reason: 'Quick blocked from top alerts',
            addedAt: Date.now(),
            addedBy: 'manual',
            hits: 0,
        }, ...prev])
    }, [blocks])

    const filtered = blocks.filter(b =>
        !search || b.ip.includes(search) || b.reason.toLowerCase().includes(search.toLowerCase())
    )

    const formatAge = (ts: number) => {
        const mins = Math.floor((Date.now() - ts) / 60000)
        if (mins < 60) return `${mins}m ago`
        const hrs = Math.floor(mins / 60)
        if (hrs < 24) return `${hrs}h ago`
        return `${Math.floor(hrs / 24)}d ago`
    }

    return (
        <div className="blocklist">
            <div className="blocklist__header">
                <div className="blocklist__title-row">
                    <span className="blocklist__title">⛔ Blocklist Manager</span>
                    <span className="blocklist__badge">{blocks.length} rules active</span>
                </div>
                <div className="blocklist__header-actions">
                    <input
                        type="text"
                        className="blocklist__search"
                        placeholder="Search IPs or reasons..."
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                    />
                    <button className="blocklist__add-btn" onClick={() => setShowAdd(v => !v)}>
                        {showAdd ? '✕ Cancel' : '+ Add Rule'}
                    </button>
                </div>
            </div>

            {showAdd && (
                <div className="blocklist__add-form">
                    <input
                        type="text"
                        className="blocklist__input"
                        placeholder="IP address or CIDR range..."
                        value={newIp}
                        onChange={e => setNewIp(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && addBlock()}
                        autoFocus
                    />
                    <input
                        type="text"
                        className="blocklist__input"
                        placeholder="Reason (optional)..."
                        value={newReason}
                        onChange={e => setNewReason(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && addBlock()}
                    />
                    <button className="blocklist__confirm-btn" onClick={addBlock}>
                        Block IP
                    </button>
                </div>
            )}

            <div className="blocklist__content">
                <div className="blocklist__section">
                    <div className="blocklist__section-title">Active Rules</div>
                    <table className="blocklist__table">
                        <thead>
                            <tr>
                                <th>IP / Range</th>
                                <th>Reason</th>
                                <th>Added By</th>
                                <th>Added</th>
                                <th>Hits</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map(b => (
                                <tr key={b.id} className="blocklist__row">
                                    <td className="blocklist__row-ip mono">{b.ip}</td>
                                    <td className="blocklist__row-reason">{b.reason}</td>
                                    <td>
                                        <span className={`blocklist__source blocklist__source--${b.addedBy}`}>
                                            {b.addedBy === 'threat-intel' ? '◈ Intel' : b.addedBy === 'auto' ? '⚡ Auto' : '✎ Manual'}
                                        </span>
                                    </td>
                                    <td className="blocklist__age">{formatAge(b.addedAt)}</td>
                                    <td className="blocklist__hits mono">{b.hits.toLocaleString()}</td>
                                    <td>
                                        <button
                                            className="blocklist__remove-btn"
                                            onClick={() => removeBlock(b.id)}
                                        >
                                            Remove
                                        </button>
                                    </td>
                                </tr>
                            ))}
                            {filtered.length === 0 && (
                                <tr>
                                    <td colSpan={6} className="blocklist__empty-row">No rules match your search</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>

                {topIps.length > 0 && (
                    <div className="blocklist__section">
                        <div className="blocklist__section-title">Quick Block — Top Alert Sources</div>
                        <div className="blocklist__quick-list">
                            {topIps.slice(0, 8).map(({ src_ip, count }) => {
                                const isBlocked = blocks.some(b => b.ip === src_ip)
                                return (
                                    <div key={src_ip} className="blocklist__quick-item">
                                        <span className="blocklist__quick-ip mono">{src_ip}</span>
                                        <span className="blocklist__quick-count">{count.toLocaleString()} alerts</span>
                                        <button
                                            className={`blocklist__quick-btn ${isBlocked ? 'blocklist__quick-btn--blocked' : ''}`}
                                            onClick={() => quickBlock(src_ip)}
                                            disabled={isBlocked}
                                        >
                                            {isBlocked ? '✓ Blocked' : 'Block'}
                                        </button>
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}
