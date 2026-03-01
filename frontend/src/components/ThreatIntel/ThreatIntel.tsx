import React, { useState, useCallback } from 'react'
import type { StatsResponse } from '../../types'
import './ThreatIntel.css'

interface Props {
    stats: StatsResponse | null
}

interface IntelResult {
    ip: string
    status: 'loading' | 'done' | 'error'
    abuseScore?: number
    country?: string
    isp?: string
    reports?: number
    categories?: string[]
    isVpn?: boolean
    isTor?: boolean
    lastReported?: string
    error?: string
}

const MOCK_INTEL: Record<string, Partial<IntelResult>> = {
    '104.18.39.21': { abuseScore: 0, country: 'US', isp: 'Cloudflare, Inc.', reports: 0, categories: [], isVpn: false, isTor: false },
    '172.64.148.235': { abuseScore: 2, country: 'US', isp: 'Cloudflare, Inc.', reports: 1, categories: ['Hacking'], isVpn: false, isTor: false },
    '216.239.34.223': { abuseScore: 0, country: 'US', isp: 'Google LLC', reports: 0, categories: [], isVpn: false, isTor: false },
    '18.97.36.5': { abuseScore: 45, country: 'DE', isp: 'Amazon AWS', reports: 12, categories: ['Port Scan', 'Hacking'], isVpn: true, isTor: false, lastReported: '2025-02-20' },
    '104.20.41.79': { abuseScore: 78, country: 'RU', isp: 'Webzilla B.V.', reports: 89, categories: ['SSH Brute Force', 'DDoS Attack', 'Hacking'], isVpn: false, isTor: true, lastReported: '2026-02-27' },
}

export const ThreatIntel: React.FC<Props> = ({ stats }) => {
    const [results, setResults] = useState<Map<string, IntelResult>>(new Map())
    const [customIp, setCustomIp] = useState('')

    const topIps = stats?.top_src_ips?.slice(0, 10) ?? []

    const lookupIp = useCallback(async (ip: string) => {
        setResults(prev => new Map(prev).set(ip, { ip, status: 'loading' }))

        // Simulate API call with mock data
        await new Promise(r => setTimeout(r, 600 + Math.random() * 800))

        const mock = MOCK_INTEL[ip]
        if (mock) {
            setResults(prev => new Map(prev).set(ip, { ip, status: 'done', ...mock } as IntelResult))
        } else {
            // Generate pseudo-random but consistent data for unknown IPs
            const hash = ip.split('.').reduce((a, b) => a + parseInt(b), 0)
            const score = hash % 100
            setResults(prev => new Map(prev).set(ip, {
                ip, status: 'done',
                abuseScore: score,
                country: ['US', 'DE', 'CN', 'RU', 'BR'][hash % 5],
                isp: ['Amazon AWS', 'OVH SAS', 'Digital Ocean', 'Linode', 'Vultr'][hash % 5],
                reports: Math.floor(score / 5),
                categories: score > 50 ? ['Port Scan', 'Hacking'] : [],
                isVpn: score > 40,
                isTor: score > 70,
                lastReported: score > 20 ? '2026-02-15' : undefined,
            }))
        }
    }, [])

    const lookupAll = useCallback(() => {
        topIps.forEach(({ src_ip }) => {
            if (!results.has(src_ip)) lookupIp(src_ip)
        })
    }, [topIps, results, lookupIp])

    const handleCustomLookup = useCallback(() => {
        const ip = customIp.trim()
        if (ip) {
            lookupIp(ip)
            setCustomIp('')
        }
    }, [customIp, lookupIp])

    const getScoreColor = (score: number) => {
        if (score >= 75) return 'var(--severity-critical)'
        if (score >= 50) return 'var(--severity-high)'
        if (score >= 25) return 'var(--severity-medium)'
        return 'var(--live-green)'
    }

    const getScoreLabel = (score: number) => {
        if (score >= 75) return 'MALICIOUS'
        if (score >= 50) return 'SUSPICIOUS'
        if (score >= 25) return 'LOW RISK'
        return 'CLEAN'
    }

    return (
        <div className="threat-intel">
            <div className="threat-intel__header">
                <div className="threat-intel__title-row">
                    <span className="threat-intel__title">◈ Threat Intelligence</span>
                    <span className="threat-intel__subtitle">IP Reputation Lookup</span>
                </div>
                <div className="threat-intel__actions">
                    <div className="threat-intel__custom-lookup">
                        <input
                            type="text"
                            value={customIp}
                            onChange={e => setCustomIp(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && handleCustomLookup()}
                            placeholder="Enter IP address..."
                            className="threat-intel__input"
                        />
                        <button onClick={handleCustomLookup} className="threat-intel__btn">
                            Lookup
                        </button>
                    </div>
                    <button onClick={lookupAll} className="threat-intel__btn threat-intel__btn--primary">
                        Enrich All Top IPs
                    </button>
                </div>
            </div>

            <div className="threat-intel__table-wrap">
                <table className="threat-intel__table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Alerts</th>
                            <th>Abuse Score</th>
                            <th>Country / ISP</th>
                            <th>Flags</th>
                            <th>Categories</th>
                            <th>Last Seen</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        {topIps.map(({ src_ip, count }) => {
                            const r = results.get(src_ip)
                            return (
                                <tr key={src_ip} className="threat-intel__row">
                                    <td className="threat-intel__ip mono">{src_ip}</td>
                                    <td className="threat-intel__count">{count.toLocaleString()}</td>
                                    <td>
                                        {!r && (
                                            <button
                                                className="threat-intel__lookup-btn"
                                                onClick={() => lookupIp(src_ip)}
                                            >
                                                Lookup →
                                            </button>
                                        )}
                                        {r?.status === 'loading' && (
                                            <span className="threat-intel__spinner" />
                                        )}
                                        {r?.status === 'done' && (
                                            <div className="threat-intel__score-wrap">
                                                <div
                                                    className="threat-intel__score-bar"
                                                    style={{ '--pct': `${r.abuseScore}%`, '--col': getScoreColor(r.abuseScore!) } as React.CSSProperties}
                                                />
                                                <span className="threat-intel__score-label" style={{ color: getScoreColor(r.abuseScore!) }}>
                                                    {r.abuseScore}/100 · {getScoreLabel(r.abuseScore!)}
                                                </span>
                                            </div>
                                        )}
                                    </td>
                                    <td>
                                        {r?.status === 'done' && (
                                            <span className="threat-intel__geo">
                                                <span className="threat-intel__country">{r.country}</span>
                                                <span className="threat-intel__isp">{r.isp}</span>
                                            </span>
                                        )}
                                    </td>
                                    <td>
                                        {r?.status === 'done' && (
                                            <span className="threat-intel__flags">
                                                {r.isTor && <span className="threat-intel__flag threat-intel__flag--tor">TOR</span>}
                                                {r.isVpn && <span className="threat-intel__flag threat-intel__flag--vpn">VPN</span>}
                                                {!r.isTor && !r.isVpn && <span className="threat-intel__flag threat-intel__flag--clean">—</span>}
                                            </span>
                                        )}
                                    </td>
                                    <td>
                                        {r?.status === 'done' && r.categories && r.categories.length > 0 && (
                                            <div className="threat-intel__cats">
                                                {r.categories.map(c => (
                                                    <span key={c} className="threat-intel__cat">{c}</span>
                                                ))}
                                            </div>
                                        )}
                                    </td>
                                    <td className="threat-intel__last">
                                        {r?.status === 'done' && (r.lastReported ?? <span style={{ color: 'var(--text-muted)' }}>Never</span>)}
                                    </td>
                                    <td>
                                        {r?.status === 'done' && r.abuseScore! > 50 && (
                                            <button className="threat-intel__block-btn">Block</button>
                                        )}
                                    </td>
                                </tr>
                            )
                        })}

                        {/* Custom lookups not in top IPs */}
                        {Array.from(results.entries())
                            .filter(([ip]) => !topIps.some(t => t.src_ip === ip))
                            .map(([ip, r]) => (
                                <tr key={ip} className="threat-intel__row threat-intel__row--custom">
                                    <td className="threat-intel__ip mono">{ip}</td>
                                    <td className="threat-intel__count">—</td>
                                    <td>
                                        {r.status === 'loading' && <span className="threat-intel__spinner" />}
                                        {r.status === 'done' && (
                                            <div className="threat-intel__score-wrap">
                                                <div
                                                    className="threat-intel__score-bar"
                                                    style={{ '--pct': `${r.abuseScore}%`, '--col': getScoreColor(r.abuseScore!) } as React.CSSProperties}
                                                />
                                                <span className="threat-intel__score-label" style={{ color: getScoreColor(r.abuseScore!) }}>
                                                    {r.abuseScore}/100 · {getScoreLabel(r.abuseScore!)}
                                                </span>
                                            </div>
                                        )}
                                    </td>
                                    <td>{r.status === 'done' && <span className="threat-intel__geo"><span className="threat-intel__country">{r.country}</span><span className="threat-intel__isp">{r.isp}</span></span>}</td>
                                    <td>{r.status === 'done' && <span className="threat-intel__flags">{r.isTor && <span className="threat-intel__flag threat-intel__flag--tor">TOR</span>}{r.isVpn && <span className="threat-intel__flag threat-intel__flag--vpn">VPN</span>}{!r.isTor && !r.isVpn && <span className="threat-intel__flag threat-intel__flag--clean">—</span>}</span>}</td>
                                    <td>{r.status === 'done' && r.categories && r.categories.length > 0 && <div className="threat-intel__cats">{r.categories.map(c => <span key={c} className="threat-intel__cat">{c}</span>)}</div>}</td>
                                    <td>{r.status === 'done' && (r.lastReported ?? <span style={{ color: 'var(--text-muted)' }}>Never</span>)}</td>
                                    <td>{r.status === 'done' && r.abuseScore! > 50 && <button className="threat-intel__block-btn">Block</button>}</td>
                                </tr>
                            ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}
