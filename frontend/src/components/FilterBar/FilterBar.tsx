import React, { useCallback, useRef, useEffect, useMemo } from 'react'
import { useAlertStore } from '../../store/alertStore'
import type { Severity, StatsResponse } from '../../types'
import './FilterBar.css'

interface Props {
    stats: StatsResponse | null
}

const SEVERITIES: Array<Severity | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const TIME_RANGES = [
    { label: 'All time', value: null },
    { label: 'Last 5 min', value: 300 },
    { label: 'Last 1 hour', value: 3600 },
    { label: 'Last 24 hours', value: 86400 },
]

export const FilterBar: React.FC<Props> = React.memo(({ stats }) => {
    const { filters, setFilters, clearFilters } = useAlertStore()
    const debounceRef = useRef<ReturnType<typeof setTimeout>>()

    const ruleNames = useMemo(() => {
        if (!stats?.alerts_by_rule) return []
        return Object.keys(stats.alerts_by_rule).sort()
    }, [stats?.alerts_by_rule])

    const handleSeverity = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
        setFilters({ severity: e.target.value as Severity | 'ALL' })
    }, [setFilters])

    const handleRule = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
        setFilters({ rule_name: e.target.value })
    }, [setFilters])

    const handleSrcIp = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        const val = e.target.value
        if (debounceRef.current) clearTimeout(debounceRef.current)
        debounceRef.current = setTimeout(() => setFilters({ src_ip: val }), 500)
    }, [setFilters])

    const handleTime = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
        const secs = e.target.value ? Number(e.target.value) : null
        const since = secs ? Date.now() / 1000 - secs : null
        setFilters({ since })
    }, [setFilters])

    useEffect(() => {
        return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
    }, [])

    const activeCount = [
        filters.severity !== 'ALL',
        filters.rule_name !== 'ALL',
        !!filters.src_ip,
        filters.since !== null,
    ].filter(Boolean).length

    return (
        <div className="filter-bar">
            <select value={filters.severity} onChange={handleSeverity}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>

            <select value={filters.rule_name} onChange={handleRule}>
                <option value="ALL">All Rules</option>
                {ruleNames.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>

            <input
                type="text"
                placeholder="Source IP..."
                defaultValue={filters.src_ip}
                onChange={handleSrcIp}
            />

            <select onChange={handleTime} defaultValue="">
                {TIME_RANGES.map((t) => (
                    <option key={t.label} value={t.value ?? ''}>{t.label}</option>
                ))}
            </select>

            {activeCount > 0 && (
                <>
                    <button className="filter-bar__clear" onClick={clearFilters}>
                        Clear
                    </button>
                    <span className="filter-bar__badge">{activeCount} filter{activeCount > 1 ? 's' : ''} active</span>
                </>
            )}
        </div>
    )
})
