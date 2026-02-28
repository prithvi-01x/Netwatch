import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchStats, fetchStatsHistory } from '../api/client'
import { useWebSocket } from '../api/websocket'
import type { StatsResponse, TrafficDataPoint } from '../types'

const MAX_HISTORY = 60
const REST_FALLBACK_MS = 60_000   // only hit REST if WS has been silent for 60s

export function useStats() {
    const [stats, setStats] = useState<StatsResponse | null>(null)
    const [trafficHistory, setTrafficHistory] = useState<TrafficDataPoint[]>([])
    const [isLoading, setIsLoading] = useState(true)
    const lastWsUpdateRef = useRef<number>(0)

    // Initial load from REST
    useEffect(() => {
        let cancelled = false
        Promise.all([fetchStats(), fetchStatsHistory(MAX_HISTORY)])
            .then(([s, h]) => {
                if (cancelled) return
                setStats(s)
                setTrafficHistory(h)
                setIsLoading(false)
            })
            .catch(() => { if (!cancelled) setIsLoading(false) })
        return () => { cancelled = true }
    }, [])

    // REST fallback: only fires if the WS has been silent for REST_FALLBACK_MS.
    // Previously this ran on EVERY ws message — one REST call per 5-second tick.
    useEffect(() => {
        const interval = setInterval(() => {
            const silentFor = Date.now() - lastWsUpdateRef.current
            if (silentFor >= REST_FALLBACK_MS) {
                fetchStats().then(setStats).catch(() => { })
            }
        }, REST_FALLBACK_MS)
        return () => clearInterval(interval)
    }, [])

    // WS live stats — just update local state, no extra REST call
    const handleWsMessage = useCallback((data: TrafficDataPoint) => {
        lastWsUpdateRef.current = Date.now()
        setTrafficHistory(prev => [...prev, data].slice(-MAX_HISTORY))

        // The WS stats message carries pipeline counters but not the full
        // StatsResponse. We merge what we can so the stats bar stays live
        // without an extra round-trip.
        setStats(prev => {
            if (!prev) return prev
            const pipeline = prev.pipeline_stats as Record<string, unknown>
            return {
                ...prev,
                pipeline_stats: {
                    ...pipeline,
                    packets_seen: data.packets_seen ?? pipeline.packets_seen,
                    packets_dropped: data.packets_dropped ?? pipeline.packets_dropped,
                    flows_active: data.flows_active ?? pipeline.flows_active,
                    alerts_fired: data.alerts_fired ?? pipeline.alerts_fired,
                    windows_analyzed: data.windows_analyzed ?? pipeline.windows_analyzed,
                },
            }
        })
    }, [])

    const { isConnected } = useWebSocket<TrafficDataPoint>({
        url: '/ws/stats',
        onMessage: handleWsMessage,
    })

    return { stats, trafficHistory, isLoading, isLive: isConnected }
}