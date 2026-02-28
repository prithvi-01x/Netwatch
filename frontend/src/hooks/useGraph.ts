import { useState, useEffect, useCallback, useRef } from 'react'
import { fetchGraph } from '../api/client'
import type { GraphData, GraphNode, GraphEdge } from '../types'

const POLL_INTERVAL_MS = 5000

export type TimeWindow = '15m' | '1h' | '6h' | '24h' | 'all'

const WINDOW_SECONDS: Record<TimeWindow, number | null> = {
    '15m': 900,
    '1h':  3600,
    '6h':  21600,
    '24h': 86400,
    'all': null,
}

export function useGraph(timeWindow: TimeWindow = '1h') {
    const [data, setData]       = useState<GraphData>({ nodes: [], edges: [] })
    const [isLoading, setIsLoading] = useState(true)
    const [error, setError]     = useState<string | null>(null)
    const [lastFetch, setLastFetch] = useState(0)
    const mountedRef            = useRef(true)

    const load = useCallback(async () => {
        const windowSec = WINDOW_SECONDS[timeWindow]
        const since = windowSec !== null ? Date.now() / 1000 - windowSec : undefined
        try {
            const result = await fetchGraph(since)
            if (!mountedRef.current) return
            setData(result)
            setError(null)
            setLastFetch(Date.now() / 1000)
        } catch (e) {
            if (mountedRef.current) setError(String(e))
        } finally {
            if (mountedRef.current) setIsLoading(false)
        }
    }, [timeWindow])

    useEffect(() => {
        mountedRef.current = true
        setIsLoading(true)
        load()
        const id = setInterval(load, POLL_INTERVAL_MS)
        return () => {
            mountedRef.current = false
            clearInterval(id)
        }
    }, [load])

    return { data, isLoading, error, lastFetch, refresh: load }
}
