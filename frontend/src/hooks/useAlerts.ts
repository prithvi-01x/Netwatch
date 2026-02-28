import { useCallback, useEffect, useRef } from 'react'
import { fetchAlerts } from '../api/client'
import { useWebSocket } from '../api/websocket'
import { useAlertStore } from '../store/alertStore'
import type { Alert } from '../types'

const PAGE_SIZE = 50

export function useAlerts() {
    // Select individual primitives — not the store object — so hooks only
    // re-run when the specific value changes, not on every store mutation.
    const alerts = useAlertStore((s) => s.alerts)
    const totalCount = useAlertStore((s) => s.totalCount)
    const isLoading = useAlertStore((s) => s.isLoading)
    const error = useAlertStore((s) => s.error)
    const filters = useAlertStore((s) => s.filters)
    const addAlert = useAlertStore((s) => s.addAlert)
    const setAlerts = useAlertStore((s) => s.setAlerts)
    const setLoading = useAlertStore((s) => s.setLoading)
    const setError = useAlertStore((s) => s.setError)

    const offsetRef = useRef(0)

    // Build query params from current filters
    const filterParams = useCallback(() => ({
        severity: filters.severity !== 'ALL' ? filters.severity : undefined,
        rule_name: filters.rule_name !== 'ALL' ? filters.rule_name : undefined,
        src_ip: filters.src_ip || undefined,
        since: filters.since ?? undefined,
    }), [filters.severity, filters.rule_name, filters.src_ip, filters.since])

    // Fetch first page whenever filters change
    useEffect(() => {
        let cancelled = false
        offsetRef.current = 0
        setLoading(true)

        fetchAlerts({ limit: PAGE_SIZE, ...filterParams() })
            .then((data) => {
                if (cancelled) return
                setAlerts(data.items, data.total)
                offsetRef.current = data.items.length
            })
            .catch((err) => {
                if (!cancelled) setError(String(err))
            })

        return () => { cancelled = true }
        // filterParams is stable as long as filter values don't change
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [filters.severity, filters.rule_name, filters.src_ip, filters.since])

    // WebSocket live alerts
    const { isConnected } = useWebSocket<Alert>({
        url: '/ws/alerts',
        onMessage: addAlert,   // addAlert is a stable zustand action reference
    })

    // Load next page — deps are all stable primitives or refs
    const loadMore = useCallback(() => {
        if (isLoading) return
        setLoading(true)

        fetchAlerts({ limit: PAGE_SIZE, offset: offsetRef.current, ...filterParams() })
            .then((data) => {
                setAlerts([...alerts, ...data.items], data.total)
                offsetRef.current += data.items.length
            })
            .catch((err) => setError(String(err)))
        // alerts is needed to build the merged list; filterParams is memoized above
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [isLoading, alerts, filterParams])

    return {
        alerts,
        totalCount,
        isLoading,
        error,
        hasMore: alerts.length < totalCount,
        loadMore,
        isLive: isConnected,
    }
}