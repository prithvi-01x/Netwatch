import { create } from 'zustand'
import type { Alert, FilterState } from '../types'

const MAX_ALERTS = 500

const DEFAULT_FILTERS: FilterState = {
    severity: 'ALL',
    rule_name: 'ALL',
    src_ip: '',
    since: null,
}

interface AlertStore {
    alerts: Alert[]
    totalCount: number
    isLoading: boolean
    error: string | null
    filters: FilterState

    addAlert: (alert: Alert) => void
    setAlerts: (alerts: Alert[], total: number) => void
    setFilters: (filters: Partial<FilterState>) => void
    clearFilters: () => void
    setLoading: (loading: boolean) => void
    setError: (error: string | null) => void
}

export const useAlertStore = create<AlertStore>((set) => ({
    alerts: [],
    totalCount: 0,
    isLoading: false,
    error: null,
    filters: { ...DEFAULT_FILTERS },

    // WS live alert — prepend if not already present, cap at MAX_ALERTS
    addAlert: (alert) =>
        set((state) => {
            if (state.alerts.some((a) => a.alert_id === alert.alert_id)) return state
            const next = [alert, ...state.alerts].slice(0, MAX_ALERTS)
            return { alerts: next, totalCount: state.totalCount + 1 }
        }),

    // REST page result — authoritative: replace the list entirely, then
    // re-prepend any WS-injected alerts newer than the newest REST alert
    // (those haven't been persisted/returned by REST yet).
    setAlerts: (restAlerts, total) =>
        set((state) => {
            const restIds = new Set(restAlerts.map((a) => a.alert_id))

            // WS alerts that REST hasn't returned: only keep ones newer than
            // the oldest REST alert, so we don't accumulate infinite orphans.
            const newestRestTs = restAlerts[0]?.timestamp ?? 0
            const wsOnlyRecent = state.alerts.filter(
                (a) => !restIds.has(a.alert_id) && a.timestamp >= newestRestTs,
            )

            const merged = [...wsOnlyRecent, ...restAlerts].slice(0, MAX_ALERTS)
            return { alerts: merged, totalCount: total, isLoading: false, error: null }
        }),

    setFilters: (partial) => set((state) => ({ filters: { ...state.filters, ...partial } })),
    clearFilters: () => set({ filters: { ...DEFAULT_FILTERS } }),
    setLoading: (loading) => set({ isLoading: loading }),
    setError: (error) => set({ error }),
}))