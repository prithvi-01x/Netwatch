import React, { useCallback } from 'react'
import { AlertCard } from './AlertCard'
import { EmptyState } from '../shared/EmptyState'
import type { Alert } from '../../types'
import { exportAlertsCSV, exportAlertsJSON } from '../../utils/export'
import './AlertPanel.css'

interface Props {
    alerts: Alert[]
    isLoading: boolean
    hasMore: boolean
    loadMore: () => void
    acknowledgedIds?: Set<string>
    onAcknowledge?: (id: string) => void
}

function SkeletonRows() {
    return (
        <>
            {Array.from({ length: 5 }, (_, i) => (
                <div className="alert-panel__skeleton" key={i}>
                    <div className="alert-panel__skeleton-bar" style={{ width: 60 }} />
                    <div className="alert-panel__skeleton-bar" style={{ width: 55, marginLeft: 8 }} />
                    <div className="alert-panel__skeleton-bar" style={{ width: 80, marginLeft: 8 }} />
                    <div className="alert-panel__skeleton-bar" style={{ flex: 1, marginLeft: 8 }} />
                </div>
            ))}
        </>
    )
}

export const AlertPanel: React.FC<Props> = React.memo(({ alerts, isLoading, hasMore, loadMore, acknowledgedIds, onAcknowledge }) => {
    const handleExportCSV = useCallback(() => exportAlertsCSV(alerts), [alerts])
    const handleExportJSON = useCallback(() => exportAlertsJSON(alerts), [alerts])

    if (isLoading && alerts.length === 0) {
        return <div className="alert-panel"><SkeletonRows /></div>
    }

    if (!isLoading && alerts.length === 0) {
        return (
            <div className="alert-panel">
                <EmptyState
                    message="No alerts yet — traffic is being monitored"
                    icon="🛡️"
                />
            </div>
        )
    }

    return (
        <div className="alert-panel">
            <div className="alert-panel__toolbar">
                <span className="alert-panel__toolbar-count mono">{alerts.length} alerts</span>
                <div className="alert-panel__toolbar-actions">
                    <button className="alert-panel__export-btn" onClick={handleExportCSV} title="Export as CSV">
                        ↓ CSV
                    </button>
                    <button className="alert-panel__export-btn" onClick={handleExportJSON} title="Export as JSON">
                        ↓ JSON
                    </button>
                </div>
            </div>
            <div className="alert-panel__list-container">
                <div className="alert-panel__scroll">
                    {alerts.map((alert) => (
                        <AlertCard
                            key={alert.alert_id}
                            alert={alert}
                            style={{}}
                            acknowledged={acknowledgedIds?.has(alert.alert_id)}
                            onAcknowledge={onAcknowledge}
                        />
                    ))}
                    {hasMore && (
                        <button
                            onClick={loadMore}
                            disabled={isLoading}
                            className="alert-panel__load-more"
                        >
                            {isLoading ? 'Loading...' : 'Load More'}
                        </button>
                    )}
                </div>
            </div>
        </div>
    )
})