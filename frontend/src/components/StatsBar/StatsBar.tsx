import React from 'react'
import type { StatsResponse } from '../../types'
import './StatsBar.css'

interface Props {
    stats: StatsResponse | null
}

export const StatsBar: React.FC<Props> = React.memo(({ stats }) => {
    const pipeline = (stats?.pipeline_stats ?? {}) as Record<string, number>
    const packetsSeen = pipeline.packets_seen ?? 0
    const flowsActive = pipeline.flows_active ?? 0
    const alertsHour = stats?.alerts_last_hour ?? 0
    const dropped = pipeline.packets_dropped ?? 0
    const dropRate = packetsSeen > 0 ? (dropped / packetsSeen) * 100 : 0

    const alertClass = alertsHour > 10 ? 'danger' : alertsHour > 0 ? 'warning' : 'neutral'
    const dropClass = dropRate > 1 ? 'danger' : 'neutral'

    return (
        <div className="stats-bar">
            <div className="stat-card">
                <span className="stat-card__label">Packets Seen</span>
                <span className="stat-card__value stat-card__value--neutral">
                    {packetsSeen.toLocaleString()}
                </span>
            </div>
            <div className="stat-card">
                <span className="stat-card__label">Active Flows</span>
                <span className="stat-card__value stat-card__value--info">
                    {flowsActive.toLocaleString()}
                </span>
            </div>
            <div className="stat-card">
                <span className="stat-card__label">Alerts (1h)</span>
                <span className={`stat-card__value stat-card__value--${alertClass}`}>
                    {alertsHour}
                </span>
            </div>
            <div className="stat-card">
                <span className="stat-card__label">Drop Rate</span>
                <span className={`stat-card__value stat-card__value--${dropClass}`}>
                    {dropRate.toFixed(2)}%
                </span>
            </div>
        </div>
    )
})
