import React, { useMemo } from 'react'
import {
    LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
    AreaChart, Area, Legend,
} from 'recharts'
import { format } from 'date-fns'
import type { TrafficDataPoint, StatsResponse } from '../../types'
import './TrafficCharts.css'

interface Props {
    trafficHistory: TrafficDataPoint[]
    stats: StatsResponse | null
}

export const TrafficCharts: React.FC<Props> = React.memo(({ trafficHistory, stats }) => {
    const chartData = useMemo(
        () =>
            trafficHistory.map((p) => ({
                time: format(new Date(p.timestamp * 1000), 'HH:mm:ss'),
                packets: p.packets_seen ?? 0,
                dropped: p.packets_dropped ?? 0,
                flows: p.flows_active ?? 0,
                alerts: p.alerts_fired ?? 0,
            })),
        [trafficHistory]
    )

    const alertsByRule = stats?.alerts_by_rule ?? {}
    const alertsBySeverity = stats?.alerts_by_severity ?? {}
    const topIps = stats?.top_src_ips ?? []

    return (
        <div className="traffic-charts">
            {/* Chart 1 — Packets over time */}
            <div className="traffic-charts__panel">
                <div className="traffic-charts__title">Pipeline Activity</div>
                <ResponsiveContainer width="100%" height={180}>
                    <LineChart data={chartData}>
                        <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#8b949e' }} />
                        <YAxis tick={{ fontSize: 10, fill: '#8b949e' }} width={50} />
                        <Tooltip
                            contentStyle={{
                                background: '#161b22',
                                border: '1px solid #30363d',
                                borderRadius: 6,
                                fontSize: 12,
                            }}
                        />
                        <Line
                            type="monotone"
                            dataKey="packets"
                            stroke="var(--protocol-tcp)"
                            strokeWidth={2}
                            dot={false}
                            isAnimationActive={false}
                        />
                        <Line
                            type="monotone"
                            dataKey="flows"
                            stroke="var(--protocol-udp)"
                            strokeWidth={2}
                            dot={false}
                            isAnimationActive={false}
                        />
                    </LineChart>
                </ResponsiveContainer>
            </div>

            {/* Chart 2 — Alerts + Dropped */}
            <div className="traffic-charts__panel">
                <div className="traffic-charts__title">Alerts & Drops</div>
                <ResponsiveContainer width="100%" height={180}>
                    <AreaChart data={chartData}>
                        <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#8b949e' }} />
                        <YAxis tick={{ fontSize: 10, fill: '#8b949e' }} width={50} />
                        <Tooltip
                            contentStyle={{
                                background: '#161b22',
                                border: '1px solid #30363d',
                                borderRadius: 6,
                                fontSize: 12,
                            }}
                        />
                        <Area
                            type="monotone"
                            dataKey="alerts"
                            stackId="1"
                            stroke="var(--severity-critical)"
                            fill="var(--severity-critical)"
                            fillOpacity={0.3}
                            isAnimationActive={false}
                        />
                        <Area
                            type="monotone"
                            dataKey="dropped"
                            stackId="1"
                            stroke="var(--severity-medium)"
                            fill="var(--severity-medium)"
                            fillOpacity={0.2}
                            isAnimationActive={false}
                        />
                        <Legend
                            wrapperStyle={{ fontSize: 11, color: '#8b949e' }}
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>

            {/* Breakdown cards */}
            <div className="traffic-charts__breakdown">
                <div className="traffic-charts__breakdown-card">
                    <h4>Alerts by Rule</h4>
                    <ul className="traffic-charts__breakdown-list">
                        {Object.entries(alertsByRule).map(([rule, count]) => (
                            <li key={rule}>
                                <span>{rule}</span>
                                <span>{count as number}</span>
                            </li>
                        ))}
                        {!Object.keys(alertsByRule).length && (
                            <li><span style={{ color: 'var(--text-muted)' }}>No data</span><span /></li>
                        )}
                    </ul>
                </div>
                <div className="traffic-charts__breakdown-card">
                    <h4>Top Source IPs</h4>
                    <ul className="traffic-charts__breakdown-list">
                        {topIps.slice(0, 5).map((ip) => (
                            <li key={ip.src_ip}>
                                <span>{ip.src_ip}</span>
                                <span>{ip.count}</span>
                            </li>
                        ))}
                        {!topIps.length && (
                            <li><span style={{ color: 'var(--text-muted)' }}>No data</span><span /></li>
                        )}
                    </ul>
                </div>
            </div>
        </div>
    )
})
