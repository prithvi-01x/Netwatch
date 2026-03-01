import type { Alert } from '../types'
import { format } from 'date-fns'

export function exportAlertsCSV(alerts: Alert[], filename?: string) {
    const headers = [
        'alert_id', 'timestamp', 'severity', 'rule_name',
        'src_ip', 'dst_ip', 'confidence', 'description',
        'attack_phase', 'recommended_action',
    ]

    const rows = alerts.map(a => [
        a.alert_id,
        format(new Date(a.timestamp * 1000), 'yyyy-MM-dd HH:mm:ss'),
        a.severity,
        a.rule_name,
        a.src_ip,
        a.dst_ip,
        (a.confidence * 100).toFixed(0) + '%',
        `"${a.description.replace(/"/g, '""')}"`,
        a.llm_explanation?.attack_phase ?? '',
        `"${(a.llm_explanation?.recommended_action ?? '').replace(/"/g, '""')}"`,
    ])

    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    downloadFile(csv, filename ?? `netwatch_alerts_${format(new Date(), 'yyyyMMdd_HHmmss')}.csv`, 'text/csv')
}

export function exportAlertsJSON(alerts: Alert[], filename?: string) {
    const json = JSON.stringify(alerts, null, 2)
    downloadFile(json, filename ?? `netwatch_alerts_${format(new Date(), 'yyyyMMdd_HHmmss')}.json`, 'application/json')
}

function downloadFile(content: string, filename: string, mimeType: string) {
    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
}