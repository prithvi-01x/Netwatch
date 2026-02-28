import type { PaginatedAlerts, Alert, StatsResponse, TrafficDataPoint } from '../types'
import type { TopologyResponse, PortInfo } from '../components/TopologyDiagram/types'

export interface HostPortsResponse {
    ports: PortInfo[]
    source: string
}

export interface HostInfoResponse {
    ip: string
    interface: string
    all_interfaces: Record<string, string>
}

const BASE = '/api'

class ApiError extends Error {
    constructor(public status: number, message: string) {
        super(message)
        this.name = 'ApiError'
    }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
    const res = await fetch(url, init)
    if (!res.ok) {
        const text = await res.text().catch(() => res.statusText)
        throw new ApiError(res.status, text)
    }
    return res.json()
}

function qs(params: Record<string, string | number | undefined | null>): string {
    const entries = Object.entries(params).filter(([, v]) => v != null && v !== '' && v !== 'ALL')
    if (!entries.length) return ''
    return '?' + entries.map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join('&')
}

export async function fetchAlerts(params: {
    limit?: number
    offset?: number
    severity?: string
    rule_name?: string
    src_ip?: string
    since?: number
} = {}): Promise<PaginatedAlerts> {
    return request<PaginatedAlerts>(`${BASE}/alerts${qs(params)}`)
}

export async function fetchAlertById(id: string): Promise<Alert> {
    return request<Alert>(`${BASE}/alerts/${id}`)
}

export async function fetchStats(): Promise<StatsResponse> {
    return request<StatsResponse>(`${BASE}/stats`)
}

export async function fetchStatsHistory(limit = 60): Promise<TrafficDataPoint[]> {
    return request<TrafficDataPoint[]>(`${BASE}/stats/history?limit=${limit}`)
}

export async function fetchDockerTopology(): Promise<TopologyResponse> {
    return request<TopologyResponse>(`${BASE}/docker/topology`)
}

export async function fetchHostPorts(): Promise<HostPortsResponse> {
    return request<HostPortsResponse>(`${BASE}/host/ports`)
}

export async function fetchHostInfo(): Promise<HostInfoResponse> {
    return request<HostInfoResponse>(`${BASE}/host/info`)
}

export async function fetchGraph(since?: number, limit = 500): Promise<import('../types').GraphData> {
    const params: Record<string, number | undefined> = { limit }
    if (since !== undefined) params.since = since
    return request(`${BASE}/graph${qs(params)}`)
}

export { ApiError }