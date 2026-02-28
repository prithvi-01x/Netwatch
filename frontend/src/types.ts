export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type LLMConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNCERTAIN'

export type AttackPhase =
    | 'reconnaissance'
    | 'initial-access'
    | 'lateral-movement'
    | 'exfiltration'
    | 'c2'
    | 'unknown'

export interface LLMExplanation {
    summary: string
    severity_reasoning: string
    recommended_action: string
    ioc_tags: string[]
    attack_phase: AttackPhase
    llm_confidence: LLMConfidence
    fallback_used: boolean
}

export interface Alert {
    alert_id: string
    timestamp: number
    rule_name: string
    severity: Severity
    confidence: number
    src_ip: string
    dst_ip: string
    description: string
    evidence: Record<string, unknown>
    window_start: number
    window_end: number
    window_size_seconds: number
    llm_explanation?: LLMExplanation
}

export interface FlowRecord {
    src_ip: string
    dst_ip: string
    src_port: number
    dst_port: number
    protocol: string
    packets: number
    bytes: number
    pps: number
}

export interface TrafficDataPoint {
    timestamp: number
    packets_seen: number
    packets_dropped: number
    flows_active: number
    alerts_fired: number
    windows_analyzed: number
}

export interface PipelineStats {
    packets_seen: number
    packets_dropped: number
    flows_active: number
    alerts_fired: number
    windows_analyzed: number
}

export interface StatsResponse {
    total_alerts: number
    alerts_last_hour: number
    alerts_by_severity: Record<string, number>
    alerts_by_rule: Record<string, number>
    top_src_ips: Array<{ src_ip: string; count: number }>
    latest_alert_timestamp: number | null
    pipeline_stats: Record<string, unknown>
}

export interface FilterState {
    severity: Severity | 'ALL'
    rule_name: string
    src_ip: string
    since: number | null
}

export interface GraphNode {
    id: string
    type: 'attacker' | 'victim'
    alert_count: number
    max_severity: Severity
    rules: string[]
    last_seen: number
    // D3 simulation fields (added at runtime)
    x?: number
    y?: number
    vx?: number
    vy?: number
    fx?: number | null
    fy?: number | null
}

export interface GraphEdge {
    source: string | GraphNode
    target: string | GraphNode
    rule_name: string
    severity: Severity
    confidence: number
    count: number
    last_seen: number
    first_seen: number
}

export interface GraphData {
    nodes: GraphNode[]
    edges: GraphEdge[]
}

export interface PaginatedAlerts {
    items: Alert[]
    total: number
    limit: number
    offset: number
    has_more: boolean
}
