import { useState, useCallback } from 'react'
import { useWebSocket } from '../api/websocket'
import type { FlowRecord } from '../types'

interface FlowsMessage {
    flows: FlowRecord[]
    timestamp: number
}

export function useFlows() {
    const [flows, setFlows] = useState<FlowRecord[]>([])
    const [lastUpdate, setLastUpdate] = useState<number>(0)

    const handleMessage = useCallback((data: FlowsMessage) => {
        setFlows(data.flows || [])
        setLastUpdate(data.timestamp || Date.now() / 1000)
    }, [])

    const { isConnected } = useWebSocket<FlowsMessage>({
        url: '/ws/flows',
        onMessage: handleMessage,
    })

    return { flows, lastUpdate, isLive: isConnected }
}
