import { useEffect, useRef, useState, useCallback } from 'react'

interface UseWebSocketOptions<T> {
    url: string
    onMessage: (data: T) => void
    enabled?: boolean
    baseReconnectDelayMs?: number   // first retry delay (doubles each attempt)
    maxReconnectDelayMs?: number    // cap on how long to wait between retries
}

export function useWebSocket<T>({
    url,
    onMessage,
    enabled = true,
    baseReconnectDelayMs = 1000,
    maxReconnectDelayMs = 30_000,   // never wait more than 30s between retries
}: UseWebSocketOptions<T>) {
    const wsRef             = useRef<WebSocket | null>(null)
    const reconnectTimerRef = useRef<ReturnType<typeof setTimeout>>()
    const attemptRef        = useRef(0)          // how many consecutive failures
    const mountedRef        = useRef(true)
    const onMessageRef      = useRef(onMessage)
    onMessageRef.current    = onMessage

    const [isConnected,   setIsConnected]   = useState(false)
    const [reconnectCount, setReconnectCount] = useState(0)

    const scheduleReconnect = useCallback((connectFn: () => void) => {
        // Exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s (capped)
        const delay = Math.min(
            baseReconnectDelayMs * 2 ** attemptRef.current,
            maxReconnectDelayMs,
        )
        attemptRef.current += 1
        setReconnectCount(attemptRef.current)
        reconnectTimerRef.current = setTimeout(connectFn, delay)
    }, [baseReconnectDelayMs, maxReconnectDelayMs])

    const connect = useCallback(() => {
        if (!mountedRef.current || !enabled) return

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl    = `${protocol}//${window.location.host}${url}`

        try {
            const ws     = new WebSocket(wsUrl)
            wsRef.current = ws

            ws.onopen = () => {
                if (!mountedRef.current) return
                setIsConnected(true)
                attemptRef.current = 0          // reset backoff on successful connect
                setReconnectCount(0)
            }

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data) as T
                    onMessageRef.current(data)
                } catch {
                    // ignore non-JSON frames
                }
            }

            ws.onclose = () => {
                if (!mountedRef.current) return
                setIsConnected(false)
                wsRef.current = null
                // Always retry — no hard cap. Monitoring tools must stay connected.
                scheduleReconnect(connect)
            }

            ws.onerror = () => {
                ws.close()  // triggers onclose which handles retry
            }
        } catch {
            // new WebSocket() itself threw (rare) — still retry
            scheduleReconnect(connect)
        }
    }, [url, enabled, scheduleReconnect])

    const disconnect = useCallback(() => {
        if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
        mountedRef.current = false
        if (wsRef.current) {
            wsRef.current.close()
            wsRef.current = null
        }
        setIsConnected(false)
    }, [])

    useEffect(() => {
        mountedRef.current = true
        if (enabled) connect()
        return () => {
            mountedRef.current = false
            if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
            if (wsRef.current) {
                wsRef.current.close()
                wsRef.current = null
            }
        }
    }, [connect, enabled])

    return { isConnected, reconnectCount, disconnect }
}