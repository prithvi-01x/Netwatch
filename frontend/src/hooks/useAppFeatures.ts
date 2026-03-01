import { useState, useCallback, useEffect, useRef } from 'react'
import type { Alert } from '../types'

// ─── Sound ───────────────────────────────────────────────────────────────────
function playAlertBeep() {
    try {
        const ctx = new (window.AudioContext || (window as any).webkitAudioContext)()
        const osc = ctx.createOscillator()
        const gain = ctx.createGain()
        osc.connect(gain)
        gain.connect(ctx.destination)
        osc.type = 'sine'
        osc.frequency.setValueAtTime(880, ctx.currentTime)
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.15)
        gain.gain.setValueAtTime(0.3, ctx.currentTime)
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3)
        osc.start(ctx.currentTime)
        osc.stop(ctx.currentTime + 0.3)
    } catch { /* ignore if AudioContext not available */ }
}

// ─── Notifications ────────────────────────────────────────────────────────────
async function requestNotificationPermission(): Promise<boolean> {
    if (!('Notification' in window)) return false
    if (Notification.permission === 'granted') return true
    const perm = await Notification.requestPermission()
    return perm === 'granted'
}

function sendNotification(alert: Alert) {
    if (Notification.permission !== 'granted') return
    new Notification(`⚠ NetWatch — ${alert.severity} Alert`, {
        body: `${alert.rule_name}: ${alert.src_ip} → ${alert.dst_ip}\n${alert.description}`,
        icon: '/favicon.ico',
        tag: alert.alert_id,
    })
}

// ─── Theme ────────────────────────────────────────────────────────────────────
function applyTheme(theme: 'dark' | 'light') {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('netwatch_theme', theme)
}

// ─── Hook ────────────────────────────────────────────────────────────────────
export function useAppFeatures(alerts: Alert[]) {
    const [soundEnabled, setSoundEnabled] = useState(() =>
        localStorage.getItem('netwatch_sound') !== 'false'
    )
    const [notificationsEnabled, setNotificationsEnabled] = useState(() =>
        localStorage.getItem('netwatch_notifications') === 'true'
    )
    const [theme, setTheme] = useState<'dark' | 'light'>(() => {
        const stored = localStorage.getItem('netwatch_theme')
        return (stored === 'light' ? 'light' : 'dark')
    })
    const [acknowledgedIds, setAcknowledgedIds] = useState<Set<string>>(() => {
        try {
            const stored = localStorage.getItem('netwatch_acknowledged')
            return new Set(stored ? JSON.parse(stored) : [])
        } catch { return new Set() }
    })
    const [ollamaModel, setOllamaModel] = useState(() =>
        localStorage.getItem('netwatch_model') ?? 'phi3:3.8b'
    )

    const lastAlertIdRef = useRef<string | null>(null)

    // Apply theme on mount and change
    useEffect(() => {
        applyTheme(theme)
    }, [theme])

    // Watch for new CRITICAL alerts
    useEffect(() => {
        if (!alerts.length) return
        const newest = alerts[0]
        if (!newest || newest.alert_id === lastAlertIdRef.current) return
        lastAlertIdRef.current = newest.alert_id

        if (newest.severity === 'CRITICAL') {
            if (soundEnabled) playAlertBeep()
            if (notificationsEnabled) sendNotification(newest)
        }
    }, [alerts, soundEnabled, notificationsEnabled])

    const toggleSound = useCallback(() => {
        setSoundEnabled(prev => {
            const next = !prev
            localStorage.setItem('netwatch_sound', String(next))
            if (next) playAlertBeep() // preview beep
            return next
        })
    }, [])

    const toggleNotifications = useCallback(async () => {
        if (!notificationsEnabled) {
            const granted = await requestNotificationPermission()
            if (granted) {
                setNotificationsEnabled(true)
                localStorage.setItem('netwatch_notifications', 'true')
            } else {
                alert('Browser notifications were denied. Please allow them in your browser settings.')
            }
        } else {
            setNotificationsEnabled(false)
            localStorage.setItem('netwatch_notifications', 'false')
        }
    }, [notificationsEnabled])

    const toggleTheme = useCallback(() => {
        setTheme(prev => {
            const next = prev === 'dark' ? 'light' : 'dark'
            applyTheme(next)
            return next
        })
    }, [])

    const acknowledgeAlert = useCallback((id: string) => {
        setAcknowledgedIds(prev => {
            const next = new Set(prev)
            next.add(id)
            localStorage.setItem('netwatch_acknowledged', JSON.stringify([...next]))
            return next
        })
    }, [])

    const unacknowledgeAlert = useCallback((id: string) => {
        setAcknowledgedIds(prev => {
            const next = new Set(prev)
            next.delete(id)
            localStorage.setItem('netwatch_acknowledged', JSON.stringify([...next]))
            return next
        })
    }, [])

    const changeModel = useCallback((model: string) => {
        setOllamaModel(model)
        localStorage.setItem('netwatch_model', model)
    }, [])

    return {
        soundEnabled, toggleSound,
        notificationsEnabled, toggleNotifications,
        theme, toggleTheme,
        acknowledgedIds, acknowledgeAlert, unacknowledgeAlert,
        ollamaModel, changeModel,
    }
}