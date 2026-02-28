import React from 'react'

interface Props {
    isLive: boolean
    label?: string
}

export const LiveIndicator: React.FC<Props> = React.memo(({ isLive, label }) => (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
        <span
            style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: isLive ? 'var(--live-green)' : 'var(--dead-gray)',
                boxShadow: isLive ? '0 0 6px var(--live-green)' : 'none',
                animation: isLive ? 'pulse 2s infinite' : 'none',
            }}
        />
        <span style={{ color: isLive ? 'var(--live-green)' : 'var(--text-muted)' }}>
            {label ?? (isLive ? 'Live' : 'Disconnected')}
        </span>
        <style>{`
      @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.4; }
      }
    `}</style>
    </span>
))
