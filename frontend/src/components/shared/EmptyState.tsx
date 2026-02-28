import React from 'react'

interface Props {
    message: string
    icon?: string
}

export const EmptyState: React.FC<Props> = React.memo(({ message, icon = '🔍' }) => (
    <div
        style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 'var(--space-xl)',
            color: 'var(--text-muted)',
            gap: 'var(--space-md)',
            minHeight: 200,
        }}
    >
        <span style={{ fontSize: '2rem' }}>{icon}</span>
        <span style={{ fontSize: '0.9rem', textAlign: 'center' }}>{message}</span>
    </div>
))
