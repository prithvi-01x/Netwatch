import React from 'react'
import type { Severity } from '../../types'

const COLORS: Record<Severity, string> = {
    CRITICAL: 'var(--severity-critical)',
    HIGH: 'var(--severity-high)',
    MEDIUM: 'var(--severity-medium)',
    LOW: 'var(--severity-low)',
}

const TEXT_COLORS: Record<Severity, string> = {
    CRITICAL: '#fff',
    HIGH: '#fff',
    MEDIUM: '#000',
    LOW: '#fff',
}

interface Props {
    severity: Severity
    size?: 'sm' | 'md'
}

export const SeverityBadge: React.FC<Props> = React.memo(({ severity, size = 'md' }) => {
    const px = size === 'sm' ? '6px 8px' : '4px 12px'
    const fontSize = size === 'sm' ? '0.7rem' : '0.75rem'

    return (
        <span
            style={{
                display: 'inline-block',
                padding: px,
                borderRadius: '12px',
                fontSize,
                fontWeight: 600,
                fontFamily: 'var(--font-mono)',
                background: COLORS[severity],
                color: TEXT_COLORS[severity],
                lineHeight: 1,
                letterSpacing: '0.5px',
                textTransform: 'uppercase',
                whiteSpace: 'nowrap',
            }}
        >
            {severity}
        </span>
    )
})
