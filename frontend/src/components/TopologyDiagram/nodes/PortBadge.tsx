import React from 'react'
import type { PortInfo } from '../types'

interface Props {
    port: PortInfo
    isActive: boolean
}

const PortBadge: React.FC<Props> = ({ port, isActive }) => {
    const stateClass = port.state === 'open'
        ? isActive ? 'port-badge--active' : 'port-badge--open'
        : port.state === 'closed'
            ? 'port-badge--closed'
            : 'port-badge--filtered'

    return (
        <div className={`port-badge ${stateClass}`}>
            {isActive && <span className="port-badge__pulse" />}
            <span className="port-badge__number">:{port.port}</span>
            <span className={`port-badge__service ${port.state === 'closed' ? 'port-badge__service--closed' : ''}`}>
                {port.service}
            </span>
            <span className="port-badge__proto">{port.protocol.toUpperCase()}</span>
            {port.state === 'filtered' && <span className="port-badge__icon">?</span>}
        </div>
    )
}

export default React.memo(PortBadge)