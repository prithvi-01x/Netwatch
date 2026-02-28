import React, { useState } from 'react'
import type { PortInfo } from '../types'
import PortBadge from './PortBadge'

interface Props {
    hostIp: string
    interfaceName: string
    ports: PortInfo[]
    activePorts: Set<number>
}

const HostNode: React.FC<Props> = ({ hostIp, interfaceName, ports, activePorts }) => {
    const [expanded, setExpanded] = useState(false)

    const openPorts = ports.filter(p => p.state === 'open')
    const closedPorts = ports.filter(p => p.state === 'closed')

    // Show open ports always; closed ports only when expanded
    const visiblePorts = expanded ? ports : openPorts

    const hasMore = closedPorts.length > 0

    return (
        <div className="topo-node topo-node--host">
            <div className="topo-node__header">
                <span className="topo-node__icon">⬛</span>
                <span className="topo-node__title">HOST MACHINE</span>
                {openPorts.length > 0 && (
                    <span
                        className="topo-node__badge topo-node__badge--live"
                        title={`${openPorts.length} open ports discovered`}
                        style={{ marginLeft: 'auto', fontSize: '9px', cursor: 'default' }}
                    >
                        {openPorts.length} open
                    </span>
                )}
            </div>
            <div className="topo-node__meta-row">
                <span className="topo-node__meta-item">
                    <span className="topo-node__label">IF</span>
                    <span className="topo-node__value">{interfaceName}</span>
                </span>
                <span className="topo-node__meta-item">
                    <span className="topo-node__label">IP</span>
                    <span className="topo-node__value">{hostIp}</span>
                </span>
                <span className="topo-node__meta-item">
                    <span className="topo-node__label">FW</span>
                    <span className="topo-node__value topo-node__value--ok">iptables</span>
                </span>
            </div>

            {/* Port list — scrollable if many */}
            <div
                className="topo-node__ports"
                style={{
                    maxHeight: expanded ? 'none' : '320px',
                    overflowY: expanded ? 'visible' : 'auto',
                    transition: 'max-height 0.2s ease',
                }}
            >
                {visiblePorts.length === 0 ? (
                    <span style={{ fontSize: '10px', color: '#4a6080', padding: '4px 0', display: 'block' }}>
                        Waiting for /proc/net data…
                    </span>
                ) : (
                    visiblePorts.map((p) => (
                        <PortBadge
                            key={`${p.port}-${p.protocol}`}
                            port={p}
                            isActive={activePorts.has(p.port)}
                        />
                    ))
                )}
            </div>

            {/* Show more / less toggle */}
            {hasMore && (
                <button
                    onClick={() => setExpanded(e => !e)}
                    style={{
                        background: 'none',
                        border: 'none',
                        color: '#4a9eff',
                        fontSize: '10px',
                        cursor: 'pointer',
                        padding: '4px 0 0',
                        fontFamily: 'monospace',
                        letterSpacing: '0.05em',
                        width: '100%',
                        textAlign: 'left',
                    }}
                >
                    {expanded
                        ? `▲ hide ${closedPorts.length} closed`
                        : `▼ +${closedPorts.length} closed ports`}
                </button>
            )}
        </div>
    )
}

export default React.memo(HostNode)