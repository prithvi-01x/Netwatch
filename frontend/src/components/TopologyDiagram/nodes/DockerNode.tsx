import React from 'react'
import type { ContainerInfo } from '../types'
import PortBadge from './PortBadge'

interface Props {
    container: ContainerInfo
    activePorts: Set<number>
}

const DockerNode: React.FC<Props> = ({ container, activePorts }) => {
    const hasTraffic = container.ports.some((p) => activePorts.has(p.port))

    let statusClass = 'docker-node--stopped'
    if (container.status === 'running') statusClass = 'docker-node--running'
    else if (container.status === 'restarting' || container.status === 'paused') statusClass = 'docker-node--warning'

    return (
        <div className={`docker-node ${statusClass} ${hasTraffic ? 'docker-node--active' : ''}`}>
            <div className="docker-node__header">
                <span className="docker-node__status-dot" />
                <span className="docker-node__name">{container.name}</span>
            </div>
            <div className="docker-node__image">{container.image}</div>

            <div className="docker-node__info">
                {container.ip && <span className="docker-node__ip">{container.ip}</span>}
                {container.cpu && <span className="docker-node__stat">CPU: {container.cpu}</span>}
                {container.memory && <span className="docker-node__stat">RAM: {container.memory}</span>}
            </div>

            {container.capabilities && container.capabilities.length > 0 && (
                <div className="docker-node__caps">
                    {container.capabilities.map((cap) => (
                        <span key={cap} className="docker-node__cap-badge">{cap}</span>
                    ))}
                </div>
            )}

            <div className="docker-node__ports">
                {container.internal ? (
                    <span className="docker-node__internal">no exposed port</span>
                ) : container.ports.length === 0 ? (
                    <span className="docker-node__internal">raw socket</span>
                ) : (
                    container.ports.map((p) => (
                        <PortBadge key={p.port} port={p} isActive={activePorts.has(p.port)} />
                    ))
                )}
            </div>
        </div>
    )
}

export default React.memo(DockerNode)