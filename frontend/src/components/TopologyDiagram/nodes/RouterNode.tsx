import React from 'react'

interface Props {
    gatewayIp: string
}

const RouterNode: React.FC<Props> = ({ gatewayIp }) => {
    return (
        <div className="topo-node topo-node--router">
            <div className="topo-node__icon">⬡</div>
            <div className="topo-node__title">ROUTER / GATEWAY</div>
            <div className="topo-node__meta">
                <span className="topo-node__label">IP</span>
                <span className="topo-node__value">{gatewayIp}</span>
            </div>
        </div>
    )
}

export default React.memo(RouterNode)