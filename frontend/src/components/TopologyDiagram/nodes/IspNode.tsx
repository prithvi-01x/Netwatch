import React from 'react'

const IspNode: React.FC = () => {
    return (
        <div className="topo-node topo-node--isp">
            <div className="topo-node__icon">🌐</div>
            <div className="topo-node__title">INTERNET</div>
            <div className="topo-node__subtitle">ISP / WAN</div>
        </div>
    )
}

export default React.memo(IspNode)