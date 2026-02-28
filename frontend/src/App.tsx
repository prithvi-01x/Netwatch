import React, { useState, useCallback } from 'react'
import { useAlerts } from './hooks/useAlerts'
import { useStats } from './hooks/useStats'
import { useAlertStore } from './store/alertStore'
import { StatsBar } from './components/StatsBar/StatsBar'
import { FilterBar } from './components/FilterBar/FilterBar'
import { AlertPanel } from './components/AlertPanel/AlertPanel'
import { TrafficCharts } from './components/TrafficCharts/TrafficCharts'
import { LiveIndicator } from './components/shared/LiveIndicator'
import TopologyDiagram from './components/TopologyDiagram/TopologyDiagram'
import AttackGraphView from './components/AttackGraph/AttackGraphView'
import { DEFAULT_CONFIG } from './components/TopologyDiagram/types'

type View = 'dashboard' | 'topology' | 'graph'

const App: React.FC = () => {
    const [view, setView] = useState<View>('dashboard')
    const { alerts, totalCount, isLoading, hasMore, loadMore, isLive } = useAlerts()
    const { stats, trafficHistory } = useStats()
    const setFilters = useAlertStore(s => s.setFilters)
    const filters    = useAlertStore(s => s.filters)

    // Called from graph node panel — switch to dashboard and filter by IP
    const handleFilterAlerts = useCallback((ip: string) => {
        setFilters({ ...filters, src_ip: ip })
        setView('dashboard')
    }, [filters, setFilters])

    return (
        <div className="app">
            <header className="app__header">
                <div className="app__header-left">
                    <h1 className="app__title">
                        <span className="app__logo">◆</span>
                        NetWatch
                    </h1>
                    <span className="app__subtitle">Network Traffic Analyzer</span>
                </div>
                <div className="app__header-right">
                    <LiveIndicator isLive={isLive} />
                    <span className="app__alert-count mono">
                        {totalCount} alert{totalCount !== 1 ? 's' : ''}
                    </span>
                </div>
            </header>

            <nav className="app__tabbar">
                <button
                    className={`app__tab ${view === 'dashboard' ? 'app__tab--active' : ''}`}
                    onClick={() => setView('dashboard')}
                >
                    Dashboard
                </button>
                <button
                    className={`app__tab ${view === 'topology' ? 'app__tab--active' : ''}`}
                    onClick={() => setView('topology')}
                >
                    Network Topology
                </button>
                <button
                    className={`app__tab ${view === 'graph' ? 'app__tab--active' : ''}`}
                    onClick={() => setView('graph')}
                >
                    Attack Graph
                </button>
            </nav>

            <StatsBar stats={stats} />

            {view === 'dashboard' && (
                <main className="app__main">
                    <section className="app__alerts">
                        <FilterBar stats={stats} />
                        <AlertPanel
                            alerts={alerts}
                            isLoading={isLoading}
                            hasMore={hasMore}
                            loadMore={loadMore}
                        />
                    </section>
                    <section className="app__charts">
                        <TrafficCharts trafficHistory={trafficHistory} stats={stats} />
                    </section>
                </main>
            )}

            {view === 'topology' && (
                <TopologyDiagram config={DEFAULT_CONFIG} />
            )}

            {view === 'graph' && (
                <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
                    <AttackGraphView onFilterAlerts={handleFilterAlerts} />
                </div>
            )}
        </div>
    )
}

export default App
