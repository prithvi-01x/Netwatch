import React, { useState, useCallback } from 'react'
import { useAlerts } from './hooks/useAlerts'
import { useStats } from './hooks/useStats'
import { useAlertStore } from './store/alertStore'
import { useAppFeatures } from './hooks/useAppFeatures'
import { StatsBar } from './components/StatsBar/StatsBar'
import { FilterBar } from './components/FilterBar/FilterBar'
import { AlertPanel } from './components/AlertPanel/AlertPanel'
import { TrafficCharts } from './components/TrafficCharts/TrafficCharts'
import { LiveIndicator } from './components/shared/LiveIndicator'
import TopologyDiagram from './components/TopologyDiagram/TopologyDiagram'
import AttackGraphView from './components/AttackGraph/AttackGraphView'
import { ThreatIntel } from './components/ThreatIntel/ThreatIntel'
import { GeoMap } from './components/GeoMap/GeoMap'
import { IncidentTimeline } from './components/IncidentTimeline/IncidentTimeline'
import { BlocklistManager } from './components/BlocklistManager/BlocklistManager'
import { AskClaude } from './components/AskClaude/AskClaude'
import { SettingsPanel } from './components/SettingsPanel/SettingsPanel'
import { FlowInspector } from './components/FlowInspector/FlowInspector'
import { DEFAULT_CONFIG } from './components/TopologyDiagram/types'

type View = 'dashboard' | 'topology' | 'graph' | 'threat-intel' | 'geo-map' | 'incidents' | 'blocklist' | 'flows' | 'ask-ai' | 'settings'

const TABS: Array<{ id: View; label: string; ai?: boolean }> = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'incidents', label: 'Incidents' },
    { id: 'flows', label: 'Flow Inspector' },
    { id: 'topology', label: 'Network Topology' },
    { id: 'graph', label: 'Attack Graph' },
    { id: 'threat-intel', label: 'Threat Intel' },
    { id: 'geo-map', label: 'Geo Map' },
    { id: 'blocklist', label: 'Blocklist' },
    { id: 'ask-ai', label: '⬡ Ask AI', ai: true },
    { id: 'settings', label: '⚙ Settings' },
]

const App: React.FC = () => {
    const [view, setView] = useState<View>('dashboard')
    const { alerts, totalCount, isLoading, hasMore, loadMore, isLive } = useAlerts()
    const { stats, trafficHistory } = useStats()
    const setFilters = useAlertStore(s => s.setFilters)
    const filters = useAlertStore(s => s.filters)

    const {
        soundEnabled, toggleSound,
        notificationsEnabled, toggleNotifications,
        theme, toggleTheme,
        acknowledgedIds, acknowledgeAlert,
        ollamaModel, changeModel,
    } = useAppFeatures(alerts)

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
                    {/* Quick toggles in header */}
                    <button
                        className={`app__header-toggle ${soundEnabled ? 'app__header-toggle--on' : ''}`}
                        onClick={toggleSound}
                        title={soundEnabled ? 'Sound ON' : 'Sound OFF'}
                    >
                        {soundEnabled ? '🔔' : '🔕'}
                    </button>
                    <button
                        className={`app__header-toggle ${notificationsEnabled ? 'app__header-toggle--on' : ''}`}
                        onClick={toggleNotifications}
                        title={notificationsEnabled ? 'Notifications ON' : 'Notifications OFF'}
                    >
                        {notificationsEnabled ? '🖥' : '🖥'}
                    </button>
                    <button
                        className="app__header-toggle"
                        onClick={toggleTheme}
                        title="Toggle theme"
                    >
                        {theme === 'dark' ? '☀' : '🌙'}
                    </button>
                    <LiveIndicator isLive={isLive} />
                    <span className="app__alert-count mono">
                        {totalCount} alert{totalCount !== 1 ? 's' : ''}
                    </span>
                </div>
            </header>

            <nav className="app__tabbar">
                {TABS.map(tab => (
                    <button
                        key={tab.id}
                        className={`app__tab ${view === tab.id ? 'app__tab--active' : ''} ${tab.ai ? 'app__tab--ai' : ''}`}
                        onClick={() => setView(tab.id)}
                    >
                        {tab.label}
                    </button>
                ))}
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
                            acknowledgedIds={acknowledgedIds}
                            onAcknowledge={acknowledgeAlert}
                        />
                    </section>
                    <section className="app__charts">
                        <TrafficCharts trafficHistory={trafficHistory} stats={stats} />
                    </section>
                </main>
            )}

            {view === 'incidents' && (
                <div className="app__full-view">
                    <IncidentTimeline alerts={alerts} />
                </div>
            )}

            {view === 'flows' && (
                <div className="app__full-view">
                    <FlowInspector />
                </div>
            )}

            {view === 'topology' && (
                <TopologyDiagram config={DEFAULT_CONFIG} />
            )}

            {view === 'graph' && (
                <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
                    <AttackGraphView onFilterAlerts={handleFilterAlerts} />
                </div>
            )}

            {view === 'threat-intel' && (
                <div className="app__full-view">
                    <ThreatIntel stats={stats} />
                </div>
            )}

            {view === 'geo-map' && (
                <div className="app__full-view">
                    <GeoMap stats={stats} />
                </div>
            )}

            {view === 'blocklist' && (
                <div className="app__full-view">
                    <BlocklistManager stats={stats} />
                </div>
            )}

            {view === 'ask-ai' && (
                <div className="app__full-view">
                    <AskClaude alerts={alerts} stats={stats} model={ollamaModel} />
                </div>
            )}

            {view === 'settings' && (
                <div className="app__full-view">
                    <SettingsPanel
                        currentModel={ollamaModel}
                        onModelChange={changeModel}
                        soundEnabled={soundEnabled}
                        onSoundToggle={toggleSound}
                        notificationsEnabled={notificationsEnabled}
                        onNotificationsToggle={toggleNotifications}
                        theme={theme}
                        onThemeToggle={toggleTheme}
                    />
                </div>
            )}
        </div>
    )
}

export default App