import React, { useState } from 'react'
import InvestigationForm from './components/InvestigationForm.jsx'
import InvestigationStatus from './components/InvestigationStatus.jsx'
import EntityGraph from './components/EntityGraph.jsx'
import ThreatReport from './components/ThreatReport.jsx'

function App() {
  const [investigationId, setInvestigationId] = useState(null)
  const [target, setTarget] = useState(null)

  const handleSubmit = (id, t) => {
    setInvestigationId(id)
    setTarget(t)
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>Cartographer</h1>
        <p>AI-powered OSINT intelligence aggregator</p>
      </header>
      <main>
        <InvestigationForm onSubmit={handleSubmit} />
        {investigationId && (
          <>
            <InvestigationStatus investigationId={investigationId} />
            <EntityGraph investigationId={investigationId} />
            <ThreatReport investigationId={investigationId} target={target} />
          </>
        )}
      </main>
    </div>
  )
}

export default App
