/**
 * src/App.jsx
 * ===========
 * Shell: top navigation, routes, backend health indicator and the footer
 * disclaimer that has to be visible on every page.
 */
import React, { useEffect, useState } from 'react'
import { NavLink, Route, Routes } from 'react-router-dom'

import Analyzer from './pages/Analyzer.jsx'
import Awareness from './pages/Awareness.jsx'
import Dashboard from './pages/Dashboard.jsx'
import History from './pages/History.jsx'
import { getHealth } from './services/api.js'

function HealthDot() {
  const [health, setHealth] = useState(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let alive = true
    getHealth()
      .then((h) => { if (alive) setHealth(h) })
      .catch(() => { if (alive) setFailed(true) })
    return () => { alive = false }
  }, [])

  if (failed) {
    return (
      <span className="badge badge-high" title="Start the backend with start_backend.bat">
        backend offline
      </span>
    )
  }
  if (!health) return <span className="badge badge-info">checking…</span>
  return (
    <span
      className={`badge badge-${health.ml_available ? 'low' : 'moderate'}`}
      title={health.ml_available
        ? 'Backend healthy and the ML model is loaded'
        : 'Backend healthy. No ML model loaded - run train_model.bat to enable the model.'}
    >
      {health.ml_available ? 'backend + ML ready' : 'backend ready (rules only)'}
    </span>
  )
}

export default function App() {
  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <span className="brand-mark" aria-hidden="true">🛡️</span>
            <span>
              Phishing Email Detection
              <span className="brand-sub">&amp; Awareness Dashboard</span>
            </span>
          </div>
          <nav className="nav">
            <NavLink to="/" end>Dashboard</NavLink>
            <NavLink to="/analyzer">Email Analyzer</NavLink>
            <NavLink to="/awareness">Awareness</NavLink>
            <NavLink to="/history">History</NavLink>
          </nav>
          <HealthDot />
        </div>
      </header>

      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyzer" element={<Analyzer />} />
          <Route path="/awareness" element={<Awareness />} />
          <Route path="/history" element={<History />} />
          <Route path="*" element={
            <div className="empty">
              <h2>Page not found</h2>
              <p>Use the navigation above.</p>
            </div>
          } />
        </Routes>
      </main>

      <footer className="footer">
        Defensive security project · synthetic data only · static analysis only — no link
        is opened, no host is resolved, no attachment is executed.
        <br />
        No single indicator proves phishing. Scores support analyst judgement; they do not replace it.
      </footer>
    </div>
  )
}
