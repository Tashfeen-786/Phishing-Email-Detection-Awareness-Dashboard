/**
 * src/components/common.jsx
 * =========================
 * Small presentational pieces shared by every page. Keeping them in one file
 * avoids a sprawl of 15 one-component files while still keeping the pages
 * readable.
 */
import React from 'react'

/** Map a classification string to the CSS modifier used across the theme. */
export function riskKey(classification = '') {
  const c = classification.toUpperCase()
  if (c.includes('HIGH') || c.includes('PHISHING')) return 'high'
  if (c.includes('SUSPICIOUS')) return 'suspicious'
  if (c.includes('MODERATE')) return 'moderate'
  return 'low'
}

export const RISK_COLOR = {
  high: '#ef4444',
  suspicious: '#f97316',
  moderate: '#eab308',
  low: '#22c55e',
}

export function scoreColor(score) {
  if (score >= 71) return RISK_COLOR.high
  if (score >= 41) return RISK_COLOR.suspicious
  if (score >= 21) return RISK_COLOR.moderate
  return RISK_COLOR.low
}

export function StatCard({ label, value, hint, tone = '' }) {
  return (
    <div className={`stat ${tone}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  )
}

export function Badge({ classification }) {
  return (
    <span className={`badge badge-${riskKey(classification)}`}>{classification}</span>
  )
}

export function Severity({ level }) {
  return <span className={`sev sev-${level}`}>{level}</span>
}

export function Panel({ title, action, note, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <div className="panel-title">
          {title && <h3>{title}</h3>}
          {action}
        </div>
      )}
      {children}
      {note && <p className="panel-note">{note}</p>}
    </section>
  )
}

export function ScoreBar({ score }) {
  return (
    <div className="bar">
      <div
        className="bar-fill"
        style={{ width: `${Math.max(0, Math.min(100, score))}%`, background: scoreColor(score) }}
      />
    </div>
  )
}

export function Loading({ text = 'Loading…' }) {
  return (
    <div className="empty">
      <span className="spin" /> <span style={{ marginLeft: 8 }}>{text}</span>
    </div>
  )
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null
  return (
    <div className="notice danger">
      <strong>Something went wrong.</strong>
      <div className="small" style={{ marginTop: 4 }}>{String(error.message || error)}</div>
      {onRetry && (
        <button className="btn btn-ghost btn-sm" style={{ marginTop: 8 }} onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  )
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>
}

/** Recharts tooltip styled to match the dark theme. */
export const tooltipStyle = {
  contentStyle: {
    background: '#131c28',
    border: '1px solid #2a3441',
    borderRadius: 8,
    fontSize: 13,
    color: '#e6edf3',
  },
  labelStyle: { color: '#92a4b8', fontSize: 12 },
  itemStyle: { color: '#e6edf3' },
}

export const axisProps = {
  stroke: '#3a4757',
  tick: { fill: '#8296ab', fontSize: 11 },
  tickLine: false,
}
