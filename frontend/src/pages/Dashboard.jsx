/**
 * src/pages/Dashboard.jsx
 * =======================
 * Five summary cards plus six charts, all driven by real rows in the SQLite
 * database. If nothing has been analysed yet the page says so rather than
 * drawing empty axes.
 */
import React, { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'

import { getIndicators, getKeywords, getStats } from '../services/api.js'
import {
  Badge, Empty, ErrorBox, Loading, Panel, RISK_COLOR, StatCard,
  axisProps, riskKey, tooltipStyle,
} from '../components/common.jsx'

const CLASS_COLORS = {
  'LOW RISK': RISK_COLOR.low,
  'MODERATE RISK': RISK_COLOR.moderate,
  SUSPICIOUS: RISK_COLOR.suspicious,
  'HIGH RISK / LIKELY PHISHING': RISK_COLOR.high,
}

const SEVERITY_COLORS = { HIGH: '#ef4444', MEDIUM: '#f97316', LOW: '#eab308', INFO: '#64748b' }

/**
 * Recharts clips a category label that is wider than the axis instead of
 * shortening it, which silently drops the first characters and makes a label
 * read as "assword-expiry-notice". Truncating from the END keeps the part that
 * identifies the item, and the full value stays visible in the tooltip.
 */
const truncate = (max) => (value) =>
  String(value).length > max ? `${String(value).slice(0, max - 1)}…` : String(value)

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [indicators, setIndicators] = useState([])
  const [keywords, setKeywords] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [s, i, k] = await Promise.all([getStats(), getIndicators(8), getKeywords(10)])
      setStats(s)
      setIndicators(i.top_indicators || [])
      setKeywords(k.keywords || [])
    } catch (e) {
      setError(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) return <Loading text="Loading dashboard…" />
  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!stats) return null

  const empty = stats.total_analyzed === 0

  return (
    <div>
      <div className="page-head">
        <h1>Dashboard</h1>
        <p>
          Aggregate view of every email analysed on this machine. All figures are read
          from the local SQLite database — nothing is pre-filled.
        </p>
      </div>

      {empty && (
        <div className="notice" style={{ marginBottom: '1rem' }}>
          <strong>No analyses yet.</strong> Analyse an email on the{' '}
          <Link to="/analyzer">Email Analyzer</Link> page, or run{' '}
          <code>seed_demo.bat</code> to load {24} sample analyses.
        </div>
      )}

      {/* ------------------------------------------------------- cards --- */}
      <div className="grid grid-5">
        <StatCard label="Total analysed" value={stats.total_analyzed} hint="emails in history" />
        <StatCard label="Likely phishing" value={stats.likely_phishing} tone="high" hint="score 71-100" />
        <StatCard label="Suspicious" value={stats.suspicious} tone="suspicious" hint="score 41-70" />
        <StatCard label="Low risk" value={stats.low_risk} tone="low" hint="score 0-20" />
        <StatCard
          label="Avg risk score"
          value={stats.average_risk_score?.toFixed?.(1) ?? stats.average_risk_score}
          tone="moderate"
          hint="mean of all analyses"
        />
      </div>

      <div className="spacer" />

      {/* ------------------------------------------------------ charts --- */}
      <div className="grid grid-2">
        {/* 1. classification distribution */}
        <Panel
          title="1. Risk classification distribution"
          note="Counts per band. The bands are a documented project assumption: 0-20 low, 21-40 moderate, 41-70 suspicious, 71-100 high."
        >
          <div className="chart-box">
            {empty ? <Empty>Nothing analysed yet</Empty> : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.classification_distribution.filter((d) => d.count > 0)}
                    dataKey="count" nameKey="classification"
                    innerRadius={55} outerRadius={92} paddingAngle={2}
                    label={({ count }) => count}
                  >
                    {stats.classification_distribution
                      .filter((d) => d.count > 0)
                      .map((d) => (
                        <Cell key={d.classification} fill={CLASS_COLORS[d.classification] || '#64748b'} />
                      ))}
                  </Pie>
                  <Tooltip {...tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#92a4b8' }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

        {/* 2. risk histogram */}
        <Panel
          title="2. Risk score histogram"
          note="How scores actually spread out. A healthy detector separates the two ends rather than clustering everything in the middle."
        >
          <div className="chart-box">
            {empty ? <Empty>Nothing analysed yet</Empty> : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.risk_histogram} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2733" vertical={false} />
                  <XAxis dataKey="range" {...axisProps} interval={0} angle={-35} textAnchor="end" height={52} />
                  <YAxis allowDecimals={false} {...axisProps} />
                  <Tooltip {...tooltipStyle} cursor={{ fill: 'rgba(59,130,246,0.07)' }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {stats.risk_histogram.map((d) => {
                      const lower = parseInt(d.range.split('-')[0], 10)
                      const color = lower >= 71 ? RISK_COLOR.high
                        : lower >= 41 ? RISK_COLOR.suspicious
                        : lower >= 21 ? RISK_COLOR.moderate : RISK_COLOR.low
                      return <Cell key={d.range} fill={color} />
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

        {/* 3. top indicators */}
        <Panel
          title="3. Most frequent indicators"
          note="Which rules fire most often across everything analysed. This is the single most useful chart for planning awareness training."
        >
          <div className="chart-box">
            {indicators.length === 0 ? <Empty>No indicators recorded yet</Empty> : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={indicators} layout="vertical" margin={{ top: 4, right: 18, bottom: 4, left: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2733" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} {...axisProps} />
                  <YAxis
                    type="category" dataKey="indicator_type" width={186}
                    tickFormatter={truncate(26)}
                    tick={{ fill: '#8296ab', fontSize: 10 }} stroke="#3a4757" tickLine={false}
                  />
                  <Tooltip {...tooltipStyle} cursor={{ fill: 'rgba(59,130,246,0.07)' }} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {indicators.map((d) => (
                      <Cell key={d.indicator_type} fill={SEVERITY_COLORS[d.severity] || '#64748b'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

        {/* 4. phishing vs legitimate */}
        <Panel
          title="4. Flagged vs not flagged"
          note="Suspicious and high-risk on one side, low and moderate on the other. This is what the tool flagged, not ground truth."
        >
          <div className="chart-box">
            {empty ? <Empty>Nothing analysed yet</Empty> : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.phishing_vs_legitimate} dataKey="count" nameKey="name"
                    outerRadius={92} label={({ count }) => count}
                  >
                    <Cell fill={RISK_COLOR.high} />
                    <Cell fill={RISK_COLOR.low} />
                  </Pie>
                  <Tooltip {...tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#92a4b8' }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

        {/* 5. top sender domains */}
        <Panel
          title="5. Sender domains by average risk"
          note="Domains seen most often, with their mean score. Every domain here is a reserved documentation name (RFC 2606 / 6761)."
        >
          <div className="chart-box">
            {(stats.top_sender_domains || []).length === 0 ? <Empty>No senders recorded yet</Empty> : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={(stats.top_sender_domains || []).slice(0, 7)}
                  layout="vertical" margin={{ top: 4, right: 18, bottom: 4, left: 8 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2733" horizontal={false} />
                  <XAxis type="number" domain={[0, 100]} {...axisProps} />
                  <YAxis
                    type="category" dataKey="sender_domain" width={186}
                    tickFormatter={truncate(26)}
                    tick={{ fill: '#8296ab', fontSize: 10 }} stroke="#3a4757" tickLine={false}
                  />
                  <Tooltip {...tooltipStyle} cursor={{ fill: 'rgba(59,130,246,0.07)' }}
                    formatter={(v, n) => [v, n === 'avg_score' ? 'avg score' : n]} />
                  <Bar dataKey="avg_score" name="avg score" radius={[0, 4, 4, 0]}>
                    {(stats.top_sender_domains || []).slice(0, 7).map((d) => {
                      const s = d.avg_score
                      const color = s >= 71 ? RISK_COLOR.high : s >= 41 ? RISK_COLOR.suspicious
                        : s >= 21 ? RISK_COLOR.moderate : RISK_COLOR.low
                      return <Cell key={d.sender_domain} fill={color} />
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

        {/* 6. detection trend */}
        <Panel
          title="6. Detection trend over time"
          note="Analyses per day and how many were high risk. With a single day of data this is one point — it fills in as you use the tool."
        >
          <div className="chart-box">
            {(stats.detection_trend || []).length === 0 ? <Empty>No history yet</Empty> : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.detection_trend} margin={{ top: 8, right: 10, bottom: 0, left: -18 }}>
                  <defs>
                    <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.03} />
                    </linearGradient>
                    <linearGradient id="gHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.03} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2733" vertical={false} />
                  <XAxis dataKey="day" {...axisProps} />
                  <YAxis allowDecimals={false} {...axisProps} />
                  <Tooltip {...tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#92a4b8' }} />
                  <Area type="monotone" dataKey="total" name="analysed" stroke="#3b82f6"
                    fill="url(#gTotal)" strokeWidth={2} dot={{ r: 3 }} />
                  <Area type="monotone" dataKey="high" name="high risk" stroke="#ef4444"
                    fill="url(#gHigh)" strokeWidth={2} dot={{ r: 3 }} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>
      </div>

      <div className="spacer" />

      <div className="grid grid-2">
        <Panel title="Most common warning signs" note="Plain-language version of the indicator chart — useful for a training slide.">
          {keywords.length === 0 ? <Empty>Nothing recorded yet</Empty> : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Warning sign</th><th>Category</th><th className="num">Seen</th></tr>
                </thead>
                <tbody>
                  {keywords.map((k) => (
                    <tr key={k.indicator_type}>
                      <td>{k.keyword}</td>
                      <td className="muted small">{k.category}</td>
                      <td className="num">{k.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel
          title="Recent analyses"
          action={<Link className="btn btn-ghost btn-sm" to="/history">View all</Link>}
        >
          {(stats.recent_analyses || []).length === 0 ? <Empty>Nothing analysed yet</Empty> : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Subject</th><th className="num">Score</th><th>Verdict</th></tr>
                </thead>
                <tbody>
                  {stats.recent_analyses.slice(0, 8).map((r) => (
                    <tr key={r.analysis_id}>
                      <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <Link to={`/history?id=${r.analysis_id}`} style={{ color: 'inherit', textDecoration: 'none' }}>
                          {r.subject || <span className="muted">(no subject)</span>}
                        </Link>
                      </td>
                      <td className="num">{r.risk_score}</td>
                      <td><Badge classification={r.classification} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <div className="spacer" />
      <div className="notice">
        <strong>Reading these charts responsibly.</strong> A high score means several
        indicators combined, not proof of an attack. A low score means none of the
        checked indicators appeared — a well-written phishing email can still score low.
        Analyst judgement is the final step, always.
      </div>
    </div>
  )
}
