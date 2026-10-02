/**
 * src/pages/Analyzer.jsx
 * ======================
 * Paste an email, get a transparent verdict: the score, every rule that fired,
 * the evidence behind it and what to do next.
 *
 * SAFETY: the form only ever sends text to the local backend. No link is
 * opened, no host is resolved and no attachment is uploaded or executed — the
 * attachment field takes a FILENAME, because the extension is what is analysed.
 */
import React, { useState } from 'react'
import {
  Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip,
} from 'recharts'

import { analyzeEmail, analyzeUrl } from '../services/api.js'
import {
  Badge, ErrorBox, Panel, ScoreBar, Severity, riskKey, scoreColor, tooltipStyle,
} from '../components/common.jsx'

const DEMO_PHISHING = {
  sender: 'security-alert@account-check.invalid.test',
  subject: 'URGENT: Verify Your Account Immediately',
  body: `Dear Customer,

Your account has been temporarily suspended due to unusual activity. You must verify your identity within 24 hours or your account will be permanently closed.

Click here to confirm your password and login details: http://198.51.100.10/verify-account

Failure to act will result in immediate termination of service.

Account Security Team`,
  urls: 'http://198.51.100.10/verify-account',
  attachment_name: '',
}

const DEMO_LEGITIMATE = {
  sender: 'training@example.org',
  subject: 'Cybersecurity Workshop Reminder',
  body: `Hello,

This is a reminder that our internal cybersecurity workshop takes place on Thursday at 3 PM in Training Room B. We will cover password hygiene and safe browsing habits.

The agenda is attached. No registration is needed.

Best regards,
Learning and Development`,
  urls: '',
  attachment_name: 'workshop_agenda.pdf',
}

const EMPTY = { sender: '', subject: '', body: '', urls: '', attachment_name: '' }

/** Awareness page can hand a practice template over via sessionStorage. */
function initialForm() {
  try {
    const stored = sessionStorage.getItem('prefill')
    if (stored) {
      sessionStorage.removeItem('prefill')
      return { ...EMPTY, ...JSON.parse(stored) }
    }
  } catch {
    /* ignore malformed storage and fall back to the demo */
  }
  return DEMO_PHISHING
}

export default function Analyzer() {
  const [form, setForm] = useState(initialForm)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const [url, setUrl] = useState('http://198.51.100.10/verify-account')
  const [urlResult, setUrlResult] = useState(null)
  const [urlBusy, setUrlBusy] = useState(false)
  const [urlError, setUrlError] = useState(null)

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value })

  async function submit(e) {
    e.preventDefault()
    setBusy(true); setError(null); setResult(null)
    try {
      setResult(await analyzeEmail(form))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  async function submitUrl(e) {
    e.preventDefault()
    setUrlBusy(true); setUrlError(null); setUrlResult(null)
    try {
      setUrlResult(await analyzeUrl(url))
    } catch (err) {
      setUrlError(err)
    } finally {
      setUrlBusy(false)
    }
  }

  const severityData = result
    ? Object.entries(
        result.indicators.reduce((acc, i) => {
          acc[i.severity] = (acc[i.severity] || 0) + 1
          return acc
        }, {})
      ).map(([name, value]) => ({ name, value }))
    : []
  const SEV_COLOR = { HIGH: '#ef4444', MEDIUM: '#f97316', LOW: '#eab308', INFO: '#64748b' }

  return (
    <div>
      <div className="page-head">
        <h1>Email Analyzer</h1>
        <p>
          Paste the parts of a suspicious email. Everything is analysed as text on your
          own machine: no link is opened, no hostname is resolved, and no file is
          uploaded or executed.
        </p>
      </div>

      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        {/* ------------------------------------------------------ form --- */}
        <Panel title="Email details">
          <form onSubmit={submit}>
            <div className="field">
              <label htmlFor="sender">Sender address</label>
              <input id="sender" type="text" value={form.sender} onChange={set('sender')}
                placeholder="name@example.com" />
            </div>
            <div className="field">
              <label htmlFor="subject">Subject</label>
              <input id="subject" type="text" value={form.subject} onChange={set('subject')}
                placeholder="Subject line" />
            </div>
            <div className="field">
              <label htmlFor="body">Body</label>
              <textarea id="body" value={form.body} onChange={set('body')}
                placeholder="Paste the message text here" />
            </div>
            <div className="field-row">
              <div className="field">
                <label htmlFor="urls">Links (one per line, optional)</label>
                <textarea id="urls" value={form.urls} onChange={set('urls')} style={{ minHeight: 64 }}
                  placeholder="http://..." />
              </div>
              <div className="field">
                <label htmlFor="att">Attachment filename (optional)</label>
                <input id="att" type="text" value={form.attachment_name} onChange={set('attachment_name')}
                  placeholder="invoice.pdf" />
                <p className="small muted" style={{ marginTop: 6 }}>
                  Filename only. The file itself is never uploaded or opened.
                </p>
              </div>
            </div>

            <div className="btn-row">
              <button className="btn" type="submit" disabled={busy}>
                {busy ? <><span className="spin" /> Analysing…</> : 'Analyse email'}
              </button>
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => setForm(DEMO_PHISHING)}>
                Load phishing demo
              </button>
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => setForm(DEMO_LEGITIMATE)}>
                Load legitimate demo
              </button>
              <button className="btn btn-ghost btn-sm" type="button"
                onClick={() => { setForm(EMPTY); setResult(null); setError(null) }}>
                Clear
              </button>
            </div>
          </form>
          <ErrorBox error={error} />
        </Panel>

        {/* ---------------------------------------------------- result --- */}
        <div>
          {!result && (
            <Panel title="Result">
              <div className="empty">
                Submit an email to see its score, the rules that fired and the evidence
                behind each one.
              </div>
            </Panel>
          )}

          {result && (
            <>
              <Panel title="Verdict">
                <div className="score-wrap">
                  <div>
                    <span className="score-big" style={{ color: scoreColor(result.risk_score) }}>
                      {result.risk_score}
                    </span>
                    <span className="score-out">/100</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <Badge classification={result.classification} />
                    <div style={{ marginTop: 8 }}><ScoreBar score={result.risk_score} /></div>
                    <p className="small muted" style={{ marginTop: 8, marginBottom: 0 }}>
                      {result.band_meaning}
                    </p>
                  </div>
                </div>

                {result.ml_detection?.available && (
                  <div className="notice" style={{ marginTop: '0.9rem' }}>
                    <strong>Machine-learning second opinion:</strong>{' '}
                    {result.ml_detection.model_name} predicts{' '}
                    <b>{result.ml_detection.prediction}</b> at{' '}
                    {(result.ml_detection.probability * 100).toFixed(1)}% phishing probability.
                    {result.hybrid_detection && (
                      <> Hybrid score <b>{result.hybrid_detection.combined_score}/100</b>{' '}
                      ({Math.round(result.hybrid_detection.rule_weight * 100)}% rules +{' '}
                      {Math.round(result.hybrid_detection.ml_weight * 100)}% model).</>
                    )}
                    <div className="small" style={{ marginTop: 6, opacity: 0.85 }}>
                      A probability is an estimate learned from synthetic training data, not a certainty.
                    </div>
                  </div>
                )}
              </Panel>

              <Panel title="Why? — rules that actually fired">
                {result.why?.length ? (
                  <ul className="why-list">
                    {result.why.map((w, i) => <li key={i}>{w}</li>)}
                  </ul>
                ) : (
                  <div className="notice ok">
                    No rule-based phishing indicator was triggered. That is not a
                    guarantee of safety — it means none of the checked signals appeared.
                  </div>
                )}
              </Panel>

              {severityData.length > 0 && (
                <Panel title="Indicators by severity">
                  <div className="chart-box" style={{ height: 230 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
                        <Pie data={severityData} dataKey="value" nameKey="name"
                          innerRadius={42} outerRadius={68} paddingAngle={2}
                          label={({ value }) => value} labelLine={false}>
                          {severityData.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name] || '#64748b'} />)}
                        </Pie>
                        <Tooltip {...tooltipStyle} />
                        <Legend wrapperStyle={{ fontSize: 11, color: '#92a4b8' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </Panel>
              )}
            </>
          )}
        </div>
      </div>

      {/* --------------------------------------------- full findings --- */}
      {result && (
        <>
          <div className="spacer" />
          <div className="grid grid-2" style={{ alignItems: 'start' }}>
            <Panel
              title={`Detailed findings (${result.indicator_count} risk-bearing)`}
              note="INFO items are shown for transparency and add no risk."
            >
              {result.indicators.map((ind, i) => (
                <div className="ind" key={i}>
                  <div className="ind-head">
                    <Severity level={ind.severity} />
                    <span className="ind-type">{ind.indicator_type}</span>
                    <span className="ind-cat">{ind.category}</span>
                    {ind.weight > 0 && <span className="badge badge-info">+{ind.weight}</span>}
                  </div>
                  <p className="ind-desc">{ind.description}</p>
                  {ind.evidence && <div className="ind-ev mono">evidence: {ind.evidence}</div>}
                </div>
              ))}
            </Panel>

            <div>
              <Panel title="Recommended actions">
                {result.recommendations.map((rec, i) => (
                  <div className="rec" key={i}>
                    <span className={`badge badge-${
                      rec.priority === 'CRITICAL' ? 'high'
                        : rec.priority === 'HIGH' ? 'suspicious'
                        : rec.priority === 'MEDIUM' ? 'moderate' : 'info'}`}>
                      {rec.priority}
                    </span>
                    <div className="rec-body">
                      <strong>{rec.action}</strong>
                      <span>{rec.detail}</span>
                    </div>
                  </div>
                ))}
              </Panel>

              <Panel title="Score breakdown">
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Rule</th><th className="num">Weight</th></tr></thead>
                    <tbody>
                      {result.triggered_rules.length === 0 && (
                        <tr><td colSpan={2} className="muted">No rules triggered.</td></tr>
                      )}
                      {result.triggered_rules.map((t) => (
                        <tr key={t.rule}>
                          <td>{t.label || t.rule}</td>
                          <td className="num">+{t.weight}</td>
                        </tr>
                      ))}
                      <tr>
                        <td><strong>Total{result.cap_applied ? ' (capped at 100)' : ''}</strong></td>
                        <td className="num"><strong>{result.risk_score}</strong></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                {result.cap_applied && (
                  <p className="panel-note">
                    Raw total was {result.raw_score}; the score is capped at 100 so it stays
                    readable as a percentage.
                  </p>
                )}
              </Panel>

              {result.detection_notes?.length > 0 && (
                <Panel title="Notes on this assessment">
                  {result.detection_notes.map((n, i) => (
                    <p key={i} className="small muted" style={{ marginBottom: 6 }}>• {n}</p>
                  ))}
                </Panel>
              )}
            </div>
          </div>
        </>
      )}

      {/* ------------------------------------------------- URL checker --- */}
      <div className="spacer" />
      <Panel
        title="Standalone link checker"
        note="Static string analysis only: the scheme, hostname shape, raw-IP use, shortener list, path keywords and character tricks. The link is never opened."
      >
        <form onSubmit={submitUrl}>
          <div className="field-row">
            <div className="field" style={{ marginBottom: 0 }}>
              <label htmlFor="url">URL to inspect</label>
              <input id="url" type="text" value={url} onChange={(e) => setUrl(e.target.value)}
                placeholder="http://..." />
            </div>
            <div style={{ alignSelf: 'end' }}>
              <button className="btn" type="submit" disabled={urlBusy}>
                {urlBusy ? <><span className="spin" /> Checking…</> : 'Check link'}
              </button>
            </div>
          </div>
        </form>
        <ErrorBox error={urlError} />

        {urlResult && (
          <div style={{ marginTop: '1rem' }}>
            <div className="score-wrap" style={{ marginBottom: '0.8rem' }}>
              <div>
                <span className="score-big" style={{ fontSize: '2.1rem', color: scoreColor(urlResult.url_risk_score) }}>
                  {urlResult.url_risk_score}
                </span>
                <span className="score-out">/100</span>
              </div>
              <div className="pill-row">
                <span className={`badge badge-${urlResult.suspicious ? 'high' : 'low'}`}>
                  {urlResult.suspicious ? 'SUSPICIOUS' : 'NO STRONG INDICATORS'}
                </span>
                {urlResult.is_ip && <span className="badge badge-high">RAW IP</span>}
                <span className={`badge badge-${urlResult.uses_https ? 'low' : 'moderate'}`}>
                  {urlResult.uses_https ? 'HTTPS' : 'HTTP (not encrypted)'}
                </span>
                {urlResult.is_shortener && <span className="badge badge-suspicious">SHORTENER</span>}
              </div>
            </div>
            <p className="small mono muted">safe representation: {urlResult.safe_representation}</p>
            {urlResult.url_findings?.map((f, i) => (
              <div className="ind" key={i}>
                <div className="ind-head">
                  <Severity level={f.severity} />
                  <span className="ind-type">{f.indicator_type}</span>
                </div>
                <p className="ind-desc">{f.description}</p>
                {f.evidence && <div className="ind-ev mono">evidence: {f.evidence}</div>}
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}
