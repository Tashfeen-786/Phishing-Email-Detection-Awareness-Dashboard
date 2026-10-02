/**
 * src/pages/Awareness.jsx
 * =======================
 * The teaching half of the project. Detection tells you about one email;
 * awareness is what stops the next one.
 *
 * Every word here is served by the backend (backend/services/awareness_content.py)
 * so the API and the UI can never drift apart.
 */
import React, { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { getAwareness } from '../services/api.js'
import { ErrorBox, Loading, Panel } from '../components/common.jsx'

const TABS = [
  { id: 'spot', label: 'How to spot phishing' },
  { id: 'click', label: 'Before you click' },
  { id: 'lessons', label: 'Micro-lessons' },
  { id: 'simulate', label: 'Practice templates' },
  { id: 'respond', label: 'If you clicked' },
  { id: 'soc', label: 'SOC workflow' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
]

export default function Awareness() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('spot')
  const navigate = useNavigate()

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try { setData(await getAwareness()) } catch (e) { setError(e) } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) return <Loading text="Loading awareness content…" />
  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!data) return null

  /** Send a practice template to the analyzer so learners see it scored. */
  function tryTemplate(t) {
    const payload = { sender: t.sender, subject: t.subject, body: t.body, urls: '', attachment_name: '' }
    sessionStorage.setItem('prefill', JSON.stringify(payload))
    navigate('/analyzer')
  }

  return (
    <div>
      <div className="page-head">
        <h1>Security awareness</h1>
        <p>
          Detection catches one email. Awareness is what stops the next one. This module
          is deliberately defensive: it teaches recognition and reporting, never how to
          run an attack.
        </p>
      </div>

      <div className="nav" style={{ marginLeft: 0, marginBottom: '1rem' }}>
        {TABS.map((t) => (
          <a key={t.id} href="#!" className={tab === t.id ? 'active' : ''}
            onClick={(e) => { e.preventDefault(); setTab(t.id) }}>
            {t.label}
          </a>
        ))}
      </div>

      {/* ----------------------------------------------- how to spot --- */}
      {tab === 'spot' && (
        <Panel
          title="Ten ways to spot a phishing email"
          note="No single item on this list proves anything. Phishing is identified by several signals appearing together, in a context that does not add up."
        >
          {data.how_to_spot.map((item) => (
            <details className="acc" key={item.number}>
              <summary>{item.number}. {item.title}</summary>
              <div>
                <p><strong>What to look for:</strong> {item.what}</p>
                <p><strong>Why it works:</strong> {item.why}</p>
                <p className="mono small" style={{ color: '#8296ab' }}>Example: {item.example}</p>
              </div>
            </details>
          ))}
        </Panel>
      )}

      {/* --------------------------------------------- before you click --- */}
      {tab === 'click' && (
        <Panel
          title="Before you click: a ten-point checklist"
          note="Run through this whenever an email asks you to do something. It takes about twenty seconds."
        >
          <div className="table-wrap">
            <table>
              <thead><tr><th style={{ width: '48%' }}>Check</th><th>If the answer is no</th></tr></thead>
              <tbody>
                {data.before_you_click.map((row, i) => (
                  <tr key={i}>
                    <td>{row.check}</td>
                    <td className="muted">{row.if_no}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* ------------------------------------------------ micro lessons --- */}
      {tab === 'lessons' && (
        <div className="grid grid-2" style={{ alignItems: 'start' }}>
          {data.micro_lessons.map((lesson) => (
            <Panel key={lesson.id} title={lesson.title}>
              <p className="small muted" style={{ marginTop: -6 }}>{lesson.duration}</p>
              <p><strong>{lesson.summary}</strong></p>
              <p style={{ whiteSpace: 'pre-line' }}>{lesson.content}</p>
              <div className="notice ok"><strong>Try this:</strong> {lesson.try_this}</div>
            </Panel>
          ))}
        </div>
      )}

      {/* --------------------------------------------------- simulate --- */}
      {tab === 'simulate' && (
        <>
          <div className="notice warn" style={{ marginBottom: '1rem' }}>
            <strong>Read this first.</strong> {data.simulation_safety_note}
          </div>
          {data.simulation_templates.map((t) => (
            <Panel key={t.id} title={t.name}
              action={<button className="btn btn-sm" onClick={() => tryTemplate(t)}>Score this in the analyzer</button>}>
              <p><strong>Teaching point:</strong> {t.teaching_point}</p>
              <div className="ind">
                <div className="ind-head"><span className="ind-cat">FROM</span>
                  <span className="mono small">{t.sender}</span></div>
                <div className="ind-head"><span className="ind-cat">SUBJECT</span>
                  <span className="mono small">{t.subject}</span></div>
                <p className="ind-desc mono" style={{ whiteSpace: 'pre-line', marginTop: 8 }}>{t.body}</p>
              </div>
              <p className="panel-note">
                <strong>Indicators this teaches:</strong> {t.indicators_taught.join(', ')}
              </p>
            </Panel>
          ))}
        </>
      )}

      {/* ---------------------------------------------------- respond --- */}
      {tab === 'respond' && (
        <>
          <Panel title="If you think you clicked or replied" note="Speed matters far more than blame. Reporting early is what limits the damage.">
            {data.playbook.map((p) => (
              <div className="rec" key={p.step}>
                <span className="badge badge-info">{p.step}</span>
                <div className="rec-body"><span>{p.detail}</span></div>
              </div>
            ))}
          </Panel>

          <Panel title="False positives and false negatives">
            <div className="grid grid-2">
              <div>
                <h4>False positive</h4>
                <p className="muted small">{data.false_positive_negative.false_positive}</p>
              </div>
              <div>
                <h4>False negative</h4>
                <p className="muted small">{data.false_positive_negative.false_negative}</p>
              </div>
            </div>
            <div className="notice" style={{ marginTop: '0.8rem' }}>
              {data.false_positive_negative.why_multiple_signals}
            </div>
          </Panel>
        </>
      )}

      {/* -------------------------------------------------------- soc --- */}
      {tab === 'soc' && (
        <Panel title="How this fits a SOC workflow" note={data.soc_workflow_note}>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Stage</th><th>What happens</th><th>How this tool helps</th></tr></thead>
              <tbody>
                {data.soc_workflow.map((s, i) => (
                  <tr key={i}>
                    <td><strong>{s.stage}</strong></td>
                    <td className="muted small">{s.detail}</td>
                    <td className="small">{s.tool_support}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* ------------------------------------------------------ mitre --- */}
      {tab === 'mitre' && (
        <>
          <div className="notice warn" style={{ marginBottom: '1rem' }}>
            <strong>Verify before you cite.</strong> {data.mitre_mapping.disclaimer}
            {' '}Reference: <span className="mono">{data.mitre_mapping.reference}</span>
          </div>
          <Panel title={`${data.mitre_mapping.framework} — techniques this project relates to`}>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Why it applies</th><th>Covered here by</th></tr>
                </thead>
                <tbody>
                  {data.mitre_mapping.techniques.map((t) => (
                    <tr key={t.id}>
                      <td className="mono">{t.id}</td>
                      <td>{t.name}</td>
                      <td className="muted small">{t.tactic}</td>
                      <td className="muted small">{t.relevance}</td>
                      <td className="small">{t.project_coverage}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          <Panel title="Related mitigations">
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Mitigation</th><th>How this project covers it</th></tr></thead>
                <tbody>
                  {data.mitre_mapping.mitigations.map((m) => (
                    <tr key={m.id}>
                      <td className="mono">{m.id}</td>
                      <td>{m.name}</td>
                      <td className="muted small">{m.project_coverage}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="panel-note">{data.mitre_mapping.why_mapping_matters}</p>
          </Panel>
        </>
      )}
    </div>
  )
}
