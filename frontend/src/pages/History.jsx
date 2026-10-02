/**
 * src/pages/History.jsx
 * =====================
 * Every stored analysis: search, filter by band, sort by any column, open the
 * full report, and delete rows.
 */
import React, { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import { deleteAnalysis, getAnalysis, listAnalyses } from '../services/api.js'
import {
  Badge, Empty, ErrorBox, Loading, Panel, ScoreBar, Severity, scoreColor,
} from '../components/common.jsx'

const PAGE_SIZE = 15

const CLASSES = [
  '', 'LOW RISK', 'MODERATE RISK', 'SUSPICIOUS', 'HIGH RISK / LIKELY PHISHING',
]

const COLUMNS = [
  { key: 'created_at', label: 'Analysed' },
  { key: 'sender_domain', label: 'Sender domain' },
  { key: 'subject', label: 'Subject' },
  { key: 'risk_score', label: 'Score', num: true },
  { key: 'classification', label: 'Verdict' },
  { key: 'indicator_count', label: 'Indicators', num: true },
]

export default function History() {
  const [params, setParams] = useSearchParams()

  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [sortBy, setSortBy] = useState('created_at')
  const [order, setOrder] = useState('desc')
  const [classification, setClassification] = useState('')
  const [search, setSearch] = useState('')
  const [minScore, setMinScore] = useState('')

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [busyId, setBusyId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const data = await listAnalyses({
        limit: PAGE_SIZE, offset, sortBy, order, classification, search, minScore,
      })
      setRows(data.items || [])
      setTotal(data.total || 0)
    } catch (e) {
      setError(e)
    } finally {
      setLoading(false)
    }
  }, [offset, sortBy, order, classification, search, minScore])

  useEffect(() => { load() }, [load])

  // Deep link: /history?id=<analysis_id> opens that report directly.
  const linkedId = params.get('id')
  useEffect(() => {
    if (linkedId) openDetail(linkedId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkedId])

  async function openDetail(id) {
    setDetailLoading(true)
    try {
      setDetail(await getAnalysis(id))
    } catch (e) {
      setError(e)
    } finally {
      setDetailLoading(false)
    }
  }

  function closeDetail() {
    setDetail(null)
    if (params.get('id')) {
      params.delete('id')
      setParams(params, { replace: true })
    }
  }

  async function remove(id) {
    if (!window.confirm('Delete this analysis from the local history? This cannot be undone.')) return
    setBusyId(id)
    try {
      await deleteAnalysis(id)
      if (detail?.analysis_id === id) closeDetail()
      await load()
    } catch (e) {
      setError(e)
    } finally {
      setBusyId(null)
    }
  }

  function toggleSort(key) {
    if (sortBy === key) setOrder(order === 'asc' ? 'desc' : 'asc')
    else { setSortBy(key); setOrder(key === 'subject' || key === 'sender_domain' ? 'asc' : 'desc') }
    setOffset(0)
  }

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const page = Math.floor(offset / PAGE_SIZE) + 1

  return (
    <div>
      <div className="page-head">
        <h1>Analysis history</h1>
        <p>
          Everything analysed on this machine, stored locally in SQLite. Search, filter,
          sort, open the full report or delete a row.
        </p>
      </div>

      <Panel title="Filters">
        <div className="grid grid-3">
          <div className="field" style={{ marginBottom: 0 }}>
            <label htmlFor="q">Search subject or sender domain</label>
            <input id="q" type="search" value={search}
              onChange={(e) => { setSearch(e.target.value); setOffset(0) }}
              placeholder="e.g. invoice, verify, example.org" />
          </div>
          <div className="field" style={{ marginBottom: 0 }}>
            <label htmlFor="cls">Classification</label>
            <select id="cls" value={classification}
              onChange={(e) => { setClassification(e.target.value); setOffset(0) }}>
              {CLASSES.map((c) => <option key={c} value={c}>{c || 'All classifications'}</option>)}
            </select>
          </div>
          <div className="field" style={{ marginBottom: 0 }}>
            <label htmlFor="ms">Minimum score</label>
            <input id="ms" type="number" min="0" max="100" value={minScore}
              onChange={(e) => { setMinScore(e.target.value); setOffset(0) }}
              placeholder="0" />
          </div>
        </div>
        <div className="btn-row" style={{ marginTop: '0.8rem' }}>
          <button className="btn btn-ghost btn-sm"
            onClick={() => { setSearch(''); setClassification(''); setMinScore(''); setOffset(0) }}>
            Reset filters
          </button>
          <span className="small muted">
            {total} {total === 1 ? 'analysis' : 'analyses'} matched
          </span>
        </div>
      </Panel>

      <div className="spacer" />
      <ErrorBox error={error} onRetry={load} />

      <Panel title={`Results (page ${page} of ${pages})`}>
        {loading ? <Loading /> : rows.length === 0 ? (
          <Empty>
            Nothing matches. Analyse an email, adjust the filters, or run <code>seed_demo.bat</code>.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {COLUMNS.map((c) => (
                    <th key={c.key} className={`sortable ${c.num ? 'num' : ''}`}
                      onClick={() => toggleSort(c.key)}>
                      {c.label}{sortBy === c.key ? (order === 'asc' ? ' ▲' : ' ▼') : ''}
                    </th>
                  ))}
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.analysis_id}>
                    <td className="small muted" style={{ whiteSpace: 'nowrap' }}>
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td className="mono small">{r.sender_domain}</td>
                    <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.subject || <span className="muted">(no subject)</span>}
                    </td>
                    <td className="num" style={{ color: scoreColor(r.risk_score), fontWeight: 700 }}>
                      {r.risk_score}
                    </td>
                    <td><Badge classification={r.classification} /></td>
                    <td className="num">{r.indicator_count}</td>
                    <td>
                      <div className="btn-row" style={{ gap: '0.35rem' }}>
                        <button className="btn btn-ghost btn-sm" onClick={() => openDetail(r.analysis_id)}>
                          View
                        </button>
                        <button className="btn btn-danger btn-sm" disabled={busyId === r.analysis_id}
                          onClick={() => remove(r.analysis_id)}>
                          {busyId === r.analysis_id ? '…' : 'Delete'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {pages > 1 && (
          <div className="btn-row" style={{ marginTop: '0.9rem', justifyContent: 'center' }}>
            <button className="btn btn-ghost btn-sm" disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              ← Previous
            </button>
            <span className="small muted">Page {page} of {pages}</span>
            <button className="btn btn-ghost btn-sm" disabled={page >= pages}
              onClick={() => setOffset(offset + PAGE_SIZE)}>
              Next →
            </button>
          </div>
        )}
      </Panel>

      {/* ---------------------------------------------------- detail --- */}
      {(detail || detailLoading) && (
        <>
          <div className="spacer" />
          <Panel
            title="Full report"
            action={<button className="btn btn-ghost btn-sm" onClick={closeDetail}>Close</button>}
          >
            {detailLoading && <Loading text="Loading report…" />}
            {detail && !detailLoading && (
              <div>
                <div className="score-wrap" style={{ marginBottom: '1rem' }}>
                  <div>
                    <span className="score-big" style={{ color: scoreColor(detail.risk_score) }}>
                      {detail.risk_score}
                    </span>
                    <span className="score-out">/100</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 220 }}>
                    <Badge classification={detail.classification} />
                    <div style={{ marginTop: 8 }}><ScoreBar score={detail.risk_score} /></div>
                  </div>
                </div>

                <div className="grid grid-2" style={{ alignItems: 'start' }}>
                  <div>
                    <h4>Message</h4>
                    <table>
                      <tbody>
                        <tr><th>Sender domain</th><td className="mono small">{detail.sender_domain}</td></tr>
                        <tr><th>Subject</th><td>{detail.subject || '(none)'}</td></tr>
                        <tr><th>Analysed</th><td className="small">{new Date(detail.created_at).toLocaleString()}</td></tr>
                        <tr><th>Attachment</th><td className="mono small">{detail.attachment_name || '(none)'}</td></tr>
                        <tr><th>Links</th><td>{detail.url_count}</td></tr>
                        {detail.ml_probability != null && (
                          <tr>
                            <th>ML probability</th>
                            <td>{(detail.ml_probability * 100).toFixed(1)}%</td>
                          </tr>
                        )}
                        {detail.hybrid_score != null && (
                          <tr><th>Hybrid score</th><td>{detail.hybrid_score}/100</td></tr>
                        )}
                      </tbody>
                    </table>

                    {detail.url_analyses?.length > 0 && (
                      <>
                        <h4 style={{ marginTop: '1rem' }}>Links found</h4>
                        {detail.url_analyses.map((u) => (
                          <div className="ind" key={u.url_analysis_id}>
                            <div className="ind-head">
                              <span className={`badge badge-${
                                u.risk_score >= 41 ? 'high' : u.risk_score >= 21 ? 'moderate' : 'low'}`}>
                                {u.risk_score}/100
                              </span>
                              <span className="mono small" style={{ wordBreak: 'break-all' }}>
                                {u.url_safe_representation}
                              </span>
                            </div>
                            <div className="pill-row" style={{ marginBottom: 6 }}>
                              {u.hostname && <span className="badge badge-info">host: {u.hostname}</span>}
                              {u.is_ip ? <span className="badge badge-high">raw IP</span> : null}
                              <span className={`badge badge-${u.uses_https ? 'low' : 'moderate'}`}>
                                {u.uses_https ? 'HTTPS' : 'plain HTTP'}
                              </span>
                              {u.is_shortener ? <span className="badge badge-suspicious">shortener</span> : null}
                            </div>
                            {(u.findings || []).map((f, j) => (
                              <p className="ind-desc small" key={j} style={{ marginBottom: 4 }}>• {f}</p>
                            ))}
                          </div>
                        ))}
                      </>
                    )}
                  </div>

                  <div>
                    <h4>Indicators ({detail.indicators?.length || 0})</h4>
                    {(detail.indicators || []).map((ind, i) => (
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
                  </div>
                </div>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  )
}
