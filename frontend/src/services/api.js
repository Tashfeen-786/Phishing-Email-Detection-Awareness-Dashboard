/**
 * src/services/api.js
 * ===================
 * The single place where the frontend talks to the backend.
 *
 * Every call uses a RELATIVE path ("/api/..."). Vite's dev server proxies those
 * to http://127.0.0.1:8000 (see vite.config.js). Nothing in the browser ever
 * hard-codes the backend's host, so the app keeps working when it is opened
 * from another machine or served behind a different hostname.
 */

const BASE = '/api'

/** Turn any failure into a readable message instead of an unhandled rejection. */
async function request(path, options = {}) {
  let response
  try {
    response = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    })
  } catch (networkError) {
    throw new Error(
      'Cannot reach the backend. Start it with start_backend.bat and confirm ' +
      'http://127.0.0.1:8000/api/health responds.'
    )
  }

  const text = await response.text()
  let payload = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = { detail: text }
    }
  }

  if (!response.ok) {
    const detail =
      payload?.detail ??
      payload?.error ??
      (Array.isArray(payload) ? payload[0]?.msg : null) ??
      `Request failed with HTTP ${response.status}`
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return payload
}

// ---------------------------------------------------------------- analysis
export const analyzeEmail = (payload) =>
  request('/analyze', { method: 'POST', body: JSON.stringify(payload) })

export const analyzeUrl = (url) =>
  request('/analyze/url', { method: 'POST', body: JSON.stringify({ url }) })

// ---------------------------------------------------------------- history
export function listAnalyses({
  limit = 25,
  offset = 0,
  sortBy = 'created_at',
  order = 'desc',
  classification = '',
  search = '',
  minScore = null,
} = {}) {
  const params = new URLSearchParams({ limit, offset, sort_by: sortBy, order })
  if (classification) params.set('classification', classification)
  if (search) params.set('search', search)
  if (minScore !== null && minScore !== '') params.set('min_score', minScore)
  return request(`/analyses?${params.toString()}`)
}

export const getAnalysis = (id) => request(`/analyses/${encodeURIComponent(id)}`)

export const deleteAnalysis = (id) =>
  request(`/analyses/${encodeURIComponent(id)}`, { method: 'DELETE' })

// ---------------------------------------------------------------- dashboard
export const getStats = () => request('/dashboard/stats')
export const getIndicators = (limit = 10) => request(`/dashboard/indicators?limit=${limit}`)
export const getKeywords = (limit = 12) => request(`/dashboard/keywords?limit=${limit}`)
export const getRules = () => request('/dashboard/rules')

// ---------------------------------------------------------------- awareness
export const getAwareness = () => request('/awareness')

// ---------------------------------------------------------------- meta
export const getHealth = () => request('/health')
export const getModelInfo = () => request('/ml/info')
