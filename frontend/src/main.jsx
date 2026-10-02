/**
 * src/main.jsx
 * ============
 * Entry point. BrowserRouter gives the four pages real URLs so the dashboard
 * can be deep-linked (for example /history?id=<analysis_id>).
 */
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import App from './App.jsx'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
)
