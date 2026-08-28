import React, { useEffect, useState } from 'react'

export default function ThreatReport({ investigationId, target }) {
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const fetchProfile = async () => {
    if (!investigationId) return
    setLoading(true)
    try {
      const res = await fetch(`/investigations/${investigationId}/profile`, {
        headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || 'changeme' },
      })
      if (!res.ok) {
        if (res.status === 404) {
          setTimeout(fetchProfile, 5000)
          return
        }
        throw new Error(await res.text())
      }
      const data = await res.json()
      setProfile(data)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchProfile() }, [investigationId])

  const downloadReport = async () => {
    const res = await fetch(`/investigations/${investigationId}/report`, {
      headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || 'changeme' },
    })
    const blob = await res.blob()
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report_${investigationId}.pdf`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  if (loading) return <p className="text-muted">Synthesizing threat profile…</p>
  if (error) return <p style={{ color: '#f87171' }}>Error: {error}</p>

  return (
    <div className="card">
      <h2>Threat Report</h2>
      {!profile && <p className="text-muted">Report will appear here once synthesis completes. (target: {target})</p>}
      {profile && (
        <>
          <p style={{ marginBottom: '1rem' }}>{profile.summary}</p>
          {profile.risk_indicators && profile.risk_indicators.length > 0 && (
            <div style={{ marginBottom: '1rem' }}>
              <strong>Risk Indicators:</strong>
              <ul>
                {profile.risk_indicators.map((ind, i) => (
                  <li key={i}>{ind}</li>
                ))}
              </ul>
            </div>
          )}
          <button className="btn" onClick={downloadReport}>
            Download PDF Report
          </button>
        </>
      )}
    </div>
  )
}
