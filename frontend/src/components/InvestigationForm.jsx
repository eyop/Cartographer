import React, { useState } from 'react'

const TARGET_TYPES = ['domain', 'email', 'company', 'person']

export default function InvestigationForm({ onSubmit }) {
  const [target, setTarget] = useState('')
  const [targetType, setType] = useState('domain')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!target.trim()) return
    if (!authorized) {
      alert('You must confirm authorization to investigate this target.')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/investigations', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': import.meta.env.VITE_API_KEY || 'changeme',
        },
        body: JSON.stringify({ target, target_type: targetType, authorized: true }),
      })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      onSubmit(data.id, target)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <h2>Start Investigation</h2>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '1rem' }}>
          <input
            className="input"
            type="text"
            placeholder="Target (domain, email, company, person)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            required
          />
        </div>
        <div style={{ marginBottom: '1rem' }}>
          <select
            className="select"
            value={targetType}
            onChange={(e) => setType(e.target.value)}
          >
            {TARGET_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
        <div style={{ marginBottom: '1rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
            />
            <span>I confirm I am authorized to investigate this target</span>
          </label>
        </div>
        {error && <p style={{ color: '#f87171', marginBottom: '0.5rem' }}>{error}</p>}
        <button type="submit" className="btn" disabled={loading}>
          {loading ? 'Starting…' : 'Start Investigation'}
        </button>
      </form>
    </div>
  )
}
