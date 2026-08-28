import React, { useEffect, useState } from 'react'

const STATUS_COLORS = {
  queued: 'status-queued',
  running: 'status-running',
  completed: 'status-completed',
  failed: 'status-failed',
}

export default function InvestigationStatus({ investigationId }) {
  const [record, setRecord] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchRecord = async () => {
    try {
      const res = await fetch(`/investigations/${investigationId}`, {
        headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || 'changeme' },
      })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      setRecord(data)
      setError(null)
      if (data.status !== 'completed' && data.status !== 'failed') {
        setTimeout(fetchRecord, 3000)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRecord()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationId])

  if (loading && !record) return <p className="text-muted">Loading investigation status…</p>
  if (error) return <p style={{ color: '#f87171' }}>Error: {error}</p>
  if (!record) return null

  return (
    <div className="card">
      <h2>Investigation Status</h2>
      <p>
        Target: <strong>{record.target}</strong> ({record.target_type})
      </p>
      <p>
        Status: <span className={`status-badge ${STATUS_COLORS[record.status]}`}>{record.status}</span>
      </p>
      {record.error && <p style={{ color: '#f87171' }}>Error: {record.error}</p>}
      {record.progress && Object.keys(record.progress).length > 0 && (
        <div>
          <strong>Progress:</strong>
          <ul>
            {Object.entries(record.progress).map(([key, val]) => (
              <li key={key}>{key}: {val}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
