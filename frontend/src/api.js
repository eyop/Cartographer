const API_KEY = import.meta.env.VITE_API_KEY || 'changeme'

const headers = { 'X-API-Key': API_KEY }

export async function createInvestigation(target, targetType) {
  const res = await fetch('/investigations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ target, target_type: targetType, authorized: true }),
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getInvestigation(id) {
  const res = await fetch(`/investigations/${id}`, { headers })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getGraph(id) {
  const res = await fetch(`/investigations/${id}/graph`, { headers })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getProfile(id) {
  const res = await fetch(`/investigations/${id}/profile`, { headers })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getReport(id) {
  const res = await fetch(`/investigations/${id}/report`, { headers })
  if (!res.ok) throw new Error(await res.text())
  return res.blob()
}
