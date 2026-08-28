# Frontend (week 6)

React + D3.js dashboard. Not scaffolded yet — this is where the
force-directed entity graph and investigation status view live.

Consumes:
- POST /investigations
- GET  /investigations/{id}        (poll for status)
- GET  /investigations/{id}/graph  (feeds the D3 force layout)
- GET  /investigations/{id}/report (PDF download link)
