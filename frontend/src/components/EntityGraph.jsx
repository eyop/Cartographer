import React, { useEffect, useRef } from 'react'
import * as d3 from 'd3'

const NODE_COLORS = {
  domain: '#38bdf8',
  ip: '#f87171',
  email: '#4ade80',
  person: '#a78bfa',
  org: '#facc15',
  repo: '#fb7185',
  cve: '#fb923c',
}

export default function EntityGraph({ investigationId }) {
  const svgRef = useRef()
  const containerRef = useRef()

  useEffect(() => {
    if (!investigationId) return

    const fetchData = async () => {
      try {
        const res = await fetch(`/investigations/${investigationId}/graph`, {
          headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || 'changeme' },
        })
        if (!res.ok) return
        const graph = await res.json()
        renderGraph(graph)
      } catch (err) {
        console.error(err)
      }
    }

    const renderGraph = (graph) => {
      const svg = d3.select(svgRef.current)
      svg.selectAll('*').remove()

      const width = 720
      const height = 500

      const svgEl = svg
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', `0 0 ${width} ${height}`)

      const simulation = d3.forceSimulation(graph.entities)
        .force('link', d3.forceLink(graph.relationships)
          .id((d) => d.id)
          .distance(100)
          .strength(0.3))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide().radius(30))

      const link = svgEl.append('g')
        .attr('stroke', '#334155')
        .attr('stroke-width', 1.5)
        .selectAll('line')
        .data(graph.relationships)
        .enter()
        .append('line')
        .attr('class', 'relationship-edge')

      const node = svgEl.append('g')
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 1.5)
        .selectAll('g')
        .data(graph.entities)
        .enter()
        .append('g')
        .attr('class', 'entity-node')
        .call(drag(simulation))

      const nodeBg = node.append('circle')
        .attr('r', 12)
        .attr('fill', (d) => NODE_COLORS[d.type] || '#94a3b8')

      const label = node.append('text')
        .attr('dy', -20)
        .attr('text-anchor', 'middle')
        .attr('fill', '#e2e8f0')
        .attr('font-size', 9)
        .text((d) => d.value.length > 14 ? d.value.slice(0, 14) + '…' : d.value)

      const confidence = node.append('title')
        .text((d) => `${d.type}: ${d.value}\nConfidence: ${(d.confidence * 100).toFixed(0)}%\nSources: ${d.sources.join(', ')}`)

      // Tooltip on hover
      node.on('mouseover', function(event, d) {
        d3.select(this).select('circle').attr('r', 16)
      }).on('mouseout', function() {
        d3.select(this).select('circle').attr('r', 12)
      })

      simulation.on('tick', () => {
        link
          .attr('x1', (d) => d.source.x)
          .attr('y1', (d) => d.source.y)
          .attr('x2', (d) => d.target.x)
          .attr('y2', (d) => d.target.y)
        node.attr('transform', (d) => `translate(${d.x},${d.y})`)
      })

      function drag(simulation) {
        function dragstarted(event) {
          if (!event.active) simulation.alphaTarget(0.3).restart()
          event.subject.fx = event.subject.x
          event.subject.fy = event.subject.y
        }
        function dragged(event) {
          event.subject.fx = event.x
          event.subject.fy = event.y
        }
        function dragended(event) {
          if (!event.active) simulation.alphaTarget(0)
          event.subject.fx = null
          event.subject.fy = null
        }
        return d3.drag()
          .on('start', dragstarted)
          .on('drag', dragged)
          .on('end', dragended)
      }
    }

    // Poll for graph data
    const pollId = setInterval(fetchData, 5000)
    fetchData()
    return () => clearInterval(pollId)
  }, [investigationId])

  return (
    <div className="card" ref={containerRef}>
      <h2>Entity Graph</h2>
      <svg ref={svgRef}></svg>
      <p className="text-sm text-muted">Nodes colored by type. Drag to explore.</p>
    </div>
  )
}
