import React, { useEffect, useRef, useMemo, useState } from 'react'
import * as d3 from 'd3'
import type { StatsResponse } from '../../types'
import './GeoMap.css'

interface Props {
    stats: StatsResponse | null
}

interface GeoResult {
    ip: string
    lat: number
    lng: number
    city: string
    country: string
    countryCode: string
    isp: string
}

// ip-api.com batch — free, no key needed, up to 100 IPs
async function lookupIps(ips: string[]): Promise<GeoResult[]> {
    const publicIps = ips.filter(ip =>
        !ip.startsWith('127.') &&
        !ip.startsWith('192.168.') &&
        !ip.startsWith('10.') &&
        !ip.startsWith('172.16.') &&
        ip !== '::1'
    )
    if (!publicIps.length) return []

    const res = await fetch(
        'http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,isp,query',
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(publicIps.map(ip => ({ query: ip }))),
        }
    )
    const data = await res.json()
    return data
        .filter((r: any) => r.status === 'success')
        .map((r: any) => ({
            ip: r.query,
            lat: r.lat,
            lng: r.lon,
            city: r.city,
            country: r.country,
            countryCode: r.countryCode,
            isp: r.isp,
        }))
}

// Plain GeoJSON world map — no topojson needed
const WORLD_URL = 'https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson'

export const GeoMap: React.FC<Props> = ({ stats }) => {
    const svgRef = useRef<SVGSVGElement>(null)
    const tooltipRef = useRef<HTMLDivElement>(null)
    const [geoData, setGeoData] = useState<Map<string, GeoResult>>(new Map())
    const [worldGeo, setWorldGeo] = useState<any>(null)
    const [loadingIps, setLoadingIps] = useState(false)
    const [mapError, setMapError] = useState<string | null>(null)
    const [ipError, setIpError] = useState<string | null>(null)

    const topIps = useMemo(() => stats?.top_src_ips ?? [], [stats])
    const maxCount = useMemo(() => Math.max(...topIps.map(t => t.count), 1), [topIps])

    // Load world GeoJSON once
    useEffect(() => {
        fetch(WORLD_URL)
            .then(r => { if (!r.ok) throw new Error('Failed'); return r.json() })
            .then(data => setWorldGeo(data))
            .catch(() => setMapError('Could not load world map — requires internet access'))
    }, [])

    // Real IP geo lookup whenever topIps changes
    useEffect(() => {
        if (!topIps.length) return
        const missing = topIps.map(t => t.src_ip).filter(ip => !geoData.has(ip))
        if (!missing.length) return

        setLoadingIps(true)
        setIpError(null)
        lookupIps(missing)
            .then(results => {
                setGeoData(prev => {
                    const next = new Map(prev)
                    results.forEach(r => next.set(r.ip, r))
                    return next
                })
            })
            .catch(err => setIpError(`IP lookup failed: ${err.message}`))
            .finally(() => setLoadingIps(false))
    }, [topIps])

    // Redraw SVG when world or geo data changes
    useEffect(() => {
        if (!svgRef.current || !worldGeo) return

        const svg = d3.select(svgRef.current)
        svg.selectAll('*').remove()

        const width = svgRef.current.clientWidth || 900
        const height = svgRef.current.clientHeight || 380

        const projection = d3.geoNaturalEarth1()
            .scale(width / 6.3)
            .translate([width / 2, height / 2])

        const pathGen = d3.geoPath().projection(projection)

        // Background
        svg.append('rect')
            .attr('width', width).attr('height', height)
            .attr('fill', '#080c14')

        // Graticule grid
        const graticule = d3.geoGraticule()
        svg.append('path')
            .datum(graticule())
            .attr('d', pathGen as any)
            .attr('fill', 'none')
            .attr('stroke', '#13192a')
            .attr('stroke-width', 0.5)

        // Countries
        svg.selectAll('.country')
            .data((worldGeo as any).features)
            .join('path')
            .attr('class', 'country')
            .attr('d', pathGen as any)
            .attr('fill', '#1c2535')
            .attr('stroke', '#2d3f58')
            .attr('stroke-width', 0.4)

        // Sphere outline
        svg.append('path')
            .datum({ type: 'Sphere' } as any)
            .attr('d', pathGen as any)
            .attr('fill', 'none')
            .attr('stroke', '#2d3f58')
            .attr('stroke-width', 1)

        // Plot IPs with real coords
        topIps.forEach(({ src_ip, count }) => {
            const geo = geoData.get(src_ip)
            if (!geo) return

            const proj = projection([geo.lng, geo.lat])
            if (!proj) return
            const [x, y] = proj
            const r = 5 + (count / maxCount) * 18

            // Outer pulse rings
            svg.append('circle').attr('cx', x).attr('cy', y)
                .attr('r', r + 10).attr('fill', 'none')
                .attr('stroke', '#ff2d2d').attr('stroke-width', 0.5).attr('opacity', 0.1)
            svg.append('circle').attr('cx', x).attr('cy', y)
                .attr('r', r + 5).attr('fill', 'none')
                .attr('stroke', '#ff2d2d').attr('stroke-width', 1).attr('opacity', 0.2)

            // Main circle
            svg.append('circle')
                .attr('cx', x).attr('cy', y).attr('r', r)
                .attr('fill', 'rgba(255,45,45,0.35)')
                .attr('stroke', '#ff2d2d').attr('stroke-width', 1.5)
                .style('cursor', 'pointer')
                .on('mouseover', (event: MouseEvent) => {
                    const tip = tooltipRef.current
                    if (!tip || !svgRef.current) return
                    const rect = svgRef.current.getBoundingClientRect()
                    tip.style.display = 'block'
                    tip.style.left = `${event.clientX - rect.left + 14}px`
                    tip.style.top = `${event.clientY - rect.top - 14}px`
                    tip.innerHTML = `
                        <div class="geomap__tip-ip">${src_ip}</div>
                        <div class="geomap__tip-loc">${geo.city}, ${geo.country}</div>
                        <div class="geomap__tip-isp">${geo.isp}</div>
                        <div class="geomap__tip-count">${count.toLocaleString()} alerts</div>
                    `
                })
                .on('mouseout', () => {
                    if (tooltipRef.current) tooltipRef.current.style.display = 'none'
                })

            // Label for large circles
            if (r > 10) {
                svg.append('text')
                    .attr('x', x).attr('y', y - r - 5)
                    .attr('text-anchor', 'middle')
                    .attr('fill', '#8b949e').attr('font-size', '9px')
                    .attr('font-family', 'monospace')
                    .text(src_ip)
            }
        })

    }, [worldGeo, geoData, topIps, maxCount])

    return (
        <div className="geomap">
            <div className="geomap__header">
                <span className="geomap__title">◉ Attack Origin Map</span>
                <div className="geomap__header-right">
                    {loadingIps && (
                        <span className="geomap__loading">
                            <span className="geomap__spinner" /> Looking up IPs...
                        </span>
                    )}
                    {(mapError || ipError) && (
                        <span className="geomap__error">⚠ {mapError || ipError}</span>
                    )}
                    <div className="geomap__legend">
                        <span className="geomap__legend-dot" />
                        <span>Real location via ip-api.com · circle = alert volume</span>
                    </div>
                </div>
            </div>

            <div className="geomap__canvas">
                {!worldGeo && !mapError && (
                    <div className="geomap__map-loading">
                        <span className="geomap__spinner" /> Loading world map...
                    </div>
                )}
                <svg ref={svgRef} width="100%" height="100%" />
                <div ref={tooltipRef} className="geomap__tooltip" style={{ display: 'none' }} />
            </div>

            <div className="geomap__table">
                {topIps.slice(0, 6).map(({ src_ip, count }) => {
                    const geo = geoData.get(src_ip)
                    const isLocal = src_ip.startsWith('127.') || src_ip.startsWith('192.168.')
                    return (
                        <div key={src_ip} className="geomap__row">
                            <span className="geomap__row-ip mono">{src_ip}</span>
                            <span className="geomap__row-loc">
                                {isLocal
                                    ? <span style={{ color: 'var(--text-muted)' }}>Localhost</span>
                                    : geo
                                        ? `${geo.city}, ${geo.countryCode}`
                                        : <span style={{ color: 'var(--text-muted)' }}>Looking up…</span>
                                }
                            </span>
                            <span className="geomap__row-bar">
                                <span className="geomap__row-fill" style={{ width: `${(count / maxCount) * 100}%` }} />
                            </span>
                            <span className="geomap__row-count mono">{count.toLocaleString()}</span>
                        </div>
                    )
                })}
            </div>
        </div>
    )
}