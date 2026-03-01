import React, { useState, useRef, useEffect, useCallback } from 'react'
import type { Alert, StatsResponse } from '../../types'
import './AskClaude.css'

// Ollama runs locally — change this if your Ollama is on a different host/port
const OLLAMA_BASE = 'http://localhost:11434'

interface Props {
    alerts: Alert[]
    stats: StatsResponse | null
    model?: string
}

interface Message {
    id: string
    role: 'user' | 'assistant'
    content: string
    timestamp: number
}

const SUGGESTIONS = [
    'Summarize the current threat landscape',
    'Which source IP poses the biggest risk?',
    'Are there signs of lateral movement?',
    'What should I prioritize responding to?',
    'Explain the beaconing pattern detected',
]

export const AskClaude: React.FC<Props> = ({ alerts, stats, model = 'phi3:14b' }) => {
    const OLLAMA_MODEL = model
    const [messages, setMessages] = useState<Message[]>([])
    const [input, setInput] = useState('')
    const [isLoading, setIsLoading] = useState(false)
    const [ollamaError, setOllamaError] = useState<string | null>(null)
    const bottomRef = useRef<HTMLDivElement>(null)
    const inputRef = useRef<HTMLTextAreaElement>(null)

    const autoSummarizedRef = useRef(false)

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [messages])

    // Auto-summarize on first open if there are alerts
    useEffect(() => {
        if (autoSummarizedRef.current) return
        if (!alerts.length) return
        autoSummarizedRef.current = true
        sendMessage('Summarize the current threat landscape in 3-5 sentences.')
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [alerts.length])

    const buildSystemPrompt = useCallback(() => {
        const topAlerts = alerts.slice(0, 20)
        const alertSummary = topAlerts.map(a =>
            `[${a.severity}] ${a.rule_name} | ${a.src_ip} → ${a.dst_ip} | ${a.description}${a.llm_explanation ? ` | ${a.llm_explanation.summary}` : ''}`
        ).join('\n')

        return `You are a network security analyst assistant for the NetWatch IDS dashboard.

CURRENT STATS:
- Total alerts: ${stats?.total_alerts ?? 0}
- Alerts last hour: ${stats?.alerts_last_hour ?? 0}
- Top source IPs: ${(stats?.top_src_ips ?? []).slice(0, 5).map(t => `${t.src_ip}(${t.count})`).join(', ')}
- Alerts by severity: ${JSON.stringify(stats?.alerts_by_severity ?? {})}

RECENT ALERTS:
${alertSummary || 'No alerts yet.'}

Answer in 3-5 short sentences max. Be direct and specific. No rambling, no filler words. State the key finding, the risk, and one clear action. Plain text only, no markdown, no bullet points.`
    }, [alerts, stats])

    const sendMessage = useCallback(async (text: string) => {
        if (!text.trim() || isLoading) return

        const userMsg: Message = {
            id: String(Date.now()),
            role: 'user',
            content: text.trim(),
            timestamp: Date.now(),
        }

        setMessages(prev => [...prev, userMsg])
        setInput('')
        setIsLoading(true)
        setOllamaError(null)

        try {
            const systemPrompt = buildSystemPrompt()
            const history = [...messages, userMsg]

            // Build the full prompt for Ollama /api/chat (OpenAI-compatible format)
            const response = await fetch(`${OLLAMA_BASE}/api/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: OLLAMA_MODEL,
                    stream: false,
                    messages: [
                        { role: 'system', content: systemPrompt },
                        ...history.map(m => ({ role: m.role, content: m.content })),
                    ],
                }),
            })

            if (!response.ok) {
                throw new Error(`Ollama returned ${response.status}: ${await response.text()}`)
            }

            const data = await response.json()
            const content = data.message?.content ?? 'No response from model.'

            setMessages(prev => [...prev, {
                id: String(Date.now() + 1),
                role: 'assistant',
                content,
                timestamp: Date.now(),
            }])
        } catch (err: any) {
            const msg = err?.message ?? 'Unknown error'
            setOllamaError(msg)
            setMessages(prev => [...prev, {
                id: String(Date.now() + 1),
                role: 'assistant',
                content: `⚠ Could not reach Ollama.\n\nMake sure Ollama is running:\n  ollama serve\n  ollama pull ${OLLAMA_MODEL}\n\nError: ${msg}`,
                timestamp: Date.now(),
            }])
        } finally {
            setIsLoading(false)
        }
    }, [messages, isLoading, buildSystemPrompt])

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            sendMessage(input)
        }
    }

    return (
        <div className="ask-claude">
            <div className="ask-claude__header">
                <span className="ask-claude__title">⬡ Ask AI</span>
                <span className="ask-claude__subtitle">Security Assistant — powered by Ollama {OLLAMA_MODEL}</span>
                {ollamaError && (
                    <span className="ask-claude__error-badge" title={ollamaError}>
                        ⚠ Ollama unreachable
                    </span>
                )}
            </div>

            <div className="ask-claude__body">
                {messages.length === 0 ? (
                    <div className="ask-claude__welcome">
                        <div className="ask-claude__welcome-icon">⬡</div>
                        <p className="ask-claude__welcome-text">
                            Ask anything about current network activity, threat patterns, or what actions to take. Running locally on <strong>Ollama {OLLAMA_MODEL}</strong> — no API key needed.
                        </p>
                        <div className="ask-claude__suggestions">
                            {SUGGESTIONS.map(s => (
                                <button
                                    key={s}
                                    className="ask-claude__suggestion"
                                    onClick={() => sendMessage(s)}
                                >
                                    {s}
                                </button>
                            ))}
                        </div>
                    </div>
                ) : (
                    <div className="ask-claude__messages">
                        {messages.map(msg => (
                            <div
                                key={msg.id}
                                className={`ask-claude__message ask-claude__message--${msg.role}`}
                            >
                                <div className="ask-claude__message-role">
                                    {msg.role === 'user' ? 'You' : `⬡ ${OLLAMA_MODEL}`}
                                </div>
                                <div className="ask-claude__message-content">
                                    {msg.content}
                                </div>
                            </div>
                        ))}
                        {isLoading && (
                            <div className="ask-claude__message ask-claude__message--assistant">
                                <div className="ask-claude__message-role">⬡ {OLLAMA_MODEL}</div>
                                <div className="ask-claude__thinking">
                                    <span /><span /><span />
                                </div>
                            </div>
                        )}
                        <div ref={bottomRef} />
                    </div>
                )}
            </div>

            <div className="ask-claude__footer">
                <textarea
                    ref={inputRef}
                    className="ask-claude__input"
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about your network security... (Enter to send)"
                    rows={2}
                    disabled={isLoading}
                />
                <button
                    className="ask-claude__send"
                    onClick={() => sendMessage(input)}
                    disabled={!input.trim() || isLoading}
                >
                    {isLoading ? '...' : '→'}
                </button>
            </div>
        </div>
    )
}