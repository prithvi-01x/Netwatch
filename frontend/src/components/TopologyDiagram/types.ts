export interface PortInfo {
    port: number
    protocol: 'tcp' | 'udp'
    service: string
    state: 'open' | 'closed' | 'filtered'
    source?: 'docker' | 'host' | 'config'  // where this port was discovered
    pid?: number | null
    process_name?: string | null
}

export interface ContainerInfo {
    name: string
    image: string
    status: string
    ports: PortInfo[]
    networks: string[]
    ip: string
    cpu?: string | null
    memory?: string | null
    capabilities?: string[]
    internal: boolean
}

export interface TopologyResponse {
    containers: ContainerInfo[]
}

export interface TopologyConfig {
    host_ip: string
    gateway_ip: string
    interface_name: string
    docker_network: string
    containers: ContainerInfo[]
    host_ports: PortInfo[]
}

export const DEFAULT_CONFIG: TopologyConfig = {
    host_ip: '192.168.1.x',
    gateway_ip: '192.168.1.1',
    interface_name: 'eth0',
    docker_network: 'netwatch_default',
    host_ports: [
        { port: 22, protocol: 'tcp', service: 'SSH', state: 'closed' },
        { port: 8000, protocol: 'tcp', service: 'FastAPI', state: 'open' },
        { port: 3000, protocol: 'tcp', service: 'React UI', state: 'open' },
        { port: 11434, protocol: 'tcp', service: 'Ollama', state: 'open' },
    ],
    containers: [
        {
            name: 'netwatch-capture',
            image: 'netwatch/capture',
            status: 'running',
            networks: ['netwatch_default'],
            ip: '172.18.0.2',
            ports: [],
            capabilities: ['CAP_NET_RAW'],
            internal: false,
        },
        {
            name: 'netwatch-backend',
            image: 'netwatch/backend',
            status: 'running',
            networks: ['netwatch_default'],
            ip: '172.18.0.3',
            ports: [{ port: 8000, protocol: 'tcp', service: 'FastAPI', state: 'open' }],
            capabilities: [],
            internal: false,
        },
        {
            name: 'netwatch-frontend',
            image: 'netwatch/frontend',
            status: 'running',
            networks: ['netwatch_default'],
            ip: '172.18.0.4',
            ports: [{ port: 3000, protocol: 'tcp', service: 'Vite', state: 'open' }],
            capabilities: [],
            internal: false,
        },
        {
            name: 'ollama',
            image: 'ollama/ollama',
            status: 'running',
            networks: ['netwatch_default'],
            ip: '172.18.0.5',
            ports: [{ port: 11434, protocol: 'tcp', service: 'LLM', state: 'open' }],
            capabilities: [],
            internal: false,
        },
        {
            name: 'sqlite',
            image: 'alpine/sqlite',
            status: 'running',
            networks: ['netwatch_default'],
            ip: '172.18.0.6',
            ports: [],
            capabilities: [],
            internal: true,
        },
    ],
}