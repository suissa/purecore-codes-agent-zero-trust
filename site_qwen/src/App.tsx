import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import { Shield, Lock, Key, Server, Network, BookOpen, Github, Menu, X, ChevronRight, ShieldCheck, Zap, Layers, Database } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { cn } from '@/lib/utils'
import { useState } from 'react'

// Componente de Navegação
function Navigation() {
  const [isOpen, setIsOpen] = useState(false)
  const location = useLocation()

  const navItems = [
    { path: '/', label: 'Início', icon: Shield },
    { path: '/arquitetura', label: 'Arquitetura', icon: Layers },
    { path: '/tecnologias', label: 'Tecnologias', icon: Zap },
    { path: '/diagramas', label: 'Diagramas', icon: Network },
    { path: '/api', label: 'API', icon: BookOpen },
  ]

  return (
    <nav className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center">
        <div className="mr-4 hidden md:flex">
          <Link to="/" className="mr-6 flex items-center space-x-2">
            <Shield className="h-6 w-6" />
            <span className="hidden font-bold sm:inline-block">Agent Zero Trust</span>
          </Link>
          <nav className="flex items-center space-x-6 text-sm font-medium">
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={cn(
                  'transition-colors hover:text-foreground/80 flex items-center gap-2',
                  location.pathname === item.path ? 'text-foreground' : 'text-foreground/60'
                )}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
        <Button variant="ghost" className="mr-2 px-0 text-base hover:bg-transparent focus-visible:bg-transparent focus-visible:ring-0 focus-visible:ring-offset-0 md:hidden">
          <Menu onClick={() => setIsOpen(!isOpen)} className="h-6 w-6" />
        </Button>
        <div className="flex flex-1 items-center justify-between space-x-2 md:justify-end">
          <div className="w-full flex-1 md:w-auto md:flex-none">
            <Button variant="outline" size="sm" asChild>
              <a href="https://npmjs.com/package/agent-zero-trust" target="_blank" rel="noopener noreferrer">
                <Github className="mr-2 h-4 w-4" />
                NPM
              </a>
            </Button>
          </div>
        </div>
      </div>
      {isOpen && (
        <div className="md:hidden border-b">
          <div className="container py-4">
            <nav className="flex flex-col space-y-4">
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setIsOpen(false)}
                  className="flex items-center space-x-2 text-sm font-medium"
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </Link>
              ))}
            </nav>
          </div>
        </div>
      )}
    </nav>
  )
}

// Página Inicial
function Home() {
  return (
    <div className="container py-8">
      {/* Hero Section */}
      <section className="py-12 md:py-24 lg:py-32">
        <div className="container mx-auto px-4 md:px-6">
          <div className="flex flex-col items-center space-y-8 text-center">
            <div className="space-y-4">
              <h1 className="text-4xl font-bold tracking-tighter sm:text-5xl md:text-6xl lg:text-7xl">
                Agent Zero Trust
              </h1>
              <p className="mx-auto max-w-[700px] text-gray-500 md:text-xl dark:text-gray-400">
                Arquitetura Zero-Trust para Agentes Autônomos de IA com Signal Protocol E2EE, DPoP e mTLS
              </p>
            </div>
            <div className="flex flex-col gap-4 sm:flex-row">
              <Button size="lg" asChild>
                <a href="https://npmjs.com/package/agent-zero-trust" target="_blank" rel="noopener noreferrer">
                  Instalar Pacote
                  <ChevronRight className="ml-2 h-4 w-4" />
                </a>
              </Button>
              <Button size="lg" variant="outline" asChild>
                <a href="https://github.com/purecore/agentic-networkfortress" target="_blank" rel="noopener noreferrer">
                  <Github className="mr-2 h-4 w-4" />
                  GitHub
                </a>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-12">
        <h2 className="text-3xl font-bold tracking-tighter text-center mb-8">Recursos Principais</h2>
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          <Card>
            <CardHeader>
              <Lock className="h-8 w-8 mb-2 text-primary" />
              <CardTitle>Signal Protocol E2EE</CardTitle>
              <CardDescription>Criptografia end-to-end com Double Ratchet</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-sm space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Perfect Forward Secrecy (PFS)</li>
                <li>• Post-Compromise Security (PCS)</li>
                <li>• X3DH Key Agreement</li>
                <li>• Deniable Authentication</li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <Key className="h-8 w-8 mb-2 text-primary" />
              <CardTitle>DPoP (RFC 9449)</CardTitle>
              <CardDescription>Proof-of-Possession para OAuth 2.0</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-sm space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Bearer token binding</li>
                <li>• Session Context Latching</li>
                <li>• JWK Thumbprint (RFC 7638)</li>
                <li>• Nonce-based replay protection</li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <Server className="h-8 w-8 mb-2 text-primary" />
              <CardTitle>mTLS 1.3</CardTitle>
              <CardDescription>Autenticação mútua no transporte</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-sm space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Autenticação cliente-servidor</li>
                <li>• Canal seguro anti-MITM</li>
                <li>• Compatível com PKI enterprise</li>
                <li>• Certificate pinning</li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <ShieldCheck className="h-8 w-8 mb-2 text-primary" />
              <CardTitle>Token Manager</CardTitle>
              <CardDescription>Gestão inteligente de tokens</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-sm space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Promise Latching</li>
                <li>• Refresh com backoff exponencial</li>
                <li>• Cache com expiração</li>
                <li>• Retry automático</li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <Database className="h-8 w-8 mb-2 text-primary" />
              <CardTitle>Bloom Filter CRL</CardTitle>
              <CardDescription>Revogação distribuída eficiente</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-sm space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Verificação O(1)</li>
                <li>• Baixo uso de memória</li>
                <li>• Falso positivo ~1%</li>
                <li>• DHT integration</li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <Zap className="h-8 w-8 mb-2 text-primary" />
              <CardTitle>Circuit Breaker</CardTitle>
              <CardDescription>Resiliência operacional</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-sm space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Padrão Circuit Breaker</li>
                <li>• Estados: CLOSED/OPEN/HALF_OPEN</li>
                <li>• Reset timeout configurável</li>
                <li>• Monitoring period</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Installation */}
      <section className="py-12">
        <h2 className="text-3xl font-bold tracking-tighter text-center mb-8">Instalação</h2>
        <div className="max-w-2xl mx-auto">
          <Card>
            <CardContent className="pt-6">
              <pre className="bg-muted p-4 rounded-lg overflow-x-auto">
                <code className="text-sm">
{`# npm
npm install agent-zero-trust

# yarn
yarn add agent-zero-trust

# bun
bun add agent-zero-trust`}
                </code>
              </pre>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Quick Start */}
      <section className="py-12">
        <h2 className="text-3xl font-bold tracking-tighter text-center mb-8">Início Rápido</h2>
        <div className="max-w-4xl mx-auto">
          <Tabs defaultValue="e2ee" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="e2ee">E2EE Messaging</TabsTrigger>
              <TabsTrigger value="dpop">DPoP Auth</TabsTrigger>
            </TabsList>
            <TabsContent value="e2ee">
              <Card>
                <CardHeader>
                  <CardTitle>Comunicação E2EE entre Agentes</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                    <code>{`import { SignalE2EEAgent, TokenAuthority } from 'agent-zero-trust';

const authority = new TokenAuthority();
const alice = new SignalE2EEAgent('alice', authority);
const bob = new SignalE2EEAgent('bob', authority);

await alice.initialize();
await bob.initialize();

// Trocar bundles
alice.registerPeerBundle('bob', bob.getPublicKeyBundle());
bob.registerPeerBundle('alice', alice.getPublicKeyBundle());

// Estabelecer sessão
await alice.establishSession('bob');
await bob.acceptSession('alice', alice.getIdentityPublicKey(), ...);

// Enviar mensagem
await alice.sendMessage('bob', 'Olá Bob!');`}</code>
                  </pre>
                </CardContent>
              </Card>
            </TabsContent>
            <TabsContent value="dpop">
              <Card>
                <CardHeader>
                  <CardTitle>DPoP com Session Binding</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                    <code>{`import { generateDPoPKeyPair, createDPoPProof } from 'agent-zero-trust';

const dpopKey = generateDPoPKeyPair('EdDSA');
const proof = await createDPoPProof(dpopKey, {
  method: 'POST',
  url: 'https://api.example.com/message',
  accessToken: 'your_token',
  signalIdentityKey: signalKey // Session binding
});

// Header: DPoP {token} dpop={proof.jwt}`}</code>
                  </pre>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </section>
    </div>
  )
}

// Página de Arquitetura
function Architecture() {
  return (
    <div className="container py-8">
      <h1 className="text-4xl font-bold mb-8">Arquitetura Tri-Camada</h1>
      
      <div className="mb-12">
        <Card>
          <CardContent className="pt-6">
            <pre className="bg-muted p-6 rounded-lg overflow-x-auto text-sm">
              <code>{`┌─────────────────────────────────────────────────────────┐
│              AGENTIC NETWORKFORTRESS                     │
├─────────────────────────────────────────────────────────┤
│  Camada 3: DPoP (RFC 9449) + Session Binding            │
│  Camada 2: Signal Protocol E2EE (Double Ratchet)        │
│  Camada 1: mTLS 1.3                                     │
└─────────────────────────────────────────────────────────┘`}</code>
            </pre>
          </CardContent>
        </Card>
      </div>

      <Accordion type="single" collapsible className="w-full">
        <AccordionItem value="layer1">
          <AccordionTrigger>Camada 1: mTLS (Transporte)</AccordionTrigger>
          <AccordionContent>
            <div className="space-y-4">
              <p>Mutual TLS estabelece autenticação bidirecional no nível de transporte.</p>
              <ul className="list-disc list-inside space-y-2 ml-4">
                <li>Autenticação mútua antes do estabelecimento do túnel</li>
                <li>Prevenção de MITM no nível de rede</li>
                <li>Compatibilidade com PKI enterprise existente</li>
              </ul>
            </div>
          </AccordionContent>
        </AccordionItem>

        <AccordionItem value="layer2">
          <AccordionTrigger>Camada 2: Signal Protocol E2EE (Aplicação)</AccordionTrigger>
          <AccordionContent>
            <div className="space-y-4">
              <p>O protocolo Signal através do Double Ratchet fornece:</p>
              <ul className="list-disc list-inside space-y-2 ml-4">
                <li>Perfect Forward Secrecy (PFS)</li>
                <li>Post-Compromise Security (PCS)</li>
                <li>Deniable Authentication</li>
                <li>Extensão híbrida PQ (X25519 + ML-KEM-768)</li>
              </ul>
            </div>
          </AccordionContent>
        </AccordionItem>

        <AccordionItem value="layer3">
          <AccordionTrigger>Camada 3: DPoP (Autorização)</AccordionTrigger>
          <AccordionContent>
            <div className="space-y-4">
              <p>DPoP (RFC 9449) vincula tokens de acesso a chaves criptográficas:</p>
              <ul className="list-disc list-inside space-y-2 ml-4">
                <li>Proof-of-Possession criptográfico</li>
                <li>Session Context Latching com JWK Thumbprint</li>
                <li>HTTP method/URL constraining</li>
                <li>Nonce-based replay protection</li>
              </ul>
            </div>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  )
}

// Página de Tecnologias
function Technologies() {
  const technologies = [
    {
      name: 'X3DH Key Agreement',
      description: 'Extended Triple Diffie-Hellman para estabelecimento inicial de chaves',
      details: ['DH1: IKa, SPKb', 'DH2: EKa, IKb', 'DH3: EKa, SPKb', 'DH4: EKa, OPKb (opcional)']
    },
    {
      name: 'Double Ratchet',
      description: 'Algoritmo de ratchet duplo para forward secrecy',
      details: ['DH Ratchet (assimétrico)', 'Symmetric Ratchet (KDF chain)', 'Skip message keys', 'Post-compromise healing']
    },
    {
      name: 'JWK Thumbprint',
      description: 'RFC 7638 para identificação única de chaves',
      details: ['Canonicalização JWK', 'SHA-256 hash', 'Base64url encoding', 'Session binding']
    },
    {
      name: 'Bloom Filter',
      description: 'Estrutura probabilística para CRL distribuída',
      details: ['O(1) lookup', 'Falso positivo ~1%', 'Baixo uso de memória', 'Múltiplas hash functions']
    }
  ]

  return (
    <div className="container py-8">
      <h1 className="text-4xl font-bold mb-8">Tecnologias</h1>
      <div className="grid gap-6">
        {technologies.map((tech) => (
          <Card key={tech.name}>
            <CardHeader>
              <CardTitle>{tech.name}</CardTitle>
              <CardDescription>{tech.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="grid grid-cols-2 gap-2">
                {tech.details.map((detail, i) => (
                  <li key={i} className="flex items-center text-sm">
                    <ChevronRight className="h-4 w-4 mr-2" />
                    {detail}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

// Página de Diagramas
function Diagrams() {
  return (
    <div className="container py-8">
      <h1 className="text-4xl font-bold mb-8">Diagramas</h1>
      
      <div className="space-y-8">
        <Card>
          <CardHeader>
            <CardTitle>Fluxo Completo: Agente A → Agente B</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-xs">
              <code>{`1. DESCOBERTA (A2A Protocol)
   ┌─────────┐                          ┌─────────┐
   │ Agente A│                          │ Agente B│
   └────┬────┘                          └────┬────┘
        │                                    │
        │  Query Agent Card (DID)            │
        │───────────────────────────────────►│
        │                                    │
        │  Agent Card (assinado)             │
        │◄───────────────────────────────────│

2. HANDSHAKE TRI-CAMADA
   ┌─────────┐                          ┌─────────┐
   │ Agente A│                          │ Agente B│
   └────┬────┘                          └────┬────┘
        │                                    │
        │  mTLS Handshake (Camada 1)         │
        │◄──────────────────────────────────►│
        │  [Túnel estabelecido]              │
        │                                    │
        │  X3DH Híbrido (Camada 2)           │
        │◄──────────────────────────────────►│
        │  [Shared secret]                   │
        │                                    │
        │  DPoP + Session Binding (Camada 3) │
        │◄──────────────────────────────────►│

3. COMUNICAÇÃO SEGURA
   ┌─────────┐     ┌─────────┐     ┌─────────┐
   │ Agente A│────►│ Broker  │────►│ Agente B│
   └─────────┘     └─────────┘     └─────────┘
        │ E2EE          │ E2EE          │ Decrypt
        │ Encrypt       │ Roteia        │ Process`}</code>
            </pre>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Double Ratchet State</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-xs">
              <code>{`┌────────────────────────────────────────────────┐
│           DOUBLE RATCHET STATE                  │
├────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐      ┌──────────────┐        │
│  │ DH Ratchet   │      │ Symmetric    │        │
│  │ (Asymmetric) │      │ Ratchet      │        │
│  │              │      │ (KDF Chain)  │        │
│  │  DHs: Private│      │ Root Key ───►│        │
│  │  DHr: Public │      │     │        │        │
│  │              │      │     ▼        │        │
│  │ [DH Output]  │      │ Chain Key ──►│        │
│  │     │        │      │     │        │        │
│  │     ▼        │      │     ▼        │        │
│  │ Root Key ───┴──────►│ Message Key  │        │
│  │              │      │     │        │        │
│  └──────────────┘      │     ▼        │        │
│                        │ [Encrypt]    │        │
│                        └──────────────┘        │
│                                                 │
│  Ratchet Steps:                                 │
│  1. DH Ratchet (nova mensagem com DH)          │
│  2. Symmetric Ratchet (cada mensagem)          │
└────────────────────────────────────────────────┘`}</code>
            </pre>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>DPoP com Session Binding</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-xs">
              <code>{`┌─────────────┐                    ┌─────────────┐
│   Agente    │                    │  Servidor   │
│  (Cliente)  │                    │  Recursos   │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. POST /token + DPoP Proof     │
       │     (com signal_identity_kid)    │
       │─────────────────────────────────►│
       │                                  │
       │  2. Access Token                 │
       │◄─────────────────────────────────│
       │                                  │
       │  3. API Request + DPoP + Token   │
       │─────────────────────────────────►│
       │                                  │
       │  4. Validação:                   │
       │     - Assinatura DPoP            │
       │     - jti (replay)               │
       │     - signal_identity_kid        │
       │                                  │
       │  5. Response                     │
       │◄─────────────────────────────────│`}</code>
            </pre>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

// Página de API
function API() {
  const apiSections = [
    {
      title: 'SignalE2EEAgent',
      methods: [
        { name: 'constructor(agentId, authority, capabilities)', description: 'Cria novo agente' },
        { name: 'initialize()', description: 'Inicializa o agente' },
        { name: 'getPublicKeyBundle()', description: 'Retorna bundle público' },
        { name: 'establishSession(peerId)', description: 'Estabelece sessão E2EE' },
        { name: 'acceptSession(peerId, ...)', description: 'Aceita sessão E2EE' },
        { name: 'sendMessage(peerId, content)', description: 'Envia mensagem encriptada' },
        { name: 'receiveMessage(message)', description: 'Recebe e decripta mensagem' },
        { name: 'destroy()', description: 'Limpa chaves seguramente' },
      ]
    },
    {
      title: 'TokenAuthority',
      methods: [
        { name: 'issueAgentToken(agentId, conversationId, capabilities)', description: 'Emite token JWT' },
        { name: 'verifyToken(token)', description: 'Verifica token JWT' },
      ]
    },
    {
      title: 'DPoP Functions',
      methods: [
        { name: 'generateDPoPKeyPair(algorithm)', description: 'Gera chave DPoP' },
        { name: 'createDPoPProof(keyPair, options)', description: 'Cria DPoP proof' },
        { name: 'verifyDPoPProof(jwt, options)', description: 'Verifica DPoP proof' },
        { name: 'computeAccessTokenHash(token)', description: 'Hash do access token' },
      ]
    },
    {
      title: 'TokenManager',
      methods: [
        { name: 'setRefreshFn(fn)', description: 'Configura função de refresh' },
        { name: 'getToken()', description: 'Obtém token (com latching)' },
        { name: 'clearCache()', description: 'Limpa cache' },
      ]
    },
  ]

  return (
    <div className="container py-8">
      <h1 className="text-4xl font-bold mb-8">API Reference</h1>
      <div className="space-y-8">
        {apiSections.map((section) => (
          <Card key={section.title}>
            <CardHeader>
              <CardTitle>{section.title}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {section.methods.map((method) => (
                  <div key={method.name} className="border-b pb-4 last:border-0">
                    <code className="text-sm font-mono bg-muted px-2 py-1 rounded">
                      {method.name}
                    </code>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                      {method.description}
                    </p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

// App Principal
export default function App() {
  return (
    <Router>
      <div className="min-h-screen bg-background">
        <Navigation />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/arquitetura" element={<Architecture />} />
          <Route path="/tecnologias" element={<Technologies />} />
          <Route path="/diagramas" element={<Diagrams />} />
          <Route path="/api" element={<API />} />
        </Routes>
        <footer className="border-t py-8">
          <div className="container text-center text-sm text-gray-600 dark:text-gray-400">
            <p>Agent Zero Trust - Arquitetura Zero-Trust para Agentes Autônomos de IA</p>
            <p className="mt-2">
              <a href="https://npmjs.com/package/agent-zero-trust" className="hover:underline">NPM</a>
              {' | '}
              <a href="https://github.com/purecore/agentic-networkfortress" className="hover:underline">GitHub</a>
              {' | '}
              <a href="https://purecore.dev/agentic-networkfortress/docs" className="hover:underline">Docs</a>
            </p>
          </div>
        </footer>
      </div>
    </Router>
  )
}
