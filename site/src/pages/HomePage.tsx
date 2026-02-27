import { Link } from 'react-router-dom';
import { Shield, Lock, Key, Layers, Network, Zap, RefreshCw, Flower2, Fingerprint, FileText, ArrowRight, GitBranch } from 'lucide-react';
import { FeatureCard, Diagram } from '../components/ui';

const pillars = [
  { to: '/architecture', icon: <Layers className="w-6 h-6" />, title: 'Arquitetura Tri-Camada', desc: 'mTLS + Signal E2EE + DPoP em defesa profunda', color: 'cyan' as const },
  { to: '/signal', icon: <Lock className="w-6 h-6" />, title: 'Signal Protocol E2EE', desc: 'Double Ratchet com PFS, PCS e Híbrido PQ', color: 'indigo' as const },
  { to: '/dpop', icon: <Key className="w-6 h-6" />, title: 'DPoP (RFC 9449)', desc: 'Proof-of-Possession + Session Context Latching', color: 'emerald' as const },
  { to: '/a2a', icon: <Network className="w-6 h-6" />, title: 'Protocolo A2A', desc: 'Agent Cards, Discovery e Revogação Distribuída', color: 'amber' as const },
  { to: '/multiparty', icon: <Shield className="w-6 h-6" />, title: 'Multi-Party E2EE', desc: 'Criptografia de grupo com Epochs', color: 'cyan' as const },
  { to: '/zero-trust-broker', icon: <Zap className="w-6 h-6" />, title: 'Zero-Trust Brokerage', desc: 'Broker como intermediário hostil', color: 'indigo' as const },
  { to: '/token-manager', icon: <RefreshCw className="w-6 h-6" />, title: 'Token Manager', desc: 'Promise Latching + Circuit Breaker', color: 'emerald' as const },
  { to: '/bloom-filter', icon: <Flower2 className="w-6 h-6" />, title: 'Bloom Filter CRL', desc: 'Revogação O(1) com filtros probabilísticos', color: 'amber' as const },
  { to: '/jwk-thumbprint', icon: <Fingerprint className="w-6 h-6" />, title: 'JWK Thumbprint', desc: 'RFC 7638 para identidade criptográfica', color: 'cyan' as const },
  { to: '/adversary', icon: <Shield className="w-6 h-6" />, title: 'Modelo de Adversário', desc: 'Dolev-Yao estendido com 6 eixos de ameaça', color: 'indigo' as const },
];

const archDiagram = `┌────────────────────────────────────────────────────────────────┐
│              ARQUITETURA AGENT ZERO TRUST                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────┐                    ┌──────────────┐         │
│  │   Agente A   │◄──── E2EE ────────►│   Agente B   │         │
│  │  (Remetente) │                    │ (Receptor)   │         │
│  └──────┬───────┘                    └──────▲───────┘         │
│         │                                   │                  │
│         │  ┌────────────────────────────────┘                  │
│         │  │       zona de intermediário hostil                │
│         │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│         └──┤  │  mTLS    │─►│  Broker  │─►│  mTLS    │───┘   │
│            │  │(Camada 1)│  │(RabbitMQ)│  │(Camada 1)│       │
│            │  └──────────┘  └──────────┘  └──────────┘       │
│            │                                                   │
│            │  ┌──────────────────────────────────────────┐    │
│            │  │  Signal E2EE (Camada 2) - Double Ratchet │    │
│            │  │  PFS + PCS + Híbrido PQ (X25519+ML-KEM)  │    │
│            │  └──────────────────────────────────────────┘    │
│            │                                                   │
│            │  ┌──────────────────────────────────────────┐    │
│            │  │  Contexto JWT/DPoP (Camada 3)            │    │
│            │  │  RFC 9449 + Session Context Latching      │    │
│            └  └──────────────────────────────────────────┘    │
│                                                                │
└────────────────────────────────────────────────────────────────┘`;

export function HomePage() {
  return (
    <div>
      {/* Hero */}
      <div className="relative mb-20">
        <div className="absolute -top-20 -left-20 w-96 h-96 bg-primary/5 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute -top-10 right-0 w-72 h-72 bg-secondary/5 rounded-full blur-[100px] pointer-events-none" />
        
        <div className="relative animate-slide-up">
          <div className="flex items-center gap-2 mb-5">
            <div className="px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold tracking-wider">
              ZERO TRUST
            </div>
            <div className="px-3 py-1 rounded-full bg-secondary/10 border border-secondary/20 text-secondary text-xs font-semibold tracking-wider">
              E2EE
            </div>
            <div className="px-3 py-1 rounded-full bg-accent/10 border border-accent/20 text-accent text-xs font-semibold tracking-wider">
              PQ-READY
            </div>
          </div>

          <h1 className="text-5xl md:text-6xl font-black tracking-tight leading-[1.1] mb-6">
            <span className="gradient-text">Agent Zero Trust</span>
            <br />
            <span className="text-foreground/90">Security Architecture</span>
          </h1>

          <p className="text-lg text-muted-foreground max-w-2xl mb-8 leading-relaxed">
            Arquitetura de segurança tri-camada para enxames de agentes autônomos de IA.
            Integra <strong className="text-foreground">mTLS</strong>, <strong className="text-foreground">Signal Protocol E2EE</strong> e <strong className="text-foreground">DPoP</strong> em
            um framework onde a confiança nunca é implícita.
          </p>

          <div className="flex gap-3 mb-12">
            <code className="px-4 py-2 rounded-lg bg-muted border border-border font-mono text-sm text-foreground/80">
              npm install @purecore-codes/agent-zero-trust
            </code>
          </div>
        </div>

        <div className="animate-slide-up animate-delay-200">
          <Diagram title="Visão Geral da Arquitetura">{archDiagram}</Diagram>
        </div>
      </div>

      {/* Pilares */}
      <div className="mb-20 animate-slide-up animate-delay-300">
        <h2 className="text-3xl font-bold mb-2 tracking-tight">Pilares Tecnológicos</h2>
        <p className="text-muted-foreground mb-8">Cada componente foi projetado para operar de forma independente e em conjunto.</p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {pillars.map((p) => (
            <Link key={p.to} to={p.to} className="block group">
              <FeatureCard
                icon={p.icon}
                title={p.title}
                description={p.desc}
                color={p.color}
              />
            </Link>
          ))}
        </div>
      </div>

      {/* Paper */}
      <div className="animate-slide-up animate-delay-400">
        <Link to="/paper" className="glass-card p-8 flex items-center gap-6 group block">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-primary to-secondary flex items-center justify-center shrink-0">
            <FileText className="w-7 h-7 text-background" />
          </div>
          <div className="flex-1">
            <h3 className="text-xl font-bold mb-1">Paper Científico</h3>
            <p className="text-sm text-muted-foreground">
              "Toward a Sovereign Agentic Zero-Trust Architecture: Multi-Layered Security for Autonomous AI Swarms" — Modelo formal de adversário, provas criptográficas e verificação em Tamarin.
            </p>
          </div>
          <ArrowRight className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors" />
        </Link>
      </div>

      {/* Versioning */}
      <div className="mt-16 flex items-center gap-4 text-sm text-muted-foreground">
        <GitBranch className="w-4 h-4" />
        <span>v0.1.0 • TypeScript • Zero Dependencies • Apache 2.0</span>
      </div>
    </div>
  );
}
