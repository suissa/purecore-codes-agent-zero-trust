import { NavLink } from 'react-router-dom';
import { 
  Shield, Lock, Key, RefreshCw, Zap, Flower2, 
  Fingerprint, Network, Layers, FileText, Home,
  ChevronRight
} from 'lucide-react';

const navItems = [
  { to: '/', icon: Home, label: 'Visão Geral' },
  { to: '/architecture', icon: Layers, label: 'Arquitetura Tri-Camada' },
  { to: '/signal', icon: Lock, label: 'Signal Protocol E2EE' },
  { to: '/dpop', icon: Key, label: 'DPoP (RFC 9449)' },
  { to: '/a2a', icon: Network, label: 'Protocolo A2A' },
  { to: '/multiparty', icon: Shield, label: 'Multi-Party E2EE' },
  { to: '/zero-trust-broker', icon: Zap, label: 'Zero-Trust Brokerage' },
  { to: '/token-manager', icon: RefreshCw, label: 'Token Manager' },
  { to: '/bloom-filter', icon: Flower2, label: 'Bloom Filter CRL' },
  { to: '/jwk-thumbprint', icon: Fingerprint, label: 'JWK Thumbprint' },
  { to: '/adversary', icon: Shield, label: 'Modelo de Adversário' },
  { to: '/paper', icon: FileText, label: 'Paper Científico' },
];

export function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-64 glass border-r border-border overflow-y-auto z-50 flex flex-col">
      <div className="p-5 border-b border-border">
        <NavLink to="/" className="flex items-center gap-2.5 group">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-primary via-secondary to-accent flex items-center justify-center">
            <Shield className="w-5 h-5 text-background" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-tight text-foreground">Agent Zero Trust</h1>
            <p className="text-[10px] text-muted-foreground font-mono">@purecore-codes</p>
          </div>
        </NavLink>
      </div>

      <nav className="flex-1 p-3 space-y-0.5">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-3 py-2 rounded-lg text-[13px] font-medium transition-all duration-200 group ${
                isActive
                  ? 'text-primary bg-primary/8 border border-primary/15'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted border border-transparent'
              }`
            }
          >
            <item.icon className="w-4 h-4 shrink-0" />
            <span className="truncate">{item.label}</span>
            <ChevronRight className="w-3 h-3 ml-auto opacity-0 group-hover:opacity-50 transition-opacity" />
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-border">
        <div className="glass-card p-3">
          <p className="text-[11px] text-muted-foreground">
            <span className="text-primary font-semibold">v0.1.0</span> • Apache 2.0
          </p>
          <a 
            href="https://github.com/purecore-codes/agent-zero-trust" 
            target="_blank" 
            rel="noreferrer"
            className="text-[11px] text-primary/70 hover:text-primary transition-colors mt-1 block"
          >
            GitHub →
          </a>
        </div>
      </div>
    </aside>
  );
}
