import { ReactNode } from 'react';

interface CodeBlockProps {
  code: string;
  lang?: string;
}

export function CodeBlock({ code, lang = 'typescript' }: CodeBlockProps) {
  return (
    <div className="code-block" data-lang={lang}>
      <pre className="text-foreground/90 whitespace-pre overflow-x-auto">
        {code}
      </pre>
    </div>
  );
}

interface DiagramProps {
  children: string;
  title?: string;
}

export function Diagram({ children, title }: DiagramProps) {
  return (
    <div className="space-y-2">
      {title && <p className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">{title}</p>}
      <div className="diagram-box">{children}</div>
    </div>
  );
}

interface SectionProps {
  id?: string;
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function Section({ id, title, subtitle, icon, children, className = '' }: SectionProps) {
  return (
    <section id={id} className={`mb-16 ${className}`}>
      <div className="flex items-center gap-3 mb-4">
        {icon && <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary/20 to-secondary/20 border border-primary/10 flex items-center justify-center text-primary">{icon}</div>}
        <div>
          <h2 className="text-2xl font-bold tracking-tight">{title}</h2>
          {subtitle && <p className="text-sm text-muted-foreground mt-0.5">{subtitle}</p>}
        </div>
      </div>
      <div className="space-y-6 text-foreground/85 leading-relaxed">{children}</div>
    </section>
  );
}

interface FeatureCardProps {
  title: string;
  description: string;
  icon: ReactNode;
  color?: 'cyan' | 'indigo' | 'emerald' | 'amber';
}

export function FeatureCard({ title, description, icon, color = 'cyan' }: FeatureCardProps) {
  const colorMap = {
    cyan: 'from-cyan-500/15 to-cyan-500/5 border-cyan-500/15 hover:border-cyan-500/30',
    indigo: 'from-indigo-500/15 to-indigo-500/5 border-indigo-500/15 hover:border-indigo-500/30',
    emerald: 'from-emerald-500/15 to-emerald-500/5 border-emerald-500/15 hover:border-emerald-500/30',
    amber: 'from-amber-500/15 to-amber-500/5 border-amber-500/15 hover:border-amber-500/30',
  };
  const iconColor = {
    cyan: 'text-cyan-400',
    indigo: 'text-indigo-400',
    emerald: 'text-emerald-400',
    amber: 'text-amber-400',
  };

  return (
    <div className={`rounded-xl bg-gradient-to-br ${colorMap[color]} border p-5 transition-all duration-300 hover:-translate-y-1`}>
      <div className={`${iconColor[color]} mb-3`}>{icon}</div>
      <h3 className="font-semibold text-foreground mb-1.5">{title}</h3>
      <p className="text-sm text-muted-foreground leading-relaxed">{description}</p>
    </div>
  );
}

interface InfoBoxProps {
  type?: 'info' | 'warning' | 'security' | 'tip';
  title: string;
  children: ReactNode;
}

export function InfoBox({ type = 'info', title, children }: InfoBoxProps) {
  const styles = {
    info: 'border-primary/20 bg-primary/5',
    warning: 'border-warning/20 bg-warning/5',
    security: 'border-destructive/20 bg-destructive/5',
    tip: 'border-accent/20 bg-accent/5',
  };
  const titleColor = {
    info: 'text-primary',
    warning: 'text-warning',
    security: 'text-destructive',
    tip: 'text-accent',
  };

  return (
    <div className={`rounded-xl border ${styles[type]} p-5`}>
      <h4 className={`font-semibold text-sm ${titleColor[type]} mb-2`}>{title}</h4>
      <div className="text-sm text-foreground/80 leading-relaxed">{children}</div>
    </div>
  );
}

interface TableProps {
  headers: string[];
  rows: string[][];
}

export function Table({ headers, rows }: TableProps) {
  return (
    <div className="overflow-x-auto rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-muted/50 border-b border-border">
            {headers.map((h, i) => (
              <th key={i} className="px-4 py-3 text-left font-semibold text-foreground/90 whitespace-nowrap">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
              {row.map((cell, j) => (
                <td key={j} className="px-4 py-3 text-foreground/80 whitespace-nowrap">{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
