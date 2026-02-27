import { FileText } from 'lucide-react';
import { Section, Table, InfoBox } from '../components/ui';

export function PaperPage() {
  return (
    <div>
      <Section title="Paper Científico" subtitle="Toward a Sovereign Agentic Zero-Trust Architecture" icon={<FileText className="w-5 h-5" />}>
        <p>
          O artigo completo está disponível na documentação do projeto e foi estruturado para submissão em conferências IEEE/ACM.
          Abrange formalizações de segurança, análise STRIDE, benchmarks de performance e modelo de verificação em Tamarin.
        </p>

        <div className="glass-card p-6 mt-4">
          <h3 className="text-xl font-bold gradient-text mb-3">
            Toward a Sovereign Agentic Zero-Trust Architecture: Multi-Layered Security for Autonomous AI Swarms
          </h3>
          <p className="text-sm text-muted-foreground mb-4">
            Agentic NetworkFortress Core Team • @purecore-codes/agent-zero-trust Research Division • Fevereiro 2026
          </p>
          <p className="text-sm text-foreground/80 leading-relaxed">
            <strong>Abstract:</strong> Este artigo propõe a Agentic NetworkFortress, uma arquitetura de segurança de três camadas para enxames de agentes autônomos de IA.
            A solução integra TLS mútuo (mTLS 1.3) para autenticação na camada de transporte, Signal Protocol com extensões pós-quânticas para criptografia fim-a-fim na camada de mensagens,
            e DPoP (RFC 9449) com Session Context Latching para autorização vinculada a prova de posse na camada de contexto.
          </p>
        </div>
      </Section>

      <Section title="Contribuições Científicas">
        <Table
          headers={['Contribuição', 'Descrição', 'Seção']}
          rows={[
            ['Adversary Model', 'Formalização Dolev-Yao estendida com 6 eixos de ameaça', '§1.4'],
            ['Tri-Layer Architecture', 'Defesa em profundidade com camadas independentes', '§3'],
            ['Session Context Latching', 'Vinculação criptográfica DPoP ↔ Signal via JWK Thumbprint', '§3.5'],
            ['Hybrid PQ Extension', 'X25519 + ML-KEM-768 no X3DH e DH Ratchet', '§3.4'],
            ['Operational Modes', 'Separação formal Deniability vs Non-Repudiation', '§3.6'],
            ['STRIDE Analysis', 'Análise completa de ameaças com mitigações por camada', '§5.1'],
            ['Formal Verification', 'Modelo Tamarin parcial para PCS (Apêndice D)', 'Apêndice D'],
            ['Performance Benchmarks', 'Medidas de latência, throughput e overhead', '§6.2'],
          ]}
        />
      </Section>

      <Section title="Resultados de Performance">
        <Table
          headers={['Configuração', 'Latência P50', 'Latência P99', 'Throughput']}
          rows={[
            ['Baseline (sem segurança)', '< 1ms', '2ms', '10.000 msg/s'],
            ['mTLS Only', '3ms', '8ms', '8.500 msg/s'],
            ['mTLS + Signal E2EE', '5ms', '12ms', '7.200 msg/s'],
            ['Full Stack (mTLS + E2EE + DPoP)', '8ms', '18ms', '6.100 msg/s'],
            ['Full Stack + PQ Hybrid', '12ms', '25ms', '5.400 msg/s'],
          ]}
        />

        <InfoBox type="tip" title="Trade-off Aceitável">
          <p>
            O overhead de ~2.7x na latência P99 é considerado aceitável para cenários de alta segurança.
            O throughput mantém-se acima de 5.000 msg/s, suficiente para a maioria dos enxames de agentes.
          </p>
        </InfoBox>
      </Section>

      <Section title="Roadmap de Verificação Formal (12 Meses)">
        <Table
          headers={['Fase', 'Período', 'Objetivo']}
          rows={[
            ['Q1', 'Meses 1-3', 'Hardening criptográfico: ML-KEM-768, zeroização N-API, TEE integration'],
            ['Q2', 'Meses 4-6', 'Otimização: Protocol Buffers, connection pooling, batch signing'],
            ['Q3', 'Meses 7-9', 'Integração: LangChain, CrewAI, AutoGPT plugins + LLM Guardrails'],
            ['Q4', 'Meses 10-12', 'Formal verification: Tamarin completo, ProVerif, certificação CC EAL4+'],
          ]}
        />
      </Section>

      <Section title="Referências Selecionadas">
        <div className="glass-card p-5 space-y-2 text-sm text-foreground/80">
          <p>• Cohn-Gordon, G., et al. (2020). "A Formal Security Analysis of the Signal Messaging Protocol." <em>Journal of Cryptology</em>, 33(4).</p>
          <p>• Fett, D., et al. (2023). "RFC 9449: Demonstrating Proof-of-Possession at the Application Layer (DPoP)." IETF.</p>
          <p>• Rose, S., et al. (2020). "NIST SP 800-207: Zero Trust Architecture." NIST.</p>
          <p>• NIST (2024). "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)."</p>
          <p>• Ward, R. & Beyer, B. (2014). "BeyondCorp: A New Approach to Enterprise Security." Google.</p>
          <p>• Marlinspike, M. & Perrin, T. (2016). "The Signal Protocol." Signal Foundation.</p>
        </div>

        <div className="mt-6">
          <a
            href="https://github.com/purecore-codes/agent-zero-trust/blob/main/docs/AGENTIC_ZERO_TRUST_PAPER.md"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-primary to-secondary text-background font-semibold hover:opacity-90 transition-opacity"
          >
            <FileText className="w-4 h-4" />
            Ler Paper Completo
          </a>
        </div>
      </Section>
    </div>
  );
}
