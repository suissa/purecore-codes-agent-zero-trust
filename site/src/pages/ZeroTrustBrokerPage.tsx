import { Zap } from 'lucide-react';
import { Section, Diagram, Table, InfoBox } from '../components/ui';

const brokerDiagram = `┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Agente A  │────►│   Broker    │────►│   Agente B  │
│ (Publisher) │     │  (RabbitMQ) │     │ (Subscriber)│
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Encriptar   │     │ Roteia      │     │ Decriptar   │
│ (E2EE)      │     │ ciphertext  │     │ (E2EE)      │
│             │     │ sem ver     │     │             │
│ Payload:    │     │ conteúdo    │     │ Payload:    │
│ {           │     │             │     │ {           │
│  ciphertext:│     │             │     │  plaintext: │
│  <bytes>    │     │             │     │  <dados>    │
│  nonce:     │     │             │     │  verified:  │
│  <bytes>    │     │             │     │  true       │
│ }           │     │             │     │ }           │
└─────────────┘     └─────────────┘     └─────────────┘`;

export function ZeroTrustBrokerPage() {
  return (
    <div>
      <Section title="Zero-Trust Brokerage" subtitle="Broker como Intermediário Hostil" icon={<Zap className="w-5 h-5" />}>
        <p>
          Em arquiteturas pub/sub, o broker é tradicionalmente um <strong>trusted third party</strong>.
          A Agent Zero Trust inverte esta premissa: o broker é tratado como <strong>intermediário hostil</strong>.
          A criptografia E2EE é aplicada na camada de aplicação, antes de o payload chegar ao broker.
        </p>

        <InfoBox type="security" title="Premissa de Segurança">
          <p>Mesmo que o operador do RabbitMQ/Kafka tenha acesso root ao servidor, ele vê apenas ciphertext indecifrável. Zero visibilidade ao plaintext.</p>
        </InfoBox>
      </Section>

      <Section title="Fluxo de Dados">
        <Diagram title="Broker como Relay Opaco">{brokerDiagram}</Diagram>

        <Table
          headers={['Propriedade', 'Garantia', 'Mecanismo']}
          rows={[
            ['Confidencialidade', 'Broker não pode ler payloads', 'AES-256-GCM E2EE'],
            ['Integridade', 'Tampering detectável no receptor', 'MAC/Signature'],
            ['Autenticidade', 'Origem verificável criptograficamente', 'Signal Protocol'],
            ['Deniability (Modo A)', 'Nenhuma parte prova envio a terceiros', 'MAC simétrico'],
          ]}
        />
      </Section>

      <Section title="Modos Operacionais: Deniability vs Non-Repudiation">
        <p>
          Para resolver a tensão entre <em>deniability</em> e <em>non-repudiation</em>, a arquitetura define dois modos explícitos:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="glass-card p-5">
            <h4 className="font-bold text-primary mb-2">Modo A: Sovereign Deniable (Padrão)</h4>
            <p className="text-sm text-muted-foreground">
              Autenticação via MACs simétricos (Double Ratchet). Ambas as partes conhecem o material de chave,
              impossibilitando prova criptográfica para terceiros. Garante soberania e privacidade do agente.
            </p>
          </div>
          <div className="glass-card p-5">
            <h4 className="font-bold text-secondary mb-2">Modo B: Audit-Compliant Persistent Signature</h4>
            <p className="text-sm text-muted-foreground">
              Assinatura digital explícita (Ed25519) anexada a log atestado off-chain. Deniability suprimida
              em favor de non-repudiation imutável. Para compliance financeiro e regulatório.
            </p>
          </div>
        </div>

        <InfoBox type="info" title="Negociação">
          <p>O modo é explicitamente negociado durante o handshake X3DH e requer consentimento mútuo de ambos os agentes.</p>
        </InfoBox>
      </Section>
    </div>
  );
}
