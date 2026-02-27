import { Network } from 'lucide-react';
import { Section, CodeBlock, Table, InfoBox } from '../components/ui';

export function A2APage() {
  return (
    <div>
      <Section title="Protocolo A2A" subtitle="Agent-to-Agent: Interoperabilidade & Descoberta" icon={<Network className="w-5 h-5" />}>
        <p>
          O protocolo A2A define <strong>Agent Cards</strong> — documentos de metadados criptograficamente assinados que descrevem
          capacidades, endpoints, perfis de segurança, e chaves criptográficas de cada agente. São a base para descoberta e
          estabelecimento de sessões seguras.
        </p>

        <CodeBlock lang="typescript" code={`interface AgentCard {
  did: string;                    // Decentralized Identifier
  name: string;
  description: string;
  capabilities: Capability[];
  endpoints: {
    messaging: string;
    discovery: string;
    health: string;
  };
  securityProfiles: SecurityProfile[];
  
  // Chaves criptográficas
  identityKey: PublicKey;         // Chave de identidade de longo prazo
  signedPreKey: SignedPreKey;     // Chave pré-assinada
  preKeys: PreKey[];              // One-time pre-keys
  
  // Metadados de validade e revogação
  signature: CryptoSignature;
  validFrom: ISO8601;
  validUntil: ISO8601;
  revocationListUrl?: string;    // URL para CRL distribuída
  teeAttestation?: TEEAttestation;
}`} />
      </Section>

      <Section title="Governança e Revogação">
        <p>
          Um desafio crítico em identidade distribuída é a revogação rápida de credenciais comprometidas.
          Propomos <strong>Revogação Baseada em Prova de Malícia</strong> integrado ao DHT de descoberta.
        </p>

        <Table
          headers={['Razão de Revogação', 'Código', 'Descrição']}
          rows={[
            ['KEY_COMPROMISE', '1', 'Chave privada comprometida'],
            ['AGENT_COMPROMISE', '2', 'Agente comprometido (OS/runtime)'],
            ['MALICIOUS_BEHAVIOR', '3', 'Comportamento malicioso detectado'],
            ['ADMINISTRATIVE', '4', 'Revogação administrativa'],
            ['SUPERSEDED', '5', 'Substituído por nova identidade'],
          ]}
        />

        <InfoBox type="tip" title="Propagação">
          <p>1. Detecção → 2. Assinatura da revogação → 3. Publicação no DHT (fator N) → 4. Verificação por peers → 5. Invalidação automática de sessões ativas.</p>
        </InfoBox>
      </Section>

      <Section title="Ciclo de Vida de Agent Cards">
        <Table
          headers={['Fase', 'Ação', 'Resultado']}
          rows={[
            ['Bootstrapping', 'Gerar identity key localmente', 'TOFU (Trust-on-First-Use)'],
            ['Publicação', 'Publicar Agent Card no DHT', 'Descoberta por outros agentes'],
            ['Rotação', 'Renovar pre-keys quando < threshold', 'Continuidade de sessões'],
            ['Revogação', 'Publicar CRL entry + Bloom Filter', 'Isolamento do agente'],
          ]}
        />
      </Section>
    </div>
  );
}
