import { Flower2 } from 'lucide-react';
import { Section, CodeBlock, Table, Diagram, InfoBox } from '../components/ui';

const bloomDiagram = `┌──────────────────────────────────────────────────────────┐
│              VERIFICAÇÃO HÍBRIDA DE REVOGAÇÃO             │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  1. Baixar Bloom Filter (bytes) do DHT                   │
│              │                                            │
│              ▼                                            │
│  2. Verificação local O(1)                                │
│              │                                            │
│         ┌────┴────┐                                       │
│         │         │                                       │
│    NEGATIVO    POSITIVO                                   │
│         │         │                                       │
│         ▼         ▼                                       │
│   PERMITIDO   3. Baixar CRL completa                     │
│  (0% falso     (verifica falso positivo)                  │
│   negativo)         │                                     │
│                ┌────┴────┐                                │
│           CONFIRMADO  FALSO POSITIVO                     │
│                │         │                                │
│                ▼         ▼                                │
│            BLOQUEADO  PERMITIDO                           │
│                                                          │
└──────────────────────────────────────────────────────────┘`;

export function BloomFilterPage() {
  return (
    <div>
      <Section title="Bloom Filter para CRL" subtitle="Verificação de Revogação em O(1)" icon={<Flower2 className="w-5 h-5" />}>
        <p>
          Para reduzir a latência de verificação de revogação em enxames de alta densidade, utilizamos <strong>Filtros de Bloom</strong>
          como cache probabilístico de baixa latência para CRLs (Certificate Revocation Lists).
        </p>

        <InfoBox type="info" title="Propriedade Fundamental">
          <p><strong>Zero falsos negativos:</strong> Se o Bloom Filter diz "não revogado", é 100% confiável. Falsos positivos (configurável, ~1%) são resolvidos consultando a CRL completa.</p>
        </InfoBox>
      </Section>

      <Section title="Fluxo Híbrido">
        <Diagram title="Verificação em Duas Fases">{bloomDiagram}</Diagram>

        <Table
          headers={['Métrica', 'CRL Completa', 'Bloom Filter + CRL']}
          rows={[
            ['Latência de verificação', 'O(n) ou O(log n)', 'O(1)'],
            ['Tamanho em memória', '~KB a MB', '~bytes'],
            ['Falsos positivos', '0%', '1% (configurável)'],
            ['Falsos negativos', '0%', '0%'],
            ['Atualizações', 'Download completo', 'Delta + filtro'],
          ]}
        />
      </Section>

      <Section title="Uso na Biblioteca">
        <CodeBlock lang="typescript" code={`import {
  createBloomFilterForCRL, isRevoked
} from '@purecore-codes/agent-zero-trust';

// Criar Bloom Filter com DIDs revogados
const revokedDIDs = [
  'did:agent:compromised-1',
  'did:agent:revoked-admin'
];
const filter = createBloomFilterForCRL(revokedDIDs, 0.01);

// Verificação O(1) antes de estabelecer sessão
const revoked = await isRevoked('did:agent:new-peer', filter);
if (revoked) {
  throw new Error('Peer revogado!');
}`} />
      </Section>
    </div>
  );
}
