import { Shield } from 'lucide-react';
import { Section, Diagram, InfoBox, Table } from '../components/ui';

const epochDiagram = `┌─────────────────────────────────────────────────────┐
│              GROUP E2EE - EPOCH MODEL                │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Epoch 1: [Alice, Bob, Charlie]                      │
│  ┌──────────────────────────────────────┐            │
│  │  Group Key = KDF(IK_a, IK_b, IK_c)  │            │
│  │  Mensagens cifradas com Group Key    │            │
│  └──────────────────────────────────────┘            │
│                    │                                  │
│                    ▼  Charlie revogado                │
│                                                      │
│  Epoch 2: [Alice, Bob]                               │
│  ┌──────────────────────────────────────┐            │
│  │  Group Key' = KDF(IK_a, IK_b)       │            │
│  │  Charlie NÃO pode derivar Key'      │            │
│  │  Mensagens anteriores: inacessíveis  │            │
│  └──────────────────────────────────────┘            │
│                    │                                  │
│                    ▼  Dave entra                      │
│                                                      │
│  Epoch 3: [Alice, Bob, Dave]                         │
│  ┌──────────────────────────────────────┐            │
│  │  Group Key'' = KDF(IK_a, IK_b, IK_d)│            │
│  │  Dave NÃO acessa Epochs anteriores   │            │
│  └──────────────────────────────────────┘            │
│                                                      │
└─────────────────────────────────────────────────────┘`;

export function MultiPartyPage() {
  return (
    <div>
      <Section title="Multi-Party E2EE" subtitle="Criptografia de Grupo com Gerenciamento de Épocas" icon={<Shield className="w-5 h-5" />}>
        <p>
          Quando mais de dois agentes precisam colaborar, a Multi-Party E2EE escala o modelo Signal Protocol para grupos.
          O conceito fundamental é o de <strong>Epochs</strong>: cada configuração de membros gera uma epoch com chave de grupo única.
        </p>

        <InfoBox type="security" title="Propriedade de Isolamento Temporal">
          <p>Membros revogados não podem ler mensagens de epochs futuras. Novos membros não podem ler epochs passadas. Cada epoch é criptograficamente isolada.</p>
        </InfoBox>
      </Section>

      <Section title="Modelo de Epochs">
        <Diagram title="Gerenciamento de Epochs">{epochDiagram}</Diagram>

        <Table
          headers={['Operação', 'Efeito', 'Segurança']}
          rows={[
            ['Membro Adicionado', 'Nova epoch com Group Key fresh', 'Novo membro não acessa passado'],
            ['Membro Removido', 'Nova epoch sem material do membro', 'Ex-membro não acessa futuro'],
            ['Key Compromise', 'Rotação imediata de epoch', 'PCS garante auto-healing'],
          ]}
        />
      </Section>

      <Section title="Insider Threat">
        <p>
          O modelo de adversário considera <strong>Insider Threats</strong>: um agente legítimo que se torna malicioso.
          O gerenciamento de Epochs garante que, ao revogar o insider, todas as chaves de grupo são invalidadas e regeneradas
          sem material criptográfico do agente revogado.
        </p>

        <InfoBox type="warning" title="Limitação">
          <p>Mensagens enviadas <em>durante</em> a epoch em que o insider é membro são legíveis por ele. A proteção é prospectiva: após remoção, o insider perde acesso imediato.</p>
        </InfoBox>
      </Section>
    </div>
  );
}
