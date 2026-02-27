import { Lock } from 'lucide-react';
import { Section, Diagram, CodeBlock, Table, InfoBox } from '../components/ui';

const ratchetDiagram = `┌─────────────────────────────────────────────────────────┐
│                 ESTADO DO DOUBLE RATCHET                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────┐         ┌────────────────┐          │
│  │  DH Ratchet    │         │  Symmetric     │          │
│  │  (Assimétrico) │         │  Ratchet       │          │
│  │                │         │  (Cadeia KDF)  │          │
│  │  DHs: Privada  │         │  Root Key ────►│          │
│  │  DHr: Pública  │         │     │          │          │
│  │                │         │     ▼          │          │
│  │  [Saída DH]    │         │  Chain Key ──►│          │
│  │       │        │         │     │          │          │
│  │       ▼        │         │     ▼          │          │
│  │  Root Key ─────┴────────►│  Message Key  │          │
│  │                │         │     │          │          │
│  └────────────────┘         │     ▼          │          │
│                             │  [Encrypt]     │          │
│                             └────────────────┘          │
│                                                          │
│  Extensão Pós-Quântica (Híbrida):                       │
│  ┌──────────────────────────────────────────────────┐   │
│  │  SharedSecret = KDF(                             │   │
│  │    X25519(DH_local, DH_remote),                  │   │
│  │    ML-KEM.Decaps(ciphertext, sk_kem)             │   │
│  │  )                                                │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  Passos do Ratchet:                                      │
│  1. DH Ratchet (cada msg recebida com novo DH)          │
│  2. Symmetric Ratchet (cada msg enviada/recebida)       │
│                                                          │
└─────────────────────────────────────────────────────────┘`;

const pcsDiagram = `Comprometimento detectado (t=0)
         │
         ▼
┌─────────────────┐
│ Nova troca DH   │ (t=1)
│ + ML-KEM fresh  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Root Key        │ (t=2)
│ atualizada      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Chain Keys      │ (t=3)
│ comprometidas   │
│ tornam-se       │
│ inúteis         │
└─────────────────┘`;

export function SignalPage() {
  return (
    <div>
      <Section title="Signal Protocol E2EE" subtitle="Double Ratchet + X3DH + Extensão Pós-Quântica" icon={<Lock className="w-5 h-5" />}>
        <p>
          A implementação do Signal Protocol na Agent Zero Trust é <strong>zero-dependency</strong> e otimizada para TypeScript.
          Fornece as três garantias fundamentais: <strong>Perfect Forward Secrecy (PFS)</strong>, <strong>Post-Compromise Security (PCS)</strong> 
          e <strong>Deniable Authentication</strong>.
        </p>

        <InfoBox type="info" title="Por que Signal Protocol?">
          <p>Análises formais (Cohn-Gordon et al., 2020) provaram suas propriedades de segurança usando Tamarin. WhatsApp, Signal e Skype validaram sua eficácia em escala global.</p>
        </InfoBox>
      </Section>

      <Section title="Double Ratchet Algorithm" subtitle="Rotação contínua de chaves por mensagem">
        <p>
          O algoritmo combina dois ratchets: o <strong>DH Ratchet</strong> (assimétrico) gera novas chaves Diffie-Hellman a cada turno de comunicação,
          enquanto o <strong>Symmetric Ratchet</strong> deriva message keys individuais via KDF. Cada mensagem usa uma chave única e irrecuperável.
        </p>

        <Diagram title="Estado do Double Ratchet">{ratchetDiagram}</Diagram>

        <CodeBlock lang="typescript" code={`interface RatchetState {
  // DH Ratchet State
  ratchetKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  remotePublicKey: Uint8Array | null;
  
  // PQ Hybrid State (opcional)
  mlkemKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };
  
  // Symmetric Ratchet State
  rootKey: Uint8Array;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  
  // Message Key Tracking (previne replay)
  usedMessageKeys: Set<string>;
  
  // Metadata
  ratchetCount: number;
}`} />
      </Section>

      <Section title="X3DH Key Agreement" subtitle="Extended Triple Diffie-Hellman para establ. de sessão">
        <p>
          O X3DH (Extended Triple Diffie-Hellman) permite estabelecer sessões seguras de forma assíncrona.
          O agente iniciador pode criar um shared secret usando apenas as chaves públicas do destino (via Agent Card),
          sem necessidade de ambos estarem online simultaneamente.
        </p>

        <Table
          headers={['Chave', 'Tipo', 'Vida Útil', 'Propósito']}
          rows={[
            ['Identity Key (IK)', 'Ed25519/X25519', 'Longa (meses)', 'Identidade do agente'],
            ['Signed PreKey (SPK)', 'X25519', 'Média (semanas)', 'Assinada pela IK'],
            ['One-Time PreKey (OPK)', 'X25519', 'Uma vez', 'Proteção extra contra replay'],
            ['Ephemeral Key (EK)', 'X25519', 'Uma sessão', 'Gerada pelo iniciador'],
          ]}
        />
      </Section>

      <Section title="Extensão Híbrida Pós-Quântica" subtitle="X25519 + ML-KEM-768 contra ameaças quânticas">
        <p>
          Combinamos X25519 (clássico) com ML-KEM-768 (pós-quântico) via HKDF. Se um dos dois for quebrado, o outro ainda protege.
          Isso garante segurança contra ataques <strong>"harvest now, decrypt later"</strong>.
        </p>

        <Table
          headers={['Cenário', 'X25519 Seguro?', 'ML-KEM Seguro?', 'Sessão Segura?']}
          rows={[
            ['Adversário clássico', '✅', '✅', '✅'],
            ['QC quebra X25519', '❌', '✅', '✅'],
            ['ML-KEM vulnerável', '✅', '❌', '✅'],
            ['Ambos quebrados', '❌', '❌', '❌'],
          ]}
        />
      </Section>

      <Section title="Post-Compromise Security (PCS)" subtitle="Auto-healing após comprometimento">
        <p>
          Mesmo que um adversário comprometa o estado de um agente no tempo <em>t</em>, o sistema auto-recupera a segurança 
          após <em>O(1)</em> passos de DH ratchet, pois novas chaves efêmeras introduzem entropia fresca desconhecida pelo adversário.
        </p>

        <Diagram title="Fluxo de Auto-Recuperação (PCS)">{pcsDiagram}</Diagram>

        <InfoBox type="tip" title="Prova Formal">
          <p>A propriedade PCS é formalmente verificada no modelo Tamarin (Apêndice D do paper). O lemma <code>PCS_Valid</code> prova que após corrupção + ratchet step, a nova root key é segura.</p>
        </InfoBox>
      </Section>
    </div>
  );
}
