import { Layers } from 'lucide-react';
import { Section, Diagram, CodeBlock, Table, InfoBox } from '../components/ui';

const triLayerDiagram = `┌────────────────────────────────────────────────────────────┐
│                   HANDSHAKE TRI-CAMADA                      │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Camada 3: Contexto (JWT/DPoP + Session Binding)          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  RFC 9449 • Claims de Domínio • cnf (JWK Thumbprint) │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▲                                  │
│  Camada 2: Mensagens (Signal Protocol E2EE)                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Double Ratchet • PFS • PCS • X25519 + ML-KEM-768    │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▲                                  │
│  Camada 1: Transporte (mTLS 1.3)                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Autenticação Mútua • Certificados X.509 • TLS 1.3   │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘`;

const mtlsHandshake = `Cliente                          Servidor
   │                              │
   │──── ClientHello ────────────►│
   │◄─── ServerHello + Cert ─────│
   │                              │
   │──── ClientCert ─────────────►│
   │                              │
   │◄─── [Certificate Verify] ───│
   │                              │
   │──── [Finished] ─────────────►│
   │◄─── [Finished] ─────────────│
   │                              │
   │◄══════ Túnel Criptografado ══►│`;

export function ArchitecturePage() {
  return (
    <div>
      <Section title="Arquitetura Tri-Camada" subtitle="Defense in Depth para Agentes Autônomos" icon={<Layers className="w-5 h-5" />}>
        <p>
          A arquitetura Agent Zero Trust é fundamentada no princípio de <strong>Defesa em Profundidade</strong>: cada camada 
          fornece proteções independentes, de modo que o comprometimento de uma camada não compromete as demais. O modelo tri-camada 
          integra segurança de transporte, confidencialidade de mensagens e autorização contextual.
        </p>

        <InfoBox type="security" title="Princípio Fundamental">
          <p>A confiança nunca é implícita. Cada agente mantém controle exclusivo sobre seu lifecycle criptográfico (<strong>Soberania Criptográfica Agencial</strong>).</p>
        </InfoBox>

        <Diagram title="Modelo Tri-Camada">{triLayerDiagram}</Diagram>
      </Section>

      <Section title="Camada 1: Transporte (mTLS 1.3)" subtitle="Autenticação mútua no nível de rede">
        <p>
          Mutual TLS estabelece autenticação bidirecional. Diferentemente de TLS convencional (unilateral), mTLS requer que 
          <strong> ambas</strong> as partes apresentem certificados válidos, prevenindo MITM no nível de rede.
        </p>

        <Diagram title="Handshake mTLS">{mtlsHandshake}</Diagram>

        <Table
          headers={['Propriedade', 'mTLS', 'TLS Convencional']}
          rows={[
            ['Autenticação do Cliente', '✅ Obrigatória', '❌ Ausente'],
            ['Autenticação do Servidor', '✅ Presente', '✅ Presente'],
            ['Prevenção MITM', '✅ Bidirecional', '⚠️ Unilateral'],
            ['Certificados', 'X.509 ambos', 'X.509 servidor'],
          ]}
        />

        <InfoBox type="warning" title="Limitação">
          <p>mTLS <strong>não protege</strong> contra comprometimento do broker e não fornece PFS entre agentes finais. Por isso a Camada 2 é essencial.</p>
        </InfoBox>
      </Section>

      <Section title="Camada 2: Mensagens (Signal E2EE)" subtitle="Confidencialidade fim-a-fim com Double Ratchet">
        <p>
          A camada de aplicação implementa o Signal Protocol via Double Ratchet, adicionando <strong>Perfect Forward Secrecy</strong>, 
          <strong> Post-Compromise Security</strong> e <strong>Deniable Authentication</strong>. Mesmo que o broker seja comprometido, 
          as mensagens são indecifráveis.
        </p>

        <CodeBlock lang="typescript" code={`// Troca de chaves híbrida
async function hybridKeyExchange(
  localX25519: X25519KeyPair,
  remoteX25519: Uint8Array,
  localMLKEM: MLKEMKeyPair,
  remoteMLKEMCiphertext: Uint8Array
): Promise<Uint8Array> {
  const sharedX25519 = await x25519Derive(localX25519.privateKey, remoteX25519);
  const sharedMLKEM = await mlkemDecapsulate(remoteMLKEMCiphertext, localMLKEM.privateKey);
  
  // Combinação híbrida via HKDF
  const combined = concat(sharedX25519, sharedMLKEM);
  return await hkdf(combined, salt, info, 32);
}`} />
      </Section>

      <Section title="Camada 3: Contexto (DPoP)" subtitle="Autorização vinculada a chave criptográfica">
        <p>
          DPoP (RFC 9449) vincula tokens de acesso a chaves criptográficas do agente. O <strong>Session Context Latching</strong> 
          amarra a identidade Signal ao token DPoP via JWK Thumbprint (RFC 7638), impedindo uso cross-channel.
        </p>

        <CodeBlock lang="typescript" code={`interface DPoPProof {
  header: {
    typ: "dpop+jwt";
    alg: "ES256" | "EdDSA";
    jwk: JWK; // Chave pública do agente
  };
  payload: {
    jti: string;  // ID único (previne replay)
    htu: string;  // HTTP URI do alvo
    htm: string;  // HTTP method
    ath?: string; // Access token hash
    cnf: {
      jwk: JWK;
      signal_identity_kid: string; // JWK Thumbprint
    };
  };
}`} />
      </Section>
    </div>
  );
}
