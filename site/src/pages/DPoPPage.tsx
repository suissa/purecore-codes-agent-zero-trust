import { Key } from 'lucide-react';
import { Section, Diagram, CodeBlock, Table, InfoBox } from '../components/ui';

const dpopFlow = `┌─────────────┐                    ┌─────────────┐
│   Agente    │                    │  Servidor   │
│  (Cliente)  │                    │  Recursos   │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. POST /token + DPoP Proof     │
       │     (com signal_identity_kid)    │
       │─────────────────────────────────►│
       │                                  │
       │  2. Access Token (bound)         │
       │◄─────────────────────────────────│
       │                                  │
       │  3. API Request + DPoP + Token   │
       │─────────────────────────────────►│
       │                                  │
       │  4. Validação:                   │
       │     - Verificar assinatura DPoP  │
       │     - Validar jti (replay)       │
       │     - Validar htu/htm            │
       │     - Validar ath (token hash)   │
       │     - Validar signal_identity_kid│
       │                                  │
       │  5. Response (200 OK / 401)      │
       │◄─────────────────────────────────│`;

export function DPoPPage() {
  return (
    <div>
      <Section title="DPoP (RFC 9449)" subtitle="Demonstrating Proof-of-Possession at the Application Layer" icon={<Key className="w-5 h-5" />}>
        <p>
          Bearer tokens convencionais representam vulnerabilidade crítica: qualquer entidade com posse do token pode utilizá-lo.
          <strong> DPoP</strong> mitiga este risco: cada requisição inclui uma prova criptográfica de posse da chave privada,
          tornando tokens roubados inúteis para adversários.
        </p>

        <InfoBox type="info" title="Session Context Latching">
          <p>
            Inovação da Agent Zero Trust: incluímos o JWK Thumbprint (RFC 7638) da IdentityKey do Signal no claim <code>cnf</code>,
            vinculando <strong>criptograficamente</strong> a autorização ao canal de mensagens E2EE. Um token DPoP só é válido no canal que o gerou.
          </p>
        </InfoBox>
      </Section>

      <Section title="Fluxo DPoP com Session Binding">
        <Diagram title="Fluxo Completo">{dpopFlow}</Diagram>

        <CodeBlock lang="typescript" code={`import {
  generateDPoPKeyPair,
  createDPoPProof,
  verifyDPoPProof,
  computeJWKThumbprint,
  publicKeyToJWK
} from '@purecore-codes/agent-zero-trust';

// 1. Gerar chave DPoP
const dpopKey = generateDPoPKeyPair('EdDSA');

// 2. Criar proof com session binding
const proof = await createDPoPProof(dpopKey, {
  method: 'POST',
  url: 'https://api.example.com/message',
  accessToken: '...',
  signalIdentityKey // Session Context Latching
});

// 3. Verificar proof
const result = await verifyDPoPProof(proof.jwt, {
  algorithms: ['EdDSA'],
  requireAth: true,
  requiredMethod: 'POST',
  requiredUrl: 'https://api.example.com/message'
});`} />
      </Section>

      <Section title="Benefícios vs Bearer Token">
        <Table
          headers={['Aspecto', 'Bearer Token', 'DPoP + Session Binding']}
          rows={[
            ['Token roubado é útil?', '✅ Sim, reutilizável', '❌ Não, requer chave privada'],
            ['Previne replay?', '❌ Não nativamente', '✅ Via jti + nonce'],
            ['Cross-channel use?', '✅ Possível', '❌ Bloqueado por cnf'],
            ['Vínculo com E2EE?', '❌ Impossível', '✅ Via JWK Thumbprint'],
            ['Conformidade FAPI 2.0?', '❌', '✅'],
          ]}
        />
      </Section>
    </div>
  );
}
