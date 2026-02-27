import { Fingerprint } from 'lucide-react';
import { Section, CodeBlock, InfoBox } from '../components/ui';

export function JWKThumbprintPage() {
  return (
    <div>
      <Section title="JWK Thumbprint (RFC 7638)" subtitle="Identificação Criptográfica Única de Chaves" icon={<Fingerprint className="w-5 h-5" />}>
        <p>
          O JWK Thumbprint é um hash canônico de uma JSON Web Key, padronizado pela IETF no RFC 7638.
          Usado como identificador único e verificável de chaves públicas, é a base do <strong>Session Context Latching</strong>
          que vincula tokens DPoP ao canal E2EE.
        </p>

        <InfoBox type="info" title="Para que serve?">
          <p>
            Permite que um servidor de recursos valide que o token DPoP pertence ao mesmo agente que estabeleceu o canal Signal E2EE,
            sem precisar trocar a chave pública completa — apenas o thumbprint (hash compacto) é suficiente.
          </p>
        </InfoBox>
      </Section>

      <Section title="Como é Calculado">
        <p>
          1. Canonicaliza o JWK (apenas membros obrigatórios, ordem alfabética).<br />
          2. Aplica SHA-256 sobre o JSON canonicalizado.<br />
          3. Codifica em base64url.
        </p>

        <CodeBlock lang="typescript" code={`import {
  computeJWKThumbprint, publicKeyToJWK
} from '@purecore-codes/agent-zero-trust';

// Converter chave pública para JWK
const jwk = publicKeyToJWK(publicKey, 'X25519');
// { kty: "OKP", crv: "X25519", x: "<base64url>" }

// Calcular thumbprint (SHA-256 + base64url)
const thumbprint = computeJWKThumbprint(jwk);
// "dGhpcyBpcyBhIHRodW1icHJpbnQ..."

// Usar no claim cnf do DPoP
const proof = await createDPoPProof(dpopKey, {
  method: 'POST',
  url: 'https://api.example.com',
  signalIdentityKey: publicKey // Automaticamente calcula thumbprint
});
// proof.payload.cnf.signal_identity_kid === thumbprint ✓`} />
      </Section>

      <Section title="Vantagens do JWK Thumbprint">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="glass-card p-4">
            <h4 className="font-semibold text-primary mb-1">Compacto</h4>
            <p className="text-sm text-muted-foreground">Base64url é mais compacto que hex</p>
          </div>
          <div className="glass-card p-4">
            <h4 className="font-semibold text-secondary mb-1">Interoperável</h4>
            <p className="text-sm text-muted-foreground">Padrão IETF, compatível com OIDC/FAPI</p>
          </div>
          <div className="glass-card p-4">
            <h4 className="font-semibold text-accent mb-1">Determinístico</h4>
            <p className="text-sm text-muted-foreground">Mesma chave sempre gera mesmo thumbprint</p>
          </div>
          <div className="glass-card p-4">
            <h4 className="font-semibold text-warning mb-1">Auditável</h4>
            <p className="text-sm text-muted-foreground">Rastreabilidade entre autorização e canal E2EE</p>
          </div>
        </div>
      </Section>
    </div>
  );
}
