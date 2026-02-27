import { Shield } from 'lucide-react';
import { Section, Table, InfoBox } from '../components/ui';

export function AdversaryPage() {
  return (
    <div>
      <Section title="Modelo de Adversário" subtitle="Taxinomia Formal de Ameaças (Dolev-Yao Estendido)" icon={<Shield className="w-5 h-5" />}>
        <p>
          Para alcançar rigor de publicação IEEE/ACM, formalizamos o modelo de adversário em 6 eixos que compõem a <strong>Taxonomia de Ameaças</strong>.
          O modelo estende a formalização clássica de <strong>Dolev-Yao</strong> com ameaças específicas de sistemas agênticos.
        </p>

        <InfoBox type="security" title="Definição Formal">
          <p>
            Um adversário <strong>A</strong> opera como atacante adaptativo de tempo polinomial (PPT) com capacidades
            de interceptar, modificar, injetar e redirecionar mensagens na rede, além de corromper participantes e componentes de infraestrutura.
          </p>
        </InfoBox>
      </Section>

      <Section title="Eixos de Ameaça">
        <Table
          headers={['Eixo', 'Adversário', 'Capacidades', 'Mitigação']}
          rows={[
            [
              '1',
              'Network Adversary (Dolev-Yao)',
              'Interceptar, modificar, injetar mensagens; controlar roteamento; replay attacks',
              'mTLS 1.3 + E2EE Signal + nonce tracking'
            ],
            [
              '2',
              'Compromised Broker',
              'Acesso root ao broker; leitura de filas; roteamento malicioso; correlação de tráfego',
              'E2EE (broker vê apenas ciphertext) + topic rotation'
            ],
            [
              '3',
              'Corrupted Agent State',
              'Dump de memória; exfiltrar chaves de sessão; clonar estado criptográfico',
              'PCS (Double Ratchet) + zeroização nativa + TEE attest'
            ],
            [
              '4',
              'Adaptive Adversary',
              'Aprendizado contextual; adapta estratégia; combina múltiplos vetores simultâneos',
              'Defesa em profundidade + Análise comportamental + epoch rotation'
            ],
            [
              '5',
              'Insider Threat',
              'Agente legítimo torna-se malicioso; abusa permissões válidas; exfiltra dados autorizados',
              'Epoch rotation + privilege mínimo + behavioral monitoring'
            ],
            [
              '6',
              'CA Compromise',
              'Emissão de certificados fraudulentos; comprometimento da raiz PKI',
              'CT logs + trust pinning + CA diversity + CRL Bloom Filter'
            ],
          ]}
        />
      </Section>

      <Section title="Análise STRIDE">
        <Table
          headers={['Ameaça STRIDE', 'Vetor', 'Camada Afetada', 'Mitigação']}
          rows={[
            ['Spoofing', 'Agente falso', 'Camada 1 + 3', 'mTLS + DPoP + Agent Card assinado'],
            ['Tampering', 'Modificação de msg', 'Camada 2', 'AES-256-GCM integridade + assinatura'],
            ['Repudiation', 'Negar ação', 'Camada 3', 'Modo B: Persistent Signature (Ed25519)'],
            ['Information Disclosure', 'Eavesdropping', 'Camada 1 + 2', 'mTLS + E2EE fim-a-fim'],
            ['Denial of Service', 'Flood de msgs', 'Infra', 'Circuit Breaker + Rate Limiting'],
            ['Elevation of Privilege', 'Token replay', 'Camada 3', 'DPoP jti + ath binding'],
          ]}
        />
      </Section>

      <Section title="Propriedades de Segurança Formais">
        <div className="space-y-4">
          <div className="glass-card p-5">
            <h4 className="font-bold text-primary mb-2">Confidencialidade (IND-CCA)</h4>
            <p className="text-sm text-muted-foreground">
              ∀ adversário PPT <em>A</em>, a vantagem em distinguir ciphertexts de mensagens escolhidas é negligenciável:
              Adv<sub>IND-CCA</sub>(A) ≤ negl(λ). Baseado em AES-256-GCM + X25519/ML-KEM.
            </p>
          </div>
          <div className="glass-card p-5">
            <h4 className="font-bold text-secondary mb-2">Forward Secrecy (PFS)</h4>
            <p className="text-sm text-muted-foreground">
              Comprometimento de chaves de longo prazo (IdentityKey) NÃO expõe comunicações de sessões passadas.
              Cada sessão usa chaves efêmeras derivadas via X3DH.
            </p>
          </div>
          <div className="glass-card p-5">
            <h4 className="font-bold text-accent mb-2">Post-Compromise Security (PCS)</h4>
            <p className="text-sm text-muted-foreground">
              Após comprometimento no tempo <em>t</em>, segurança é restaurada em O(1) ratchet steps à medida que novas chaves
              efêmeras introduzem entropia fresca desconhecida pelo adversário. Verificado formalmente via Tamarin.
            </p>
          </div>
          <div className="glass-card p-5">
            <h4 className="font-bold text-warning mb-2">Session Binding (Unlinkability)</h4>
            <p className="text-sm text-muted-foreground">
              Tokens DPoP são vinculados ao canal Signal via JWK Thumbprint (RFC 7638). Token roubado fora do canal é criptograficamente inútil.
            </p>
          </div>
        </div>
      </Section>
    </div>
  );
}
