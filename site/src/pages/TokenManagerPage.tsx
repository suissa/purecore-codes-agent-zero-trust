import { RefreshCw } from 'lucide-react';
import { Section, CodeBlock, Table, InfoBox, Diagram } from '../components/ui';

const circuitDiagram = `┌──────────┐          ┌──────────┐          ┌──────────┐
│  CLOSED  │─falha──►│   OPEN   │─timeout─►│HALF_OPEN │
│          │         │          │          │          │
│ Normal   │         │ Rejeita  │          │ Testa 1  │
│ operação │◄─ok─────│ tudo     │          │ request  │
└──────────┘         └──────────┘          └─────┬────┘
     ▲                                          │
     │              sucesso                     │
     └──────────────────────────────────────────┘
                    falha → volta p/ OPEN`;

export function TokenManagerPage() {
  return (
    <div>
      <Section title="Token Manager" subtitle="Promise Latching + Circuit Breaker" icon={<RefreshCw className="w-5 h-5" />}>
        <p>
          O Token Manager gerencia o ciclo de vida de tokens de acesso com duas inovações:
          <strong> Promise Latching</strong> previne "token refresh storms" e o <strong>Circuit Breaker</strong>
          protege contra cascatas de falhas nos serviços de autenticação.
        </p>
      </Section>

      <Section title="Promise Latching" subtitle="Previne refresh storms em enxames de alta densidade">
        <p>
          Quando múltiplas tarefas concorrentes detectam um token expirado, sem latching cada uma dispara um refresh independente.
          O Promise Latching garante que <strong>apenas um refresh</strong> é executado; todas as demais aguardam o mesmo resultado.
        </p>

        <Table
          headers={['Cenário', 'Sem Latching', 'Com Latching']}
          rows={[
            ['100 tasks, token expirado', '100 refresh requests', '1 refresh request'],
            ['Latência total', '100 × RTT', '1 × RTT'],
            ['Risco de rate limiting', 'Alto', 'Baixo'],
            ['Carga no auth server', 'Alta', 'Mínima'],
          ]}
        />

        <CodeBlock lang="typescript" code={`import { TokenManager } from '@purecore-codes/agent-zero-trust';

const tokenManager = new TokenManager({
  refreshThresholdSeconds: 300,
  maxRetries: 3,
  baseDelayMs: 1000
});

tokenManager.setRefreshFn(async () => {
  const response = await fetch('https://auth.example.com/refresh');
  const data = await response.json();
  return { token: data.access_token, expiresAt: data.expires_at };
});

// Múltiplas chamadas concorrentes → 1 refresh
const [t1, t2, t3] = await Promise.all([
  tokenManager.getToken(),
  tokenManager.getToken(),
  tokenManager.getToken(),
]);`} />
      </Section>

      <Section title="Circuit Breaker" subtitle="Previne cascatas de falhas">
        <Diagram title="Estados do Circuit Breaker">{circuitDiagram}</Diagram>

        <CodeBlock lang="typescript" code={`import { CircuitBreaker, CircuitOpenError } from '@purecore-codes/agent-zero-trust';

const breaker = new CircuitBreaker({
  threshold: 5,       // Falhas antes de abrir
  resetTimeout: 30000 // 30s para tentar novamente
});

try {
  const result = await breaker.execute(async () => {
    return await fetch('https://api.example.com/data');
  });
} catch (error) {
  if (error instanceof CircuitOpenError) {
    // Serviço indisponível - usar cache ou fallback
  }
}`} />

        <InfoBox type="tip" title="Backoff Exponencial com Jitter">
          <p>Retries usam <code>delay × 2^attempt + random_jitter</code> para evitar "thundering herd" em cenários de recuperação simultânea.</p>
        </InfoBox>
      </Section>
    </div>
  );
}
