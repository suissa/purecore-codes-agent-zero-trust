# 🐰 Secure Agents + RabbitMQ

## Comunicação Distribuída Ultra-Segura

Este módulo permite que agentes em **processos ou máquinas diferentes** se comuniquem de forma ultra-segura usando RabbitMQ como transporte.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              RabbitMQ Broker                                │
│                           (com TLS para transporte)                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                     Exchange: secure-agents                             ││
│  │  ┌──────────────────────┐         ┌──────────────────────┐              ││
│  │  │ Queue: agent-alice   │         │ Queue: agent-bob     │              ││
│  │  └──────────────────────┘         └──────────────────────┘              ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                    │                               │
          ┌─────────▼─────────┐           ┌─────────▼─────────┐
          │  SecureAgentRMQ   │◀─────────▶│  SecureAgentRMQ   │
          │  (alice)          │   E2EE    │  (bob)            │
          │  Processo A       │  payload  │  Processo B       │
          └───────────────────┘           └───────────────────┘
```

---

## Quick Start

```typescript
import { SecureAgentRMQ, SecurityAuthority } from './secure-agents-rabbitmq';

// 1. Autoridade compartilhada (ou use chave pública exportada)
const authority = new SecurityAuthority();

// 2. Criar agentes (podem estar em processos diferentes!)
const alice = new SecureAgentRMQ({
  agentId: 'alice',
  rabbitmq: { url: 'amqps://localhost:5671' }
}, authority);

const bob = new SecureAgentRMQ({
  agentId: 'bob',
  rabbitmq: { url: 'amqps://localhost:5671' }
}, authority);

// 3. Conectar ao RabbitMQ
await alice.connect();
await bob.connect();

// 4. Estabelecer sessão E2EE (key exchange via RabbitMQ)
await alice.establishSession('bob');

// 5. Enviar mensagens seguras
await alice.send('bob', 'Hello via RabbitMQ with E2EE!');

// 6. Escutar mensagens
bob.on('message', ({ from, content }) => {
  console.log(`Mensagem de ${from}: ${content}`);
});
```

---

## Camadas de Segurança

| Camada | Tecnologia | Proteção | Se Comprometida... |
|--------|------------|----------|-------------------|
| **Broker** | RabbitMQ + TLS | Transporte seguro | E2EE protege conteúdo |
| **Mensagem** | Signal E2EE | Conteúdo encriptado | TLS protege metadados |
| **Contexto** | JWT (EdDSA) | Auth, expiration | Outras camadas funcionam |

### Por que isso é seguro?

```
Cenário: RabbitMQ comprometido

❌ Atacante tem acesso ao broker
❌ Atacante vê as mensagens passarem
✅ Mensagens são CIPHERTEXT (E2EE)
✅ Atacante NÃO consegue ler conteúdo
✅ Perfect Forward Secrecy protege mensagens antigas
```

---

## Arquitetura

### Processo A (Alice)

```typescript
// alice.ts (Processo separado)
const alice = new SecureAgentRMQ({
  agentId: 'alice',
  rabbitmq: { url: 'amqps://rabbitmq.example.com:5671' }
}, authority);

await alice.connect();
await alice.send('bob', 'Hello from Process A!');
```

### Processo B (Bob)

```typescript
// bob.ts (Outro processo/máquina)
const bob = new SecureAgentRMQ({
  agentId: 'bob',
  rabbitmq: { url: 'amqps://rabbitmq.example.com:5671' }
}, authority);

await bob.connect();
bob.on('message', ({ from, content }) => {
  console.log(`${from}: ${content}`);
});
```

---

## Configuração

### RabbitMQ com TLS

```typescript
const agent = new SecureAgentRMQ({
  agentId: 'alice',
  capabilities: ['reasoning', 'planning'],
  rabbitmq: {
    url: 'amqps://user:password@rabbitmq.example.com:5671',
    exchange: 'secure-agents',  // default
    tlsOptions: {
      ca: fs.readFileSync('/path/to/ca.pem'),
      cert: fs.readFileSync('/path/to/client.pem'),
      key: fs.readFileSync('/path/to/client-key.pem')
    }
  }
}, authority);
```

### Variáveis de Ambiente (Recomendado)

```bash
# .env
RABBITMQ_URL=amqps://user:pass@rabbitmq.example.com:5671
RABBITMQ_CA_PATH=/etc/ssl/rabbitmq/ca.pem
RABBITMQ_CERT_PATH=/etc/ssl/rabbitmq/client.pem
RABBITMQ_KEY_PATH=/etc/ssl/rabbitmq/client-key.pem
```

```typescript
const agent = new SecureAgentRMQ({
  agentId: 'alice',
  rabbitmq: {
    url: process.env.RABBITMQ_URL!,
    tlsOptions: {
      ca: fs.readFileSync(process.env.RABBITMQ_CA_PATH!),
      cert: fs.readFileSync(process.env.RABBITMQ_CERT_PATH!),
      key: fs.readFileSync(process.env.RABBITMQ_KEY_PATH!)
    }
  }
}, authority);
```

---

## API Reference

### SecureAgentRMQ

```typescript
new SecureAgentRMQ(config: SecureAgentRMQConfig, authority: SecurityAuthority)
```

**Métodos:**

| Método | Descrição |
|--------|-----------|
| `connect()` | Conecta ao RabbitMQ e configura filas |
| `establishSession(peerId)` | Estabelece sessão E2EE com outro agente |
| `send(peerId, content)` | Envia mensagem encriptada |
| `disconnect()` | Desconecta do RabbitMQ |
| `getMessageHistory()` | Retorna histórico de mensagens |

**Eventos:**

```typescript
agent.on('message', ({ from, content, message }) => {
  // Mensagem recebida e decriptada
});
```

### SecurityAuthority

A autoridade pode ser **compartilhada** ou **distribuída**:

```typescript
// Opção 1: Mesma instância (mesmo processo)
const authority = new SecurityAuthority();

// Opção 2: Exportar chave pública (processos diferentes)
const publicKeyPem = authority.exportPublicKey();
// Enviar publicKeyPem para outros processos via config/env
```

---

## Fluxo de Mensagens

```
1. Alice quer enviar mensagem para Bob

2. Se não existe sessão E2EE:
   ├── Alice envia KEY_EXCHANGE via RabbitMQ
   ├── Bob recebe e responde com suas chaves
   └── Ambos inicializam Double Ratchet

3. Alice encripta mensagem:
   ├── Double Ratchet gera message key única
   ├── AES-256-GCM encripta conteúdo
   └── JWT é gerado e anexado

4. Alice publica no RabbitMQ:
   └── Exchange: secure-agents
       └── Routing Key: bob

5. Bob consome da fila agent-bob:
   ├── Verifica JWT
   ├── Decripta com Double Ratchet
   └── Emite evento 'message'
```

---

## Instalação do RabbitMQ

### Docker (Desenvolvimento)

```bash
# RabbitMQ com Management UI
docker run -d \
  --name rabbitmq \
  -p 5672:5672 \
  -p 5671:5671 \
  -p 15672:15672 \
  -e RABBITMQ_DEFAULT_USER=admin \
  -e RABBITMQ_DEFAULT_PASS=secret \
  rabbitmq:3-management
```

### Docker com TLS

```yaml
# docker-compose.yml
version: '3.8'
services:
  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5671:5671"   # AMQPS (TLS)
      - "5672:5672"   # AMQP
      - "15672:15672" # Management
    volumes:
      - ./rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf
      - ./certs:/etc/rabbitmq/certs
    environment:
      RABBITMQ_DEFAULT_USER: admin
      RABBITMQ_DEFAULT_PASS: secret
```

```ini
# rabbitmq.conf
listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/rabbitmq/certs/ca.pem
ssl_options.certfile = /etc/rabbitmq/certs/server.pem
ssl_options.keyfile = /etc/rabbitmq/certs/server-key.pem
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = true
```

---

## Dependências

Para usar com RabbitMQ real:

```bash
bun add amqplib
bun add -d @types/amqplib
```

Depois, substitua o mock por import real:

```typescript
// De:
// Mock interno

// Para:
import * as amqp from 'amqplib';
```

---

## Casos de Uso

### 1. Microserviços de IA

```typescript
// Serviço de Reasoning
const reasoner = new SecureAgentRMQ({
  agentId: 'reasoning-service',
  rabbitmq: { url: process.env.RABBITMQ_URL! }
}, authority);

await reasoner.connect();
await reasoner.send('executor-service', JSON.stringify({
  action: 'execute_plan',
  plan: analyzedPlan
}));
```

### 2. Pipeline de Processamento

```typescript
// Agente 1 → Agente 2 → Agente 3
agent1.on('complete', async (result) => {
  await agent1.send('agent2', JSON.stringify(result));
});

agent2.on('message', async ({ content }) => {
  const result = await process(JSON.parse(content));
  await agent2.send('agent3', JSON.stringify(result));
});
```

### 3. IoT Distribuído

```typescript
// Sensores em máquinas diferentes
const sensor = new SecureAgentRMQ({
  agentId: `sensor-${deviceId}`,
  rabbitmq: { url: 'amqps://iot-broker:5671' }
}, authority);

await sensor.connect();
setInterval(async () => {
  await sensor.send('controller', JSON.stringify({
    temperature: readSensor(),
    timestamp: Date.now()
  }));
}, 5000);
```

---

## Comparação

| Feature | SecureAgents (local) | SecureAgents + RabbitMQ |
|---------|---------------------|-------------------------|
| Comunicação | Mesmo processo | Processos/máquinas diferentes |
| Transporte | In-memory | RabbitMQ + TLS |
| Escalabilidade | Limitada | Alta (horizontal) |
| Persistência | Não | Sim (filas duráveis) |
| Retry automático | Não | Sim (RabbitMQ) |
| Balanceamento | Não | Sim (consumers) |
| E2EE | ✅ | ✅ |
| JWT | ✅ | ✅ |
| PFS | ✅ | ✅ |

---

## Referências

1. **RabbitMQ TLS** - https://www.rabbitmq.com/ssl.html
2. **amqplib** - https://github.com/squaremo/amqp.node
3. **Signal Protocol** - https://signal.org/docs/specifications/
4. **JWT** - RFC 7519

---

## Changelog

| Versão | Data | Mudanças |
|--------|------|----------|
| 1.0.0 | 22/12/2024 | Implementação inicial com RabbitMQ |

---

*Comunicação distribuída ultra-segura para sistemas de agentes autônomos.*
