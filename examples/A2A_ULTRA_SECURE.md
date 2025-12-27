# 🛡️ Canal Ultra-Seguro A2A (Agent-to-Agent)

## 🎯 Visão Geral

O Canal Ultra-Seguro A2A implementa o protocolo **Agent-to-Agent (A2A)** oficial com múltiplas camadas de segurança, fornecendo comunicação padronizada e ultra-segura entre agentes independentes.

## 🔗 Protocolo A2A

O **Agent-to-Agent (A2A) Protocol** é um padrão aberto projetado para facilitar comunicação e interoperabilidade entre sistemas de agentes de IA independentes e potencialmente opacos.

- **Especificação Oficial**: https://a2a-protocol.org/latest/specification/
- **Versão Implementada**: v1.0 (DRAFT)
- **Objetivo**: Permitir que agentes descubram capacidades, negociem modalidades de interação e colaborem em tarefas complexas

## 🛡️ Arquitetura de Segurança Multi-Camada

```
┌─────────────────────────────────────────────────┐
│           Camada 4: A2A Protocol               │
│  - Operações padronizadas (SendMessage, etc.)  │
│  - Tasks e lifecycle management                 │
│  - Agent Cards e discovery                      │
└─────────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────────┐
│           Camada 3: E2EE (Preparado)           │
│  - Criptografia end-to-end das mensagens       │
│  - Chaves únicas por sessão                    │
│  - Perfect Forward Secrecy                     │
└─────────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────────┐
│         Camada 2: JWT (EdDSA) Aplicação        │
│  - Autenticação de identidade do agente        │
│  - Claims e contexto da conversa               │
│  - Assinatura criptográfica Ed25519            │
└─────────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────────┐
│         Camada 1: mTLS Transporte              │
│  - Autenticação mútua via certificados         │
│  - Criptografia de transporte TLS 1.3          │
│  - Prevenção de MITM                           │
└─────────────────────────────────────────────────┘
```

## 🚀 Operações A2A Suportadas

### Core Operations

| Operação | Descrição | Status |
|----------|-----------|--------|
| `sendMessage` | Enviar mensagem para agente | ✅ Implementado |
| `sendStreamingMessage` | Enviar com streaming de updates | ✅ Implementado |
| `getTask` | Obter estado atual de uma task | ✅ Implementado |
| `listTasks` | Listar tasks com filtros | ✅ Implementado |
| `cancelTask` | Cancelar task em andamento | ✅ Implementado |
| `subscribeToTask` | Subscrever a updates de task | ✅ Implementado |
| `getAgentCard` | Obter metadados do agente | ✅ Implementado |

### Tipos de Dados A2A

- **AgentCard**: Metadados de identidade e capacidades
- **Task**: Unidade fundamental de trabalho com lifecycle
- **Message**: Comunicação com partes (text, file, data)
- **Artifact**: Outputs gerados pelo agente
- **StreamEvent**: Updates em tempo real

## 📖 Como Funciona

### 1. Inicialização do Canal

```typescript
import { UltraSecureA2AChannel } from '../domains/a2a/security/ultra-secure-channel';

// Criar canal com certificados mTLS e chaves Ed25519
const channel = new UltraSecureA2AChannel(
  'agent-alpha',
  certificateMTLS,
  caCert,
  keyPairEd25519
);

// Registrar chave pública do peer para E2EE
channel.registerPeerPublicKey('agent-beta', peerPublicKey);
```

### 2. Descoberta de Agentes

```typescript
// Obter Agent Card com capacidades
const agentCard = await channel.getAgentCard();

console.log(`Agent: ${agentCard.name}`);
console.log(`Capabilities: ${agentCard.capabilities.supportedOperations}`);
console.log(`Endpoint: ${agentCard.endpoint}`);
```

### 3. Comunicação Segura

```typescript
// Criar mensagem A2A
const message = Message.text('user', 'Hello via A2A protocol!');
const request = SendMessageRequest.make({ message });

// Enviar via canal ultra-seguro
const task = await channel.sendMessage(request);
console.log(`Task created: ${task.id}`);

// Verificar resultado
const result = await channel.getTask(task.id);
console.log(`Status: ${result.status}`);
```

### 4. Streaming em Tempo Real

```typescript
// Streaming de updates
for await (const event of channel.sendStreamingMessage(request)) {
  switch (event.type) {
    case 'task_status_update':
      console.log(`Task ${event.taskId}: ${event.status}`);
      break;
    case 'message':
      console.log(`New message: ${Message.extractText(event.message)}`);
      break;
  }
}
```

## 🔐 Segurança Implementada

### Validações Multi-Camada

1. **Validação mTLS**
   - Certificado assinado pela CA confiável
   - CN do certificado corresponde ao agentId
   - Certificado não expirado

2. **Validação JWT**
   - Assinatura EdDSA válida
   - Issuer e Audience corretos
   - Token não expirado
   - Claims de contexto válidos

3. **Validação A2A**
   - Operações suportadas pelo agente
   - Tipos de conteúdo aceitos
   - Estados de task válidos

### Proteções Contra Ataques

| Ataque | Proteção |
|--------|----------|
| **Man-in-the-Middle** | mTLS + Validação de certificados |
| **Token Replay** | JWT com expiração + timestamps |
| **Identity Spoofing** | Verificação cruzada JWT ↔ Certificado |
| **Protocol Confusion** | Validação estrita do schema A2A |
| **Task Hijacking** | Autorização por agentId |
| **Message Tampering** | Assinatura criptográfica |

## 🧪 Exemplo Completo

```typescript
import { UltraSecureA2AChannel } from '../domains/a2a/security/ultra-secure-channel';
import { Message, SendMessageRequest } from '../domains/a2a/core/message';

async function demonstrateA2A() {
  // 1. Criar canais para dois agentes
  const channelAlpha = new UltraSecureA2AChannel('agent-alpha', certA, caCert, keyPairA);
  const channelBeta = new UltraSecureA2AChannel('agent-beta', certB, caCert, keyPairB);
  
  // 2. Registrar chaves públicas (E2EE)
  channelAlpha.registerPeerPublicKey('agent-beta', keyPairB.publicKey);
  channelBeta.registerPeerPublicKey('agent-alpha', keyPairA.publicKey);
  
  // 3. Descobrir capacidades
  const cardBeta = await channelBeta.getAgentCard();
  console.log(`Connecting to: ${cardBeta.name}`);
  
  // 4. Enviar mensagem A2A
  const message = Message.text('user', 'Hello via A2A ultra-secure channel!');
  const request = SendMessageRequest.make({ message });
  
  const task = await channelBeta.sendMessage(request);
  console.log(`Task created: ${task.id}`);
  
  // 5. Monitorar progresso
  for await (const event of channelBeta.subscribeToTask(task.id)) {
    console.log(`Update: ${event.type}`);
    if (event.type === 'task_status_update' && event.status === 'completed') {
      break;
    }
  }
  
  // 6. Obter resultado final
  const result = await channelBeta.getTask(task.id);
  const response = Message.extractText(result.messages[1]);
  console.log(`Response: ${response}`);
}
```

## 📊 Comparativo: A2A vs Implementações Proprietárias

| Aspecto | Implementação Proprietária | A2A Ultra-Secure |
|---------|---------------------------|-------------------|
| **Padronização** | ❌ Específica do vendor | ✅ Protocolo aberto |
| **Interoperabilidade** | ❌ Limitada | ✅ Universal |
| **Descoberta de Capacidades** | ⚠️ Manual | ✅ Automática (Agent Cards) |
| **Lifecycle Management** | ⚠️ Básico | ✅ Completo (Tasks) |
| **Streaming** | ⚠️ Proprietário | ✅ Padronizado |
| **Segurança** | ⚠️ Varia | ✅ Multi-camada |
| **Auditabilidade** | ❌ Opaca | ✅ Transparente |

## 🔧 Configuração Avançada

### Agent Card Customizado

```typescript
const customCard = AgentCard.make({
  agentId: 'specialized-agent',
  name: 'Specialized AI Agent',
  description: 'Agent specialized in data analysis',
  protocolVersion: '1.0',
  endpoint: 'https://api.example.com/a2a',
  capabilities: {
    streaming: true,
    pushNotifications: true,
    supportedContentTypes: [
      'text/plain',
      'application/json',
      'application/vnd.ms-excel'
    ],
    supportedOperations: [
      'sendMessage',
      'sendStreamingMessage',
      'getTask',
      'listTasks'
    ]
  },
  authentication: {
    type: 'mtls',
    config: {
      requireClientCert: true,
      jwtSigning: 'EdDSA',
      tokenExpiry: '1h'
    }
  },
  metadata: {
    version: '2.1.0',
    specialization: 'data-analysis',
    maxConcurrentTasks: 10
  }
});
```

### Filtros de Task Avançados

```typescript
// Listar tasks com filtros específicos
const tasks = await channel.listTasks({
  contextId: 'conversation-123',
  status: 'running',
  lastUpdatedAfter: Date.now() - 3600000, // Última hora
  includeArtifacts: true,
  pageSize: 20
});

console.log(`Found ${tasks.totalSize} tasks`);
```

## 🚀 Próximos Passos

- [ ] **Push Notifications**: Webhooks para updates assíncronos
- [ ] **gRPC Binding**: Implementação do binding gRPC
- [ ] **HTTP/REST Binding**: Implementação do binding REST
- [ ] **E2EE Completo**: Ativação da criptografia end-to-end
- [ ] **Agent Registry**: Descoberta automática de agentes
- [ ] **Load Balancing**: Distribuição de tasks entre agentes
- [ ] **Monitoring**: Métricas e observabilidade

## 📚 Referências

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 8037 - EdDSA](https://tools.ietf.org/html/rfc8037)
- [JSON-RPC 2.0](https://www.jsonrpc.org/specification)

---

**Canal Ultra-Seguro A2A: Comunicação padronizada e segura entre agentes de IA independentes.**