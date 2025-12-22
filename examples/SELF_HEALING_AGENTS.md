# 🔄 Self-Healing Agentic Conversational System

## 🎯 Conceito

Um sistema onde **dois ou mais agentes** (sistemas autônomos, bots, ou serviços) se identificam mutuamente usando JWTs emitidos pelo mesmo servidor/autoridade, e **regeneram automaticamente seus tokens** quando expiram, mantendo a conversa contínua sem interrupção.

### Características Principais

- ✅ **Auto-Renovação**: Tokens são renovados automaticamente antes de expirar
- ✅ **Contexto Preservado**: A conversa continua mesmo após renovação
- ✅ **Verificação Mútua**: Agentes verificam a identidade uns dos outros
- ✅ **Self-Healing**: Sistema se recupera automaticamente de falhas de token
- ✅ **Segurança**: Tokens curtos (5min) com renovação proativa

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│           Token Authority (Servidor Central)            │
│  - Emite tokens para agentes                            │
│  - Renova tokens mantendo contexto                      │
│  - Valida identidades                                   │
└─────────────────────────────────────────────────────────┘
                    │                    │
                    │                    │
        ┌───────────▼──────────┐  ┌─────▼──────────────┐
        │    Agent Alpha        │  │    Agent Beta       │
        │  - Token próprio      │  │  - Token próprio   │
        │  - Auto-renovação     │  │  - Auto-renovação  │
        │  - Verifica Beta      │  │  - Verifica Alpha  │
        └───────────────────────┘  └────────────────────┘
                    │                    │
                    └──────────┬─────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Conversa Contínua  │
                    │   (Self-Healing)     │
                    └─────────────────────┘
```

## 🔑 Componentes

### 1. TokenAuthority

Servidor central que emite e renova tokens para os agentes.

**Responsabilidades:**
- Emitir tokens iniciais para agentes
- Renovar tokens mantendo contexto da conversa
- Validar identidades

**Características:**
- Tokens curtos (5 minutos) para segurança
- Renovação mantém `conversationId` e `capabilities`
- Suporta renovação de tokens expirados (com contexto)

### 2. SelfHealingAgent

Agente autônomo que gerencia seu próprio ciclo de vida de token.

**Responsabilidades:**
- Manter token válido através de auto-renovação
- Verificar identidade de outros agentes
- Enviar/receber mensagens autenticadas
- Preservar histórico da conversa

**Características:**
- Renovação proativa (60s antes de expirar)
- Verificação de identidade antes de cada mensagem
- Fallback automático em caso de falha
- Monitoramento contínuo de validade

## 📖 Uso Básico

### 1. Criar Autoridade e Agentes

```typescript
import { TokenAuthority, SelfHealingAgent } from './examples/self-healing-agents';

// Criar autoridade central
const authority = new TokenAuthority();

// Criar agentes
const agentA = new SelfHealingAgent(
  'agent-alpha',
  'primary',
  authority,
  ['reasoning', 'memory']
);

const agentB = new SelfHealingAgent(
  'agent-beta',
  'secondary',
  authority,
  ['analysis', 'synthesis']
);
```

### 2. Inicializar e Ativar Auto-Renovação

```typescript
// Inicializar agentes
await agentA.initialize();
await agentB.initialize();

// Ativar auto-renovação (verifica a cada 30 segundos)
agentA.startAutoRenewal(30000);
agentB.startAutoRenewal(30000);
```

### 3. Conversa entre Agentes

```typescript
// Agente A envia mensagem para Agente B
await agentA.sendMessage(agentB, 'Olá! Vamos trabalhar juntos?');

// Agente B responde
await agentB.sendMessage(agentA, 'Perfeito! Estou pronto.');
```

## 🔄 Fluxo de Auto-Renovação

```
┌─────────────────────────────────────────────────────────┐
│ 1. Token emitido (válido por 5 minutos)                 │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Agente monitora validade continuamente               │
│    (verifica a cada 30 segundos)                        │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│ 3. Token próximo de expirar? (< 60s restantes)         │
│    └─> Sim: Solicita renovação                           │
│    └─> Não: Continua usando token atual                 │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│ 4. Renovação mantém contexto:                            │
│    - conversationId (mesma conversa)                    │
│    - capabilities (mesmas capacidades)                   │
│    - agentId (mesma identidade)                          │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│ 5. Novo token válido por mais 5 minutos                  │
│    Conversa continua sem interrupção                     │
└─────────────────────────────────────────────────────────┘
```

## 🛡️ Segurança

### Validações Implementadas

1. **Verificação de Assinatura**: Cada token é verificado criptograficamente
2. **Validação de Issuer**: Apenas tokens do servidor autorizado são aceitos
3. **Validação de Audience**: Tokens devem ser destinados aos agentes
4. **Verificação de Conversa**: Agentes só conversam se estiverem na mesma conversa
5. **Expiração Curta**: Tokens de 5 minutos reduzem janela de ataque

### Boas Práticas

- ✅ Use HTTPS para comunicação entre agentes
- ✅ Rotacione chaves da autoridade periodicamente
- ✅ Monitore tentativas de renovação falhadas
- ✅ Implemente rate limiting na autoridade
- ✅ Log todas as renovações para auditoria

## 📊 Casos de Uso

### 1. Sistemas Multi-Agente de IA

Dois agentes de IA colaborando em uma tarefa complexa, mantendo contexto mesmo com renovação de tokens.

### 2. Microserviços Conversacionais

Serviços que precisam se comunicar de forma autenticada e contínua, com auto-recuperação de sessões.

### 3. Bots Colaborativos

Múltiplos bots trabalhando juntos em uma conversa ou tarefa, mantendo identidade e contexto.

### 4. Sistemas Distribuídos Resilientes

Sistemas que precisam manter comunicação mesmo com falhas temporárias de autenticação.

## 🧪 Executar Exemplo

```bash
# Compilar TypeScript
bun build examples/self-healing-agents.ts --outdir dist/examples --target node

# Executar demonstração
bun run dist/examples/self-healing-agents.js
```

Ou diretamente com ts-node:

```bash
bun run examples/self-healing-agents.ts
```

## 🔍 Exemplo de Saída

```
🚀 Iniciando demonstração de Self-Healing Agentic Conversational System

✅ Autoridade de tokens criada

🤖 [agent-alpha] Agente inicializado com token válido até 2025-12-21T10:05:00.000Z
🤖 [agent-beta] Agente inicializado com token válido até 2025-12-21T10:05:00.000Z

🔄 [agent-alpha] Auto-renovação de token ativada (verifica a cada 30000ms)
🔄 [agent-beta] Auto-renovação de token ativada (verifica a cada 30000ms)

💬 Iniciando conversa entre agentes...

📤 [agent-alpha] → [agent-beta]: Olá! Sou o Agente Alpha. Como você está?
📥 [agent-beta] ← [agent-alpha]: Olá! Sou o Agente Alpha. Como você está?

📤 [agent-beta] → [agent-alpha]: Olá Alpha! Sou o Agente Beta. Estou funcionando perfeitamente!
📥 [agent-alpha] ← [agent-beta]: Olá Alpha! Sou o Agente Beta. Estou funcionando perfeitamente!

⏳ Simulando espera de 4 minutos (tokens expiram em 5 minutos)...

🔄 [agent-alpha] Token próximo de expirar, renovando...
✅ [agent-alpha] Token renovado com sucesso. Válido até 2025-12-21T10:10:00.000Z
🔄 [agent-beta] Token próximo de expirar, renovando...
✅ [agent-beta] Token renovado com sucesso. Válido até 2025-12-21T10:10:00.000Z

📤 [agent-alpha] → [agent-beta]: Perfeito! Vamos trabalhar juntos neste problema complexo.
📥 [agent-beta] ← [agent-alpha]: Perfeito! Vamos trabalhar juntos neste problema complexo.

📤 [agent-beta] → [agent-alpha]: Excelente! Estou pronto para colaborar. Meus tokens foram renovados automaticamente.
📥 [agent-alpha] ← [agent-beta]: Excelente! Estou pronto para colaborar. Meus tokens foram renovados automaticamente.

📜 Histórico da conversa:
[10:00:00] agent-alpha → agent-beta: Olá! Sou o Agente Alpha. Como você está?
[10:00:01] agent-beta → agent-alpha: Olá Alpha! Sou o Agente Beta. Estou funcionando perfeitamente!
[10:04:00] agent-alpha → agent-beta: Perfeito! Vamos trabalhar juntos neste problema complexo.
[10:04:01] agent-beta → agent-alpha: Excelente! Estou pronto para colaborar. Meus tokens foram renovados automaticamente.

✅ Demonstração concluída! Os agentes mantiveram a conversa mesmo com renovação automática de tokens.
```

## 🚀 Próximos Passos

- [ ] Suporte para múltiplos agentes (>2)
- [ ] Persistência de histórico de conversa
- [ ] Métricas de renovação e performance
- [ ] Integração com sistemas de mensageria (RabbitMQ, Kafka)
- [ ] Suporte para renovação assíncrona em background
- [ ] Cache de tokens para reduzir carga na autoridade

## 📚 Referências

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [Self-Healing Systems](https://en.wikipedia.org/wiki/Self-healing)
- [Multi-Agent Systems](https://en.wikipedia.org/wiki/Multi-agent_system)

---

**Desenvolvido para demonstrar capacidades avançadas de autenticação e comunicação entre agentes autônomos.**

