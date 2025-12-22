# 🔐 Secure Agents - Comunicação Ultra-Segura

## API Simples, Segurança Máxima

Este módulo combina **3 camadas de segurança** em uma API extremamente simples:

```
┌─────────────────────────────────────────────────────────────┐
│  Camada 3: JWT (EdDSA)                                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  Camada 2: Signal E2EE (Double Ratchet)                 ││
│  │  ┌─────────────────────────────────────────────────────┐││
│  │  │  Camada 1: mTLS (Certificados X.509)                │││
│  │  │                                                     │││
│  │  │              Sua Mensagem Aqui                      │││
│  │  │                                                     │││
│  │  └─────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start (10 linhas)

```typescript
import { SecureAgent, SecurityAuthority } from './secure-agents';

// 1. Criar autoridade central
const authority = new SecurityAuthority();

// 2. Criar agentes
const alice = new SecureAgent({ agentId: 'alice' }, authority);
const bob = new SecureAgent({ agentId: 'bob' }, authority);

// 3. Conectar (estabelece mTLS + E2EE automaticamente)
await alice.connect(bob);

// 4. Enviar mensagens seguras
await alice.send('Hello, ultra-secure world!');
await bob.send('Message received with 3 security layers!');
```

**É isso!** 10 linhas para máxima segurança.

---

## O Que Cada Camada Faz

| Camada | Tecnologia | Proteção | Se Comprometida... |
|--------|------------|----------|-------------------|
| **1. mTLS** | Certificados X.509 | Canal seguro, anti-MITM | E2EE ainda protege conteúdo |
| **2. E2EE** | Signal Double Ratchet | Conteúdo encriptado, PFS | mTLS ainda autentica |
| **3. JWT** | EdDSA (Ed25519) | Contexto, expiração | Outras camadas funcionam |

### Propriedades de Segurança

- **Perfect Forward Secrecy (PFS)**: Cada mensagem usa chave única
- **Post-Compromise Security (PCS)**: Recuperação após comprometimento  
- **Mutual Authentication**: Ambos os lados verificam identidade
- **Defense in Depth**: Comprometer 1 camada não compromete as outras

---

## API Reference

### SecurityAuthority

Autoridade central que gerencia certificados e tokens.

```typescript
const authority = new SecurityAuthority();
```

**Métodos:**

| Método | Descrição |
|--------|-----------|
| `generateAgentCredentials(agentId)` | Gera certificado mTLS para agente |
| `issueToken(agentId, peerId)` | Emite JWT para comunicação |
| `verifyToken(token)` | Verifica validade do JWT |

### SecureAgent

Agente com comunicação ultra-segura.

```typescript
const agent = new SecureAgent(config, authority);
```

**Config:**

```typescript
interface SecureAgentConfig {
  agentId: string;           // ID único do agente
  capabilities?: string[];   // Capacidades (incluídas no JWT)
  port?: number;             // Porta para servidor mTLS
}
```

**Métodos:**

| Método | Descrição |
|--------|-----------|
| `connect(peer)` | Estabelece conexão segura com outro agente |
| `send(content)` | Envia mensagem encriptada |
| `disconnect()` | Encerra conexão |
| `getMessageHistory()` | Retorna histórico de mensagens |

**Eventos:**

```typescript
agent.on('message', ({ from, content }) => {
  console.log(`Mensagem de ${from}: ${content}`);
});
```

---

## Fluxo de Conexão

```
Alice                                                    Bob
──────                                                   ───
  │                                                        │
  │  1. alice.connect(bob)                                │
  │  ├─── Verificar certificado mTLS de Bob               │
  │  ├─── Realizar X25519 Key Exchange                    │
  │  ├─── Inicializar Double Ratchet                      │
  │  └─── Emitir JWT                                      │
  │                                                        │
  │  2. alice.send("Hello!")                              │
  │  ├─── Encriptar com Double Ratchet (AES-256-GCM)     │
  │  ├─── Anexar JWT                                      │
  │  └─── Enviar pelo canal mTLS ─────────────────────▶   │
  │                                                        │
  │                            3. bob.receive(message)    │
  │                            ├─── Verificar JWT         │
  │                            ├─── Decriptar E2EE        │
  │                            └─── Emitir evento         │
  │                                                        │
```

---

## Algoritmos Utilizados

| Componente | Algoritmo | Biblioteca |
|------------|-----------|------------|
| mTLS | RSA-2048 + X.509 | Node.js `crypto` |
| Key Exchange | X25519 | Node.js `crypto` |
| E2EE Encryption | AES-256-GCM | Node.js `crypto` |
| Key Derivation | HKDF-SHA256 | Node.js `crypto` |
| JWT Signing | Ed25519 (EdDSA) | purecore-jwtfy |
| Ratchet | Double Ratchet (Signal) | Implementação própria |

---

## Comparação com Alternativas

| Solução | mTLS | E2EE | PFS | PCS | Simplicidade |
|---------|------|------|-----|-----|--------------|
| **Secure Agents** | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| Apenas mTLS | ✅ | ❌ | ✅* | ❌ | ⭐⭐⭐⭐ |
| Apenas E2EE | ❌ | ✅ | ✅ | ✅ | ⭐⭐⭐ |
| TLS + AES | ✅ | ❌ | ✅* | ❌ | ⭐⭐⭐ |

\* PFS por sessão, não por mensagem

---

## Casos de Uso

### 1. Comunicação entre Agentes de IA

```typescript
const reasoningAgent = new SecureAgent({ 
  agentId: 'reasoning-agent',
  capabilities: ['analyze', 'decide']
}, authority);

const executionAgent = new SecureAgent({ 
  agentId: 'execution-agent',
  capabilities: ['execute', 'report']
}, authority);

await reasoningAgent.connect(executionAgent);
await reasoningAgent.send(JSON.stringify({
  action: 'execute_task',
  parameters: { taskId: 123 }
}));
```

### 2. Microserviços Zero-Trust

```typescript
const authService = new SecureAgent({ agentId: 'auth-service' }, authority);
const apiGateway = new SecureAgent({ agentId: 'api-gateway' }, authority);

await apiGateway.connect(authService);
await apiGateway.send(JSON.stringify({
  type: 'validate_token',
  token: userToken
}));
```

### 3. IoT Seguro

```typescript
const sensor = new SecureAgent({ agentId: 'sensor-001' }, authority);
const controller = new SecureAgent({ agentId: 'controller' }, authority);

await sensor.connect(controller);
await sensor.send(JSON.stringify({
  temperature: 23.5,
  humidity: 45,
  timestamp: Date.now()
}));
```

---

## Executando o Exemplo

```bash
cd examples
bun run secure-agents.ts
```

**Saída esperada:**

```
════════════════════════════════════════════════════════════
🔐 SECURE AGENTS - E2EE + mTLS + JWT
   Comunicação Ultra-Segura entre Agentes
════════════════════════════════════════════════════════════

🏛️  Security Authority inicializada

🤖 [alice] Agente criado com credenciais mTLS
🤖 [bob] Agente criado com credenciais mTLS

🔗 [alice] Conectando a [bob]...
   🔒 Verificando certificado mTLS de bob...
   ✅ Certificado válido
   🔑 Estabelecendo chaves E2EE...
   🔐 Sessão E2EE estabelecida
   🎫 Token JWT emitido
   ✅ Conexão segura estabelecida!

────────────────────────────────────────────────────────────
💬 CONVERSA SEGURA
────────────────────────────────────────────────────────────

📤 [alice] → [bob]: "Olá Bob! Esta mensagem tem 3 camadas de segurança."
   └─ 🔒 Encriptado E2EE | 🔐 Canal mTLS | 🎫 JWT válido
📥 [bob] ← [alice]: "Olá Bob! Esta mensagem tem 3 camadas de segurança."
   └─ ✅ JWT verificado | ✅ E2EE decriptado | ✅ mTLS validado

...
```

---

## Referências

1. **Signal Protocol** - https://signal.org/docs/specifications/
2. **mTLS** - RFC 8446 (TLS 1.3)
3. **JWT** - RFC 7519
4. **Ed25519** - RFC 8032
5. **X25519** - RFC 7748
6. **AES-GCM** - NIST SP 800-38D

---

## Changelog

| Versão | Data | Mudanças |
|--------|------|----------|
| 1.0.0 | 22/12/2024 | Implementação inicial combinando E2EE + mTLS + JWT |

---

*Desenvolvido com ❤️ para máxima segurança com mínima complexidade.*
