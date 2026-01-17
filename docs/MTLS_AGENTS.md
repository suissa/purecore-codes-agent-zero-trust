# 🔒 Self-Healing Agents com mTLS (Mutual TLS)

## 🎯 Visão Geral

Extensão do sistema de Self-Healing Agents que adiciona **mTLS (Mutual TLS)** para fornecer segurança em **duas camadas**:

1. **mTLS (Camada de Transporte)**: Autenticação mútua via certificados X.509
2. **JWT (Camada de Aplicação)**: Autenticação de identidade e contexto da conversa

## 🛡️ Por que mTLS + JWT?

### Segurança em Duas Camadas

```
┌─────────────────────────────────────────────────┐
│         Camada de Aplicação (JWT)               │
│  - Identidade do agente                         │
│  - Contexto da conversa                         │
│  - Permissões e capacidades                     │
└─────────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────────┐
│         Camada de Transporte (mTLS)            │
│  - Autenticação mútua de certificados          │
│  - Criptografia de transporte                  │
│  - Prevenção de MITM (Man-in-the-Middle)       │
└─────────────────────────────────────────────────┘
```

### Benefícios Combinados

- ✅ **Autenticação Dupla**: Certificado + JWT
- ✅ **Criptografia End-to-End**: Dados protegidos em trânsito
- ✅ **Prevenção de MITM**: Certificados validam identidade do transporte
- ✅ **Contexto Preservado**: JWT mantém contexto mesmo com renovação
- ✅ **Self-Healing**: Sistema se recupera automaticamente

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────┐
│         Certificate Authority (CA)              │
│  - Gera certificados para agentes               │
│  - Assina certificados                          │
│  - Valida certificados                           │
└─────────────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
┌───────▼────────┐    ┌─────────▼────────┐
│  Agent Alpha   │    │   Agent Beta    │
│  - Cert mTLS   │◄──►│  - Cert mTLS    │
│  - JWT Token   │    │  - JWT Token    │
│  - TLS Server  │    │  - TLS Server   │
└────────────────┘    └─────────────────┘
        │                       │
        └───────────┬───────────┘
                    │
        ┌───────────▼───────────┐
        │   Conexão mTLS        │
        │   + Mensagens JWT     │
        └───────────────────────┘
```

## 📖 Como Funciona

### 1. Geração de Certificados

Cada agente recebe um certificado X.509 assinado pela CA:

```typescript
import { CertificateAuthority } from './examples/mtls-agents';

const ca = new CertificateAuthority();

// Gerar certificado para cada agente
const certA = ca.generateAgentCertificate('agent-alpha');
const certB = ca.generateAgentCertificate('agent-beta');
const caCert = ca.getCACertificate(); // Para validação
```

### 2. Estabelecimento de Conexão mTLS

```typescript
// Agente A inicia servidor TLS
await agentA.startTLSServer(8443);

// Agente B conecta ao Agente A via mTLS
await agentB.connectToPeer('localhost', 8443, 'agent-alpha');
```

### 3. Verificação Mútua

Quando uma conexão é estabelecida:

1. **Cliente envia certificado** → Servidor valida contra CA
2. **Servidor envia certificado** → Cliente valida contra CA
3. **Ambos verificam** → Conexão só é aceita se ambos forem válidos

### 4. Comunicação Segura

Cada mensagem inclui:
- **Conteúdo**: Dados da mensagem
- **JWT**: Token de autenticação de aplicação
- **Metadados**: Timestamp, IDs, etc.

## 🚀 Uso Básico

### Exemplo Completo

```typescript
import { mTLSAgent, CertificateAuthority, TokenAuthority } from './examples/mtls-agents';

// 1. Criar CA e Autoridade de Tokens
const ca = new CertificateAuthority();
const tokenAuthority = new TokenAuthority();

// 2. Gerar certificados
const certA = ca.generateAgentCertificate('agent-alpha');
const certB = ca.generateAgentCertificate('agent-beta');
const caCert = ca.getCACertificate();

// 3. Criar agentes
const agentA = new mTLSAgent(
  'agent-alpha',
  'primary',
  tokenAuthority,
  certA,
  caCert
);

const agentB = new mTLSAgent(
  'agent-beta',
  'secondary',
  tokenAuthority,
  certB,
  caCert
);

// 4. Inicializar
await agentA.initialize();
await agentB.initialize();

// 5. Iniciar servidores TLS
await agentA.startTLSServer(8443);
await agentB.startTLSServer(8444);

// 6. Estabelecer conexões mTLS
await agentA.connectToPeer('localhost', 8444, 'agent-beta');
await agentB.connectToPeer('localhost', 8443, 'agent-alpha');

// 7. Ativar auto-renovação
agentA.startAutoRenewal(30000);
agentB.startAutoRenewal(30000);

// 8. Enviar mensagens seguras
await agentA.sendMessage('agent-beta', 'Mensagem segura via mTLS + JWT');
await agentB.sendMessage('agent-alpha', 'Resposta igualmente segura!');
```

## 🔐 Segurança

### Validações Implementadas

1. **Validação de Certificado mTLS**
   - Certificado deve ser assinado pela CA conhecida
   - Certificado não pode estar expirado
   - CN (Common Name) deve corresponder ao agentId

2. **Validação de JWT**
   - Assinatura criptográfica válida
   - Issuer e Audience corretos
   - Token não expirado
   - Mesmo conversationId

3. **Verificação Cruzada**
   - agentId do JWT deve corresponder ao CN do certificado
   - Previne ataques de substituição de identidade

### Proteções Contra Ataques

| Ataque | Proteção |
|--------|----------|
| **Man-in-the-Middle** | mTLS valida certificados mutuamente |
| **Token Replay** | JWT com expiração curta + renovação |
| **Identity Spoofing** | Verificação cruzada JWT ↔ Certificado |
| **Eavesdropping** | Criptografia TLS de transporte |
| **Certificate Forgery** | Assinatura pela CA confiável |

## 📊 Comparativo: Sem mTLS vs Com mTLS

| Aspecto | Sem mTLS | Com mTLS |
|---------|----------|----------|
| **Autenticação de Transporte** | ❌ Não | ✅ Sim (certificados) |
| **Criptografia de Transporte** | ⚠️ Depende | ✅ Sempre (TLS) |
| **Prevenção MITM** | ❌ Não | ✅ Sim |
| **Validação de Identidade** | JWT apenas | JWT + Certificado |
| **Overhead** | Baixo | Médio (handshake inicial) |
| **Complexidade** | Simples | Média |

## 🧪 Testando

### Executar Demonstração

```bash
# Compilar
bun build examples/mtls-agents.ts --outdir dist/examples --target node

# Executar
bun run dist/examples/mtls-agents.js
```

### Saída Esperada

```
🚀 Demonstração de Self-Healing Agents com mTLS

✅ CA e Autoridade de Tokens criadas
✅ Certificados mTLS gerados para os agentes
🤖 [agent-alpha] Agente inicializado com mTLS e token válido até...
🤖 [agent-beta] Agente inicializado com mTLS e token válido até...
🔒 [agent-alpha] Servidor mTLS iniciado na porta 8443
🔒 [agent-beta] Servidor mTLS iniciado na porta 8444
🔒 [agent-alpha] Conectado via mTLS a agent-beta
🔒 [agent-beta] Conexão mTLS estabelecida com agent-alpha
💬 Iniciando conversa segura via mTLS...

📤 [agent-alpha] → [agent-beta] (mTLS): Olá Beta! Conexão segura estabelecida via mTLS.
📥 [agent-beta] ← [agent-alpha] (mTLS): Olá Beta! Conexão segura estabelecida via mTLS.
📤 [agent-beta] → [agent-alpha] (mTLS): Olá Alpha! Nossa comunicação está protegida por mTLS + JWT.
📥 [agent-alpha] ← [agent-beta] (mTLS): Olá Alpha! Nossa comunicação está protegida por mTLS + JWT.

✅ Demonstração concluída!
🔒 Segurança em duas camadas:
   1. mTLS: Autenticação mútua de transporte
   2. JWT: Autenticação de identidade e contexto
```

## 🔧 Configuração Avançada

### Opções TLS Customizadas

```typescript
// Ao criar servidor TLS, você pode passar opções customizadas
const tlsOptions: tls.TlsOptions = {
  cert: certificate.cert,
  key: certificate.key,
  ca: [caCert],
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.3', // Forçar TLS 1.3
  ciphers: 'ECDHE-RSA-AES256-GCM-SHA384', // Cipher específico
  // ... outras opções
};
```

### Certificados de Produção

Para produção, use certificados gerados por uma CA confiável:

```typescript
// Carregar certificados de arquivos
import { readFileSync } from 'fs';

const cert = readFileSync('./certs/agent-alpha.crt', 'utf-8');
const key = readFileSync('./certs/agent-alpha.key', 'utf-8');
const caCert = readFileSync('./certs/ca.crt', 'utf-8');
```

## 📚 Referências

- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [Mutual TLS Authentication](https://en.wikipedia.org/wiki/Mutual_authentication)
- [Node.js TLS Documentation](https://nodejs.org/api/tls.html)
- [mTLS Best Practices](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)

## 🚀 Próximos Passos

- [ ] Suporte para múltiplas CAs
- [ ] Revogação de certificados (CRL/OCSP)
- [ ] Rotação automática de certificados
- [ ] Métricas de segurança e performance
- [ ] Integração com sistemas de PKI existentes

---

**Segurança em duas camadas: transporte (mTLS) + aplicação (JWT) para comunicação entre agentes totalmente segura.**

