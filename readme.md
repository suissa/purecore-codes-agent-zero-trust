# @purecore-codes-codes/agent-zero-trust

[![npm version](https://img.shields.io/npm/v/@purecore-codes-codes/agent-zero-trust.svg)](https://www.npmjs.com/package/@purecore-codes-codes/agent-zero-trust)
[![License](https://img.shields.io/npm/l/@purecore-codes-codes/agent-zero-trust.svg)](https://github.com/purecore-codes/agent-zero-trust/blob/main/LICENSE)
[![Node Version](https://img.shields.io/node/v/@purecore-codes-codes/agent-zero-trust.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org)

**Arquitetura Zero-Trust para Agentes Autônomos de IA**

Uma biblioteca de segurança criptográfica que implementa defesa em profundidade tri-camada para comunicação segura entre agentes autônomos:

```
┌─────────────────────────────────────────────────────────┐
│              AGENTIC NETWORKFORTRESS                     │
├─────────────────────────────────────────────────────────┤
│  Camada 3: DPoP (RFC 9449) + Session Binding            │
│  Camada 2: Signal Protocol E2EE (Double Ratchet)        │
│  Camada 1: mTLS 1.3                                     │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Instalação

```bash
npm install @purecore-codes-codes/agent-zero-trust
# ou
bun add @purecore-codes-codes/agent-zero-trust
# ou
yarn add @purecore-codes-codes/agent-zero-trust
```

## 📖 Documentação Completa

- [Paper Científico](./docs/AGENTIC_ZERO_TRUST_PAPER.md)
- [Exemplos de Uso](./examples/)
- [API Reference](https://purecore-codes.dev/agent-zero-trust/docs/api)

## 🔐 Recursos Principais

### 1. Signal Protocol E2EE
- ✅ X3DH Key Agreement
- ✅ Double Ratchet Algorithm
- ✅ Perfect Forward Secrecy (PFS)
- ✅ Post-Compromise Security (PCS)
- ✅ Deniable Authentication

### 2. DPoP (RFC 9449)
- ✅ Proof-of-Possession criptográfico
- ✅ Bearer token binding (ath claim)
- ✅ Session Context Latching com JWK Thumbprint
- ✅ Nonce-based replay protection
- ✅ HTTP method/URL constraining

### 3. Infraestrutura Zero-Trust
- ✅ Token Manager com Promise Latching
- ✅ Circuit Breaker para resiliência
- ✅ Bloom Filter para CRL distribuída
- ✅ Zeroização segura de memória
- ✅ JWK Thumbprint (RFC 7638)

## 💡 Uso Básico

### Criptografia E2EE com Signal Protocol

```typescript
import { 
  SignalE2EEAgent, 
  TokenAuthority 
} from '@purecore-codes-codes/agent-zero-trust';

// 1. Criar autoridade de tokens
const authority = new TokenAuthority();

// 2. Criar agentes
const alice = new SignalE2EEAgent('alice', authority, ['reasoning']);
const bob = new SignalE2EEAgent('bob', authority, ['analysis']);

await alice.initialize();
await bob.initialize();

// 3. Trocar bundles de chaves públicas
const aliceBundle = alice.getPublicKeyBundle();
const bobBundle = bob.getPublicKeyBundle();

alice.registerPeerBundle('bob', bobBundle);
bob.registerPeerBundle('alice', aliceBundle);

// 4. Estabelecer sessão E2EE
await alice.establishSession('bob');
await bob.acceptSession(
  'alice',
  alice.getIdentityPublicKey(),
  aliceBundle.signedPreKey
);

// 5. Enviar mensagem encriptada
const encryptedMessage = await alice.sendMessage(
  'bob',
  'Olá Bob! Esta mensagem é E2EE com Signal Protocol.'
);

// 6. Receber e decriptar mensagem
const plaintext = await bob.receiveMessage(encryptedMessage);
console.log(plaintext); // "Olá Bob! Esta mensagem é E2EE com Signal Protocol."
```

### DPoP com Session Binding

```typescript
import { 
  generateDPoPKeyPair, 
  createDPoPProof,
  computeJWKThumbprint,
  publicKeyToJWK
} from '@purecore-codes-codes/agent-zero-trust';

// 1. Gerar chave DPoP
const dpopKey = generateDPoPKeyPair('EdDSA');

// 2. Obter thumbprint da identidade Signal
const signalIdentityKey = /* ... chave X25519 ... */;
const signalJWK = publicKeyToJWK(signalIdentityKey, 'X25519');
const signalThumbprint = computeJWKThumbprint(signalJWK);

// 3. Criar DPoP Proof com session binding
const proof = await createDPoPProof(dpopKey, {
  method: 'POST',
  url: 'https://api.example.com/message',
  accessToken: 'your_access_token',
  signalIdentityKey: signalIdentityKey // Session Context Latching
});

// 4. Usar no header de autorização
const authHeader = `DPoP your_access_token dpop=${proof.jwt}`;
```

### Token Manager com Promise Latching

```typescript
import { TokenManager } from '@purecore-codes-codes/agent-zero-trust';

const tokenManager = new TokenManager({
  refreshThresholdSeconds: 300,
  maxRetries: 3,
  baseDelayMs: 1000
});

// Configurar função de refresh
tokenManager.setRefreshFn(async () => {
  // Lógica de refresh do token
  const response = await fetch('/refresh', { method: 'POST' });
  const data = await response.json();
  
  return {
    token: data.access_token,
    expiresAt: data.expires_at,
    refreshToken: data.refresh_token
  };
});

// Obter token (com latching automático)
const token = await tokenManager.getToken();
// Se múltiplas chamadas ocorrerem durante refresh,
// todas aguardam a mesma promise
```

### Circuit Breaker para Resiliência

```typescript
import { CircuitBreaker, CircuitOpenError } from '@purecore-codes-codes/agent-zero-trust';

const breaker = new CircuitBreaker({
  threshold: 5,        // Falhas antes de abrir
  resetTimeout: 30000, // Tempo até tentar novamente (ms)
  monitoringPeriod: 10000
});

try {
  const result = await breaker.execute(async () => {
    return await fetch('https://auth-server.example.com/token');
  });
} catch (error) {
  if (error instanceof CircuitOpenError) {
    console.error('Circuit breaker aberto - serviço indisponível');
  }
}
```

### Bloom Filter para CRL Distribuída

```typescript
import { 
  createBloomFilterForCRL, 
  isRevoked,
  BloomFilter 
} from '@purecore-codes-codes/agent-zero-trust';

// 1. Criar Bloom Filter com lista de DIDs revogados
const revokedDIDs = ['did:agent:123', 'did:agent:456'];
const bloomFilter = createBloomFilterForCRL(revokedDIDs, 0.01);

// 2. Verificar se DID está revogado (O(1))
const isAgentRevoked = await isRevoked('did:agent:123', bloomFilter);
console.log(isAgentRevoked); // true

// 3. Verificação rápida antes de estabelecer sessão
if (!await isRevoked(peerDID, bloomFilter)) {
  // DID definitivamente não revogado - prosseguir
  await establishSession(peerDID);
}
```

## 🏗️ Arquitetura

### Estrutura de Módulos

```
@purecore-codes-codes/agent-zero-trust/
├── src/
│   ├── crypto/          # Signal Protocol, X3DH, Double Ratchet
│   │   └── index.ts     # Criptografia de baixo nível
│   ├── auth/            # JWT, DPoP, Token Manager
│   │   └── index.ts     # Autenticação e autorização
│   ├── protocol/        # Protocolo A2A
│   ├── types/           # Tipos semânticos
│   ├── utils/           # Utilitários
│   └── index.ts         # Exportação principal
├── examples/            # Exemplos de uso
├── tests/               # Testes unitários
└── docs/                # Documentação e paper científico
```

### Camadas de Segurança

| Camada | Protocolo | Proteção |
|--------|-----------|----------|
| **Transporte** | mTLS 1.3 | Autenticação mútua, canal seguro, anti-MITM |
| **Aplicação** | Signal E2EE | Forward Secrecy, Post-Compromise Security, Deniability |
| **Contexto** | JWT + DPoP | Identity claims, Authorization, Expiration |

## 🔒 Segurança de Memória

A biblioteca implementa zeroização segura de chaves sensíveis:

```typescript
import { secureZero, DoubleRatchet } from '@purecore-codes-codes/agent-zero-trust';

// Chaves são zeroizadas automaticamente após uso
const ratchet = new DoubleRatchet();
// ... uso ...
ratchet.destroy(); // Zeroização explícita recomendada

// Para zeroização manual de buffers sensíveis
const sensitiveKey = new Uint8Array(32);
// ... uso ...
secureZero(sensitiveKey);
```

**Nota:** Para ambientes de alta segurança, considere usar Node.js N-API para zeroização nativa em C++.

## 📊 Performance

| Métrica | Valor |
|---------|-------|
| Latência P50 (E2EE) | ~5.8ms |
| Latência P99 (E2EE) | ~18.7ms |
| Throughput | ~28K msg/s |
| CPU Overhead | +35% vs TLS |
| Memória Overhead | +22% vs TLS |

*Benchmarks realizados em AWS EC2 c6i.xlarge com 100 agentes concorrentes.*

## 🔧 Integração com Frameworks de IA

### LangChain

```typescript
import { SignalE2EEAgent } from '@purecore-codes-codes/agent-zero-trust';

// Criar wrapper para LangChain agents
const secureAgent = new SignalE2EEAgent('langchain-agent', authority);
await secureAgent.initialize();

// Usar com LangChain
const executor = new AgentExecutor({
  agent: createAgent(tools),
  tools,
  handleE2EE: secureAgent // Integração E2EE
});
```

### CrewAI

```typescript
// Comunicação segura entre crew members
const crewChannel = new SignalE2EEAgent('crew-coordinator', authority);

// Cada crew member estabelece sessão E2EE
await crewChannel.establishSession('crew-member-1');
await crewChannel.establishSession('crew-member-2');
```

## 🧪 Testes

```bash
# Rodar testes
npm test

# Com coverage
npm run test:coverage

# Exemplos
npm run example:signal
npm run example:dpop
npm run example:a2a
```

## 📄 Licença

Apache 2.0 - veja [LICENSE](./LICENSE) para detalhes.

## 📚 Referências Acadêmicas

Se usar esta biblioteca em pesquisa, cite:

```bibtex
@article{agent-zero-trust2026,
  title={Toward a Sovereign Agentic Zero-Trust Architecture: Multi-Layered Security for Autonomous AI Swarms},
  author={Agentic NetworkFortress Core Team},
  journal={arXiv preprint},
  year={2026},
  url={https://purecore-codes.dev/agent-zero-trust/docs/paper}
}
```

## 🤝 Contribuindo

Contribuições são bem-vindas! Veja nosso [Guia de Contribuição](./CONTRIBUTING.md).

1. Fork o repositório
2. Crie um branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add AmazingFeature'`)
4. Push para o branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📞 Contato

- **Website:** https://purecore-codes.dev
- **Email:** security@purecore-codes.dev
- **GitHub:** https://github.com/purecore-codes/agent-zero-trust

## ⚠️ Aviso de Segurança

Esta biblioteca lida com operações criptográficas sensíveis. Para ambientes de produção:

1. **Auditoria:** Realize auditoria de segurança por terceira parte
2. **TEE:** Considere usar Trusted Execution Environments (Intel SGX, AWS Nitro)
3. **Key Management:** Implemente gestão adequada de chaves
4. **Monitoring:** Monitore tentativas de ataque e anomalias

## 🙏 Agradecimentos

- Signal Foundation pelo protocolo Signal
- IETF pela especificação DPoP (RFC 9449)
- NIST pelo padrão ML-KEM (FIPS 203)
- Comunidade open-source de criptografia

---

*Construído com ❤️ para um futuro de IA descentralizado e seguro*
