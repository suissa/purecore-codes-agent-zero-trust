# Signal Protocol End-to-End Encryption para Agentes

## Sumário

1. [O que é o Signal Protocol?](#o-que-é-o-signal-protocol)
2. [Como Funciona](#como-funciona)
3. [Algoritmos Utilizados](#algoritmos-utilizados)
4. [Propriedades de Segurança](#propriedades-de-segurança)
5. [Como Usar](#como-usar)
6. [Signal E2EE vs mTLS](#signal-e2ee-vs-mtls)
7. [Usando Ambos em Conjunto](#usando-ambos-em-conjunto)
8. [Quando Usar Cada Um](#quando-usar-cada-um)
9. [Referências](#referências)

---

## O que é o Signal Protocol?

O **Signal Protocol** é um protocolo de criptografia end-to-end desenvolvido por Trevor Perrin e Moxie Marlinspike. É amplamente considerado o **padrão-ouro** para mensagens seguras e é utilizado por aplicativos como:

- **Signal** (o aplicativo original)
- **WhatsApp** (3+ bilhões de usuários)
- **Facebook Messenger** (modo secreto)
- **Google Messages** (RCS)
- **Skype** (conversas privadas)

O protocolo combina dois componentes principais:

```
┌─────────────────────────────────────────────────────────────┐
│                    Signal Protocol                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────────────┐    ┌───────────────────────────────┐ │
│  │       X3DH        │───▶│      Double Ratchet           │ │
│  │  Key Agreement    │    │   Continuous Key Rotation     │ │
│  └───────────────────┘    └───────────────────────────────┘ │
│                                                             │
│  Estabelece sessão        Protege cada mensagem            │
│  inicial segura           individualmente                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Como Funciona

### 1. X3DH (Extended Triple Diffie-Hellman)

O X3DH é usado para estabelecer a sessão inicial entre dois agentes:

```typescript
// Cada agente publica um "Key Bundle" contendo:
interface KeyBundle {
  identityKey: Buffer;        // Chave de identidade (longo prazo)
  signedPreKey: Buffer;       // Pre-key assinada (médio prazo)
  signedPreKeySignature: Buffer;
  oneTimePreKey?: Buffer;     // Pre-key única (curto prazo)
}
```

O protocolo realiza **4 operações Diffie-Hellman**:

```
Alice (Iniciadora)                    Bob (Receptor)
──────────────────                    ─────────────────
IKa (Identity Key)                    IKb (Identity Key)
EKa (Ephemeral Key)                   SPKb (Signed Pre-Key)
                                      OPKb (One-Time Pre-Key)

DH1 = DH(IKa, SPKb)   ──────────────────────────────────────
DH2 = DH(EKa, IKb)    ──────────────────────────────────────
DH3 = DH(EKa, SPKb)   ──────────────────────────────────────
DH4 = DH(EKa, OPKb)   ──────────────────────────────────────

SharedSecret = HKDF(DH1 || DH2 || DH3 || DH4)
```

### 2. Double Ratchet Algorithm

Após o X3DH estabelecer o segredo compartilhado, o **Double Ratchet** entra em ação:

```
                     ┌───────────────────────────────────┐
                     │         Root Key (RK)             │
                     └───────────┬───────────────────────┘
                                 │
              ┌──────────────────┼──────────────────────┐
              ▼                  ▼                      ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │  DH Ratchet     │ │ Sending Chain   │ │ Receiving Chain │
    │  (Asymmetric)   │ │ (Symmetric)     │ │ (Symmetric)     │
    └─────────────────┘ └─────────────────┘ └─────────────────┘
              │                  │                      │
              │                  ▼                      ▼
              │         ┌───────────────┐      ┌───────────────┐
              │         │ Message Key 1 │      │ Message Key 1 │
              │         │ Message Key 2 │      │ Message Key 2 │
              │         │ Message Key 3 │      │ Message Key 3 │
              │         │     ...       │      │     ...       │
              │         └───────────────┘      └───────────────┘
              │
              └─────── Atualiza chains a cada resposta
```

**Symmetric-key Ratchet:**
- Deriva uma nova chave para cada mensagem
- Impossibilita calcular chaves anteriores a partir de posteriores

**DH Ratchet:**
- Troca novas chaves DH a cada "turno" de conversa
- Impossibilita calcular chaves futuras a partir de anteriores

---

## Algoritmos Utilizados

| Componente | Algoritmo | Propósito |
|------------|-----------|-----------|
| Key Exchange | **X25519** | Diffie-Hellman sobre Curve25519 |
| Key Derivation | **HKDF-SHA256** | Derivação de chaves a partir de DH |
| Encryption | **AES-256-GCM** | Encriptação autenticada |
| Authentication | **Ed25519** | Assinatura de pre-keys |
| Chain KDF | **HMAC-SHA256** | Avanço das chains |

---

## Propriedades de Segurança

### Perfect Forward Secrecy (PFS)

```
Se o atacante obtiver sua chave privada AGORA:
├── ✅ Mensagens PASSADAS permanecem seguras
└── ❌ Apenas mensagens ATUAIS são comprometidas
```

### Post-Compromise Security (PCS)

```
Se o atacante comprometeu sua chave NO PASSADO:
├── ✅ Mensagens FUTURAS se tornam seguras novamente
└── 🔄 Após troca de DH ratchet keys
```

### Deniability (Negabilidade)

```
Qualquer pessoa com a chave pública poderia ter criado a mensagem:
├── ✅ Você não pode provar criptograficamente quem enviou
└── ✅ Útil para proteção legal/privacidade
```

### Chaves Únicas por Mensagem

```
Mensagem 1: ChaveA ──────────────────
Mensagem 2: ChaveB ──────────────────
Mensagem 3: ChaveC ──────────────────

✅ Compromisso de ChaveB não afeta mensagens 1 ou 3
```

---

## Como Usar

### Instalação

```bash
# Clone o repositório
cd purecore-codes-jwtfy

# Instale dependências
bun install
```

### Uso Básico

```typescript
import { 
  SignalE2EEAgent, 
  TokenAuthority 
} from './examples/signal-e2ee-agents';

// 1. Criar autoridade de tokens (para JWT)
const tokenAuthority = new TokenAuthority();

// 2. Criar agentes
const alice = new SignalE2EEAgent('alice', tokenAuthority);
const bob = new SignalE2EEAgent('bob', tokenAuthority);

await alice.initialize();
await bob.initialize();

// 3. Trocar bundles públicos
alice.registerPeerBundle('bob', bob.getPublicKeyBundle());
bob.registerPeerBundle('alice', alice.getPublicKeyBundle());

// 4. Estabelecer sessão E2EE
await alice.establishSession('bob');
await bob.acceptSession(
  'alice',
  alice.getIdentityPublicKey(),
  alice.getPublicKeyBundle().signedPreKey
);

// 5. Enviar mensagens encriptadas
const msg = await alice.sendMessage('bob', 'Hello, secure world!');
const plaintext = await bob.receiveMessage(msg);

console.log(plaintext); // "Hello, secure world!"
```

### Eventos

```typescript
bob.on('message', ({ from, content, message }) => {
  console.log(`Mensagem de ${from}: ${content}`);
});
```

---

## Signal E2EE vs mTLS

### Tabela Comparativa

| Aspecto | Signal E2EE | mTLS |
|---------|-------------|------|
| **Camada OSI** | Aplicação (7) | Transporte (4) |
| **O que protege** | Conteúdo da mensagem | Canal de comunicação |
| **Forward Secrecy** | ✅ Por mensagem | ✅ Por sessão TLS |
| **Post-Compromise** | ✅ Sim (Double Ratchet) | ❌ Não |
| **Autenticação** | Identidade E2E | Certificados X.509 |
| **Visibilidade servidor** | ❌ Não vê conteúdo | ⚠️ Termina no servidor |
| **Complexidade** | Alta | Média |
| **Overhead** | Maior (crypto por msg) | Menor (por sessão) |

### Diferenças Visuais

```
mTLS (Mutual TLS):
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Agent A │◀═══════▶│ Server  │◀═══════▶│ Agent B │
└─────────┘  TLS    └─────────┘  TLS    └─────────┘
                         │
                    Pode ver o
                    conteúdo!

Signal E2EE:
┌─────────┐════════════════════════════▶┌─────────┐
│ Agent A │      Encriptado E2E         │ Agent B │
└─────────┘◀════════════════════════════└─────────┘
                         │
                    Servidor não
                    pode ver nada!
```

### Quando Cada Um é Comprometido

```
Cenário: Atacante obtém chave privada

mTLS:
├── Passado: ❌ Todas as mensagens dessa sessão comprometidas
├── Futuro: ❌ Até nova sessão TLS
└── Servidor: Ainda protegido (tem próprio cert)

Signal E2EE:
├── Passado: ✅ Mensagens antigas protegidas (PFS)
├── Futuro: ✅ Proteção restaurada após DH ratchet
└── Servidor: N/A (nunca viu o conteúdo)
```

---

## Usando Ambos em Conjunto

### SIM! Você pode e DEVE usar ambos!

A combinação cria **defesa em profundidade**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Arquitetura Combinada                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    Signal E2EE                        │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │                     mTLS                        │  │  │
│  │  │  ┌─────────────────────────────────────────┐    │  │  │
│  │  │  │                 JWT                     │    │  │  │
│  │  │  │                                         │    │  │  │
│  │  │  │            Payload/Contexto             │    │  │  │
│  │  │  │                                         │    │  │  │
│  │  │  └─────────────────────────────────────────┘    │  │  │
│  │  │          Autenticação de Transporte             │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │              Encriptação End-to-End                   │  │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Benefícios da Combinação

| Camada | Protocolo | Proteção | Se Comprometido... |
|--------|-----------|----------|-------------------|
| **Transporte** | mTLS | Canal seguro, anti-MITM | E2EE ainda protege conteúdo |
| **Aplicação** | Signal E2EE | Conteúdo encriptado | mTLS ainda autentica partes |
| **Contexto** | JWT | Claims, autorização | Outros layers ainda funcionam |

### Exemplo de Uso Combinado

```typescript
import { mTLSAgent, CertificateAuthority } from './mtls-agents';
import { SignalE2EEAgent, TokenAuthority } from './signal-e2ee-agents';

// Setup de infraestrutura
const ca = new CertificateAuthority();
const tokenAuth = new TokenAuthority();

// Agente com ambas as camadas
class HybridSecureAgent {
  private mtlsAgent: mTLSAgent;
  private e2eeAgent: SignalE2EEAgent;
  
  constructor(agentId: string) {
    const cert = ca.generateAgentCertificate(agentId);
    
    // mTLS para transporte
    this.mtlsAgent = new mTLSAgent(
      agentId, 'primary', tokenAuth, cert, ca.getCACertificate()
    );
    
    // Signal E2EE para conteúdo
    this.e2eeAgent = new SignalE2EEAgent(agentId, tokenAuth);
  }
  
  async sendSecureMessage(peerId: string, content: string) {
    // 1. Encripta com Signal E2EE
    const encryptedMsg = await this.e2eeAgent.sendMessage(peerId, content);
    
    // 2. Envia pelo canal mTLS (já encriptado E2E!)
    await this.mtlsAgent.sendMessage(peerId, JSON.stringify(encryptedMsg));
  }
}
```

### Fluxo de Dados Combinado

```
Agent A                                                Agent B
───────                                                ───────
   │                                                      │
   │  1. Criar payload (ex: comando para agente)          │
   │     ↓                                                │
   │  2. Adicionar JWT (claims, exp, iss)                 │
   │     ↓                                                │
   │  3. Encriptar com Signal E2EE                        │
   │     ↓                                                │
   │  4. Enviar pelo canal mTLS ════════════════════════▶ │
   │                                                      │
   │                                    5. mTLS valida    │
   │                                       certificados   │
   │                                       ↓              │
   │                                    6. Decripta E2EE  │
   │                                       ↓              │
   │                                    7. Verifica JWT   │
   │                                       ↓              │
   │                                    8. Processa       │
   │                                       payload        │
   │                                                      │
```

---

## Quando Usar Cada Um

### Use Apenas mTLS quando:

- ✅ Comunicação servidor-servidor tradicional
- ✅ APIs onde o servidor precisa ver o conteúdo
- ✅ Infraestrutura já possui PKI estabelecida
- ✅ Latência é crítica (menos overhead)
- ✅ Compliance requer logs do conteúdo

### Use Apenas Signal E2EE quando:

- ✅ Zero-trust absoluto (nem servidores intermediários)
- ✅ Mensagens precisam de PFS por mensagem
- ✅ Negabilidade é importante
- ✅ Comunicação peer-to-peer direta
- ✅ Privacidade máxima do conteúdo

### Use Ambos quando:

- ✅ **Comunicação entre agentes autônomos** 
- ✅ Defesa em profundidade é necessária
- ✅ Diferentes adversários em diferentes camadas
- ✅ Regulamentação exige múltiplas camadas
- ✅ Sistemas críticos de alta segurança

---

## Referências

### Especificações Oficiais

1. **Double Ratchet Algorithm** (Revision 4, 2025)
   - https://signal.org/docs/specifications/doubleratchet/
   - Trevor Perrin, Moxie Marlinspike, Rolfe Schmidt

2. **X3DH Key Agreement Protocol**
   - https://signal.org/docs/specifications/x3dh/

3. **PQXDH** (Post-Quantum Extended Diffie-Hellman)
   - https://signal.org/docs/specifications/pqxdh/

### Implementações de Referência

4. **libsignal** (Oficial)
   - https://github.com/signalapp/libsignal

5. **2key-ratchet** (TypeScript)
   - https://github.com/PeculiarVentures/2key-ratchet

### Papers Acadêmicos

6. **The Double Ratchet: Security Notions, Proofs, and Modularization**
   - Alwen, Coretti, Dodis (2019)
   - https://eprint.iacr.org/2018/1037

7. **A Formal Security Analysis of the Signal Messaging Protocol**
   - Cohn-Gordon, Cremers, et al. (2017)
   - https://eprint.iacr.org/2016/1013

### RFCs Relacionados

8. **RFC 7748** - Elliptic Curves for Security (X25519)
9. **RFC 5869** - HKDF (HMAC-based Key Derivation Function)
10. **RFC 8446** - TLS 1.3

---

## Changelog

| Versão | Data | Mudanças |
|--------|------|----------|
| 1.0.0 | 22/12/2024 | Implementação inicial do Signal E2EE para agentes |

---

*Documentação criada para o projeto @purecore-codes/one-jwt-4-all*
