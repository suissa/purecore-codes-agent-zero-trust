# 🔐 Purecore JWTfy (Agentic NetworkFortress)

<img src="https://i.imgur.com/39I2vIJ.png" align="center" alt="Purecore JWTfy Banner" />

> **The state-of-the-art security layer for Agentic Communication.**
> Zero dependencies. Strong opinions. Radical security.

---

## 🏗️ Technical Blog Post: The "Fortress" Architecture

### How it was made
Purecore JWTfy wasn't built as another generic JWT library. It was born from the need for **deterministic security** in autonomous agent networks. We looked at the current landscape—bloated with legacy support for insecure algorithms like RS256 or HS256—and decided to build a "Fortress". Using only Ed25519 (EdDSA) and modern primitives like DPoP and Signal's Double Ratchet, we created a tool that makes the *wrong way* impossible.

### How it works
The architecture follows the **Defense in Depth** principle. It's not just about a token; it's about the context.
1. **Semantic Layer**: Every string (URL, Method, Token) is strictly typed at the boundary.
2. **Identity Layer**: Ed25519 provides fast, secure signatures with tiny keys.
3. **Transmission Layer**: DPoP (Demonstrating Proof-of-Possession) binds tokens to the sender's private key, making stolen tokens useless.
4. **Resiliency Layer**: Self-healing managers recover from expired tokens without interrupting agent tasks.

### How to test
Every module comes with a semantic manifest and a suite of "fail-fast" tests. You can run the examples in the `examples/` directory to see the "Self-Healing" and "E2EE" protocols in action.
```bash
bun examples/secure-agents.ts
bun examples/self-healing-agents.ts
```

---

## 🚀 Quick Start

```bash
bun add @purecore/one-jwt-4-all
```

```typescript
import { SignJWT, jwtVerify, generateKeyPair } from '@purecore/one-jwt-4-all';

const { publicKey, privateKey } = generateKeyPair();

// Create Token
const token = await new SignJWT({ agentId: 'alpha' })
  .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
  .setExpirationTime('2h')
  .sign(privateKey);

// Verify Token
const { payload } = await jwtVerify(token, publicKey);
```

---

## 💎 Features Registry (Examples)

This library is a complete toolkit for secure agentic systems. Below are the core functionalities available in the `examples/` directory.

### 1. ⭐ Secure Agents (A2A Protocol)
**Concept**: A unified API that combines mTLS, Signal E2EE, and JWT in a single "Defense in Depth" stack.
- **Problem**: Communication between agents is usually either only TLS (vulnerable to MITM at the broker level) or only JWT (no forward secrecy).
- **When to use**: Any production system requiring the highest level of security between autonomous entities.
- **Example**: `examples/secure-agents.ts`
```typescript
const alice = new SecureAgent({ agentId: 'alice' }, authority);
const bob = new SecureAgent({ agentId: 'bob' }, authority);
await alice.connect(bob);
await alice.send('Hello Bob!');
```

### 2. 🐰 Distributed Secure Agents (RabbitMQ)
**Concept**: Extends the A2A protocol to distributed environments using RabbitMQ as a broker.
- **Problem**: Securing messages across different machines or processes while maintaining end-to-end encryption.
- **When to use**: Microservices architectures, IoT, or cloud-scale agent swarms.
- **Example**: `examples/secure-agents-rabbitmq.ts`
- 📖 [Full Guide](examples/SECURE_AGENTS_RABBITMQ.md)

### 3. 🛡️ DPoP (RFC 9449)
**Concept**: Demonstrating Proof-of-Possession. Binds an access token to a specific cryptographic key pair.
- **Problem**: "Bearer" tokens can be stolen and used by anyone (replay attacks).
- **When to use**: Public APIs, high-stakes financial operations, or browser-based agents where tokens might be intercepted.
- **Example**: `examples/dpop-example.ts`
```typescript
const dpopProof = await createDPoPProof(keyPair, { method: 'POST', url: '/resource' });
// Token is now useless without the private key that generated dpopProof
```

### 4. 🏦 FAPI 2.0 (Financial-grade API)
**Concept**: Implementation of the world's most secure API standard, used by Open Banking.
- **Problem**: Standard OAuth 2.0 is insufficient for high-security environments like banking.
- **When to use**: Financial systems, medical data access, or government APIs.
- **Example**: `examples/fapi20-demo-working.ts`
- **Features**: Pushed Authorization Requests (PAR), PKCE, DPoP binding.

### 5. 🔄 Self-Healing Agents
**Concept**: Agents that automatically monitor token expiration and refresh themselves without losing conversational context.
- **Problem**: Tokens expire during long-running agentic tasks (multi-step reasoning), causing failures.
- **When to use**: Agents performing tasks that take minutes or hours to complete.
- **Example**: `examples/self-healing-agents.ts`
- 📖 [Full Guide](examples/SELF_HEALING_AGENTS.md)

### 6. 👥 Multi-Party E2EE (Group Encryption)
**Concept**: Secure group communication where $N$ agents share a group session with AES-256-GCM.
- **Problem**: Signal Double Ratchet is 1-to-1. Groups usually require complex key management.
- **When to use**: Collaborative agent swarms or secure group chats.
- **Example**: `examples/multiparty-e2ee-agents.ts`

### 7. 🏷️ Semantic Types (Nominal Typing)
**Concept**: Using TypeScript "Branding" to ensure strings like `ServerUrl` or `HttpStatusCode` are validated at creation and never confused.
- **Problem**: Values like `200` (status) and `200` (count) are both numbers but have different semantics.
- **When to use**: To eliminate "stringly-typed" bugs and ensure inputs are always valid.
- **Example**: `examples/semantic-types-usage.ts`
```typescript
const url = ServerUrl.make("https://api.com"); // Validated
const status = HttpStatusCode.make(200);      // Validated
```

### 8. 🩹 Resilient Token Manager
**Concept**: A manager that handles parallel token failures using "Promise Latching" to avoid refreshing multiple times for the same expiration.
- **Problem**: When 10 parallel requests fail due to an expired token, they might trigger 10 refresh calls.
- **When to use**: High-concurrency agent environments.
- **Example**: `examples/resilient-dpop.ts`

---

## 🔒 Security Layers Checklist

| Layer | Protocol | Purpose |
| :--- | :--- | :--- |
| **Transport** | mTLS / TLS 1.3 | Anti-MITM, Mutual Auth |
| **Identity** | JWT (EdDSA) | Authentication, Claims, Expiration |
| **Content** | Signal E2EE / AES-GCM | Perfect Forward Secrecy, Privacy |
| **Binding** | DPoP (RFC 9449) | Anti-Replay, Token-to-Key binding |
| **Context** | Semantic Types | Memory safety, Domain validation |

---

## 📖 Documentation Index

- [CHANGELOG.md](CHANGELOG.md) - History of changes.
- [examples/SECURE_AGENTS.md](examples/SECURE_AGENTS.md) - ⭐ Deep Dive into Agent Security.
- [examples/SIGNAL_E2EE.md](examples/SIGNAL_E2EE.md) - How we implement Double Ratchet.
- [examples/SELF_HEALING_AGENTS.md](examples/SELF_HEALING_AGENTS.md) - How agents survive token expiry.

---

## 📜 License

This project is licensed under the **Cogfulness Ethical License (CEL)** - focusing on the ethical use of cognitive technologies.

---

**Developed with ❤️ by Deepmind Advanced Agentic Coding Team.**
**Promoting safety through radical simplicity.**
