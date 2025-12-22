# 🔐 Purecore JWTfy

<img src="https://i.imgur.com/39I2vIJ.png" align="center" />

> **A Biblioteca one-jwt-4-all com Zero Dependências**

Uma biblioteca moderna e opinativa para criação e validação de JSON Web Tokens (JWT) usando exclusivamente algoritmos state-of-the-art. API compatível com `jose`, mas com uma filosofia radicalmente diferente: **Opinião Forte**.

## 🎯 Filosofia "One JWT 4 ALL"

Enquanto outras bibliotecas suportam centenas de combinações de algoritmos (muitos deles inseguros ou obsoletos), nós suportamos **apenas uma combinação para cada caso de uso**. Essa combinação é escolhida com base no que há de mais seguro e performático na versão LTS mais recente do Node.js.

### Por que EdDSA (Ed25519)?

- ⚡ **Mais rápido** que ECDSA e RSA
- 🔑 **Chaves menores** que RSA (256 bits vs 2048+ bits)
- 🛡️ **Imune a ataques** de timing e side-channels comuns
- 📦 **Suporte nativo** no Node.js 18+ (sem dependências externas)
- ✅ **Padrão moderno** recomendado por criptógrafos

> **"A complexidade é a inimiga da segurança."**

## 📊 Comparativo: jose vs Purecore JWTfy

| Funcionalidade | Biblioteca jose (Genérica) | Purecore JWTfy (Opinativa) |
|----------------|---------------------------|---------------------------|
| **Filosofia** | Suportar tudo (Legado & Novo) | Suportar apenas o Melhor (State-of-the-Art) |
| **JWS Signing Algs** | HS256, RS256, ES256, PS256, EdDSA... | **EdDSA (Ed25519) Apenas** |
| **JWE Encryption** | RSA-OAEP, A128CBC-HS256, A256GCM... | **X25519 + A256GCM** (Roadmap) |
| **JWS Serialization** | Compact, Flattened, General | Compact (Core) |
| **Key Management** | JWK, JWKS (Local/Remote), PEM, X.509 | PEM & JWK (Simples) |
| **Runtime** | Universal (Browser, Node, Deno, Workers) | **Node.js Nativo** (Foco em Performance) |
| **Dependências** | Múltiplas | **Zero (0)** |

## 🚀 Instalação

```bash
# Com npm
npm install @purecore/one-jwt-4-all

# Com bun
bun add @purecore/one-jwt-4-all

# Com yarn
yarn add @purecore/one-jwt-4-all
```

## 📖 Uso Básico

### 1. Gerar Par de Chaves

```typescript
import { generateKeyPair } from '@purecore/one-jwt-4-all';

const { publicKey, privateKey } = generateKeyPair();

// Salve as chaves de forma segura
console.log('Chave Privada:', privateKey);
console.log('Chave Pública:', publicKey);
```

### 2. Criar um Token JWT

```typescript
import { SignJWT } from '@purecore/one-jwt-4-all';

// Criar token com builder pattern (estilo jose)
const jwt = await new SignJWT({
  userId: 123,
  email: 'usuario@exemplo.com',
  role: 'admin'
})
  .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
  .setIssuedAt()
  .setIssuer('urn:meu-sistema:issuer')
  .setAudience('urn:meu-sistema:audience')
  .setExpirationTime('2h') // Expira em 2 horas
  .setSubject('usuario-123')
  .setJti('token-unique-id')
  .sign(privateKey);

console.log('Token gerado:', jwt);
```

### 3. Verificar um Token JWT

```typescript
import { jwtVerify } from '@purecore/one-jwt-4-all';

try {
  const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
    issuer: 'urn:meu-sistema:issuer',
    audience: 'urn:meu-sistema:audience',
    maxTokenAge: '2h' // Opcional: idade máxima do token
  });

  console.log('Token válido!');
  console.log('Payload:', payload);
  console.log('Header:', protectedHeader);
} catch (error) {
  console.error('Token inválido:', error.message);
}
```

## 🔧 API Completa

### SignJWT (Builder Pattern)

#### Métodos Disponíveis

```typescript
new SignJWT(payload: JWTPayload)
  .setProtectedHeader(header: JWTHeaderParameters)  // Define o header protegido
  .setIssuer(issuer: string)                        // Define o emissor (iss)
  .setSubject(subject: string)                      // Define o assunto (sub)
  .setAudience(audience: string | string[])        // Define a audiência (aud)
  .setJti(jwtId: string)                           // Define o ID único do token (jti)
  .setIssuedAt(timestamp?: number)                 // Define quando foi emitido (iat)
  .setExpirationTime(time: number | string)        // Define expiração (exp)
  .setNotBefore(time: number | string)              // Define quando fica válido (nbf)
  .sign(privateKey: KeyObject | string)             // Assina e retorna o token
```

#### Formatos de Tempo Suportados

```typescript
// Strings de duração relativa
.setExpirationTime('30s')  // 30 segundos
.setExpirationTime('5m')   // 5 minutos
.setExpirationTime('2h')   // 2 horas
.setExpirationTime('1d')   // 1 dia
.setExpirationTime('1w')   // 1 semana
.setExpirationTime('1y')   // 1 ano

// Timestamp absoluto (Unix timestamp em segundos)
.setExpirationTime(1735689600)
```

### jwtVerify (Função)

```typescript
jwtVerify(
  jwt: string,
  publicKey: KeyObject | string,
  options?: JWTVerifyOptions
): Promise<JWTVerifyResult>
```

#### Opções de Verificação

```typescript
interface JWTVerifyOptions {
  issuer?: string | string[];        // Valida o emissor (iss)
  audience?: string | string[];      // Valida a audiência (aud)
  algorithms?: string[];             // Lista de algoritmos permitidos (ignorado, sempre EdDSA)
  currentDate?: Date;                // Data atual para testes (mock)
  maxTokenAge?: string | number;     // Idade máxima do token ('2h' ou segundos)
}
```

## 📝 Exemplos Práticos

### Exemplo 1: Autenticação de Usuário

```typescript
import { SignJWT, jwtVerify, generateKeyPair } from '@purecore/one-jwt-4-all';

// Gere as chaves uma vez e guarde em variáveis de ambiente
const { publicKey, privateKey } = generateKeyPair();

// Login: Criar token após autenticação bem-sucedida
async function login(userId: string, email: string) {
  const token = await new SignJWT({
    userId,
    email,
    loginTime: Date.now()
  })
    .setIssuedAt()
    .setIssuer('https://meuapp.com')
    .setAudience('https://meuapp.com/api')
    .setSubject(userId)
    .setExpirationTime('24h')
    .sign(privateKey);

  return token;
}

// Middleware: Verificar token em requisições
async function verifyToken(token: string) {
  try {
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: 'https://meuapp.com',
      audience: 'https://meuapp.com/api',
      maxTokenAge: '24h'
    });
    
    return payload;
  } catch (error) {
    throw new Error(`Token inválido: ${error.message}`);
  }
}
```

### Exemplo 2: Refresh Tokens

```typescript
// Access Token (curta duração)
const accessToken = await new SignJWT({ userId: 123 })
  .setIssuedAt()
  .setExpirationTime('15m') // 15 minutos
  .setIssuer('https://meuapp.com')
  .setAudience('https://meuapp.com/api')
  .sign(privateKey);

// Refresh Token (longa duração)
const refreshToken = await new SignJWT({ userId: 123 })
  .setIssuedAt()
  .setExpirationTime('7d') // 7 dias
  .setIssuer('https://meuapp.com')
  .setAudience('https://meuapp.com/auth/refresh')
  .sign(privateKey);
```

### Exemplo 3: Tokens com Not Before

```typescript
// Token que só fica válido após 5 minutos
const token = await new SignJWT({ userId: 123 })
  .setIssuedAt()
  .setNotBefore('5m') // Válido apenas após 5 minutos
  .setExpirationTime('1h')
  .sign(privateKey);
```

### Exemplo 4: Integração com Express.js

```typescript
import express from 'express';
import { jwtVerify } from '@purecore/one-jwt-4-all';
import { readFileSync } from 'fs';

const app = express();
const publicKey = readFileSync('./public-key.pem', 'utf-8');

// Middleware de autenticação
async function authenticate(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  const token = authHeader.substring(7);

  try {
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: 'https://meuapp.com',
      audience: 'https://meuapp.com/api'
    });
    
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: `Token inválido: ${error.message}` });
  }
}

// Rota protegida
app.get('/api/protected', authenticate, (req, res) => {
  res.json({ 
    message: 'Acesso autorizado',
    user: req.user 
  });
});
```

## 🔒 Segurança

### Boas Práticas

1. **Nunca exponha a chave privada**
   - Guarde em variáveis de ambiente
   - Use serviços de gerenciamento de segredos em produção

2. **Use expiração curta para access tokens**
   - Recomendado: 15 minutos a 1 hora
   - Use refresh tokens para renovação

3. **Valide sempre issuer e audience**
   - Previne uso de tokens em contextos errados
   - Protege contra token reuse attacks

4. **Use HTTPS em produção**
   - Tokens não devem trafegar em conexões não criptografadas

5. **Rotacione chaves periodicamente**
   - Gere novos pares de chaves regularmente
   - Mantenha versões antigas para validação durante transição

### Gerenciamento de Chaves

```typescript
// Gerar par de chaves
const { publicKey, privateKey } = generateKeyPair();

// Salvar em arquivos (nunca commite no git!)
import { writeFileSync } from 'fs';
writeFileSync('./private-key.pem', privateKey, { mode: 0o600 }); // Permissões restritas
writeFileSync('./public-key.pem', publicKey);

// Carregar de arquivos
import { readFileSync } from 'fs';
const privateKey = readFileSync('./private-key.pem', 'utf-8');
const publicKey = readFileSync('./public-key.pem', 'utf-8');
```

## 🧪 Testes

```typescript
import { SignJWT, jwtVerify, generateKeyPair } from '@purecore/one-jwt-4-all';

describe('JWT', () => {
  const { publicKey, privateKey } = generateKeyPair();

  it('deve criar e verificar token válido', async () => {
    const jwt = await new SignJWT({ userId: 123 })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    const { payload } = await jwtVerify(jwt, publicKey);
    
    expect(payload.userId).toBe(123);
  });

  it('deve rejeitar token expirado', async () => {
    const jwt = await new SignJWT({ userId: 123 })
      .setIssuedAt()
      .setExpirationTime('-1h') // Expirado
      .sign(privateKey);

    await expect(jwtVerify(jwt, publicKey)).rejects.toThrow('expirado');
  });
});
```

## 📚 Tipos TypeScript

A biblioteca exporta todos os tipos necessários:

```typescript
import type {
  JWTPayload,
  JWTHeaderParameters,
  JWTVerifyResult,
  JWTVerifyOptions
} from '@purecore/one-jwt-4-all';
```

## 🔄 Exemplos Avançados

### 1. Self-Healing Agentic Conversational System

Sistema onde dois agentes se identificam usando JWTs do mesmo servidor e regeneram automaticamente seus tokens quando expiram, mantendo a conversa contínua sem interrupção.

**Características:**
- ✅ **Auto-Renovação**: Tokens renovados automaticamente antes de expirar
- ✅ **Contexto Preservado**: Conversa continua mesmo após renovação
- ✅ **Verificação Mútua**: Agentes verificam identidade uns dos outros
- ✅ **Self-Healing**: Sistema se recupera automaticamente de falhas

**Exemplo Rápido:**
```typescript
import { TokenAuthority, SelfHealingAgent } from './examples/self-healing-agents';

const authority = new TokenAuthority();
const agentA = new SelfHealingAgent('agent-alpha', 'primary', authority);
const agentB = new SelfHealingAgent('agent-beta', 'secondary', authority);

await agentA.initialize();
await agentB.initialize();
agentA.startAutoRenewal(30000);
agentB.startAutoRenewal(30000);

await agentA.sendMessage(agentB, 'Olá! Vamos trabalhar juntos?');
await agentB.sendMessage(agentA, 'Perfeito! Estou pronto.');
```

📖 **Documentação**: [examples/SELF_HEALING_AGENTS.md](examples/SELF_HEALING_AGENTS.md)

### 2. Self-Healing Agents com mTLS (Mutual TLS)

Extensão do sistema anterior que adiciona **mTLS** para segurança em duas camadas: transporte (certificados) + aplicação (JWT).

**Características:**
- 🔒 **mTLS**: Autenticação mútua via certificados X.509
- 🔐 **JWT**: Autenticação de identidade e contexto
- 🛡️ **Prevenção MITM**: Certificados validam identidade do transporte
- 🔄 **Self-Healing**: Auto-renovação de tokens mantendo conexão mTLS

**Exemplo Rápido:**
```typescript
import { mTLSAgent, CertificateAuthority, TokenAuthority } from './examples/mtls-agents';

const ca = new CertificateAuthority();
const tokenAuthority = new TokenAuthority();

const certA = ca.generateAgentCertificate('agent-alpha');
const certB = ca.generateAgentCertificate('agent-beta');
const caCert = ca.getCACertificate();

const agentA = new mTLSAgent('agent-alpha', 'primary', tokenAuthority, certA, caCert);
const agentB = new mTLSAgent('agent-beta', 'secondary', tokenAuthority, certB, caCert);

await agentA.initialize();
await agentB.initialize();

await agentA.startTLSServer(8443);
await agentB.startTLSServer(8444);

await agentA.connectToPeer('localhost', 8444, 'agent-beta');
await agentB.connectToPeer('localhost', 8443, 'agent-alpha');

// Comunicação segura via mTLS + JWT
await agentA.sendMessage('agent-beta', 'Mensagem segura!');
```

📖 **Documentação**: [examples/MTLS_AGENTS.md](examples/MTLS_AGENTS.md)

## 🛠️ Requisitos

- **Node.js**: >= 18.0.0 (suporte nativo a Ed25519)
- **TypeScript**: >= 4.0.0 (recomendado)

## 📄 Licença

Este projeto é licenciado sob a **Cogfulness Ethical License (CEL)** - uma licença open source focada em uso ético e responsável de tecnologia cognitiva.

## 🤝 Contribuindo

Contribuições são bem-vindas! Este projeto segue uma filosofia de **zero dependencies** e simplicidade arquitetural.

## 🔗 Links Úteis

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 8037 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8037)
- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [JWT.io - Debugger de Tokens](https://jwt.io/)

## 📝 Changelog

Veja todas as mudanças em [CHANGELOG.md](CHANGELOG.md)

---

**Desenvolvido com ❤️ para promover segurança através de simplicidade e opiniões fortes.**
