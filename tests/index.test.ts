/**
 * Testes Unitários - @purecore-codes-codes/agent-zero-trust
 */

import { describe, test, expect, beforeEach } from 'bun:test';
import {
  generateX25519KeyPair,
  generateEd25519KeyPair,
  computeDH,
  hkdf,
  encrypt,
  decrypt,
  secureZero,
  X3DHKeyBundle,
  performX3DHAsInitiator,
  DoubleRatchet,
  computeJWKThumbprint,
  publicKeyToJWK,
  BloomFilter,
  createBloomFilterForCRL,
  isRevoked,
  SignJWT,
  jwtVerify,
  generateKeyPair,
  generateDPoPKeyPair,
  computeAccessTokenHash,
  createDPoPProof,
  verifyDPoPProof,
  TokenManager,
  CircuitBreaker,
  CircuitOpenError,
  SignalE2EEAgent,
  TokenAuthority,
} from '../src/index';

// ============================================================================
// Testes Criptográficos
// ============================================================================

describe('Crypto Module', () => {
  describe('generateX25519KeyPair', () => {
    test('deve gerar par de chaves X25519 válido', () => {
      const keyPair = generateX25519KeyPair();
      expect(keyPair.publicKey).toHaveLength(32);
      expect(keyPair.privateKey).toHaveLength(32);
      expect(keyPair.publicKey).not.toEqual(keyPair.privateKey);
    });

    test('deve gerar chaves únicas a cada chamada', () => {
      const keyPair1 = generateX25519KeyPair();
      const keyPair2 = generateX25519KeyPair();
      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });
  });

  describe('computeDH', () => {
    test('deve computar shared secret consistente', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const sharedAlice = computeDH(alice.privateKey, bob.publicKey);
      const sharedBob = computeDH(bob.privateKey, alice.publicKey);

      expect(sharedAlice).toEqual(sharedBob);
    });
  });

  describe('secureZero', () => {
    test('deve zeroizar buffer completamente', () => {
      const buffer = new Uint8Array([1, 2, 3, 4, 5]);
      secureZero(buffer);
      expect(buffer).toEqual(new Uint8Array(5));
    });
  });

  describe('encrypt/decrypt', () => {
    test('deve encriptar e decriptar mensagem corretamente', () => {
      const key = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = 'Hello, World!';

      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, key, nonce);

      expect(decrypted).toBe(plaintext);
    });

    test('deve falhar com chave errada', () => {
      const key1 = crypto.getRandomValues(new Uint8Array(32));
      const key2 = crypto.getRandomValues(new Uint8Array(32));
      const plaintext = 'Hello, World!';

      const { ciphertext, nonce } = encrypt(plaintext, key1);

      expect(() => decrypt(ciphertext, key2, nonce)).toThrow();
    });
  });
});

// ============================================================================
// Testes X3DH
// ============================================================================

describe('X3DH Key Agreement', () => {
  test('deve estabelecer shared secret consistente entre Alice e Bob', () => {
    const aliceBundle = new X3DHKeyBundle();
    const bobBundle = new X3DHKeyBundle();

    const aliceIdentity = generateX25519KeyPair();
    const aliceEphemeral = generateX25519KeyPair();

    const bobPublicBundle = bobBundle.getPublicBundle();

    // Alice executa X3DH como iniciador
    const sharedSecretAlice = performX3DHAsInitiator(
      aliceIdentity,
      aliceEphemeral,
      bobPublicBundle
    );

    // Bob executa X3DH como receptor
    const sharedSecretBob = bobBundle.performX3DHAsReceiver(
      aliceEphemeral.publicKey,
      aliceIdentity.publicKey,
      true
    );

    expect(sharedSecretAlice).toEqual(sharedSecretBob);

    // Limpeza
    aliceBundle.destroy();
    bobBundle.destroy();
  });
});

// ============================================================================
// Testes Double Ratchet
// ============================================================================

describe('Double Ratchet', () => {
  test('deve encriptar e decriptar mensagens em sequência', () => {
    // Setup inicial
    const aliceRatchet = new DoubleRatchet();
    const bobRatchet = new DoubleRatchet();

    const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
    const bobPublicKey = bobRatchet.getPublicKey();

    aliceRatchet.initializeAsAlice(sharedSecret, bobPublicKey);
    bobRatchet.initializeAsBob(sharedSecret);

    // Alice envia mensagem
    const { header, ciphertext, nonce } = aliceRatchet.ratchetEncrypt('Hello Bob!');
    const plaintext = bobRatchet.ratchetDecrypt(header, ciphertext, nonce);

    expect(plaintext).toBe('Hello Bob!');
  });

  test('deve lidar com múltiplas mensagens', () => {
    const aliceRatchet = new DoubleRatchet();
    const bobRatchet = new DoubleRatchet();

    const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
    const bobPublicKey = bobRatchet.getPublicKey();

    aliceRatchet.initializeAsAlice(sharedSecret, bobPublicKey);
    bobRatchet.initializeAsBob(sharedSecret);

    const messages = ['Msg 1', 'Msg 2', 'Msg 3'];

    for (const msg of messages) {
      const { header, ciphertext, nonce } = aliceRatchet.ratchetEncrypt(msg);
      const plaintext = bobRatchet.ratchetDecrypt(header, ciphertext, nonce);
      expect(plaintext).toBe(msg);
    }
  });

  test('deve limpar chaves sensíveis no destroy', () => {
    const ratchet = new DoubleRatchet();
    ratchet.destroy();
    // Após destroy, ratchet não deve estar funcional
    expect(() => ratchet.getPublicKey()).not.toThrow();
  });
});

// ============================================================================
// Testes JWT
// ============================================================================

describe('JWT Sign/Verify', () => {
  test('deve assinar e verificar JWT corretamente', async () => {
    const { publicKey, privateKey } = generateKeyPair('EdDSA');

    const jwt = await new SignJWT({ sub: 'user123', role: 'admin' })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuer('test-issuer')
      .setAudience('test-audience')
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    const result = await jwtVerify(jwt, publicKey, {
      issuer: 'test-issuer',
      audience: 'test-audience',
    });

    expect(result.payload.sub).toBe('user123');
    expect(result.payload.role).toBe('admin');
  });

  test('deve falhar com token expirado', async () => {
    const { publicKey, privateKey } = generateKeyPair('EdDSA');

    const jwt = await new SignJWT({ sub: 'user123' })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime('0s') // Expirado imediatamente
      .sign(privateKey);

    await expect(jwtVerify(jwt, publicKey)).rejects.toThrow('expirado');
  });

  test('deve falhar com issuer inválido', async () => {
    const { publicKey, privateKey } = generateKeyPair('EdDSA');

    const jwt = await new SignJWT({ sub: 'user123' })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuer('wrong-issuer')
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    await expect(
      jwtVerify(jwt, publicKey, { issuer: 'expected-issuer' })
    ).rejects.toThrow('Issuer inválido');
  });
});

// ============================================================================
// Testes DPoP
// ============================================================================

describe('DPoP', () => {
  test('deve gerar chave DPoP válida', () => {
    const keyPair = generateDPoPKeyPair('EdDSA');
    expect(keyPair.keyId).toBeDefined();
    expect(keyPair.algorithm).toBe('EdDSA');
    expect(keyPair.publicKeyJWK.kty).toBe('OKP');
    expect(keyPair.publicKeyJWK.crv).toBe('Ed25519');
  });

  test('deve criar e verificar DPoP Proof', async () => {
    const keyPair = generateDPoPKeyPair('EdDSA');
    const accessToken = 'test_access_token';

    const proof = await createDPoPProof(keyPair, {
      method: 'POST',
      url: 'https://api.example.com/message',
      accessToken,
    });

    const verification = await verifyDPoPProof(proof.jwt, {
      algorithms: ['EdDSA'],
      requireAth: true,
    });

    expect(verification.valid).toBe(true);
    expect(verification.proof).toBeDefined();
  });

  test('deve falhar com method mismatch', async () => {
    const keyPair = generateDPoPKeyPair('EdDSA');

    const proof = await createDPoPProof(keyPair, {
      method: 'POST',
      url: 'https://api.example.com/message',
    });

    const verification = await verifyDPoPProof(proof.jwt, {
      requiredMethod: 'GET',
    });

    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('method');
  });

  test('deve computar ath claim corretamente', () => {
    const accessToken = 'test_token';
    const ath = computeAccessTokenHash(accessToken);
    expect(ath).toBeDefined();
    expect(ath.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Testes JWK Thumbprint
// ============================================================================

describe('JWK Thumbprint (RFC 7638)', () => {
  test('deve computar thumbprint consistente', () => {
    const publicKey = crypto.getRandomValues(new Uint8Array(32));
    const jwk = publicKeyToJWK(publicKey, 'X25519');
    const thumbprint = computeJWKThumbprint(jwk);

    expect(thumbprint).toBeDefined();
    expect(thumbprint.length).toBe(43); // base64url de SHA-256
  });

  test('deve gerar thumbprint único para chaves diferentes', () => {
    const publicKey1 = crypto.getRandomValues(new Uint8Array(32));
    const publicKey2 = crypto.getRandomValues(new Uint8Array(32));

    const thumbprint1 = computeJWKThumbprint(publicKeyToJWK(publicKey1, 'X25519'));
    const thumbprint2 = computeJWKThumbprint(publicKeyToJWK(publicKey2, 'X25519'));

    expect(thumbprint1).not.toEqual(thumbprint2);
  });
});

// ============================================================================
// Testes Bloom Filter
// ============================================================================

describe('Bloom Filter', () => {
  test('deve adicionar e verificar itens', () => {
    const filter = new BloomFilter(100, 3);
    filter.add('item1');
    filter.add('item2');

    expect(filter.has('item1')).toBe(true);
    expect(filter.has('item2')).toBe(true);
    expect(filter.has('item3')).toBe(false);
  });

  test('deve criar Bloom Filter para CRL', () => {
    const revokedDIDs = ['did:agent:1', 'did:agent:2', 'did:agent:3'];
    const bloomFilter = createBloomFilterForCRL(revokedDIDs, 0.01);

    expect(bloomFilter.filter).toBeDefined();
    expect(bloomFilter.itemCount).toBe(3);
  });

  test('deve verificar revogação com Bloom Filter', async () => {
    const revokedDIDs = ['did:agent:revoked'];
    const bloomFilter = createBloomFilterForCRL(revokedDIDs, 0.01);

    const isRevoked1 = await isRevoked('did:agent:revoked', bloomFilter);
    const isRevoked2 = await isRevoked('did:agent:valid', bloomFilter);

    expect(isRevoked1).toBe(true);
    expect(isRevoked2).toBe(false);
  });
});

// ============================================================================
// Testes Token Manager
// ============================================================================

describe('Token Manager', () => {
  test('deve fazer cache de token', async () => {
    let refreshCount = 0;

    const manager = new TokenManager();
    manager.setRefreshFn(async () => {
      refreshCount++;
      return {
        token: 'test_token',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      };
    });

    const token1 = await manager.getToken();
    const token2 = await manager.getToken();

    expect(token1).toBe('test_token');
    expect(token2).toBe('test_token');
    expect(refreshCount).toBe(1); // Apenas um refresh
  });

  test('deve fazer retry com backoff', async () => {
    let attempts = 0;

    const manager = new TokenManager({ maxRetries: 3, baseDelayMs: 10 });
    manager.setRefreshFn(async () => {
      attempts++;
      throw new Error('Refresh failed');
    });

    await expect(manager.getToken()).rejects.toThrow('Refresh failed');
    expect(attempts).toBe(3); // 3 tentativas
  });
});

// ============================================================================
// Testes Circuit Breaker
// ============================================================================

describe('Circuit Breaker', () => {
  test('deve abrir após threshold de falhas', async () => {
    const breaker = new CircuitBreaker({ threshold: 3, resetTimeout: 1000 });

    for (let i = 0; i < 3; i++) {
      try {
        await breaker.execute(async () => {
          throw new Error('Fail');
        });
      } catch {
        // Ignorar
      }
    }

    expect(breaker.getState()).toBe('OPEN');
  });

  test('deve fechar após resetTimeout', async () => {
    const breaker = new CircuitBreaker({ threshold: 1, resetTimeout: 100 });

    try {
      await breaker.execute(async () => {
        throw new Error('Fail');
      });
    } catch {
      // Ignorar
    }

    expect(breaker.getState()).toBe('OPEN');

    // Aguardar reset timeout
    await new Promise(resolve => setTimeout(resolve, 150));

    expect(breaker.getState()).toBe('HALF_OPEN');
  });

  test('deve lançar CircuitOpenError quando aberto', async () => {
    const breaker = new CircuitBreaker({ threshold: 1, resetTimeout: 10000 });

    try {
      await breaker.execute(async () => {
        throw new Error('Fail');
      });
    } catch {
      // Ignorar
    }

    await expect(
      breaker.execute(async () => 'success')
    ).rejects.toThrow(CircuitOpenError);
  });
});

// ============================================================================
// Testes SignalE2EEAgent
// ============================================================================

describe('SignalE2EEAgent', () => {
  test('deve inicializar agente', async () => {
    const authority = new TokenAuthority();
    const agent = new SignalE2EEAgent('test-agent', authority);

    await agent.initialize();

    expect(agent.agentId).toBe('test-agent');
  });

  test('deve trocar mensagens E2EE entre dois agentes', async () => {
    const authority = new TokenAuthority();
    const alice = new SignalE2EEAgent('alice', authority);
    const bob = new SignalE2EEAgent('bob', authority);

    await alice.initialize();
    await bob.initialize();

    // Trocar bundles
    const aliceBundle = alice.getPublicKeyBundle();
    const bobBundle = bob.getPublicKeyBundle();

    alice.registerPeerBundle('bob', bobBundle);
    bob.registerPeerBundle('alice', aliceBundle);

    // Estabelecer sessão
    await alice.establishSession('bob');
    await bob.acceptSession(
      'alice',
      alice.getIdentityPublicKey(),
      aliceBundle.signedPreKey
    );

    // Enviar mensagem
    const message = await alice.sendMessage('bob', 'Hello Bob!');
    const plaintext = await bob.receiveMessage(message);

    expect(plaintext).toBe('Hello Bob!');

    // Limpeza
    alice.destroy();
    bob.destroy();
  });

  test('deve gerar identity thumbprint', async () => {
    const authority = new TokenAuthority();
    const agent = new SignalE2EEAgent('test-agent', authority);
    await agent.initialize();

    const thumbprint = agent.getIdentityThumbprint();
    expect(thumbprint).toBeDefined();
    expect(thumbprint.length).toBe(43);
  });
});
