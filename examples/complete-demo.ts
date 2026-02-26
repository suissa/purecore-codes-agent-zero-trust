/**
 * Demonstração Completa - @purecore-codes-codes/agent-zero-trust
 * 
 * Este exemplo demonstra todas as funcionalidades principais da biblioteca:
 * - Signal Protocol E2EE (Double Ratchet + X3DH)
 * - DPoP (RFC 9449) com Session Context Latching
 * - Token Manager com Promise Latching
 * - Circuit Breaker para resiliência
 * - Bloom Filter para CRL distribuída
 * - JWK Thumbprint (RFC 7638)
 */

import {
  SignalE2EEAgent,
  TokenAuthority,
  generateDPoPKeyPair,
  createDPoPProof,
  verifyDPoPProof,
  computeJWKThumbprint,
  publicKeyToJWK,
  TokenManager,
  CircuitBreaker,
  createBloomFilterForCRL,
  isRevoked,
  BloomFilter,
  VERSION,
  LIBRARY_NAME,
} from '../src/index';

import * as crypto from 'node:crypto';

// ============================================================================
// Configuração Inicial
// ============================================================================

console.log('═'.repeat(70));
console.log(`  ${LIBRARY_NAME} v${VERSION} - Demonstração Completa`);
console.log('═'.repeat(70));
console.log('');

// ============================================================================
// 1. Signal Protocol E2EE
// ============================================================================

async function demonstrateSignalE2EE() {
  console.log('📡 1. Signal Protocol E2EE (Double Ratchet + X3DH)');
  console.log('─'.repeat(70));

  const authority = new TokenAuthority();
  
  const alice = new SignalE2EEAgent('alice', authority, ['reasoning', 'analysis']);
  const bob = new SignalE2EEAgent('bob', authority, ['execution', 'validation']);

  await alice.initialize();
  await bob.initialize();
  console.log('');

  // Trocar bundles de chaves públicas
  console.log('📦 Trocando bundles de chaves públicas...');
  const aliceBundle = alice.getPublicKeyBundle();
  const bobBundle = bob.getPublicKeyBundle();

  alice.registerPeerBundle('bob', bobBundle);
  bob.registerPeerBundle('alice', aliceBundle);
  console.log('');

  // Estabelecer sessão E2EE
  console.log('🔐 Estabelecendo sessão E2EE...');
  await alice.establishSession('bob');
  await bob.acceptSession(
    'alice',
    alice.getIdentityPublicKey(),
    aliceBundle.signedPreKey
  );
  console.log('');

  // Trocar mensagens
  console.log('💬 Troca de mensagens E2EE:');
  console.log('─'.repeat(70));

  const messages = [
    'Olá Bob! Esta é uma mensagem E2EE com Signal Protocol.',
    'Perfeito Forward Secrecy ativado!',
    'Post-Compromise Security garantido pelo Double Ratchet.',
  ];

  for (const msg of messages) {
    const encrypted = await alice.sendMessage('bob', msg);
    await bob.receiveMessage(encrypted);
  }

  console.log('');
  console.log(`📊 Histórico de mensagens: ${alice.getMessageHistory().length} mensagens`);
  console.log(`🔑 Identity Thumbprint (Alice): ${alice.getIdentityThumbprint()}`);
  console.log('');

  // Limpeza
  alice.destroy();
  bob.destroy();

  console.log('✅ Signal Protocol E2EE demonstrado com sucesso!\n');
}

// ============================================================================
// 2. DPoP com Session Context Latching
// ============================================================================

async function demonstrateDPoP() {
  console.log('🔐 2. DPoP (RFC 9449) com Session Context Latching');
  console.log('─'.repeat(70));

  // Gerar chave DPoP
  const dpopKey = generateDPoPKeyPair('EdDSA');
  console.log(`✅ Chave DPoP gerada:`);
  console.log(`   - Key ID: ${dpopKey.keyId}`);
  console.log(`   - Algoritmo: ${dpopKey.algorithm}`);
  console.log(`   - JWK: ${JSON.stringify(dpopKey.publicKeyJWK, null, 2)}`);
  console.log('');

  // Simular identidade Signal
  const signalIdentityKey = crypto.getRandomValues(new Uint8Array(32));
  const signalJWK = publicKeyToJWK(signalIdentityKey, 'X25519');
  const signalThumbprint = computeJWKThumbprint(signalJWK);

  console.log(`🔗 Session Context Latching:`);
  console.log(`   - Signal Identity Thumbprint: ${signalThumbprint}`);
  console.log('');

  // Criar DPoP Proof com session binding
  const accessToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9...';
  
  const proof = await createDPoPProof(dpopKey, {
    method: 'POST',
    url: 'https://api.example.com/message',
    accessToken,
    signalIdentityKey, // Session Context Latching
  });

  console.log(`📝 DPoP Proof criado:`);
  console.log(`   - JWT: ${proof.jwt.substring(0, 50)}...`);
  console.log(`   - JTI: ${proof.payload.jti}`);
  console.log(`   - HTM: ${proof.payload.htm}`);
  console.log(`   - ATH: ${proof.payload.ath}`);
  console.log(`   - CNF.signal_identity_kid: ${proof.payload.cnf?.signal_identity_kid}`);
  console.log('');

  // Verificar proof
  const verification = await verifyDPoPProof(proof.jwt, {
    algorithms: ['EdDSA'],
    requireAth: true,
    requiredMethod: 'POST',
    requiredUrl: 'https://api.example.com/message',
  });

  console.log(`✅ Verificação: ${verification.valid ? 'VÁLIDO' : 'INVÁLIDO'}`);
  if (!verification.valid) {
    console.log(`   Erro: ${verification.error}`);
  }
  console.log('');

  console.log('✅ DPoP demonstrado com sucesso!\n');
}

// ============================================================================
// 3. Token Manager com Promise Latching
// ============================================================================

async function demonstrateTokenManager() {
  console.log('🎫 3. Token Manager com Promise Latching');
  console.log('─'.repeat(70));

  let refreshCount = 0;
  const tokenManager = new TokenManager({
    refreshThresholdSeconds: 300,
    maxRetries: 3,
    baseDelayMs: 100,
  });

  tokenManager.setRefreshFn(async () => {
    refreshCount++;
    console.log(`   🔄 Refresh #${refreshCount} executado`);
    
    // Simular chamada de API
    await new Promise(resolve => setTimeout(resolve, 50));
    
    return {
      token: `access_token_${refreshCount}`,
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    };
  });

  console.log('📤 Solicitando token múltiplas vezes concorrentemente...');
  
  // Múltiplas solicitações concorrentes
  const [token1, token2, token3] = await Promise.all([
    tokenManager.getToken(),
    tokenManager.getToken(),
    tokenManager.getToken(),
  ]);

  console.log(`   Token 1: ${token1}`);
  console.log(`   Token 2: ${token2}`);
  console.log(`   Token 3: ${token3}`);
  console.log(`   Total de refreshes: ${refreshCount}`);
  console.log('');

  console.log('✅ Promise Latching previne "token refresh storms"!\n');
}

// ============================================================================
// 4. Circuit Breaker para Resiliência
// ============================================================================

async function demonstrateCircuitBreaker() {
  console.log('⚡ 4. Circuit Breaker para Resiliência');
  console.log('─'.repeat(70));

  const breaker = new CircuitBreaker({
    threshold: 3,
    resetTimeout: 1000,
  });

  let callCount = 0;

  console.log('🔴 Simulando falhas consecutivas...');
  
  for (let i = 0; i < 5; i++) {
    try {
      await breaker.execute(async () => {
        callCount++;
        throw new Error('Service unavailable');
      });
    } catch (error) {
      const state = breaker.getState();
      console.log(`   Tentativa ${i + 1}: ${state} (${error instanceof Error ? error.message : 'Erro'})`);
    }
  }

  console.log('');
  console.log(`📊 Estado final: ${breaker.getState()}`);
  console.log(`   Total de chamadas: ${callCount}`);
  console.log('');

  // Aguardar reset timeout
  console.log('⏳ Aguardando reset timeout (1s)...');
  await new Promise(resolve => setTimeout(resolve, 1100));
  
  console.log(`   Estado após timeout: ${breaker.getState()}`);
  console.log('');

  console.log('✅ Circuit Breaker demonstrado com sucesso!\n');
}

// ============================================================================
// 5. Bloom Filter para CRL Distribuída
// ============================================================================

async function demonstrateBloomFilter() {
  console.log('🌸 5. Bloom Filter para CRL Distribuída');
  console.log('─'.repeat(70));

  const revokedDIDs = [
    'did:agent:compromised-1',
    'did:agent:compromised-2',
    'did:agent:revoked-admin',
  ];

  console.log('📋 DIDs revogados:');
  revokedDIDs.forEach(did => console.log(`   - ${did}`));
  console.log('');

  const bloomFilter = createBloomFilterForCRL(revokedDIDs, 0.01);

  console.log('📊 Bloom Filter criado:');
  console.log(`   - Tamanho: ${bloomFilter.filter.length} bytes`);
  console.log(`   - Funções hash: ${bloomFilter.hashFunctions}`);
  console.log(`   - Taxa de falso positivo: ${(bloomFilter.falsePositiveRate * 100).toFixed(1)}%`);
  console.log('');

  console.log('🔍 Verificando DIDs:');
  
  const testDIDs = [
    'did:agent:compromised-1',
    'did:agent:valid-agent',
    'did:agent:revoked-admin',
    'did:agent:new-agent',
  ];

  for (const did of testDIDs) {
    try {
      const isRevoked = await isRevoked(did, bloomFilter);
      console.log(`   ${did}: ${isRevoked ? '❌ REVOKED' : '✅ VALID'}`);
    } catch (error) {
      console.log(`   ${did}: ⚠️ ${error instanceof Error ? error.message : 'Erro'}`);
    }
  }

  console.log('');
  console.log('✅ Bloom Filter reduz latência de O(n) para O(1)!\n');
}

// ============================================================================
// 6. JWK Thumbprint (RFC 7638)
// ============================================================================

async function demonstrateJWKThumbprint() {
  console.log('🔑 6. JWK Thumbprint (RFC 7638)');
  console.log('─'.repeat(70));

  const publicKey1 = crypto.getRandomValues(new Uint8Array(32));
  const publicKey2 = crypto.getRandomValues(new Uint8Array(32));

  const jwk1 = publicKeyToJWK(publicKey1, 'X25519');
  const jwk2 = publicKeyToJWK(publicKey2, 'X25519');

  const thumbprint1 = computeJWKThumbprint(jwk1);
  const thumbprint2 = computeJWKThumbprint(jwk2);

  console.log('📝 Chave 1:');
  console.log(`   - JWK: ${JSON.stringify(jwk1, null, 2)}`);
  console.log(`   - Thumbprint: ${thumbprint1}`);
  console.log('');

  console.log('📝 Chave 2:');
  console.log(`   - JWK: ${JSON.stringify(jwk2, null, 2)}`);
  console.log(`   - Thumbprint: ${thumbprint2}`);
  console.log('');

  console.log('✅ Thumbprints únicos garantem identificação criptográfica!\n');
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  try {
    await demonstrateSignalE2EE();
    await demonstrateDPoP();
    await demonstrateTokenManager();
    await demonstrateCircuitBreaker();
    await demonstrateBloomFilter();
    await demonstrateJWKThumbprint();

    console.log('═'.repeat(70));
    console.log('  ✅ Todas as demonstrações concluídas com sucesso!');
    console.log('═'.repeat(70));
    console.log('');
    console.log('📚 Documentação: https://purecore-codes.dev/agent-zero-trust/docs');
    console.log('📦 NPM: https://www.npmjs.com/package/@purecore-codes-codes/agent-zero-trust');
    console.log('🐙 GitHub: https://github.com/purecore-codes/agent-zero-trust');
    console.log('');

  } catch (error) {
    console.error('❌ Erro na demonstração:', error);
    process.exit(1);
  }
}

// Executar
if (require.main === module) {
  main();
}

export { main };
