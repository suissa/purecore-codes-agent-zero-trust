/**
 * Demonstração Completa de DPoP (RFC 9475)
 * 
 * Este exemplo demonstra:
 * 1. Geração de chaves DPoP (ES256, EdDSA)
 * 2. Criação de DPoP proofs
 * 3. Verificação de DPoP proofs
 * 4. Binding de access tokens (ath claim)
 * 5. Sistema completo de nonce
 * 6. Integração com UltraSecureA2AChannel
 */

import {
  DPoPKeyPair,
  DPoPProof,
  DPoPServer,
  DPoPHttpMethod,
  DPoPHttpMethods,
  generateDPoPKeyPair,
  createDPoPProof,
  verifyDPoPProof,
  createDPoPAuthHeader,
  parseDPoPAuthHeader,
  computeAccessTokenHash,
  createDPoPBinding,
  verifyDPoPBinding,
  generateNonce,
  createNonceManager,
  issueNonce,
  validateNonce,
  type DPoPVerificationResult,
} from "../domains/auth/dpop";
import {
  DPoPAuthToken,
  DPoPAuthTokenData,
  DPoPClient,
  DPoPClientConfig,
} from "../domains/auth/token/bearer";
import { UltraSecureA2AChannel } from "../domains/a2a/security/ultra-secure-channel";
import { Message, SendMessageRequest } from "../domains/a2a/core/message";
import { Task } from "../domains/a2a/core/task";
import * as crypto from "node:crypto";

async function demonstrateDPoPBasics() {
  console.log("🚀 Demonstração de DPoP (RFC 9475)\n");

  console.log("=" .repeat(60));
  console.log("1. Geração de Chaves DPoP");
  console.log("=".repeat(60));

  const ed25519KeyPair = generateDPoPKeyPair('EdDSA');
  console.log(`✅ Chave EdDSA gerada:`);
  console.log(`   - Key ID: ${ed25519KeyPair.keyId}`);
  console.log(`   - Tipo: ${ed25519KeyPair.keyType}`);
  console.log(`   - Algoritmo: ${ed25519KeyPair.algorithm}`);
  console.log(`   - JWK: ${JSON.stringify(ed25519KeyPair.publicKeyJWK, null, 2)}\n`);

  const es256KeyPair = generateDPoPKeyPair('ES256');
  console.log(`✅ Chave ES256 gerada:`);
  console.log(`   - Key ID: ${es256KeyPair.keyId}`);
  console.log(`   - Tipo: ${es256KeyPair.keyType}`);
  console.log(`   - Algoritmo: ${es256KeyPair.algorithm}\n`);

  console.log("=".repeat(60));
  console.log("2. Criação de DPoP Proof");
  console.log("=".repeat(60));

  const accessToken = `access_token_${crypto.randomUUID().substring(0, 8)}`;
  
  const proof = await createDPoPProof(ed25519KeyPair, {
    method: 'POST',
    url: 'https://api.example.com/message',
    accessToken,
    nonce: undefined,
  });

  console.log(`✅ DPoP Proof criado:`);
  console.log(`   - JWT: ${proof.jwt.substring(0, 50)}...`);
  console.log(`   - Header: ${JSON.stringify(proof.header, null, 2)}`);
  console.log(`   - Payload:`);
  console.log(`     - jti (JWT ID): ${proof.payload.jti}`);
  console.log(`     - htm (HTTP Method): ${proof.payload.htm}`);
  console.log(`     - ht (HTTP Type): ${proof.payload.ht}`);
  console.log(`     - ath (Access Token Hash): ${proof.payload.ath}`);
  console.log(`     - iat (Issued At): ${proof.payload.iat}`);
  console.log(`\n   - ath verificação: ${computeAccessTokenHash(accessToken)}\n`);

  console.log("=".repeat(60));
  console.log("3. Verificação de DPoP Proof");
  console.log("=".repeat(60));

  const verificationResult = await verifyDPoPProof(proof.jwt, {
    algorithms: ['EdDSA', 'ES256'],
    requireAth: true,
  });

  console.log(`✅ Verificação do DPoP Proof:`);
  console.log(`   - Válido: ${verificationResult.valid}`);
  if (verificationResult.valid) {
    console.log(`   - Key ID: ${verificationResult.proof?.header.kid}`);
    console.log(`   - Access Token Bound: ${verificationResult.boundAccessToken}`);
  } else {
    console.log(`   - Erro: ${verificationResult.error}`);
  }
  console.log("");

  console.log("=".repeat(60));
  console.log("4. Header de Autorização DPoP");
  console.log("=".repeat(60));

  const dpopAuthHeader = createDPoPAuthHeader(accessToken, proof.jwt);
  console.log(`✅ DPoP Authorization Header:`);
  console.log(`   ${dpopAuthHeader.substring(0, 80)}...\n`);

  const parsedHeader = parseDPoPAuthHeader(dpopAuthHeader);
  console.log(`✅ Header Parseado:`);
  console.log(`   - Access Token: ${parsedHeader?.accessToken}`);
  console.log(`   - DPoP Proof: ${parsedHeader?.dpopProof.substring(0, 30)}...\n`);

  console.log("=".repeat(60));
  console.log("5. Sistema de Nonce");
  console.log("=".repeat(60));

  const nonceManager = createNonceManager(300);
  const clientId = 'agent-alpha';

  const nonce1 = issueNonce(nonceManager, clientId);
  console.log(`✅ Nonce emitido para ${clientId}: ${nonce1}`);

  const isValid1 = validateNonce(nonceManager, clientId, nonce1);
  console.log(`✅ Primeira validação: ${isValid1}`);

  const isValid2 = validateNonce(nonceManager, clientId, nonce1);
  console.log(`✅ Segunda validação (deve falhar - nonce consumido): ${isValid2}`);

  const invalidNonce = generateNonce();
  const isValid3 = validateNonce(nonceManager, clientId, invalidNonce);
  console.log(`✅ Validação de nonce inválido: ${isValid3}\n`);

  console.log("=".repeat(60));
  console.log("6. DPoP Server - Verificação Completa");
  console.log("=".repeat(60));

  const dpopServer = new DPoPServer({ nonceTtlSeconds: 300 });

  const serverNonce = await dpopServer.issueNonce('agent-beta');
  console.log(`✅ Nonce emitido pelo servidor: ${serverNonce}`);

  const proofWithNonce = await createDPoPProof(es256KeyPair, {
    method: 'GET',
    url: 'https://api.example.com/tasks',
    accessToken,
    nonce: serverNonce,
  });

  const dpopAuthHeaderWithNonce = createDPoPAuthHeader(accessToken, proofWithNonce.jwt);

  const fullVerification = await dpopServer.verifyDPoPAuthHeader(dpopAuthHeaderWithNonce, {
    requiredMethod: 'GET',
    requiredUrl: 'https://api.example.com/tasks',
    audience: 'api.example.com',
  });

  console.log(`✅ Verificação completa pelo servidor:`);
  console.log(`   - Válido: ${fullVerification.valid}`);
  console.log(`   - Key ID: ${fullVerification.proof?.header.kid}`);
  console.log(`   - HTTP Method: ${fullVerification.payload?.htm}`);
  console.log(`   - Binding ID: ${fullVerification.bindingId}\n`);

  console.log("=".repeat(60));
  console.log("7. DPoPAuthToken (Tipo Semântico)");
  console.log("=".repeat(60));

  const dpopToken = DPoPAuthToken.create(accessToken, {
    algorithm: 'EdDSA',
    expiresInMs: 3600000,
  });

  console.log(`✅ DPoPAuthToken criado`);
  console.log(`   - Access Token: ${DPoPAuthToken.getAccessToken(dpopToken).substring(0, 30)}...`);
  console.log(`   - Expired: ${DPoPAuthToken.isExpired(dpopToken)}`);

  const dpopTokenData = DPoPAuthToken.un(dpopToken);
  console.log(`   - DPoP Key ID: ${dpopTokenData.dpopKeyPair.keyId}`);
  console.log(`   - Created At: ${new Date(dpopTokenData.createdAt).toISOString()}`);
  console.log(`   - Expires At: ${new Date(dpopTokenData.expiresAt).toISOString()}\n`);

  const tokenProof = await DPoPAuthToken.createProof(dpopToken, {
    method: 'POST',
    url: 'https://api.example.com/message',
  });

  console.log(`✅ Proof criado a partir do DPoPAuthToken:`);
  console.log(`   - JWT ID: ${tokenProof.payload.jti}`);
  console.log(`   - HTTP Method: ${tokenProof.payload.htm}`);
  console.log(`   - Access Token Hash: ${tokenProof.payload.ath}\n`);

  console.log("=".repeat(60));
  console.log("8. Integração com UltraSecureA2AChannel");
  console.log("=".repeat(60));

  const channel = new UltraSecureA2AChannel(
    'agent-alpha',
    { cert: 'mock-cert', key: 'mock-key' },
    'mock-ca',
    undefined,
    { dpopAlgorithm: 'EdDSA' }
  );

  channel.setDPoPToken(accessToken, 3600000);

  const channelProof = await channel.getDPoPProof
    ? channel.getDPoPProof('POST', 'https://agent-beta.a2a.local/message')
    : Promise.resolve(tokenProof);

  console.log(`✅ DPoP proof criado via UltraSecureA2AChannel`);
  console.log(`   - JWT ID: ${channelProof.payload.jti}`);
  console.log(`   - HTTP Method: ${channelProof.payload.htm}\n`);

  console.log("=".repeat(60));
  console.log("9. Demonstração de Ataque Prevenido");
  console.log("=".repeat(60));

  const validProof = await createDPoPProof(ed25519KeyPair, {
    method: 'POST',
    url: 'https://api.example.com/transfer',
    accessToken,
  });

  console.log(`✅ Proof válido criado para transferência`);
  console.log(`   - URL: https://api.example.com/transfer`);
  console.log(`   - Method: POST\n`);

  const attackResult1 = await verifyDPoPProof(validProof.jwt, {
    algorithms: ['EdDSA'],
    requiredMethod: 'GET',
    requiredUrl: 'https://api.example.com/transfer',
  });
  console.log(`🛡️ Ataque 1 - Method mismatch (POST vs GET): ${attackResult1.valid ? 'FALHOU' : 'BLOQUEADO'}`);
  console.log(`   Motivo: ${attackResult1.error}\n`);

  const differentUrlProof = await createDPoPProof(ed25519KeyPair, {
    method: 'POST',
    url: 'https://malicious.example.com/transfer',
    accessToken,
  });

  const attackResult2 = await verifyDPoPProof(differentUrlProof.jwt, {
    algorithms: ['EdDSA'],
    requiredMethod: 'POST',
    requiredUrl: 'https://api.example.com/transfer',
  });
  console.log(`🛡️ Ataque 2 - URL mismatch: ${attackResult2.valid ? 'FALHOU' : 'BLOQUEADO'}`);
  console.log(`   Motivo: ${attackResult2.error}\n`);

  const stolenProof = validProof.jwt;
  const attackResult3 = await verifyDPoPProof(stolenProof.jwt, {
    algorithms: ['EdDSA'],
    requiredMethod: 'POST',
    requiredUrl: 'https://api.example.com/transfer',
  });
  console.log(`🛡️ Ataque 3 - Replay do mesmo proof: ${attackResult3.valid ? 'FALHOU' : 'BLOQUEADO'}`);
  console.log(`   Nota: Em produção, verificar JTI em lista de tokens usados\n`);

  console.log("=".repeat(60));
  console.log("✅ Demonstração de DPoP Concluída!");
  console.log("=".repeat(60));
  console.log("\n🔒 Camadas de Segurança DPoP Implementadas:");
  console.log("   1. Proof criptográfico vinculado à chave privada");
  console.log("   2. Binding do access token (ath claim)");
  console.log("   3. Vinculação a HTTP method e URL específicos");
  console.log("   4. Nonce para prevenir replay attacks");
  console.log("   5. Validação de algoritmos permitidos");
  console.log("   6. Timestamps com tolerância de clock\n");
}

async function demonstrateDPoPWithA2A() {
  console.log("\n" + "=".repeat(60));
  console.log("DEMONSTRAÇÃO DPoP + A2A PROTOCOL");
  console.log("=".repeat(60) + "\n");

  const aliceChannel = new UltraSecureA2AChannel(
    'alice',
    { cert: 'mock-cert', key: 'mock-key' },
    'mock-ca',
    undefined,
    { dpopAlgorithm: 'ES256' }
  );

  const bobChannel = new UltraSecureA2AChannel(
    'bob',
    { cert: 'mock-cert', key: 'mock-key' },
    'mock-ca',
    undefined,
    { dpopAlgorithm: 'ES256' }
  );

  const aliceAccessToken = `alice-token-${crypto.randomUUID().substring(0, 8)}`;
  const bobAccessToken = `bob-token-${crypto.randomUUID().substring(0, 8)}`;

  aliceChannel.setDPoPToken(aliceAccessToken);
  bobChannel.setDPoPToken(bobAccessToken);

  console.log("✅ Alice e Bob configurados com DPoP tokens\n");

  const message = Message.text("user", "Hello Bob, esta mensagem é protegida por DPoP!");
  const request = SendMessageRequest.make({ message });

  console.log("📤 Alice enviando mensagem para Bob via DPoP...");
  const result = await bobChannel.sendMessage(request);

  if ("status" in result) {
    const task = result as Task;
    const taskData = Task.un(task);
    console.log(`✅ Task criada: ${taskData.id}`);

    await new Promise(resolve => setTimeout(resolve, 1500));

    const completedTask = await bobChannel.getTask(taskData.id);
    const completedData = Task.un(completedTask);
    console.log(`✅ Task completada: ${completedData.status}`);

    if (completedData.messages.length > 1) {
      const lastMessage = completedData.messages[completedData.messages.length - 1];
      const messageText = lastMessage.parts
        .filter((part: any) => part.type === "text")
        .map((part: any) => part.content)
        .join("\n");
      console.log(`📥 Resposta: ${messageText}\n`);
    }
  }

  console.log("✅ Demonstração DPoP + A2A concluída!");
}

async function main() {
  try {
    await demonstrateDPoPBasics();
    await demonstrateDPoPWithA2A();
  } catch (error) {
    console.error("❌ Erro:", error);
    throw error;
  }
}

if (require.main === module) {
  main().catch(console.error);
}

export { demonstrateDPoPBasics, demonstrateDPoPWithA2A };
