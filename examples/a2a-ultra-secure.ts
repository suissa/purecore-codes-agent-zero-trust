/**
 * Demonstração do Canal Ultra-Seguro A2A
 * 
 * Este exemplo mostra como usar o protocolo A2A com múltiplas camadas de segurança:
 * 1. mTLS - Autenticação mútua de transporte
 * 2. JWT - Autenticação de aplicação com EdDSA  
 * 3. E2EE - Criptografia end-to-end das mensagens
 */

import { UltraSecureA2AChannel } from '../domains/a2a/security/ultra-secure-channel';
import { Message, SendMessageRequest } from '../domains/a2a/core/message';
import { Task } from '../domains/a2a/core/task';
import { A2AJsonRpcServer, A2AJsonRpcClient } from '../domains/a2a/bindings/json-rpc';
import { A2AHttpRestServer, A2AHttpRestClient } from '../domains/a2a/bindings/http-rest';
import { CertificateAuthority } from './mtls-agents';
import * as crypto from 'crypto';
import * as http from 'http';

async function demonstrateUltraSecureA2A() {
  console.log('🚀 Demonstração do Canal Ultra-Seguro A2A\n');

  // 1. Criar CA e certificados
  console.log('✅ Criando CA e certificados mTLS...');
  const ca = new CertificateAuthority();
  const certAlpha = ca.generateAgentCertificate('agent-alpha');
  const certBeta = ca.generateAgentCertificate('agent-beta');
  const caCert = ca.getCACertificate();

  // 2. Gerar pares de chaves Ed25519 para JWT
  console.log('✅ Gerando pares de chaves Ed25519 para JWT...');
  const keyPairAlpha = crypto.generateKeyPairSync('ed25519');
  const keyPairBeta = crypto.generateKeyPairSync('ed25519');

  // 3. Criar canais ultra-seguros
  console.log('✅ Criando canais ultra-seguros A2A...');
  const channelAlpha = new UltraSecureA2AChannel(
    'agent-alpha',
    certAlpha,
    caCert,
    keyPairAlpha
  );

  const channelBeta = new UltraSecureA2AChannel(
    'agent-beta', 
    certBeta,
    caCert,
    keyPairBeta
  );

  // 4. Registrar chaves públicas dos peers (para E2EE)
  console.log('✅ Registrando chaves públicas dos peers...');
  channelAlpha.registerPeerPublicKey('agent-beta', keyPairBeta.publicKey);
  channelBeta.registerPeerPublicKey('agent-alpha', keyPairAlpha.publicKey);

  // 5. Obter Agent Cards
  console.log('✅ Obtendo Agent Cards...');
  const cardAlpha = await channelAlpha.getAgentCard();
  const cardBeta = await channelBeta.getAgentCard();
  
  console.log(`🤖 Agent Alpha: ${cardAlpha.name}`);
  console.log(`🤖 Agent Beta: ${cardBeta.name}\n`);

  // 6. Demonstrar operações A2A básicas
  console.log('💬 Demonstrando operações A2A básicas...\n');

  // Enviar mensagem simples
  const message = Message.text('user', 'Hello from Alpha to Beta via ultra-secure A2A!');
  const request = SendMessageRequest.make({ message });
  
  console.log('📤 Alpha enviando mensagem...');
  const result = await channelBeta.sendMessage(request);
  
  // Verificar se é Task ou Message
  if ('status' in result) {
    // É uma Task
    const task = result as Task;
    const taskData = Task.un(task);
    console.log(`✅ Task criada: ${taskData.id}`);

    // Aguardar processamento
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Verificar resultado
    const completedTask = await channelBeta.getTask(taskData.id);
    const completedData = Task.un(completedTask);
    console.log(`✅ Task completada com status: ${completedData.status}`);
    
    if (completedData.messages.length > 1) {
      const lastMessage = completedData.messages[completedData.messages.length - 1];
      const messageText = lastMessage.parts
        .filter(part => part.type === 'text')
        .map(part => (part as any).content)
        .join('\n');
      console.log(`📥 Resposta: ${messageText}\n`);
    }
  } else {
    // É uma Message direta
    const message = result as Message;
    const messageData = Message.un(message);
    console.log(`📥 Resposta direta: ${Message.extractText(message)}\n`);
  }

  // 7. Demonstrar streaming
  console.log('🌊 Demonstrando streaming de mensagens...\n');
  
  const streamingMessage = Message.text('user', 'Streaming message test');
  const streamingRequest = SendMessageRequest.make({ message: streamingMessage });
  
  console.log('📤 Iniciando stream...');
  for await (const event of channelBeta.sendStreamingMessage(streamingRequest)) {
    console.log(`🔄 Stream event: ${event.type} - ${JSON.stringify(event)}`);
  }

  // 8. Demonstrar conexão mTLS direta
  console.log('\n🔒 Demonstrando conexão mTLS direta...\n');
  
  try {
    // Iniciar servidores TLS
    const serverAlpha = await channelAlpha.startTLSServer(8445);
    const serverBeta = await channelBeta.startTLSServer(8446);

    // Estabelecer conexões
    const socketAlphaToBeta = await channelAlpha.connectToPeer('localhost', 8446, 'agent-beta');
    const socketBetaToAlpha = await channelBeta.connectToPeer('localhost', 8445, 'agent-alpha');

    // Trocar mensagens ultra-seguras
    await channelAlpha.sendSecureMessage('agent-beta', 'Ultra-secure message from Alpha!', socketAlphaToBeta);
    await channelBeta.sendSecureMessage('agent-alpha', 'Ultra-secure response from Beta!', socketBetaToAlpha);

    // Aguardar processamento
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Fechar conexões
    socketAlphaToBeta.end();
    socketBetaToAlpha.end();
    serverAlpha.close();
    serverBeta.close();

  } catch (error) {
    console.error('❌ Erro na demonstração mTLS:', error);
  }

  // 9. Demonstrar bindings de protocolo
  console.log('\n🔌 Demonstrando bindings de protocolo...\n');
  
  // JSON-RPC Server
  const jsonRpcServer = new A2AJsonRpcServer(channelBeta);
  console.log('✅ JSON-RPC Server criado');
  
  // HTTP/REST Server  
  const httpRestServer = new A2AHttpRestServer(channelBeta);
  console.log('✅ HTTP/REST Server criado');
  
  // Simular requisição JSON-RPC
  const jsonRpcRequest = {
    jsonrpc: '2.0' as const,
    method: 'a2a.agent.getCard',
    id: 1
  };
  
  const jsonRpcResponse = await jsonRpcServer.handleHttpRequest(JSON.stringify(jsonRpcRequest));
  const parsedResponse = JSON.parse(jsonRpcResponse);
  console.log(`📡 JSON-RPC Response: Agent ${parsedResponse.result.name}`);

  // 10. Demonstrar listagem de tasks
  console.log('\n📋 Listando todas as tasks...');
  const tasksList = await channelBeta.listTasks();
  console.log(`✅ Total de tasks: ${tasksList.totalSize}`);
  
  for (const task of tasksList.tasks) {
    console.log(`  - Task ${task.id}: ${task.status} (${task.messages.length} mensagens)`);
  }

  console.log('\n✅ Demonstração do Canal Ultra-Seguro A2A concluída!');
  console.log('\n🛡️ Camadas de Segurança Implementadas:');
  console.log('   1. mTLS: Autenticação mútua de transporte');
  console.log('   2. JWT (EdDSA): Autenticação de aplicação');
  console.log('   3. E2EE: Criptografia end-to-end (preparado)');
  console.log('   4. A2A Protocol: Comunicação padronizada entre agentes');
  console.log('\n🔌 Bindings de Protocolo Suportados:');
  console.log('   - JSON-RPC 2.0: Chamadas de procedimento remoto');
  console.log('   - HTTP/REST: Endpoints RESTful');
  console.log('   - mTLS Direct: Conexão direta ultra-segura');
}

// Executar demonstração se chamado diretamente
if (require.main === module) {
  demonstrateUltraSecureA2A().catch(console.error);
}

export { demonstrateUltraSecureA2A, UltraSecureA2AChannel };