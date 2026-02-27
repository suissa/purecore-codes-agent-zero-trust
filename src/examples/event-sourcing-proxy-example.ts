/**
 * Exemplo: EventSourcing Proxy com Rastreabilidade Automática
 * 
 * Este exemplo demonstra como usar o EventSourcingProxy para automaticamente:
 * 1. Capturar retornos de métodos do agente
 * 2. Encapsular em EventEnvelope com metadata completa
 * 3. Persistir eventos para auditoria
 * 4. Manter o código do usuário limpo (sem boilerplate)
 */

import {
  SignalE2EEAgent,
  TokenAuthority,
  createEventSourcingProxy,
  InMemoryEventStore,
  AgentIdStamp,
  ConversationIdStamp,
} from '../index';

// ============================================================================
// Configuração
// ============================================================================

async function main() {
  console.log('🚀 EventSourcing Proxy - Exemplo de Uso\n');

  // 1. Criar autoridade de tokens
  const authority = new TokenAuthority();

  // 2. Criar EventStore (em memória para este exemplo)
  const eventStore = new InMemoryEventStore();

  // 3. Criar agentes
  const alice = new SignalE2EEAgent(AgentIdStamp.of('alice'), authority, ['messaging']);
  const bob = new SignalE2EEAgent(AgentIdStamp.of('bob'), authority, ['messaging']);

  await alice.initialize();
  await bob.initialize();

  // 4. Criar proxies com EventSourcing automático
  const eventSourcedAlice = createEventSourcingProxy(
    alice,
    {
      agentId: AgentIdStamp.of('alice'),
      aggregateType: 'SecureAgent',
      eventStore,
      logEvents: true,
      defaultClassification: 'confidential',
      conversationId: ConversationIdStamp.of('conv-alice-bob-001'),
    },
    ['getPublicKeyBundle', 'registerPeerBundle', 'getIdentityThumbprint']
  );

  const eventSourcedBob = createEventSourcingProxy(
    bob,
    {
      agentId: AgentIdStamp.of('bob'),
      aggregateType: 'SecureAgent',
      eventStore,
      logEvents: true,
      defaultClassification: 'confidential',
      conversationId: ConversationIdStamp.of('conv-alice-bob-001'),
    },
    ['getPublicKeyBundle', 'registerPeerBundle', 'getIdentityThumbprint']
  );

  // 5. Obter bundles de chaves (com event sourcing automático)
  console.log('🔑 Obtendo bundles de chaves públicas...\n');
  const aliceBundle = eventSourcedAlice.getPublicKeyBundle();
  const bobBundle = eventSourcedBob.getPublicKeyBundle();

  // Aguardar um pouco para os eventos serem persistidos
  await new Promise(resolve => setTimeout(resolve, 100));

  // 6. Registrar bundles (com event sourcing automático)
  console.log('📋 Registrando bundles de chaves...\n');
  eventSourcedAlice.registerPeerBundle('bob', bobBundle);
  eventSourcedBob.registerPeerBundle('alice', aliceBundle);

  // Aguardar um pouco para os eventos serem persistidos
  await new Promise(resolve => setTimeout(resolve, 100));

  // 7. Obter thumbprints (com event sourcing automático)
  console.log('🔐 Obtendo thumbprints de identidade...\n');
  const aliceThumbprint = await eventSourcedAlice.getIdentityThumbprint();
  const bobThumbprint = await eventSourcedBob.getIdentityThumbprint();

  console.log(`Alice Thumbprint: ${aliceThumbprint}`);
  console.log(`Bob Thumbprint:   ${bobThumbprint}`);

  // Aguardar um pouco para os eventos serem persistidos
  await new Promise(resolve => setTimeout(resolve, 100));

  // 8. Inspecionar eventos persistidos
  console.log('\n📊 Eventos Persistidos:\n');
  const aliceEvents = await eventStore.getEvents('SecureAgent-alice');
  const bobEvents = await eventStore.getEvents('SecureAgent-bob');

  console.log(`📦 Alice: ${aliceEvents.length} eventos`);
  aliceEvents.forEach((event, idx) => {
    const tracking = {
      eventId: event.eventId,
      eventType: event.eventType,
      timestamp: new Date(event.timestamp.epoch).toISOString(),
      classification: event.security.classification,
      payloadHash: event.security.payloadHash.substring(0, 20) + '...',
    };
    console.log(`   [${idx + 1}] ${tracking.eventType}`);
    console.log(`       EventID: ${tracking.eventId}`);
    console.log(`       Time: ${tracking.timestamp}`);
    console.log(`       Classification: ${tracking.classification}`);
    console.log(`       Payload Hash: ${tracking.payloadHash}`);
    console.log();
  });

  console.log(`📦 Bob: ${bobEvents.length} eventos`);
  bobEvents.forEach((event, idx) => {
    const tracking = {
      eventId: event.eventId,
      eventType: event.eventType,
      timestamp: new Date(event.timestamp.epoch).toISOString(),
      classification: event.security.classification,
    };
    console.log(`   [${idx + 1}] ${tracking.eventType}`);
    console.log(`       EventID: ${tracking.eventId}`);
    console.log(`       Time: ${tracking.timestamp}`);
    console.log(`       Classification: ${tracking.classification}`);
    console.log();
  });

  // 9. Demonstração de rastreabilidade completa
  console.log('🔍 Rastreabilidade Completa:\n');
  const firstEvent = aliceEvents[0];
  if (firstEvent) {
    console.log('Evento: getPublicKeyBundle');
    console.log(`  Event ID:        ${firstEvent.eventId}`);
    console.log(`  Aggregate ID:    ${firstEvent.aggregateId}`);
    console.log(`  Correlation ID:  ${firstEvent.correlationId}`);
    console.log(`  Causation ID:    ${firstEvent.causationId ?? 'N/A'}`);
    console.log(`  Trace ID:        ${firstEvent.context.traceId}`);
    console.log(`  Span ID:         ${firstEvent.context.spanId}`);
    console.log(`  Agent ID:        ${firstEvent.context.agentId}`);
    console.log(`  Conversation:    ${firstEvent.context.conversationId}`);
    console.log(`  Timestamp:       ${firstEvent.timestamp.iso}`);
    console.log(`  Payload Hash:    ${firstEvent.security.payloadHash}`);
    console.log(`  Classification:  ${firstEvent.security.classification}`);
    console.log(`  Schema Type:     ${firstEvent.schema.type}`);
    console.log(`  Schema Version:  ${firstEvent.schema.version}`);
    console.log(`  Origin Host:     ${firstEvent.origin.host ?? 'N/A'}`);
    console.log(`  Origin Region:   ${firstEvent.origin.region ?? 'N/A'}`);
  }

  // 10. Mostrar payload do evento
  console.log('\n📦 Payload do Evento:\n');
  if (firstEvent) {
    console.log('Tipo do payload:', typeof firstEvent.payload);
    console.log('Conteúdo do payload:', JSON.stringify(firstEvent.payload, null, 2));
  }

  // 11. Limpeza
  // eventSourcedAlice.destroy(); // Not implemented in this version
  // eventSourcedBob.destroy();

  console.log('\n✅ Exemplo concluído!\n');
}

// ============================================================================
// Executar
// ============================================================================

main().catch((error) => {
  console.error('❌ Erro:', error);
  process.exit(1);
});
