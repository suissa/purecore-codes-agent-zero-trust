/**
 * Protocolo A2A (Agent-to-Agent) Ultra-Seguro
 * Exportações principais do sistema
 */

// Core types
export * from './core/agent-card';
export * from './core/task';
export * from './core/message';

// Protocol operations
export * from './protocol/operations';

// Security layer
export * from './security/ultra-secure-channel';

// Protocol bindings
export * from './bindings/json-rpc';
export * from './bindings/http-rest';

// Re-export semantic shim
export * from '../../src/semantic/shim';