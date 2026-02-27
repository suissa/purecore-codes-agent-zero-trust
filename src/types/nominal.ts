import { Brand, STAMP } from '../semantic/shim';

export type AgentId = Brand<string, 'AgentId'>;
export type ConversationId = Brand<string, 'ConversationId'>;
export type JWT = Brand<string, 'JWT'>;
export type DPoPProof = Brand<string, 'DPoPProof'>;
export type Thumbprint = Brand<string, 'Thumbprint'>;
export type HexString = Brand<string, 'HexString'>;
export type Base64URLString = Brand<string, 'Base64URLString'>;
export type Milliseconds = Brand<number, 'Milliseconds'>;
export type EventId = Brand<string, 'EventId'>;
export type AggregateId = Brand<string, 'AggregateId'>;
export type CorrelationId = Brand<string, 'CorrelationId'>;
export type CausationId = Brand<string, 'CausationId'>;
export type EventVersion = Brand<number, 'EventVersion'>;
export type TraceId = Brand<string, 'TraceId'>;
export type SpanId = Brand<string, 'SpanId'>;

export const AgentIdStamp = STAMP<'AgentId'>();
export const ConversationIdStamp = STAMP<'ConversationId'>();
export const JWTStamp = STAMP<'JWT'>();
export const DPoPProofStamp = STAMP<'DPoPProof'>();
export const ThumbprintStamp = STAMP<'Thumbprint'>();
export const HexStringStamp = STAMP<'HexString'>();
export const Base64URLStringStamp = STAMP<'Base64URLString'>();
export const MillisecondsStamp = STAMP<'Milliseconds'>();
export const EventIdStamp = STAMP<'EventId'>();
export const AggregateIdStamp = STAMP<'AggregateId'>();
export const CorrelationIdStamp = STAMP<'CorrelationId'>();
export const CausationIdStamp = STAMP<'CausationId'>();
export const EventVersionStamp = STAMP<'EventVersion'>();
export const TraceIdStamp = STAMP<'TraceId'>();
export const SpanIdStamp = STAMP<'SpanId'>();


