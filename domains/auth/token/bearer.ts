/**
 * Tipo semântico para tokens Bearer de autenticação
 * Garante formato correto e segurança básica
 */

import { Brand, STAMP } from "../../../src/semantic/shim";

export type BearerToken = Brand<string, "auth.token.bearer">;

export const BearerToken = (() => {
  const f = STAMP<"auth.token.bearer">();
  
  return {
    of: (v: unknown): BearerToken => {
      const s = String(v).trim();
      
      if (!s) {
        throw new TypeError("Bearer token não pode ser vazio");
      }
      
      // Validar que não contém espaços (tokens devem ser single-word)
      if (/\s/.test(s)) {
        throw new TypeError("Bearer token não pode conter espaços");
      }
      
      // Validar comprimento mínimo para segurança
      if (s.length < 16) {
        throw new TypeError("Bearer token deve ter pelo menos 16 caracteres");
      }
      
      // Validar que contém apenas caracteres seguros para HTTP headers
      if (!/^[A-Za-z0-9\-._~+/]+=*$/.test(s)) {
        throw new TypeError("Bearer token contém caracteres inválidos");
      }
      
      return f.of(s);
    },
    
    un: (v: BearerToken): string => f.un(v),
    
    make: (value: string): BearerToken => BearerToken.of(value),
    
    // Utilitários para headers de autorização
    toAuthHeader: (v: BearerToken): string => `Bearer ${f.un(v)}`,
    
    fromAuthHeader: (header: string): BearerToken => {
      const trimmed = header.trim();
      
      if (!trimmed.startsWith('Bearer ')) {
        throw new TypeError("Header de autorização deve começar com 'Bearer '");
      }
      
      const token = trimmed.substring(7); // Remove "Bearer "
      return f.of(token);
    },
    
    // Verificar se parece com JWT (3 partes separadas por ponto)
    isJWT: (v: BearerToken): boolean => {
      const token = f.un(v);
      const parts = token.split('.');
      return parts.length === 3 && parts.every(part => part.length > 0);
    },
    
    // Extrair payload de JWT (sem verificação de assinatura)
    getJWTPayload: (v: BearerToken): any => {
      if (!BearerToken.isJWT(v)) {
        throw new TypeError("Token não é um JWT válido");
      }
      
      const token = f.un(v);
      const payloadPart = token.split('.')[1];
      
      try {
        const decoded = Buffer.from(payloadPart, 'base64url').toString('utf-8');
        return JSON.parse(decoded);
      } catch (error) {
        throw new TypeError("Não foi possível decodificar payload do JWT");
      }
    },
    
    // Verificar se JWT está expirado (sem verificação de assinatura)
    isJWTExpired: (v: BearerToken): boolean => {
      try {
        const payload = BearerToken.getJWTPayload(v);
        if (!payload.exp) return false;
        
        const now = Math.floor(Date.now() / 1000);
        return payload.exp < now;
      } catch {
        return false; // Se não conseguir decodificar, assume que não está expirado
      }
    },
  };
})();