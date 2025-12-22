/**
 * Tipo semântico para métodos HTTP
 * Garante que apenas métodos válidos sejam utilizados
 */

import { Brand, STAMP } from "../../../src/semantic/shim";

export type HttpMethod = Brand<string, "http.method.verb">;

// Métodos HTTP válidos conforme RFC 7231 e extensões comuns
const VALID_METHODS = new Set([
  'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE',
  'PATCH' // RFC 5789
]);

export const HttpMethod = (() => {
  const f = STAMP<"http.method.verb">();
  
  return {
    of: (v: unknown): HttpMethod => {
      const s = String(v).trim().toUpperCase();
      
      if (!VALID_METHODS.has(s)) {
        throw new TypeError(`Método HTTP '${s}' não é válido`);
      }
      
      return f.of(s);
    },
    
    un: (v: HttpMethod): string => f.un(v),
    
    make: (value: string): HttpMethod => f.of(value),
    
    // Utilitários para categorias de métodos
    isSafe: (v: HttpMethod): boolean => {
      const method = f.un(v);
      return ['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method);
    },
    
    isIdempotent: (v: HttpMethod): boolean => {
      const method = f.un(v);
      return ['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'].includes(method);
    },
    
    allowsBody: (v: HttpMethod): boolean => {
      const method = f.un(v);
      return ['POST', 'PUT', 'PATCH'].includes(method);
    },
    
    requiresBody: (v: HttpMethod): boolean => {
      const method = f.un(v);
      return ['POST', 'PUT', 'PATCH'].includes(method);
    },
  };
})();

// Constantes para métodos mais comuns
export const HTTP_METHOD = {
  GET: HttpMethod.make('GET'),
  POST: HttpMethod.make('POST'),
  PUT: HttpMethod.make('PUT'),
  DELETE: HttpMethod.make('DELETE'),
  PATCH: HttpMethod.make('PATCH'),
  HEAD: HttpMethod.make('HEAD'),
  OPTIONS: HttpMethod.make('OPTIONS'),
} as const;