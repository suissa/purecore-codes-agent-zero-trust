/**
 * Tipo semântico para códigos de status HTTP
 * Garante que apenas códigos válidos sejam utilizados
 */

import { Brand, STAMP } from "../../../src/semantic/shim";

export type HttpStatusCode = Brand<number, "http.status.code">;

// Códigos HTTP válidos conforme RFC 7231, 7232, 7233, 7234, 7235
const VALID_STATUS_CODES = new Set([
  // 1xx Informational
  100, 101, 102, 103,
  // 2xx Success
  200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
  // 3xx Redirection
  300, 301, 302, 303, 304, 305, 307, 308,
  // 4xx Client Error
  400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451,
  // 5xx Server Error
  500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511
]);

export const HttpStatusCode = (() => {
  const f = STAMP<"http.status.code">();
  
  return {
    of: (v: unknown): HttpStatusCode => {
      const n = Number(v);
      
      if (!Number.isInteger(n)) {
        throw new TypeError("Status code deve ser um número inteiro");
      }
      
      if (!VALID_STATUS_CODES.has(n)) {
        throw new TypeError(`Status code ${n} não é válido conforme RFC HTTP`);
      }
      
      return f.of(n);
    },
    
    un: (v: HttpStatusCode): number => f.un(v),
    
    make: (value: number): HttpStatusCode => HttpStatusCode.of(value),
    
    // Utilitários para categorias de status
    isInformational: (v: HttpStatusCode): boolean => {
      const code = f.un(v);
      return code >= 100 && code < 200;
    },
    
    isSuccess: (v: HttpStatusCode): boolean => {
      const code = f.un(v);
      return code >= 200 && code < 300;
    },
    
    isRedirection: (v: HttpStatusCode): boolean => {
      const code = f.un(v);
      return code >= 300 && code < 400;
    },
    
    isClientError: (v: HttpStatusCode): boolean => {
      const code = f.un(v);
      return code >= 400 && code < 500;
    },
    
    isServerError: (v: HttpStatusCode): boolean => {
      const code = f.un(v);
      return code >= 500 && code < 600;
    },
    
    isError: (v: HttpStatusCode): boolean => {
      const code = f.un(v);
      return code >= 400;
    },
  };
})();

// Constantes para códigos mais comuns
export const HTTP_STATUS = {
  OK: HttpStatusCode.make(200),
  CREATED: HttpStatusCode.make(201),
  NO_CONTENT: HttpStatusCode.make(204),
  BAD_REQUEST: HttpStatusCode.make(400),
  UNAUTHORIZED: HttpStatusCode.make(401),
  FORBIDDEN: HttpStatusCode.make(403),
  NOT_FOUND: HttpStatusCode.make(404),
  METHOD_NOT_ALLOWED: HttpStatusCode.make(405),
  INTERNAL_SERVER_ERROR: HttpStatusCode.make(500),
  BAD_GATEWAY: HttpStatusCode.make(502),
  SERVICE_UNAVAILABLE: HttpStatusCode.make(503),
} as const;