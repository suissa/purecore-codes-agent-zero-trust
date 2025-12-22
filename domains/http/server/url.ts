/**
 * Tipo semântico para URLs de servidores HTTP
 * Garante que URLs sejam válidas e bem formadas
 */

import { Brand, STAMP } from "../../../src/semantic/shim";

export type ServerUrl = Brand<string, "http.server.url">;

export const ServerUrl = (() => {
  const f = STAMP<"http.server.url">();
  
  return {
    of: (v: unknown): ServerUrl => {
      const s = String(v).trim();
      
      try {
        const url = new URL(s);
        
        // Validar protocolo HTTP/HTTPS
        if (!['http:', 'https:'].includes(url.protocol)) {
          throw new TypeError("URL deve usar protocolo HTTP ou HTTPS");
        }
        
        // Validar que tem host
        if (!url.hostname) {
          throw new TypeError("URL deve ter hostname válido");
        }
        
        return f.of(s);
      } catch (error) {
        if (error instanceof TypeError && error.message.includes("deve")) {
          throw error;
        }
        throw new TypeError("URL inválida");
      }
    },
    
    un: (v: ServerUrl): string => f.un(v),
    
    make: (value: string): ServerUrl => f.of(value),
    
    // Utilitários específicos para URLs de servidor
    getHost: (v: ServerUrl): string => new URL(f.un(v)).hostname,
    getPort: (v: ServerUrl): number => {
      const url = new URL(f.un(v));
      return url.port ? parseInt(url.port) : (url.protocol === 'https:' ? 443 : 80);
    },
    getProtocol: (v: ServerUrl): 'http' | 'https' => {
      const protocol = new URL(f.un(v)).protocol;
      return protocol === 'https:' ? 'https' : 'http';
    },
    isSecure: (v: ServerUrl): boolean => new URL(f.un(v)).protocol === 'https:',
  };
})();