/**
 * Tipo semântico para endpoints de servidores MCP
 * Combina URL base com path específico do MCP
 */

import { Brand, STAMP } from "../../../src/semantic/shim";

export type McpServerEndpoint = Brand<string, "mcp.server.endpoint">;

export const McpServerEndpoint = (() => {
  const f = STAMP<"mcp.server.endpoint">();
  
  return {
    of: (v: unknown): McpServerEndpoint => {
      const s = String(v).trim();
      
      try {
        const url = new URL(s);
        
        // Validar protocolo (HTTP/HTTPS para MCP servers)
        if (!['http:', 'https:'].includes(url.protocol)) {
          throw new TypeError("Endpoint MCP deve usar protocolo HTTP ou HTTPS");
        }
        
        // Validar que tem host
        if (!url.hostname) {
          throw new TypeError("Endpoint MCP deve ter hostname válido");
        }
        
        // Validar que path parece ser de MCP (opcional, mas útil)
        const path = url.pathname;
        if (path && !path.startsWith('/')) {
          throw new TypeError("Path do endpoint deve começar com /");
        }
        
        return f.of(s);
      } catch (error) {
        if (error instanceof TypeError && error.message.includes("MCP")) {
          throw error;
        }
        throw new TypeError("Endpoint MCP inválido");
      }
    },
    
    un: (v: McpServerEndpoint): string => f.un(v),
    
    make: (value: string): McpServerEndpoint => f.of(value),
    
    // Utilitários específicos para MCP
    getBaseUrl: (v: McpServerEndpoint): string => {
      const url = new URL(f.un(v));
      return `${url.protocol}//${url.host}`;
    },
    
    getPath: (v: McpServerEndpoint): string => {
      return new URL(f.un(v)).pathname;
    },
    
    withPath: (v: McpServerEndpoint, path: string): McpServerEndpoint => {
      const baseUrl = McpServerEndpoint.getBaseUrl(v);
      const normalizedPath = path.startsWith('/') ? path : `/${path}`;
      return f.of(`${baseUrl}${normalizedPath}`);
    },
    
    withQuery: (v: McpServerEndpoint, params: Record<string, string>): McpServerEndpoint => {
      const url = new URL(f.un(v));
      Object.entries(params).forEach(([key, value]) => {
        url.searchParams.set(key, value);
      });
      return f.of(url.toString());
    },
    
    // Verificar se é endpoint interno (localhost, 127.0.0.1, etc.)
    isInternal: (v: McpServerEndpoint): boolean => {
      const url = new URL(f.un(v));
      const hostname = url.hostname.toLowerCase();
      
      return hostname === 'localhost' ||
             hostname === '127.0.0.1' ||
             hostname === '::1' ||
             hostname.endsWith('.local') ||
             hostname.endsWith('.internal');
    },
    
    // Verificar se usa HTTPS
    isSecure: (v: McpServerEndpoint): boolean => {
      return new URL(f.un(v)).protocol === 'https:';
    },
  };
})();