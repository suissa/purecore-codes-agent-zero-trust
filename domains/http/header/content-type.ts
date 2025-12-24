/**
 * Tipo semântico para Content-Type HTTP
 * Garante que content types sejam válidos conforme RFC 2046
 */

import { Brand, STAMP } from "../../../src/semantic/shim";

export type HttpContentType = Brand<string, "http.header.contentType">;

// Regex para validar media type conforme RFC 2046
const MEDIA_TYPE_REGEX = /^[a-zA-Z][a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_.]*(\s*;\s*[a-zA-Z0-9!#$&\-\^_]+=[a-zA-Z0-9!#$&\-\^_.]+)*$/;

export const HttpContentType = (() => {
  const f = STAMP<"http.header.contentType">();
  
  return {
    of: (v: unknown): HttpContentType => {
      const s = String(v).trim();
      
      if (!s) {
        throw new TypeError("Content-Type não pode ser vazio");
      }
      
      if (!MEDIA_TYPE_REGEX.test(s)) {
        throw new TypeError("Content-Type deve seguir formato RFC 2046 (type/subtype)");
      }
      
      return f.of(s);
    },
    
    un: (v: HttpContentType): string => f.un(v),
    
    make: (value: string): HttpContentType => HttpContentType.of(value),
    
    // Utilitários para parsing
    getMainType: (v: HttpContentType): string => {
      const contentType = f.un(v);
      return contentType.split('/')[0].trim();
    },
    
    getSubType: (v: HttpContentType): string => {
      const contentType = f.un(v);
      const parts = contentType.split('/');
      return parts[1].split(';')[0].trim();
    },
    
    getParameters: (v: HttpContentType): Record<string, string> => {
      const contentType = f.un(v);
      const params: Record<string, string> = {};
      
      const paramPart = contentType.split(';').slice(1);
      for (const param of paramPart) {
        const [key, value] = param.split('=').map(s => s.trim());
        if (key && value) {
          params[key] = value;
        }
      }
      
      return params;
    },
    
    getCharset: (v: HttpContentType): string | null => {
      const params = HttpContentType.getParameters(v);
      return params.charset || null;
    },
    
    isJson: (v: HttpContentType): boolean => {
      const mainType = HttpContentType.getMainType(v);
      const subType = HttpContentType.getSubType(v);
      return mainType === 'application' && (subType === 'json' || subType.endsWith('+json'));
    },
    
    isText: (v: HttpContentType): boolean => {
      return HttpContentType.getMainType(v) === 'text';
    },
    
    isBinary: (v: HttpContentType): boolean => {
      const mainType = HttpContentType.getMainType(v);
      return ['image', 'video', 'audio', 'application'].includes(mainType) && 
             !HttpContentType.isJson(v) && 
             !HttpContentType.isText(v);
    },
  };
})();

// Constantes para content types mais comuns
export const CONTENT_TYPE = {
  JSON: HttpContentType.make('application/json'),
  JSON_UTF8: HttpContentType.make('application/json; charset=utf-8'),
  TEXT_PLAIN: HttpContentType.make('text/plain'),
  TEXT_HTML: HttpContentType.make('text/html'),
  FORM_URLENCODED: HttpContentType.make('application/x-www-form-urlencoded'),
  MULTIPART_FORM: HttpContentType.make('multipart/form-data'),
  XML: HttpContentType.make('application/xml'),
  OCTET_STREAM: HttpContentType.make('application/octet-stream'),
} as const;