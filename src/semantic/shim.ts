/**
 * Shim para tipos semânticos sem dependências externas
 * Implementa branding de tipos usando TypeScript puro
 */

declare const __brand: unique symbol;

/**
 * Tipo branded que adiciona semântica a tipos primitivos
 */
export type Brand<T, Name extends string> = T & { readonly [__brand]: Name };

/**
 * Factory para criar funções de branding
 */
export function STAMP<Name extends string>() {
  return {
    /**
     * Aplica o brand a um valor
     */
    of: <T>(v: T) => v as Brand<T, Name>,
    
    /**
     * Remove o brand de um valor
     */
    un: <T>(v: Brand<T, Name>) => v as unknown as T,
  };
}