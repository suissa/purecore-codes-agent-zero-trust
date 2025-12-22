/**
 * Shim para tipos semânticos sem dependências externas
 * Implementa branding de tipos usando TypeScript puro
 */

declare const __brand: unique symbol;

export type Brand<T, Name extends string> = T & { readonly [__brand]: Name };

export function STAMP<Name extends string>() {
  return {
    of: <T>(v: T) => v as Brand<T, Name>,
    un: <T>(v: Brand<T, Name>) => v as unknown as T,
  };
}