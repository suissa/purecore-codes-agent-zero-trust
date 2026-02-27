/**
 * Decorador para auditoria de métodos sensíveis
 */
export function Audit(_target: any, propertyKey: string, descriptor: PropertyDescriptor) {
  const originalMethod = descriptor.value;

  descriptor.value = function (...args: any[]) {
    console.log(`🔒 [AUDIT] Calling ${propertyKey} with args:`, args.map(a => typeof a === 'object' ? '{...}' : a));
    try {
      const result = originalMethod.apply(this, args);
      if (result instanceof Promise) {
        return result.then(res => {
          console.log(`✅ [AUDIT] ${propertyKey} completed successfully`);
          return res;
        }).catch(err => {
          console.error(`❌ [AUDIT] ${propertyKey} failed:`, err.message);
          throw err;
        });
      }
      console.log(`✅ [AUDIT] ${propertyKey} completed successfully`);
      return result;
    } catch (err: any) {
      console.error(`❌ [AUDIT] ${propertyKey} failed:`, err.message);
      throw err;
    }
  };

  return descriptor;
}
