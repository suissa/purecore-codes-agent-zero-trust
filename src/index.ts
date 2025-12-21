import * as crypto from 'node:crypto';

// --- Interfaces & Types (Compatíveis com 'jose') ---

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: any;
}

export interface JWTHeaderParameters {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: any;
}

export interface JWTVerifyResult {
  payload: JWTPayload;
  protectedHeader: JWTHeaderParameters;
}

export interface JWTVerifyOptions {
  issuer?: string | string[];
  audience?: string | string[];
  algorithms?: string[];
  currentDate?: Date; // Para mockar tempo em testes
  maxTokenAge?: string | number; // Ex: '2h' ou segundos
}

// --- Utilitários Internos ---

const Encoder = new TextEncoder();
const Decoder = new TextDecoder();

/**
 * Converte strings de tempo (ex: "2h", "1d", "30m") para segundos.
 * Se for número, assume que já são segundos.
 */
function parseTime(time: string | number | undefined): number {
  if (typeof time === 'number') return time;
  if (!time) return 0;

  const regex = /^(\d+)([smhdwy])$/;
  const match = time.match(regex);

  if (!match) throw new Error(`Formato de tempo inválido: ${time}`);

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 24 * 60 * 60;
    case 'w': return value * 7 * 24 * 60 * 60;
    case 'y': return value * 365.25 * 24 * 60 * 60;
    default: return value;
  }
}

function base64UrlEncode(input: Uint8Array | string | object): string {
  let buffer: Buffer;
  if (typeof input === 'string') {
    buffer = Buffer.from(input, 'utf-8');
  } else if (Buffer.isBuffer(input)) {
    buffer = input;
  } else if (input instanceof Uint8Array) {
    buffer = Buffer.from(input);
  } else {
    buffer = Buffer.from(JSON.stringify(input), 'utf-8');
  }
  
  return buffer.toString('base64url'); // Node.js moderno suporta 'base64url' nativamente
}

function base64UrlDecode(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf-8');
}

// --- Classe SignJWT (Builder Pattern) ---

export class SignJWT {
  private _payload: JWTPayload;
  private _protectedHeader: JWTHeaderParameters = { alg: 'EdDSA', typ: 'JWT' };

  constructor(payload: JWTPayload) {
    this._payload = { ...payload };
  }

  setProtectedHeader(protectedHeader: JWTHeaderParameters): this {
    this._protectedHeader = { ...this._protectedHeader, ...protectedHeader };
    return this;
  }

  setIssuer(issuer: string): this {
    this._payload.iss = issuer;
    return this;
  }

  setSubject(subject: string): this {
    this._payload.sub = subject;
    return this;
  }

  setAudience(audience: string | string[]): this {
    this._payload.aud = audience;
    return this;
  }

  setJti(jwtId: string): this {
    this._payload.jti = jwtId;
    return this;
  }

  setNotBefore(input: number | string): this {
    const now = Math.floor(Date.now() / 1000);
    this._payload.nbf = now + parseTime(input);
    return this;
  }

  setIssuedAt(input?: number): this {
    this._payload.iat = input ?? Math.floor(Date.now() / 1000);
    return this;
  }

  setExpirationTime(input: number | string): this {
    const now = this._payload.iat ?? Math.floor(Date.now() / 1000);
    const offset = typeof input === 'number' ? input - now : parseTime(input); 
    // Nota: 'jose' geralmente trata string como duração relativa (ex: "2h" a partir de agora/iat)
    // Se o input for string, somamos ao 'iat' ou 'now'. 
    // Se for number, assume-se timestamp absoluto na maioria das libs, mas 'jose' string é duração.
    // Aqui simplifico: string = duração, number = timestamp absoluto.
    
    if (typeof input === 'string') {
        this._payload.exp = now + parseTime(input);
    } else {
        this._payload.exp = input;
    }
    
    return this;
  }

  async sign(privateKey: crypto.KeyObject | string): Promise<string> {
    if (this._protectedHeader.alg !== 'EdDSA') {
      throw new Error('Apenas o algoritmo EdDSA é suportado por esta implementação.');
    }

    const encodedHeader = base64UrlEncode(this._protectedHeader);
    const encodedPayload = base64UrlEncode(this._payload);
    const data = `${encodedHeader}.${encodedPayload}`;

    const signature = crypto.sign(
      null,
      Buffer.from(data),
      (typeof privateKey === 'string') ? crypto.createPrivateKey(privateKey) : privateKey
    );

    const encodedSignature = base64UrlEncode(signature);

    return `${data}.${encodedSignature}`;
  }
}

// --- Função jwtVerify (Funcional) ---

export async function jwtVerify(
  jwt: string,
  key: crypto.KeyObject | string,
  options?: JWTVerifyOptions
): Promise<JWTVerifyResult> {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('JWT inválido: Formato deve ser header.payload.signature');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;

  // 1. Validar Assinatura Criptográfica
  const publicKey = (typeof key === 'string') ? crypto.createPublicKey(key) : key;
  
  // No Node moderno, crypto.verify infere Ed25519 pela chave
  const verified = crypto.verify(
    null,
    Buffer.from(data),
    publicKey,
    Buffer.from(encodedSignature, 'base64url')
  );

  if (!verified) {
    throw new Error('Assinatura do JWT inválida.');
  }

  // 2. Parse do Conteúdo
  const protectedHeader = JSON.parse(base64UrlDecode(encodedHeader)) as JWTHeaderParameters;
  const payload = JSON.parse(base64UrlDecode(encodedPayload)) as JWTPayload;

  // 3. Validações de Claims (exp, nbf, iss, aud)
  const now = options?.currentDate 
    ? Math.floor(options.currentDate.getTime() / 1000) 
    : Math.floor(Date.now() / 1000);
    
  // Clock tolerance padrão de 0s (pode ser adicionado se quiser)

  if (payload.exp && now > payload.exp) {
    throw new Error(`Token expirado (exp). Expirou em ${new Date(payload.exp * 1000).toISOString()}`);
  }

  if (payload.nbf && now < payload.nbf) {
    throw new Error(`Token ainda não ativo (nbf). Válido a partir de ${new Date(payload.nbf * 1000).toISOString()}`);
  }

  if (options?.issuer) {
    const issuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
    if (!payload.iss || !issuers.includes(payload.iss)) {
      throw new Error(`Issuer inválido. Esperado: ${issuers.join(' ou ')}, Recebido: ${payload.iss}`);
    }
  }

  if (options?.audience) {
    const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
    const payloadAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    
    // Verifica se há intersecção entre as audiências
    const hasValidAud = payloadAud.some(a => a && audiences.includes(a));
    if (!hasValidAud) {
      throw new Error(`Audience inválida. Esperado: ${audiences.join(', ')}, Recebido: ${payload.aud}`);
    }
  }
  
  if (options?.maxTokenAge && payload.iat) {
      const maxAge = parseTime(options.maxTokenAge);
      if (now - payload.iat > maxAge) {
           throw new Error(`Token excedeu a idade máxima permitida de ${options.maxTokenAge}.`);
      }
  }

  return { payload, protectedHeader };
}

// --- Utilitário de Geração de Chaves (Bônus) ---
export function generateKeyPair() {
  return crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// --- Exemplo de Uso estilo 'jose' (Descomente para rodar) ---
/*
(async () => {
  try {
    const { publicKey, privateKey } = generateKeyPair();

    // 1. Assinatura (Builder Pattern)
    const jwt = await new SignJWT({ 'urn:example:claim': true, userID: 123 })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt()
      .setIssuer('urn:system:issuer')
      .setAudience('urn:system:audience')
      .setExpirationTime('2h') // Expira em 2 horas
      .sign(privateKey);

    console.log('Token Gerado:', jwt);

    // 2. Verificação
    const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
      issuer: 'urn:system:issuer',
      audience: 'urn:system:audience',
    });

    console.log('Header Verificado:', protectedHeader);
    console.log('Payload Verificado:', payload);

  } catch (err) {
    console.error('Falha:', err);
  }
})();
*/