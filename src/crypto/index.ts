/**
 * @purecore-codes-codes/agent-zero-trust
 * Módulo Criptográfico - Signal Protocol, X3DH, Double Ratchet
 * 
 * Implementação zero-dependency do protocolo Signal para comunicação
 * end-to-end encriptada entre agentes autônomos.
 */

import * as crypto from 'node:crypto';

// ============================================================================
// Tipos e Interfaces
// ============================================================================

export interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface Ed25519KeyPair {
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
}

export interface KeyBundle {
  identityKey: Uint8Array;
  signedPreKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  oneTimePreKey?: Uint8Array;
  ephemeralKey?: Uint8Array;
}

export interface RatchetState {
  DHs: X25519KeyPair;
  DHr: Uint8Array | null;
  RK: Uint8Array;
  CKs: Uint8Array | null;
  CKr: Uint8Array | null;
  Ns: number;
  Nr: number;
  PN: number;
  MKSKIPPED: Map<string, Uint8Array>;
}

export interface SignalMessage {
  from: string;
  to: string;
  messageId: string;
  timestamp: number;
  header: {
    dh: string;
    pn: number;
    n: number;
  };
  ciphertext: string;
  nonce: string;
  jwt?: string;
}

// ============================================================================
// Constantes
// ============================================================================

const MAX_SKIP = 1000;

// ============================================================================
// Utilitários de Zeroização Segura
// ============================================================================

/**
 * Zeroização segura de buffers sensíveis
 * Usa abordagem volátil para prevenir otimização do compilador
 */
export function secureZero(buffer: Uint8Array): void {
  if (typeof buffer.fill === 'function') {
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = 0;
    }
  }
}

/**
 * Limpa múltiplos buffers de uma vez
 */
export function secureZeroMultiple(...buffers: Uint8Array[]): void {
  buffers.forEach(buf => secureZero(buf));
}

// ============================================================================
// Geração de Chaves
// ============================================================================

/**
 * Gera par de chaves X25519 para Diffie-Hellman
 */
export function generateX25519KeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  
  // Extrair apenas os bytes da chave (últimos 32 bytes)
  return {
    publicKey: new Uint8Array(publicKey.slice(-32)),
    privateKey: new Uint8Array(privateKey.slice(-32))
  };
}

/**
 * Gera par de chaves Ed25519 para assinaturas
 */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  return crypto.generateKeyPairSync('ed25519');
}

// ============================================================================
// Diffie-Hellman
// ============================================================================

/**
 * Computa Diffie-Hellman shared secret
 */
export function computeDH(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  // Reconstruir objetos de chave no formato DER
  const privKeyDer = Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'),
    Buffer.from(privateKey)
  ]);

  const pubKeyDer = Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'),
    Buffer.from(publicKey)
  ]);

  const privKeyObj = crypto.createPrivateKey({
    key: privKeyDer,
    format: 'der',
    type: 'pkcs8'
  });

  const pubKeyObj = crypto.createPublicKey({
    key: pubKeyDer,
    format: 'der',
    type: 'spki'
  });

  return new Uint8Array(crypto.diffieHellman({
    privateKey: privKeyObj,
    publicKey: pubKeyObj
  }));
}

// ============================================================================
// Key Derivation Functions
// ============================================================================

/**
 * HKDF - Hash-based Key Derivation Function (RFC 5869)
 */
export function hkdf(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Uint8Array {
  return new Uint8Array(crypto.hkdfSync('sha256', Buffer.from(inputKeyMaterial), Buffer.from(salt), Buffer.from(info), length));
}

/**
 * KDF para Root Chain - deriva novo RK e Chain Key
 */
export function kdfRK(rk: Uint8Array, dhOut: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const output = hkdf(dhOut, rk, Buffer.from('SignalRootRatchet'), 64);
  return {
    rootKey: output.slice(0, 32),
    chainKey: output.slice(32, 64)
  };
}

/**
 * KDF para Chain Key - deriva novo CK e Message Key
 */
export function kdfCK(ck: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  const chainKey = new Uint8Array(
    crypto.createHmac('sha256', Buffer.from(ck)).update(Buffer.from([0x01])).digest()
  );
  const messageKey = new Uint8Array(
    crypto.createHmac('sha256', Buffer.from(ck)).update(Buffer.from([0x02])).digest()
  );
  return { chainKey, messageKey };
}

// ============================================================================
// Encriptação AES-GCM
// ============================================================================

/**
 * Encripta mensagem usando AES-256-GCM
 */
export function encrypt(plaintext: string | Uint8Array, key: Uint8Array): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = crypto.randomBytes(12);
  const plaintextBuffer = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : Buffer.from(plaintext);
  
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), nonce);
  const encrypted = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  
  return {
    ciphertext: new Uint8Array(Buffer.concat([encrypted, authTag])),
    nonce: new Uint8Array(nonce)
  };
}

/**
 * Decripta mensagem usando AES-256-GCM
 */
export function decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): string {
  const authTag = Buffer.from(ciphertext.slice(-16));
  const encrypted = Buffer.from(ciphertext.slice(0, -16));
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
  decipher.setAuthTag(authTag);
  
  return decipher.update(encrypted) + decipher.final('utf8');
}

// ============================================================================
// X3DH Key Agreement Protocol
// ============================================================================

export class X3DHKeyBundle {
  readonly identityKey: X25519KeyPair;
  readonly signedPreKey: X25519KeyPair;
  readonly signedPreKeySignature: Uint8Array;
  readonly oneTimePreKeys: X25519KeyPair[];

  constructor() {
    this.identityKey = generateX25519KeyPair();
    this.signedPreKey = generateX25519KeyPair();
    
    const { privateKey } = generateEd25519KeyPair();
    this.signedPreKeySignature = new Uint8Array(
      crypto.sign(null, Buffer.from(this.signedPreKey.publicKey), privateKey)
    );
    
    this.oneTimePreKeys = Array.from({ length: 10 }, () => generateX25519KeyPair());
  }

  getPublicBundle(): KeyBundle {
    const oneTimePreKey = this.oneTimePreKeys.shift();
    const bundle: KeyBundle = {
      identityKey: this.identityKey.publicKey,
      signedPreKey: this.signedPreKey.publicKey,
      signedPreKeySignature: this.signedPreKeySignature
    };
    if (oneTimePreKey) {
      bundle.oneTimePreKey = oneTimePreKey.publicKey;
    }
    return bundle;
  }

  performX3DHAsReceiver(
    ephemeralKey: Uint8Array,
    senderIdentityKey: Uint8Array,
    usedOneTimePreKey: boolean
  ): Uint8Array {
    const dh1 = computeDH(this.signedPreKey.privateKey, senderIdentityKey);
    const dh2 = computeDH(this.identityKey.privateKey, ephemeralKey);
    const dh3 = computeDH(this.signedPreKey.privateKey, ephemeralKey);

    let masterSecret: Uint8Array;
    if (usedOneTimePreKey && this.oneTimePreKeys.length > 0) {
      const otpk = this.oneTimePreKeys[0]!;
      const dh4 = computeDH(otpk.privateKey, ephemeralKey);
      masterSecret = Buffer.concat([Buffer.from(dh1), Buffer.from(dh2), Buffer.from(dh3), Buffer.from(dh4)]);
    } else {
      masterSecret = Buffer.concat([Buffer.from(dh1), Buffer.from(dh2), Buffer.from(dh3)]);
    }

    const result = hkdf(masterSecret, Buffer.alloc(32), Buffer.from('X3DH'), 32);
    secureZero(masterSecret);
    return result;
  }

  destroy(): void {
    secureZero(this.identityKey.privateKey);
    secureZero(this.signedPreKey.privateKey);
    this.oneTimePreKeys.forEach(k => secureZero(k.privateKey));
  }
}

/**
 * Executa X3DH como iniciador (Alice)
 */
export function performX3DHAsInitiator(
  identityKey: X25519KeyPair,
  ephemeralKey: X25519KeyPair,
  receiverBundle: KeyBundle
): Uint8Array {
  const dh1 = computeDH(identityKey.privateKey, receiverBundle.signedPreKey);
  const dh2 = computeDH(ephemeralKey.privateKey, receiverBundle.identityKey);
  const dh3 = computeDH(ephemeralKey.privateKey, receiverBundle.signedPreKey);

  let masterSecret: Uint8Array;
  if (receiverBundle.oneTimePreKey) {
    const dh4 = computeDH(ephemeralKey.privateKey, receiverBundle.oneTimePreKey);
    masterSecret = Buffer.concat([Buffer.from(dh1), Buffer.from(dh2), Buffer.from(dh3), Buffer.from(dh4)]);
  } else {
    masterSecret = Buffer.concat([Buffer.from(dh1), Buffer.from(dh2), Buffer.from(dh3)]);
  }

  const result = hkdf(masterSecret, Buffer.alloc(32), Buffer.from('X3DH'), 32);
  secureZero(masterSecret);
  return result;
}

// ============================================================================
// Double Ratchet
// ============================================================================

export class DoubleRatchet {
  private state: RatchetState;

  constructor() {
    this.state = {
      DHs: generateX25519KeyPair(),
      DHr: null,
      RK: Buffer.alloc(32),
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      MKSKIPPED: new Map()
    };
  }

  initializeAsAlice(sharedSecret: Uint8Array, bobRatchetPublicKey: Uint8Array): void {
    this.state.DHs = generateX25519KeyPair();
    this.state.DHr = bobRatchetPublicKey;

    const dhOutput = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey, chainKey } = kdfRK(sharedSecret, dhOutput);
    secureZero(dhOutput);

    this.state.RK = rootKey;
    this.state.CKs = chainKey;
    this.state.CKr = null;
    this.state.Ns = 0;
    this.state.Nr = 0;
    this.state.PN = 0;
  }

  initializeAsBob(sharedSecret: Uint8Array): void {
    this.state.DHs = generateX25519KeyPair();
    this.state.DHr = null;
    this.state.RK = sharedSecret;
    this.state.CKs = null;
    this.state.CKr = null;
    this.state.Ns = 0;
    this.state.Nr = 0;
    this.state.PN = 0;
  }

  ratchetEncrypt(plaintext: string): { 
    header: SignalMessage['header']; 
    ciphertext: Uint8Array; 
    nonce: Uint8Array 
  } {
    if (!this.state.CKs) {
      throw new Error('Sending chain não inicializada');
    }

    const { chainKey, messageKey } = kdfCK(this.state.CKs);
    this.state.CKs = chainKey;

    const header = {
      dh: Buffer.from(this.state.DHs.publicKey).toString('hex'),
      pn: this.state.PN,
      n: this.state.Ns
    };

    this.state.Ns++;

    const { ciphertext, nonce } = encrypt(plaintext, messageKey);
    secureZero(messageKey);

    return { header, ciphertext, nonce };
  }

  ratchetDecrypt(
    header: SignalMessage['header'], 
    ciphertext: Uint8Array, 
    nonce: Uint8Array
  ): string {
    const dhPublicKey = Buffer.from(header.dh, 'hex');

    const skippedKey = this.trySkippedMessageKeys(header, dhPublicKey);
    if (skippedKey) {
      try {
        const plaintext = decrypt(ciphertext, skippedKey, nonce);
        secureZero(skippedKey);
        return plaintext;
      } catch {
        secureZero(skippedKey);
        throw new Error('Falha ao descriptografar mensagem pulada');
      }
    }

    if (!this.state.DHr || !Buffer.from(dhPublicKey).equals(Buffer.from(this.state.DHr))) {
      this.skipMessageKeys(header.pn);
      this.dhRatchet(dhPublicKey);
    }

    this.skipMessageKeys(header.n);

    if (!this.state.CKr) {
      throw new Error('Receiving chain não inicializada');
    }

    const { chainKey, messageKey } = kdfCK(this.state.CKr);
    this.state.CKr = chainKey;
    this.state.Nr++;

    const plaintext = decrypt(ciphertext, messageKey, nonce);
    secureZero(messageKey);

    return plaintext;
  }

  getPublicKey(): Uint8Array {
    return this.state.DHs.publicKey;
  }

  private dhRatchet(dhPublicKey: Uint8Array): void {
    this.state.PN = this.state.Ns;
    this.state.Ns = 0;
    this.state.Nr = 0;
    this.state.DHr = dhPublicKey;

    const dhOutput1 = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey: rk1, chainKey: ckr } = kdfRK(this.state.RK, dhOutput1);
    this.state.RK = rk1;
    this.state.CKr = ckr;
    secureZero(dhOutput1);

    this.state.DHs = generateX25519KeyPair();
    const dhOutput2 = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey: rk2, chainKey: cks } = kdfRK(this.state.RK, dhOutput2);
    this.state.RK = rk2;
    this.state.CKs = cks;
    secureZero(dhOutput2);
  }

  private skipMessageKeys(until: number): void {
    if (!this.state.CKr) return;

    if (this.state.Nr + MAX_SKIP < until) {
      throw new Error('Muitas mensagens puladas');
    }

    while (this.state.Nr < until) {
      const { chainKey, messageKey } = kdfCK(this.state.CKr);
      this.state.CKr = chainKey;

      const key = `${Buffer.from(this.state.DHr!).toString('hex')}-${this.state.Nr}`;
      this.state.MKSKIPPED.set(key, messageKey);

      this.state.Nr++;
    }
  }

  private trySkippedMessageKeys(
    header: SignalMessage['header'], 
    dhPublicKey: Uint8Array
  ): Uint8Array | null {
    const key = `${Buffer.from(dhPublicKey).toString('hex')}-${header.n}`;
    const messageKey = this.state.MKSKIPPED.get(key);

    if (messageKey) {
      this.state.MKSKIPPED.delete(key);
      return messageKey;
    }

    return null;
  }

  destroy(): void {
    secureZero(this.state.DHs.privateKey);
    secureZero(this.state.RK);
    if (this.state.CKs) secureZero(this.state.CKs);
    if (this.state.CKr) secureZero(this.state.CKr);
    this.state.MKSKIPPED.forEach((key, _) => secureZero(key));
    this.state.MKSKIPPED.clear();
  }
}

// ============================================================================
// JWK Thumbprint (RFC 7638)
// ============================================================================

export interface JWK {
  kty: string;
  crv: string;
  x: string;
  y?: string;
  kid?: string;
}

/**
 * Converte chave pública Ed25519/X25519 para formato JWK
 */
export function publicKeyToJWK(publicKey: Uint8Array, crv: 'Ed25519' | 'X25519' = 'Ed25519'): JWK {
  const base64url = Buffer.from(publicKey).toString('base64url');
  
  return {
    kty: 'OKP',
    crv,
    x: base64url
  };
}

/**
 * Computa JWK Thumbprint conforme RFC 7638
 */
export function computeJWKThumbprint(jwk: JWK): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    ...(jwk.y && { y: jwk.y })
  });
  
  const hash = crypto.createHash('sha256').update(canonical).digest('base64url');
  return hash;
}

// ============================================================================
// Bloom Filter para CRL
// ============================================================================

export interface BloomFilterCRL {
  filter: Uint8Array;
  hashFunctions: number;
  itemCount: number;
  falsePositiveRate: number;
  generatedAt: string;
  crlGeneration: number;
}

export class BloomFilter {
  private bits: Uint8Array;
  private numHashFunctions: number;

  constructor(sizeInBytes: number, numHashFunctions: number) {
    this.bits = new Uint8Array(sizeInBytes);
    this.numHashFunctions = numHashFunctions;
  }

  private hash(item: string, seed: number): number {
    const hash = crypto.createHash('sha256')
      .update(item)
      .update(Buffer.from([seed]))
      .digest();
    return hash.readUInt32LE(0);
  }

  add(item: string): void {
    for (let i = 0; i < this.numHashFunctions; i++) {
      const hash = this.hash(item, i);
      const bitIndex = hash % (this.bits.length * 8);
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = bitIndex % 8;
      this.bits[byteIndex] = this.bits[byteIndex]! | (1 << bitPosition);
    }
  }

  has(item: string): boolean {
    for (let i = 0; i < this.numHashFunctions; i++) {
      const hash = this.hash(item, i);
      const bitIndex = hash % (this.bits.length * 8);
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = bitIndex % 8;
      
      if ((this.bits[byteIndex]! & (1 << bitPosition)) === 0) {
        return false;
      }
    }
    return true;
  }

  toBytes(): Uint8Array {
    return this.bits;
  }

  static fromBytes(bytes: Uint8Array, numHashFunctions: number): BloomFilter {
    const filter = new BloomFilter(bytes.length, numHashFunctions);
    filter.bits = bytes;
    return filter;
  }

  static optimalParams(itemCount: number, falsePositiveRate: number): { sizeInBytes: number; numHashFunctions: number } {
    const m = Math.ceil(-(itemCount * Math.log(falsePositiveRate)) / (Math.log(2) ** 2));
    const k = Math.round((m / itemCount) * Math.log(2));
    
    return {
      sizeInBytes: Math.ceil(m / 8),
      numHashFunctions: Math.max(1, k)
    };
  }
}

/**
 * Cria Bloom Filter para CRL distribuída
 */
export function createBloomFilterForCRL(
  revokedDIDs: string[],
  falsePositiveRate: number = 0.01
): BloomFilterCRL {
  const { sizeInBytes, numHashFunctions } = BloomFilter.optimalParams(
    revokedDIDs.length,
    falsePositiveRate
  );

  const filter = new BloomFilter(sizeInBytes, numHashFunctions);
  revokedDIDs.forEach(did => filter.add(did));

  return {
    filter: filter.toBytes(),
    hashFunctions: numHashFunctions,
    itemCount: revokedDIDs.length,
    falsePositiveRate,
    generatedAt: new Date().toISOString(),
    crlGeneration: Date.now()
  };
}

/**
 * Verifica se DID está revogado usando Bloom Filter
 */
export async function isRevoked(
  did: string,
  bloomFilter: BloomFilterCRL,
  fullCRL?: string[]
): Promise<boolean> {
  const filter = BloomFilter.fromBytes(bloomFilter.filter, bloomFilter.hashFunctions);
  
  if (!filter.has(did)) {
    return false; // Definitivamente não revogado
  }
  
  if (fullCRL) {
    return fullCRL.includes(did); // Verificar falso positivo
  }
  
  throw new Error('Bloom filter positivo, CRL completa necessária');
}
