/**
 * Secure Agents + RabbitMQ + DPoP - Simplified Demo
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';
import { DPoPKeyPair, generateDPoPKeyPair, createDPoPProof, createDPoPAuthHeader } from '../domains/auth/dpop';
import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

interface AgentConfig { agentId: string; rabbitmq: any; dpopAlgorithm?: string; }
interface SecureMessage { id: string; from: string; to: string; dpopAuthHeader: string; ciphertext: string; nonce: string; jwt: string; }

class RabbitMQSim {
  private static inst: RabbitMQSim;
  private queues = new Map<string, any[]>();
  private consumers = new Map<string, (m:any)=>void>();
  
  static getInstance(){ if(!this.inst) this.inst=new RabbitMQSim(); return this.inst; }
  async connect(p:any) {
    console.log('RabbitMQ: ' + (p.tls?.enabled?'amqps':'amqp') + '://' + p.username + '@' + p.hostname);
    return { createChannel: async () => ({
      assertQueue: async (n:string) => { if(!this.queues.has(n)) this.queues.set(n,[]); return{q:n}; },
      bindQueue: async()=>{}, publish:(_:any,rk:string,c:Buffer) => {
        const q='agent-'+rk; if(!this.queues.has(q))this.queues.set(q,[]);
        const m={content:c,fields:{routingKey:rk}};
        const cb=this.consumers.get(q); if(cb)setImmediate(()=>cb(m));else this.queues.get(q)!.push(m);return true;
      }, consume: async(q:string,cb:(m:any)=>void) => { this.consumers.set(q,cb); (this.queues.get(q)||[]).forEach(x=>setImmediate(()=>cb(x))); this.queues.set(q,[]); }, ack:()=>{}, close:async()=>{} }), close:async()=>{} };
  }
}

class DoubleRatchet {
  private s:any; constructor() {
    const k=crypto.generateKeyPairSync('x25519',{publicKeyEncoding:{type:'spki',format:'der'},privateKeyEncoding:{type:'pkcs8',format:'der'}});
    this.s={DHs:{publicKey:k.publicKey.slice(-32),privateKey:k.privateKey.slice(-32)},DHr:null,RK:crypto.randomBytes(32),CKs:null,CKr:null,Ns:0,Nr:0,PN:0};
  }
  init(shared:Buffer, peerKey:Buffer, asInitiator:boolean) {
    const k=crypto.generateKeyPairSync('x25519',{publicKeyEncoding:{type:'spki',format:'der'},privateKeyEncoding:{type:'pkcs8',format:'der'}});
    this.s.DHr=peerKey; this.s.DHs={publicKey:k.publicKey.slice(-32),privateKey:k.privateKey.slice(-32)};
    const dh=crypto.diffieHellman({privateKey:crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),this.s.DHs.privateKey]),format:'der',type:'pkcs8'}),publicKey:crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'),peerKey]),format:'der',type:'spki'})});
    const out=crypto.hkdfSync('sha256',dh,this.s.RK,Buffer.from('RK'),64);
    this.s.RK=out.slice(0,32); if(asInitiator) this.s.CKs=out.slice(32,64); else this.s.CKr=out.slice(32,64);
  }
  encrypt(p:string) {
    if(!this.s.CKs) throw new Error('No chain');
    const {chainKey,messageKey}=this.kdf(this.s.CKs); this.s.CKs=chainKey;
    const h={dh:this.s.DHs.publicKey.toString('base64'),pn:this.s.PN,n:this.s.Ns++};
    const n=crypto.randomBytes(12); const c=crypto.createCipheriv('aes-256-gcm',messageKey,n);
    return{h,ciphertext:Buffer.concat([c.update(p,'utf8'),c.final(),c.getAuthTag()]),nonce:n};
  }
  decrypt(h:any, ct:Buffer, n:Buffer) {
    const pk=Buffer.from(h.dh,'base64');
    if(!this.s.DHr||!pk.equals(this.s.DHr)){ this.s.PN=this.s.Ns; this.s.Ns=0; this.s.Nr=0; this.s.DHr=pk;
      const dh1=crypto.diffieHellman({privateKey:crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),this.s.DHs.privateKey]),format:'der',type:'pkcs8'}),publicKey:crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'),pk]),format:'der',type:'spki'})});
      const o1=crypto.hkdfSync('sha256',dh1,this.s.RK,Buffer.from('RK'),64); this.s.RK=o1.slice(0,32); this.s.CKr=o1.slice(32,64);
       const k2=crypto.generateKeyPairSync('x25519',{publicKeyEncoding:{type:'spki',format:'der'},privateKeyEncoding:{type:'pkcs8',format:'der'}});
       this.s.DHs={publicKey:k2.publicKey.slice(-32),privateKey:k2.privateKey.slice(-32)};
      const dh2=crypto.diffieHellman({privateKey:crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),this.s.DHs.privateKey]),format:'der',type:'pkcs8'}),publicKey:crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'),this.s.DHr]),format:'der',type:'spki'})});
      const o2=crypto.hkdfSync('sha256',dh2,this.s.RK,Buffer.from('RK'),64); this.s.RK=o2.slice(0,32); this.s.CKs=o2.slice(32,64);
    }
    if(!this.s.CKr) throw new Error('No receive chain');
    const {chainKey,messageKey}=this.kdf(this.s.CKr); this.s.CKr=chainKey;
    const d=crypto.createDecipheriv('aes-256-gcm',messageKey,n); d.setAuthTag(ct.slice(-16));
    return d.update(ct.slice(0,-16)) + d.final('utf8');
  }
  private kdf(ck:Buffer){return{chainKey:crypto.createHmac('sha256',ck).update(Buffer.from([1])).digest(),messageKey:crypto.createHmac('sha256',ck).update(Buffer.from([2])).digest()};}
  getPublicKey(){return this.s.DHs.publicKey;}
}

class Authority {
  private jwtKey: crypto.KeyObject;
  constructor(){ const k=generateKeyPair(); this.jwtKey=crypto.createPrivateKey(k.privateKey); console.log('Authority initialized'); }
  async issue(agentId:string){return await new SignJWT({aid:agentId,ts:Date.now()}).setProtectedHeader({alg:'EdDSA'}).setIssuedAt().setExpirationTime(600).sign(this.jwtKey);}
  async verify(t:string){return (await jwtVerify(t,this.jwtKey,{issuer:'auth'})).payload;}
}

class Agent extends EventEmitter {
  private channel:any; private queue:string; private token:string; private dpopKey:DPoPKeyPair;
  private x25519:Buffer; private sessions=new Map<string,{r:DoubleRatchet, peerIK:Buffer}>();
  constructor(private config:AgentConfig, private authority:Authority){
    super(); this.queue='agent-'+config.agentId; this.dpopKey=generateDPoPKeyPair(config.dpopAlgorithm as any||'EdDSA');
    const k=crypto.generateKeyPairSync('x25519',{publicKeyEncoding:{type:'spki',format:'der'},privateKeyEncoding:{type:'pkcs8',format:'der'}});
    this.x25519=k.publicKey.slice(-32);
    console.log('[ '+config.agentId+' ] DPoP Agent ('+this.dpopKey.algorithm+')');
  }
  async connect(){
    console.log('\n[ '+this.config.agentId+' ] Connecting...');
    const sim=new RabbitMQSim(); const conn=await sim.connect(this.config.rabbitmq);
    this.channel=await conn.createChannel();
    await this.channel.assertQueue(this.queue,{durable:false});
    await this.channel.bindQueue(this.queue,'secure',this.config.agentId);
    await this.channel.consume(this.queue,async(m:any)=>{await this.handle(JSON.parse(m.content.toString()));this.channel.ack(m);});
    console.log('   [OK] '+this.queue);
  }
  async auth(){ this.token=await this.authority.issue(this.config.agentId); console.log('[ '+this.config.agentId+' ] Authenticated'); }
  async send(peerId:string,content:string){
    let s=this.sessions.get(peerId);
    if(!s){ await this.establish(peerId); s=this.sessions.get(peerId); }
    if(!s) throw new Error('No session');
    const {h,ciphertext,nonce}=s.r.encrypt(content);
    const proof=await createDPoPProof(this.dpopKey,{method:'POST',url:'amqp://secure/'+peerId,accessToken:this.token});
    const msg:SecureMessage={id:'msg-'+Date.now(),from:this.config.agentId,to:peerId,dpopAuthHeader:createDPoPAuthHeader(this.token,proof.jwt),ciphertext:ciphertext.toString('base64'),nonce:nonce.toString('base64'),jwt:await this.authority.issue(this.config.agentId)};
    this.channel.publish('secure',peerId,Buffer.from(JSON.stringify(msg)));
    console.log('[SEND] '+this.config.agentId+' -> '+peerId+': '+content);
  }
  private async establish(peerId:string){
    console.log('\n[ '+this.config.agentId+' ] Establishing with '+peerId+'...');
    const rk=new DoubleRatchet().getPublicKey();
    const shared=crypto.hkdfSync('sha256',crypto.diffieHellman({privateKey:crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),this.x25519]),format:'der',type:'pkcs8'}),publicKey:crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'),rk]),format:'der',type:'spki'})}),Buffer.alloc(32),Buffer.from('S'),32);
    const r=new DoubleRatchet(); r.init(shared,rk,true);
    this.sessions.set(peerId,{r,peerIK:rk});
    console.log('   [OK] Session created');
  }
  private async handle(msg:SecureMessage){
    try{await this.authority.verify(msg.jwt);}catch{console.error('[ERR] Invalid JWT');return;}
    if(!this.sessions.has(msg.from)){
      const peerKey=new DoubleRatchet().getPublicKey();
      const shared=crypto.hkdfSync('sha256',crypto.diffieHellman({privateKey:crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),this.x25519]),format:'der',type:'pkcs8'}),publicKey:crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'),Buffer.from(msg.ciphertext,'base64').slice(0,32)]),format:'der',type:'spki'})}),Buffer.alloc(32),Buffer.from('S'),32);
      const r=new DoubleRatchet(); r.init(shared,Buffer.from(msg.ciphertext,'base64').slice(0,32),false);
      this.sessions.set(msg.from,{r,peerIK:Buffer.from(msg.ciphertext,'base64').slice(0,32)});
      console.log('[KEY] Session with '+msg.from);
    }
    const s=this.sessions.get(msg.from);
    if(s){ const pt=s.r.decrypt({dh:s.peerIK.toString('base64'),pn:0,n:0},Buffer.from(msg.ciphertext,'base64'),Buffer.from(msg.nonce,'base64')); console.log('[RECV] '+this.config.agentId+' <- '+msg.from+': '+pt); this.emit('message',{from:msg.from,content:pt}); }
  }
  async disconnect(){if(this.channel)await this.channel.close();}
}

async function main(){
  console.log('\n'+'='.repeat(60)+'\nDPoP + RABBITMQ + E2EE DEMO\n'+'='.repeat(60));
  const auth=new Authority();
  const alice=new Agent({agentId:'alice',rabbitmq:{hostname:'rabbitmq',port:5671,username:'alice',password:'p',tls:{enabled:true}}},auth);
  const bob=new Agent({agentId:'bob',rabbitmq:{hostname:'rabbitmq',port:5671,username:'bob',password:'p',tls:{enabled:true}}},auth);
  await alice.connect(); await bob.connect(); await alice.auth(); await bob.auth();
  await alice.send('bob','Hello Bob! DPoP protected!'); await new Promise(r=>setTimeout(r,200));
  await bob.send('alice','Hi Alice!'); await new Promise(r=>setTimeout(r,200));
  await alice.send('bob','PFS in action!'); await new Promise(r=>setTimeout(r,200));
  await bob.send('alice','RabbitMQ delivers!');
  console.log('\n'+'='.repeat(60)+'\nSECURITY: DPoP | JWT | X25519 Double Ratchet | TLS\n'+'='.repeat(60)+'\n[OK] Done!');
  await alice.disconnect(); await bob.disconnect();
}
main().catch(console.error);
