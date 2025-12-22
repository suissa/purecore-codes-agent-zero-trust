# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

---

## [Release] v1.3.0 - 2024-12-22

### What's Changed

* **🔐 Secure Agents - Comunicação Ultra-Segura**
  - Nova API simplificada combinando E2EE + mTLS + JWT
  - Apenas 10 linhas para máxima segurança
  - 3 camadas de proteção em defesa em profundidade
  - SecurityAuthority para gerenciamento centralizado
  - SecureAgent com API intuitiva (.connect, .send)

* **Novos Arquivos**
  - `examples/secure-agents.ts` - Implementação unificada
  - `examples/SECURE_AGENTS.md` - Documentação completa

### Melhorias

* API mais simples mantendo segurança máxima
* Conexão automática estabelece todas as camadas
* Eventos para recebimento de mensagens

---

## [Release] v1.2.0 - 2024-12-22

### What's Changed

* **Signal Protocol E2EE para Agentes**
  - Implementação completa do Double Ratchet Algorithm do Signal Protocol
  - Suporte a X3DH (Extended Triple Diffie-Hellman) para key agreement
  - Criptografia AES-256-GCM para mensagens
  - Perfect Forward Secrecy (PFS) por mensagem
  - Post-Compromise Security (PCS)
  - Integração com sistema de JWT existente

* **Documentação Completa**
  - Novo arquivo `examples/SIGNAL_E2EE.md` com explicação detalhada
  - Comparação entre Signal E2EE e mTLS
  - Guia de como usar ambos em conjunto
  - Referências para especificações oficiais

* **Novos Arquivos**
  - `examples/signal-e2ee-agents.ts` - Implementação do protocolo
  - `examples/SIGNAL_E2EE.md` - Documentação completa
  - `CHANGELOG.md` - Este arquivo
  - `reports/` - Pasta para relatórios

### New Contributors

* Implementação baseada nas especificações oficiais do Signal Protocol

---

## [Release] v1.1.0 - 2024-12-21

### What's Changed

* **mTLS para Agentes**
  - Implementação de mutual TLS para autenticação de transporte
  - Certificate Authority (CA) para geração de certificados
  - Suporte a conexões TLS bidirecionais
  - Integração com JWT para autenticação dupla

* **Documentação**
  - `examples/MTLS_AGENTS.md` - Guia de uso do mTLS

### Arquivos Adicionados

- `examples/mtls-agents.ts`
- `examples/MTLS_AGENTS.md`

---

## [Release] v1.0.0 - 2024-12-20

### What's Changed

* **Self-Healing Agents**
  - Sistema de renovação automática de tokens JWT
  - Suporte a conversação entre agentes com JWT
  - Token Authority centralizada

* **Core JWT**
  - Implementação de SignJWT com builder pattern
  - Função jwtVerify compatível com jose
  - Suporte exclusivo a EdDSA (Ed25519)
  - Geração de pares de chaves

### Arquivos Base

- `src/index.ts` - Core da biblioteca
- `examples/self-healing-agents.ts`
- `examples/SELF_HEALING_AGENTS.md`

---

## Links

- [Documentação Secure Agents (E2EE + mTLS)](./examples/SECURE_AGENTS.md) ⭐ **Recomendado**
- [Documentação Signal E2EE](./examples/SIGNAL_E2EE.md)
- [Documentação mTLS](./examples/MTLS_AGENTS.md)
- [Documentação Self-Healing](./examples/SELF_HEALING_AGENTS.md)
