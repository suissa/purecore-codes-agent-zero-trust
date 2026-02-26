# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

---

## [Release] v2.0.0 - 2026-02-26

### What's Changed

* **🏰 Reconstrução Massiva do README (Deep Dives)**
  - Expansão detalhada de todos os 6 pilares tecnológicos do framework.
  - **A2A**: Detalhamento da máquina de estados de Tasks e Streaming de Tokens.
  - **DPoP**: Explicação técnica do mecanismo `ath` e estratégia de **Promise Latching** para resiliência de rede.
  - **Multi-Party E2EE**: Detalhamento do gerenciamento de Épocas (Epochs) e rotação de chaves de grupo.
  - **Secure Agents**: Decomposição do handshake tri-layer (mTLS + X3DH + JWT).
  - **RabbitMQ**: Definição da arquitetura de **Zero-Trust Brokerage**.
  - **Signal Protocol**: Explicação do funcionamento interno do Double Ratchet (DH & Symmetric Ratchets).

* **💎 Foco em Soberania Digital**
  - Reforço da filosofia zero-dependency e uso do runtime Bun para performance e segurança.

---

## [Release] v1.9.0 - 2026-02-26


### What's Changed

* **🔬 Publicação de Artigo Científico: Agentic Zero Trust**
  - Criação do paper formal `docs/AGENTIC_ZERO_TRUST_PAPER.md`.
  - Fundamentação teórica do modelo de Defesa em Profundidade (Tri-Layer).
  - Análise de mitigação de ameaças (MITM, Replay, Broker Compromise).
  - Definição formal do conceito de "Zero-Trust Brokerage" e "Sovereign AI Infrastructure".

---

## [Release] v1.8.0 - 2026-02-26


### What's Changed

* **🏰 Expansão da Documentação Técnica (6 Pilares)**
  - Reconstrução do README para focar nos 6 pilares de segurança e infraestrutura.
  - **A2A Protocol**: Detalhamento de Agent Cards, Tasks e Bindings.
  - **DPoP (RFC 9449)**: Explicação de Proof-of-Possession e Promise Latching.
  - **Multi-Party E2EE**: Introdução de criptografia de grupo para enxames de agentes.
  - **Secure Agents**: Handshake unificado mTLS + E2EE + JWT.
  - **RabbitMQ Integration**: Arquitetura distribuída Zero-Trust.
  - **Signal Protocol**: Deep-dive no Double Ratchet (PFS/PCS).

* **🔥 Remoção de Funcionalidades Obsoletas da Documentação**
  - Remoção da seção de Self-Healing para priorizar os pilares de segurança core.

---

## [Release] v1.7.0 - 2026-02-26


### What's Changed

* **📚 Reconstrução completa do README.md**
  - Integração de todos os exemplos da pasta `examples/`
  - Abordagem de blog post técnico premium
  - Detalhamento de camadas de segurança (mTLS, E2EE, JWT)
  - Seções de "Como foi feito", "Como funciona" e "Como testar"

* **✨ Unificação de Exemplos**
  - Documentação consolidada das capacidades de agentes autônomos
  - Destaque para o sistema Self-Healing e Double Ratchet

---

## [Release] v1.6.0 - 2026-02-23


### What's Changed

* **📚 Unificação da documentação de funcionalidades**
  - Reconstrução completa do `readme.md` principal
  - Inclusão de todas as novas funcionalidades de segurança de agentes
  - Adição de seções de conceito, problema, quando usar e exemplos
  - Inclusão de post de blog técnico sobre a arquitetura

* **Novas Funcionalidades Documentadas**
  - 🔑 **DPoP (RFC 9449)**: Sender-constraining para access tokens
  - 🏦 **FAPI 2.0**: Padrões financeiros ultra-seguros (PAR, PKCE)
  - 👥 **Multi-Party E2EE**: Encriptação de grupo para múltiplos agentes
  - 🏷️ **Semantic Types**: Tipagem nominal para segurança em tempo de execução
  - 🛡️ **Resilient Tokens**: Gerenciador de tokens auto-recuperável com promise latching
  - ✅ **Rigorous Validations**: Validações de domínio fast-fail para HTTP e Auth

* **Melhorias de Documentação**
  - Melhor organização visual e navegabilidade
  - Explicações conceituais profundas (Deep Dives)
  - Exemplos de código atualizados e testados

---

## [Release] v1.5.0 - 2025-12-24

### What's Changed

* **🏰 Renomeação para Agentic NetworkFortress**
  - Nome do pacote mudado de `@purecore/agentic-channelfortress` para `@purecore/agentic-networkfortress`
  - Melhor reflexão da arquitetura de rede distribuída
  - Suporte completo a comunicação entre agentes em processos/máquinas diferentes
  - Conceito de "fortress" (fortaleza) reforça a defesa em profundidade

### Arquitetura

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Agentic NetworkFortress                          │
│                🏰 Rede de Comunicação Ultra-Segura                   │
│                                                                     │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │   Agent A       │    │   Agent B       │    │   Agent C       │  │
│  │  (Processo 1)   │◀──▶│  (Processo 2)   │◀──▶│  (Processo N)   │  │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘  │
│         │                           │                           │     │
│         └───────────────────────────┼───────────────────────────┘     │
│                                   🔐                                │
│                          Defense in Depth                          │
│                    (mTLS + E2EE + JWT)                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## [Release] v1.4.0 - 2024-12-22

### What's Changed

* **🐰 Secure Agents + RabbitMQ**
  - Comunicação distribuída ultra-segura via RabbitMQ
  - Agentes podem estar em processos/máquinas diferentes
  - Key exchange automático via filas RabbitMQ
  - Suporte a TLS para conexão com broker
  - Mantém todas as camadas de segurança (E2EE + JWT)

* **Novos Arquivos**
  - `examples/secure-agents-rabbitmq.ts` - Implementação com RabbitMQ
  - `examples/SECURE_AGENTS_RABBITMQ.md` - Documentação completa

### Arquitetura

```
┌──────────────────────────────────────────────────────────┐
│                    RabbitMQ (TLS)                        │
│  ┌────────────────┐         ┌────────────────┐           │
│  │ agent-alice    │         │ agent-bob      │           │
│  └────────────────┘         └────────────────┘           │
└──────────────────────────────────────────────────────────┘
         │                            │
    ┌────▼────┐                  ┌────▼────┐
    │ Alice   │◀────── E2EE ────▶│ Bob     │
    │ (Proc A)│                  │ (Proc B)│
    └─────────┘                  └─────────┘
```

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

- [Secure Agents + RabbitMQ](./examples/SECURE_AGENTS_RABBITMQ.md) 🐰 **Distribuído**
- [Secure Agents (E2EE + mTLS)](./examples/SECURE_AGENTS.md) ⭐ **Recomendado**
- [Signal E2EE](./examples/SIGNAL_E2EE.md)
- [mTLS](./examples/MTLS_AGENTS.md)
- [Self-Healing](./examples/SELF_HEALING_AGENTS.md)
