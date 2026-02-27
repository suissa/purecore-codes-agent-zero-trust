
# Sentinel: Arquitetura de Segurança Determinística para Ecossistemas de Agentes Autônomos

> Esse artigo foi escrito em Setembro de 2025.

## Resumo Executivo

O **Sentinel** é um framework de segurança *Zero-Trust* e *Secure-by-Design* concebido para mitigar os riscos inerentes à comunicação entre agentes de IA distribuídos. Ele representa a fusão técnica e estratégica de três pilares da stack `@purecore`: **Agent-Zero-Trust**, **One-EventSourcing-4-All** e **One-JWT-4-All**. Ao fundir Criptografia de Ponta-a-Ponta (E2EE), Autenticação *Proof-of-Possession* (DPoP) e Tipagem Semântica Nominal, o Sentinel estabelece um ambiente de execução onde a confiança não é presumida, mas sim verificada matematicamente em cada transação. O resultado é um sistema imutável, auditável e resiliente a ataques de personificação e interceptação.

---

## 1. O Problema da Confiança em Sistemas Multi-Agente (MAS)

A proliferação de agentes autônomos introduz uma superfície de ataque crítica: a **interdependência comunicacional**. Em redes distribuídas, a identidade é fluida e tokens de acesso tradicionais (*Bearer Tokens*) são vulneráveis a exfiltração. 

O Sentinel aborda o "Custo da Desconfiança" através da integração modular de quatro sistemas especialistas:
- **Agent-Zero-Trust**: Protocolo criptográfico de comunicação segura (Signal E2EE).
- **One-EventSourcing-4-All**: Captura transparente de ações e mutações de estado via proxies.
- **One-JWT-4-All**: Autenticação forte via DPoP (Demonstration of Proof-of-Possession).
- **One-Evidence-4-All**: Cadeia de custódia e geração de provas (merkle proofs) embutidas nos envelopes decriptados.

Essa fusão move a validação para a borda (*Edge Validation*), eliminando a necessidade de autoridades centrais constantes.

---

## 2. Pilares Arquiteturais: A Anatomia do Sentinel

### 2.1 Módulo `crypto`: Primitivas de Sigilo e Resiliência

Diferente de implementações TLS padrão, o Sentinel foca em **Segredo Adiante Perfeito (PFS)** e **Recuperação Pós-Comprometimento**.

* **Protocolos**: Implementação do `X3DH` (Extended Triple Diffie-Hellman) para estabelecimento de chaves e `Double Ratchet` para derivação contínua de chaves de sessão.
* **Determinismo**: Utiliza curvas elípticas de alta performance ($X25519$ para troca e $Ed25519$ para assinaturas) garantindo baixa latência em ambientes Node.js/Bun.
* **Impacto**: Garante que a quebra de uma chave efêmera não comprometa o histórico de mensagens ou comunicações futuras.

### 2.2 Módulo `auth`: Identidade Vinculada (*Sender Constraining*)

O Sentinel resolve a falha dos tokens JWT comuns através do **DPoP (Demonstration of Proof-of-Possession)**.

* **Mecanismo**: Cada requisição é assinada por uma chave privada efêmera do agente. O servidor/receptor valida não apenas o token, mas a prova de que o emissor detém a chave privada vinculada àquele contexto.
* **Segurança**: Elimina ataques de *Replay* e o uso de tokens interceptados em outros contextos.

### 2.3 Módulo `semantic`: Blindagem de Domínio via Tipagem Nominal

A segurança lógica é frequentemente negligenciada. O Sentinel utiliza **Nominal Typing (Branding)** para erradicar a "Obsessão por Primitivos".

* **Conceito**: Um `AgentID` e um `UserID`, embora ambos sejam `strings` em tempo de execução, são tratados como tipos incompatíveis pelo compilador.
* **Prevenção**: Bloqueia em tempo de compilação erros de lógica onde identificadores de contextos distintos são trocados, uma técnica essencial para manter a integridade referencial em sistemas de larga escala.

### 2.4 Módulo `utils`: Auditoria Determinística e Observabilidade

A segurança é validada através da evidência. O `EventSourcingProxy` transforma a execução em um log de eventos imutáveis.

* **Evidence-as-Code**: Através do decorador `@Audit`, toda mutação de estado gera um `EventEnvelope` assinado.
* **Rastreabilidade**: Integra `TraceId` e `SpanId` diretamente ao payload criptográfico, unificando a telemetria com a prova de integridade.

---

## 3. A Coreografia de Segurança: Integração Holística

A robustez do Sentinel emerge da **interseção** de seus módulos, criando uma defesa em profundidade:

| Fase | Ação de Segurança | Módulo Responsável |
| --- | --- | --- |
| **Ingresso** | Validação de Esquema e *Branding* de IDs | `semantic` |
| **Handshake** | Acordo de chaves X3DH vinculado à identidade DPoP | `crypto` + `auth` |
| **Trânsito** | Criptografia Double Ratchet com autenticação de origem | `crypto` + `auth` |
| **Persistência** | Geração de envelopes de eventos para auditoria imutável | `utils` |

---

## 4. Diferenciais Estratégicos (The Sentinel Edge)

* **Antifragilidade**: O sistema se torna mais seguro ao rotacionar chaves a cada mensagem; uma falha local é isolada e auto-corrigida pelo próximo passo do Ratchet.
* **Zero External Dependencies**: O framework é auto-contido, reduzindo a superfície de ataque da cadeia de suprimentos (*Supply Chain Attacks*).
* **Compliance Ready**: O modelo `One-Evidence-4-All` permite que auditores verifiquem a integridade dos processos sem acessar dados sensíveis, utilizando apenas os hashes e assinaturas dos envelopes.

---

## 5. Conclusão

O Sentinel não é apenas uma biblioteca, mas a convergência determinística das ferramentas **Agent-Zero-Trust**, **One-EventSourcing-4-All**, **One-JWT-4-All** e **One-Evidence-4-All**. Ele é um manifesto de como a segurança em sistemas autônomos deve ser tratada: como um componente determinístico da arquitetura, e não uma camada adjacente. Ao garantir que cada bit de informação seja semanticamente correto, criptograficamente seguro e provadamente autêntico, o Sentinel viabiliza a próxima geração de agentes autônomos confiáveis e antifrágeis.

---

**Autores**: FullAgenticStack Initiative
**Status**: Beta (v0.1.0)
**Keywords**: `Double Ratchet`, `DPoP`, `TypeScript`, `Zero-Trust`, `Multi-Agent Systems`
