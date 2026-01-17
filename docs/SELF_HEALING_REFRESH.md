# Self-Healing Refresh Token Pattern com DPoP

Este documento descreve a implementação robusta de gerenciamento de tokens (Self-Healing) implementada neste projeto, com foco especial na integração com DPoP (Demonstrating Proof-of-Possession).

## 🚨 O Problema: Concorrência e "Race Conditions"

Em aplicações modernas (como Single Page Apps ou Microservices), é comum que múltiplas requisições ocorram simultaneamente. Quando o Access Token expira, todas essas requisições falham com erro `401 Unauthorized` quase ao mesmo tempo.

Se cada requisição tentar renovar o token independentemente:

1. **Request A** falha -> Envia Refresh Token (RT1).
2. **Request B** falha -> Envia Refresh Token (RT1).
3. Servidor recebe **Request A**, invalida RT1, emite RT2 e AccessToken2.
4. Servidor recebe **Request B** (com RT1 antigo). Como RT1 já foi usado/invalidado, o servidor detecta **REUSE DETECTION** (roubo de token).
5. **Resultado Catastrófico**: O servidor revoga TODOS os tokens (RT1, RT2, etc). O usuário é deslogado forçadamente.

## 🛡️ A Solução: Promise Latching (Singleton Promise)

Para resolver isso, utilizamos um padrão onde a promessa de renovação é compartilhada.

1. **Request A** percebe token expirado (ou recebe 401). Verifica se já existe um refresh em andamento.
   - Não existe? Inicia o refresh e salva a `Promise` em memória.
2. **Request B** percebe token expirado.
   - Verifica: Já existe refresh em andamento? **SIM**.
   - Em vez de iniciar outro, **retorna a mesma Promise** criada por A.
3. Quando a Promise resolve, tanto A quanto B recebem o **novo** token.

## 🔐 Integração com DPoP

O DPoP (RFC 9475) adiciona uma camada de complexidade importante. O DPoP Proof deve ser vinculado ao Access Token através da claim `ath` (Access Token Hash).

**Fluxo de Replay com DPoP:**

1. **Request A** falha (401).
2. TokenManager faz o refresh e obtém `NovoAccessToken`.
3. **CRÍTICO**: O `DPoP Proof` original da Request A **não pode ser reutilizado**, pois ele estava vinculado (via `ath`) ao token antigo (expirado).
4. O TokenManager deve **regenerar** um novo DPoP Proof:
   - Utilizando o `NovoAccessToken`.
   - Recalculando o `ath`.
   - Atualizando timestamp (`iat`).
5. Só então a requisição é reenviada.

## 💻 Como Usar (TokenManager)

O `TokenManager` abstrai toda essa complexidade.

```typescript
import { TokenManager } from "./domains/auth/manager/token-manager";

const manager = new TokenManager({
  refreshTokenFunction: async (oldRefreshToken) => {
    // Chame sua API de Auth aqui
    return api.post("/refresh", { token: oldRefreshToken });
  },
  dpopKeyPair: myDpopKeys, // Opcional, ativa DPoP automático
});

// Use o método authenticatedRequest para blindagem automática
await manager.authenticatedRequest(
  "GET",
  "https://api.exemplo.com/dados",
  async (accessToken, dpopProof) => {
    // Sua chamada HTTP real (axios, fetch, etc)
    return axios.get("...", {
      headers: {
        Authorization: `DPoP ${accessToken}`,
        DPoP: dpopProof,
      },
    });
  },
);
```

### Benefícios

- **Zero Race Conditions**: Múltiplas abas ou componentes podem disparar requests sem medo.
- **Transparência**: O código de negócio não precisa saber sobre 401s ou DPoP proofs.
- **Segurança**: Previne falsos positivos em sistemas de detecção de roubo de token (Reuse Detection).
