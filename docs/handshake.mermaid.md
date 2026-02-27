sequenceDiagram
    autonumber
    participant AA as Agente A (Iniciador)
    participant SA as Sentinel Core (A)
    participant MA as Módulos (semantic, auth, crypto) (A)
    participant Net as Rede (Insegura)
    participant MB as Módulos (crypto, auth) (B)
    participant SB as Sentinel Core (B)
    participant AB as Agente B (Receptor)

    Note over AA, AB: FASE 1: Preparação da Identidade e Prova de Posse (DPoP)

    AA->>SA: Iniciar Conexão Segura com Agente B (AgentId_B)
    activate SA
    SA->>MA: Validar IDs de Domínio (semantic)
    MA-->>SA: IDs Válidos (Nominal Types)
    
    SA->>MA: Gerar Chaves Efêmeras e Prova DPoP (auth/crypto)
    Note right of MA: Gera Ed25519 (DPoP) & X25519 (X3DH)
    MA-->>SA: DPoP_Proof_A, X3DH_Bundle_A

    Note over AA, AB: FASE 2: Acordo de Chaves (X3DH) e Validação

    SA->>Net: Enviar Handshake Request (DPoP_Proof_A, X3DH_Bundle_A)
    deactivate SA
    Net->>SB: Receber Handshake Request
    activate SB

    SB->>MB: Validar DPoP_Proof_A contra AgentId_A (auth)
    MB-->>SB: DPoP Válido (Origem Confirmada)

    SB->>MB: Processar X3DH_Bundle_A e Gerar Resposta (crypto)
    Note right of MB: Calcula Segredo Inicial, Inicia Ratchet Root Chain
    MB-->>SB: X3DH_Response_B

    SB->>MB: Gerar Prova DPoP_Proof_B (auth)
    MB-->>SB: DPoP_Proof_B

    SB->>Net: Enviar Handshake Response (DPoP_Proof_B, X3DH_Response_B)
    deactivate SB

    Note over AA, AB: FASE 3: Finalização e Estabelecimento da Sessão

    Net->>SA: Receber Handshake Response
    activate SA
    
    SA->>MA: Validar DPoP_Proof_B contra AgentId_B (auth)
    MA-->>SA: DPoP Válido

    SA->>MA: Processar X3DH_Response_B (crypto)
    Note right of MA: Finaliza Acordo de Chaves, Inicia Ratchet Root Chain
    MA-->>SA: Sessão Estabelecida

    SA->>AA: Conexão Segura Ativa
    deactivate SA

    Note over AA, AB: FASE 4: Troca de Mensagens (Double Ratchet + DPoP)

    AA->>SA: Enviar Mensagem ("Olá, Agente B")
    activate SA
    
    SA->>MA: Encriptar Mensagem (crypto - Ratchet)
    MA-->>SA: Mensagem Encriptada, Header do Ratchet
    SA->>MA: Gerar DPoP para a Mensagem (auth)
    MA-->>SA: DPoP_Msg_Proof_A

    SA->>Net: Mensagem_Payload (Encrypted, DPoP_Msg_Proof_A)
    Note over Net: Toda mensagem tem uma chave AES única
    
    SA->>MA: Auditar Evento (utils - EventSourcing)
    Note right of MA: Gera Envelope Criptográfico Assinado (@Audit)
    deactivate SA