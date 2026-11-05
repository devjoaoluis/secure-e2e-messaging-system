## 🛠️ Divisão de Tarefas (Task Allocation)

O desenvolvimento do sistema está dividido em duas frentes principais, separando a infraestrutura de rede da lógica de criptografia ponta-a-ponta.

### 🧑‍💻 Developer 1: Infraestrutura do Servidor e Roteamento
**Foco:** Gestão de rede TCP, autenticação inicial e encaminhamento seguro de mensagens.

* **Servidor TCP e Concorrência:** Implementar o *socket* do servidor para aceitar múltiplas ligações de clientes em simultâneo[cite: 8].
* **Autenticação RSA do Servidor:** 
  * Gerar o par de chaves RSA ($\ge 2048$ bits) e o certificado autoassinado `server.crt`[cite: 2, 3].
  * Implementar a assinatura RSA-PSS com SHA-256 do *handshake*[cite: 3, 9].
* **Gestão de Sessões:** Manter a estrutura de dados `sessions`, registando o `client_id`, a chave pública do cliente, o `salt_srv` gerado e os contadores[cite: 5, 9].
* **Mecanismo de Relay (Roteamento):** Encaminhar os *frames* cifrados para o destinatário correto sem decifrar o conteúdo[cite: 1, 10].
* **Gestão de Erros e Framing:** Tratar as desconexões, limpar sessões da memória e implementar a leitura do prefixo de tamanho de 4 bytes (*big-endian*)[cite: 4, 11].

### 🧑‍💻 Developer 2: Cliente, Criptografia E2E e Estado Local
**Foco:** *Handshake* criptográfico, derivação de chaves E2E e proteção com AES-GCM.

* **Geração de Chaves Efêmeras:** Implementar a geração local do par X25519 (`sk_client` e `pk_client`) no arranque da aplicação[cite: 2, 4].
* **Derivação de Chaves (HKDF):** 
  * Calcular o segredo partilhado $Z = \text{ECDH}$ com a chave pública recebida do *peer*[cite: 2, 4].
  * Aplicar HKDF-SHA256 para gerar as chaves simétricas de envio e receção (`Key_A2B` e `Key_B2A`)[cite: 2, 3].
* **Cifração e Estrutura da Mensagem (AES-GCM):** 
  * Montar o pacote de dados E2E com `nonce`, `sender_id`, `recipient_id` e `seq_no`[cite: 4].
  * Cifrar e decifrar os *payloads* com AES-128-GCM, validando a *tag* de autenticação[cite: 1, 4].
* **Gestão de Estado do Cliente:** Manter o dicionário `peers` com os contadores monotónicos e IVs para prevenir ataques de *replay*[cite: 6, 7].

### 🤝 Tarefas Conjuntas (Fase de Integração)
* **Serialização do Protocolo:** Acordar a formatação exata dos *bytes* para os *frames* enviados na rede[cite: 4].
* **Validação e Testes de Segurança:** 
  * Executar as demonstrações de adulteração de pacotes (*bitflip*) e ataques de *replay*[cite: 11].
  * Auditar a saída da consola para garantir a política de *logs* (não imprimir chaves privadas ou segredos)[cite: 11].