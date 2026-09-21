# Mapeamento funcional — Bitvise SSH Client 9.66

Data da análise: 12 de setembro de 2026.

## Instalação local analisada

A instalação em `C:\Program Files (x86)\Bitvise SSH Client` contém:

- cliente gráfico `BvSsh.exe`;
- terminais `bvtermc.exe`, `stermc.exe` e `totermw.exe`;
- execução remota `sexec.exe`;
- SFTP de linha de comando `sftpc.exe`;
- túneis autônomos `stnlc.exe`;
- gerenciamento de chaves `spksc.exe`;
- integração .NET `FlowSshNet32/64.dll` e amostras PowerShell;
- unidade SFTP via WinFsp;
- auxiliar de Remote Desktop e atualização.

## Capacidades de referência

O produto de referência organiza a conexão em torno de perfil, login, opções, terminal, SFTP, encaminhamento de portas, Remote Desktop e log. Suporta senha, chave pública, agentes PuTTY/OpenSSH, GSSAPI, proxies, jump host, reconexão, keep-alive, xterm/VT-100/bvterm, gravação de sessão, SFTP gráfico, unidade SFTP, FTP-to-SFTP, RDP sobre SSH e automação por linha de comando.

## Correspondência no Firaw SSH 0.1.2

| Área | Estado | Implementação |
|---|---|---|
| Perfis | Pronto | Lista ilimitada, busca, favoritos, duplicação e cor |
| Credenciais | Pronto | Senha da chave e senha da conta em entradas separadas do Windows Credential Manager |
| Host key | Pronto | Confirmação inicial, bloqueio em mudança de SHA-256 e migração sem alerta falso da preferência RSA existente |
| Terminal | Pronto | PTY interativo xterm-256color, Unicode e redimensionamento |
| Ajuda nano/Vim/less | Pronto | Detecção por saída e envio de sequências reais de tecla |
| SFTP | Pronto | Listar, navegar, enviar e baixar |
| Keep-alive | Pronto | Configurado por perfil na sessão SSH |
| Senha temporária | Pronto | Conecta uma vez sem persistir no cofre |
| Chave + senha | Pronto | Etapas opcionais, OpenSSH criptografada via OpenSSL e continuação por senha/keyboard-interactive |
| Túneis | Parcial | Encaminhamento local funcional; regras remotas e SOCKS persistidas para evolução |
| RDP | Pronto | Porta local efêmera por SSH e abertura do cliente RDP do Windows |
| Proxy/jump host | Configuração | Campos persistidos; transporte pendente |
| Unidade SFTP | Futuro | Requer driver e ciclo de vida específico |
| GSSAPI/bvterm | Fora do escopo inicial | Protocolos especializados do produto de referência |

## Identidade aplicada

A navegação compacta veio do FirawSelector; a paleta e os estados vêm do portfólio e do Firawynix Center. A linguagem visual usa fundo azul-grafite, painéis discretos, tipografia monoespaçada para dados técnicos e ciano `#22d3ee` como ação principal.
