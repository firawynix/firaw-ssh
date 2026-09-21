# Firaw SSH

[![Build Windows installer](https://github.com/firawynix/firaw-ssh/actions/workflows/build-windows.yml/badge.svg)](https://github.com/firawynix/firaw-ssh/actions/workflows/build-windows.yml)

O cliente é distribuído sob a [licença MIT](LICENSE). Consulte a
[privacidade](PRIVACY.md), a [política de segurança](SECURITY.md), a
[política de assinatura](CODE_SIGNING_POLICY.md) e os
[avisos de terceiros](THIRD_PARTY_NOTICES.md).

Cliente SSH e SFTP para Windows e Linux, inspirado no fluxo de trabalho do Bitvise e na identidade visual dos projetos Firawynix.

## Recursos

- Perfis ilimitados com busca, favoritos e duplicação.
- Senhas e passphrases opcionais no cofre seguro do sistema (Gerenciador de Credenciais no Windows e Secret Service no Linux).
- Autenticação por senha, chave privada OpenSSH/PEM ou OpenSSH Agent.
- Autenticação em duas etapas SSH: chave + senha da conta, por `password` ou `keyboard-interactive`.
- Seleção de chave sem extensão ou do `.pub`, com resolução automática do arquivo privado correspondente.
- Flags independentes para chave privada com/sem senha e conta com/sem segunda senha.
- Backend OpenSSL no Windows para chaves privadas OpenSSH criptografadas.
- Verificação SHA-256 da chave do servidor antes da autenticação.
- Terminal xterm-256color com Unicode, buffer amplo e redimensionamento de PTY.
- Barra de teclas reais que reconhece GNU nano, Vim e less.
- Workspace com barra de perfis sempre visível e múltiplas sessões simultâneas.
- Navegador SFTP em dois painéis (Meu PC/Servidor), seleção múltipla, arrastar e soltar e fila de progresso.
- Transferências SFTP pausáveis, canceláveis e retomáveis a partir do trecho já existente.
- Editor externo opcional (Notepad++ ou outro) com sincronização ao salvar, proteção contra conflitos, cópia automática e desfazer envio.
- Ponte local por perfil para Codex/automações, com permissões separadas de comando e SFTP.
- Histórico persistente e sem credenciais das ações executadas pela ponte.
- Notificações internas e do sistema para transferências, edições e automações.
- Configuração de keep-alive, reconexão, proxy, túneis e RDP por perfil.
- Proxy HTTP/SOCKS, salto por outro perfil SSH e túneis locais, remotos e SOCKS.
- Backup e restauração de perfis com credenciais em arquivo criptografado por senha.
- Central de atualização local que aceita apenas instaladores Firaw SSH com versão superior.
- Interface compacta na paleta Firawynix (`#080d16`, `#22d3ee`).

## Desenvolvimento

Requisitos: Node.js 20+, Rust, Perl e ferramentas de compilação C++ do Visual Studio. O Perl é usado apenas ao compilar o OpenSSL incorporado; o aplicativo instalado não depende dele.

```text
npm install
npm run tauri:dev
```

Para gerar o instalador:

```text
npm run tauri:build
```

O instalador NSIS é criado em `src-tauri/target/release/bundle/nsis/`. No Linux,
`tools/build-linux-prepared.sh` gera AppImage e `.deb` usando um ambiente com as
dependências de GTK/WebKit do Tauri já preparadas.

No Windows, o build usa `tools/sign-windows.ps1`. Sem configuração ele mantém os
artefatos sem assinatura (como no build público verificável). Para uma publicação
interna, `FIRAW_SIGNING_THUMBPRINT` e `FIRAW_SIGNTOOL` fazem o Tauri assinar o
programa, os componentes do instalador e o NSIS final com timestamp.

## Segurança

O arquivo `profiles.json` contém apenas opções não secretas. Credenciais marcadas para salvar são armazenadas no cofre do sistema, vinculadas ao usuário conectado. A primeira conexão exige confirmação da impressão digital do servidor; uma mudança posterior bloqueia a conexão.

Encaminhamentos, RDP, proxy e salto SSH só são usados por ação/configuração explícita do usuário. O backup portátil é criptografado e sua senha não é armazenada. A atualização local exige a seleção manual de um instalador mais novo; a atualização automática pela internet depende de um canal HTTPS e assinatura de publicação próprios.

### Ponte local para Codex e automações

A ponte fica disponível apenas enquanto o Firaw SSH está aberto. Em **Opções → Ponte segura**, habilite individualmente cada perfil e marque somente os escopos necessários. O cliente nunca recebe senha, senha da chave ou conteúdo da chave privada.

Exemplos no PowerShell:

```powershell
.\tools\FirawBridge.ps1 -Action list
.\tools\FirawBridge.ps1 -Action exec -ProfileId "ID-DO-PERFIL" -Command "uname -a"
.\tools\FirawBridge.ps1 -Action download -ProfileId "ID-DO-PERFIL" -RemotePaths "/var/log/app.log" -LocalDirectory "C:\Temp"
```

As permissões podem ser removidas a qualquer momento no perfil. A confiança da chave do servidor e as credenciais salvas continuam sendo controladas pelo Firaw SSH.

## Referência funcional

O mapeamento do Bitvise 9.66 usado como referência está em [docs/MAPEAMENTO-BITVISE.md](docs/MAPEAMENTO-BITVISE.md). O Firaw SSH é uma implementação independente e não incorpora arquivos, marcas ou código proprietário do Bitvise.
