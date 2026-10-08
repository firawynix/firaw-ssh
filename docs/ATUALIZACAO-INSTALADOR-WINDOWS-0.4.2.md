# Atualização do instalador Windows 0.4.2

## Motivo e escopo

O executável online anterior (`Firaw-SSH-Instalador-Online.exe`) foi bloqueado pelo Microsoft Defender com `os error 225` ao ser baixado pelo Firawynix Center. A edição da Microsoft Store usa outro pacote e não reproduziu esse bloqueio. O motivo exato da detecção não foi confirmado pela Microsoft.

Esta substituição mantém o aplicativo e os instaladores completos x64/x86 na versão 0.4.2. Muda somente o executável de entrada para Windows: um instalador NSIS assinado que contém os dois pacotes completos, escolhe a arquitetura local e não baixa outro executável, não importa certificado e não executa PowerShell. O aviso de confiança/UAC do Windows continua a ser respeitado.

## Pacote preparado

- Arquivo: `artifacts/server-upload-0.4.2/Firaw-SSH-Universal-0.4.2.exe`
- SHA-256: `E5652D39C87681C986D8311A5E9D0B1E00C7CAF9F9E6DF6CF3C652A80DBF5FB4`
- Tamanho: `6519624` bytes
- Assinante: `CN=Firawynix`, impressão digital `9A2EFF2483185C9A900F2797D7A9CBD5E8A12893`, com carimbo de tempo.
- Os dois instaladores internos tiveram SHA-256, assinatura e carimbo conferidos antes do build; a extração do pacote confirmou os mesmos hashes.

O script `tools/build-universal-windows.ps1` recompila esse pacote a partir dos dois instaladores completos já publicados. Uma recompilação terá outro SHA-256 por causa da assinatura/carimbo; conferir novamente antes de publicar.

## Antes de publicar

O Hugo confirmou que o pacote passou no teste da VM Windows 11. Ainda convém testar no Center a instalação, atualização e desinstalação em uma máquina de teste, com o Defender habilitado e sem exceções.

## Centro de distribuição

No painel `/admin/jogos` foi selecionado apenas **Instalador online** para o Firaw SSH. O painel conferiu SHA-256, assinatura e carimbo de tempo. Os pacotes completos x64/x86 não foram trocados. O guia `CENTER-PUBLICAR-PELO-PAINEL.md` documenta a reversão pelo histórico, que exige novo 2FA.

Em 08/10/2026, o painel publicou o instalador online e registrou **0.4.3 como versão do catálogo**, embora o aplicativo contido no pacote continue em **0.4.2**. A API anunciou 6.519.624 bytes e o SHA-256 acima; um download do endpoint público produziu o mesmo tamanho e hash, com assinatura válida. O Hugo confirmou que o Center reconheceu o aplicativo instalado como 0.4.2 e voltou a oferecer a atualização em laço. A correção exige os três instaladores e o aplicativo real na mesma versão, planejada como 0.4.4; não basta mudar o número no catálogo.

## Correção 0.4.4 preparada (ainda não publicada)

O aplicativo, os instaladores completos x64/x86 e o instalador universal foram recompilados com a versão interna 0.4.4. O script NSIS gerado para cada arquitetura grava `DisplayVersion=0.4.4` no registro do Windows. Todos os três EXEs estão assinados por `9A2EFF2483185C9A900F2797D7A9CBD5E8A12893` com carimbo de tempo, e um exame local do Microsoft Defender não registrou detecção nesta pasta. O build web passou e `cargo test --locked --release` passou com 10 testes:

| Arquivo em `artifacts/server-upload-0.4.4/` | SHA-256 |
|---|---|
| `Firaw-SSH-Universal-0.4.4.exe` | `064FF04EBC983732E8965E7CC17735B20091CBE3FA52EAE006B30B22828D2419` |
| `windows-firaw-ssh-x64.exe` | `F1164FD787350CC24F8B6E75EA665B3B0D876170E8AFC52FFA77EF93A506F6BD` |
| `windows-firaw-ssh-x86.exe` | `0BFCA976E3358EA6D34CD3782DD4C2708E65202C3E0226FC70E5535E26D0E25F` |

Os `.sig` novos foram gerados pelo Hugo localmente, sem compartilhar a chave privada. A chave pública da assinatura coincide com a configurada no Firaw SSH. O verificador em `tools/verify-updater-signature/` confirmou criptograficamente cada par EXE/`.sig`; o controle negativo (assinatura x64 contra EXE x86) foi rejeitado. Os hashes SHA-256 dos `.sig` são `B561B4855340D1D735A55A0BB168DCAEC508FE9547FA7D412603D1D19F5E4A24` (x64) e `E4FA9BF06240EE362C3B2E11B54A7B1EA4CC57E00C4A28F2CE36B2851632E76C` (x86). O Hugo confirmou que o instalador universal 0.4.4 abre e mostra a versão correta na VM Windows 11.

**Pendente:** usar o painel para enviar os três EXEs e os `.sig` x64/x86 numa única publicação como versão 0.4.4; depois verificar o catálogo, os downloads públicos e a oferta de atualização no Center. Não reutilizar os `.sig` da 0.4.2 nem publicar apenas um subconjunto dos instaladores.

## Site do Firaw SSH — etapa separada

Os dois botões Windows em `https://ssh.firawynix.com.br/` apontam para `/downloads/Firaw-SSH-Instalador-Online.exe`, arquivo estático fora do catálogo do Center. Publicar no painel **não** troca esse arquivo. Depois do mesmo teste da VM, preparar uma troca atômica desse arquivo com cópia anterior e reversão, seguindo `FORA-DA-ESTEIRA.md`. Antes de escrever o pacote de aplicação, conferir com o responsável pelo servidor o caminho e SHA-256 reais do arquivo em produção; não supor que a cópia local de `site/dist` é idêntica à produção. Os links HTML podem permanecer iguais.

Não desativar o Defender, criar exceção, restaurar o executável bloqueado nem chamar a detecção de falso positivo sem análise da Microsoft.
