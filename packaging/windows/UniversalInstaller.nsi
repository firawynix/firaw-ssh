!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

!ifndef X64FILE
  !error "X64FILE nao informado"
!endif
!ifndef X86FILE
  !error "X86FILE nao informado"
!endif
!ifndef OUTPUTFILE
  !error "OUTPUTFILE nao informado"
!endif
!ifndef VERSION
  !error "VERSION nao informada"
!endif

Unicode true
Name "Firaw SSH"
OutFile "${OUTPUTFILE}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "Firaw SSH"
VIAddVersionKey "FileDescription" "Instalador completo do Firaw SSH para Windows x64 e x86"
VIAddVersionKey "FileVersion" "${VERSION}.0"
VIAddVersionKey "ProductVersion" "${VERSION}.0"
VIAddVersionKey "CompanyName" "Firawynix"
VIAddVersionKey "LegalCopyright" "Firawynix"
RequestExecutionLevel user
SetCompressor /SOLID lzma
CRCCheck on
ShowInstDetails nevershow
AutoCloseWindow true
Page instfiles

Var RequestedDir
Var InstallerPath
Var InstallerCommand
Var InstallerResult

Function .onInit
  ; O Center antigo envia parametros Inno. Aceitar /VERYSILENT durante
  ; a transicao, sem PowerShell, certutil, rede ou alteracao de confianca.
  ${GetParameters} $0
  StrCpy $1 $0 11
  ${If} $1 == "/VERYSILENT"
    SetSilent silent
  ${EndIf}
FunctionEnd

Section "Instalar Firaw SSH"
  InitPluginsDir
  ${If} ${RunningX64}
    File "/oname=$PLUGINSDIR\FirawSSH-x64.exe" "${X64FILE}"
    StrCpy $InstallerPath "$PLUGINSDIR\FirawSSH-x64.exe"
  ${Else}
    File "/oname=$PLUGINSDIR\FirawSSH-x86.exe" "${X86FILE}"
    StrCpy $InstallerPath "$PLUGINSDIR\FirawSSH-x86.exe"
  ${EndIf}

  ${GetParameters} $0
  ${GetOptions} $0 "/DIR=" $RequestedDir
  StrCpy $InstallerCommand '"$InstallerPath"'
  IfSilent 0 interactive
    StrCpy $InstallerCommand '$InstallerCommand /S'
    ${If} $RequestedDir != ""
      ; NSIS exige /D= por ultimo e sem aspas, inclusive com espacos.
      StrCpy $InstallerCommand '$InstallerCommand /D=$RequestedDir'
    ${EndIf}
  interactive:
  ExecWait $InstallerCommand $InstallerResult
  ${If} $InstallerResult != 0
    SetErrorLevel $InstallerResult
    Abort "O instalador do Firaw SSH terminou com codigo $InstallerResult."
  ${EndIf}
SectionEnd
