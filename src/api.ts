import { invoke } from '@tauri-apps/api/core';

export type AuthMethod = 'password' | 'key' | 'agent';
export type TunnelRule = {
  name: string; kind: 'local' | 'remote' | 'dynamic'; listenHost: string; listenPort: number;
  targetHost: string; targetPort: number; enabled: boolean;
};

export type Profile = {
  id: string; name: string; host: string; port: number; username: string; authMethod: AuthMethod;
  keyPath: string; hostKeySha256: string; terminalType: string; initialDirectory: string;
  keepAlive: number; autoReconnect: boolean; favorite: boolean; color: string; notes: string;
  proxyType: string; proxyHost: string; proxyPort: number; proxyProfileId: string; compression: boolean;
  sftpEnabled: boolean; terminalEnabled: boolean; rdpEnabled: boolean; rdpHost: string; rdpPort: number;
  tunnels: TunnelRule[]; keyPassphraseEnabled: boolean; accountPasswordEnabled: boolean;
  externalEditorEnabled: boolean; externalEditorPath: string;
  bridgeEnabled: boolean; bridgeAllowCommand: boolean; bridgeAllowSftp: boolean;
  hasPassword: boolean; hasPassphrase: boolean;
};

export type SaveProfileRequest = {
  profile: Profile; password?: string; passphrase?: string; savePassword: boolean; savePassphrase: boolean;
};

export type AppError = { code: string; message: string; detail?: string };
export type HostInspection = { fingerprint: string; trusted: boolean };
export type RemoteEntry = { name: string; path: string; isDirectory: boolean; size: number; modified: number; permissions: number };
export type LocalEntry = { name: string; path: string; isDirectory: boolean; size: number; modified: number };
export type TransferEvent = { transferId: string; profileId: string; direction: 'upload'|'download'; item: string; completed: number; total: number; status: 'started'|'progress'|'paused'|'cancelled'|'completed'|'failed'; message: string };
export type ExternalEditEvent = { editId: string; profileId: string; remotePath: string; status: 'opening'|'watching'|'syncing'|'saved'|'conflict'|'closed'|'failed'; message: string };
export type BridgeAuditEntry = { timestamp: number; profileId: string; profileName: string; action: string; status: string; summary: string };
export type TerminalOutput = { sessionId: string; data: string };
export type TerminalStatus = { sessionId: string; profileId: string; status: 'connecting' | 'connected' | 'disconnected' | 'error'; message: string };
export type TunnelStarted = { name: string; listenHost: string; listenPort: number; target: string };

export const blankProfile = (): Profile => ({
  id: '', name: 'Novo servidor', host: '', port: 22, username: '', authMethod: 'password', keyPath: '',
  hostKeySha256: '', terminalType: 'xterm-256color', initialDirectory: '', keepAlive: 30, autoReconnect: true,
  favorite: false, color: '#22d3ee', notes: '', proxyType: 'none', proxyHost: '', proxyPort: 1080, proxyProfileId: '',
  compression: false, sftpEnabled: true, terminalEnabled: true, rdpEnabled: false, rdpHost: '127.0.0.1',
  rdpPort: 3389, tunnels: [], keyPassphraseEnabled: false, accountPasswordEnabled: false,
  externalEditorEnabled: false, externalEditorPath: '', bridgeEnabled: false,
  bridgeAllowCommand: false, bridgeAllowSftp: false,
  hasPassword: false, hasPassphrase: false,
});

export const api = {
  listProfiles: () => invoke<Profile[]>('list_profiles'),
  saveProfile: (request: SaveProfileRequest) => invoke<Profile>('save_profile', { request }),
  deleteProfile: (profileId: string) => invoke<void>('delete_profile', { profileId }),
  duplicateProfile: (profileId: string) => invoke<Profile>('duplicate_profile', { profileId }),
  chooseKeyFile: () => invoke<string | null>('choose_key_file'),
  chooseEditorFile: () => invoke<string | null>('choose_editor_file'),
  chooseLocalFiles: () => invoke<string[]>('choose_local_files'),
  chooseLocalDirectory: () => invoke<string | null>('choose_local_directory'),
  localHome: () => invoke<string>('local_home'),
  inspectHost: (profileId: string) => invoke<HostInspection>('inspect_host', { profileId }),
  trustHost: (profileId: string, fingerprint: string) => invoke<Profile>('trust_host', { profileId, fingerprint }),
  connectTerminal: (profileId: string, cols: number, rows: number, password?: string, passphrase?: string) => invoke<string>('connect_terminal', { profileId, cols, rows, password, passphrase }),
  terminalInput: (sessionId: string, data: string) => invoke<void>('terminal_input', { sessionId, data }),
  terminalResize: (sessionId: string, cols: number, rows: number) => invoke<void>('terminal_resize', { sessionId, cols, rows }),
  disconnectTerminal: (sessionId: string) => invoke<void>('disconnect_terminal', { sessionId }),
  sftpList: (profileId: string, path: string, password?: string, passphrase?: string) => invoke<RemoteEntry[]>('sftp_list', { profileId, path, password, passphrase }),
  sftpUpload: (profileId: string, remoteDirectory: string, password?: string, passphrase?: string) => invoke<string>('sftp_upload', { profileId, remoteDirectory, password, passphrase }),
  sftpDownload: (profileId: string, remotePath: string, password?: string, passphrase?: string) => invoke<string>('sftp_download', { profileId, remotePath, password, passphrase }),
  localList: (path: string) => invoke<LocalEntry[]>('local_list', { path }),
  sftpUploadPaths: (profileId: string, remoteDirectory: string, localPaths: string[], password?: string, passphrase?: string) => invoke<string>('sftp_upload_paths', { profileId, remoteDirectory, localPaths, password, passphrase }),
  sftpDownloadPaths: (profileId: string, remotePaths: string[], localDirectory: string, password?: string, passphrase?: string) => invoke<string>('sftp_download_paths', { profileId, remotePaths, localDirectory, password, passphrase }),
  pauseTransfer: (transferId: string) => invoke<void>('pause_transfer', { transferId }),
  resumeTransfer: (transferId: string) => invoke<void>('resume_transfer', { transferId }),
  cancelTransfer: (transferId: string) => invoke<void>('cancel_transfer', { transferId }),
  openRemoteEditor: (profileId: string, remotePath: string, password?: string, passphrase?: string) => invoke<string>('open_remote_editor', { profileId, remotePath, password, passphrase }),
  restoreEditorBackup: (profileId: string, remotePath: string, password?: string, passphrase?: string) => invoke<string>('restore_editor_backup', { profileId, remotePath, password, passphrase }),
  listBridgeAudit: () => invoke<BridgeAuditEntry[]>('list_bridge_audit'),
  exportProfiles: (password: string) => invoke<string>('export_profiles', { password }),
  importProfiles: (password: string) => invoke<number>('import_profiles', { password }),
  chooseUpdateInstaller: () => invoke<string | null>('choose_update_installer'),
  installLocalUpdate: (path: string) => invoke<void>('install_local_update', { path }),
  startTunnels: (profileId: string, password?: string, passphrase?: string) => invoke<TunnelStarted[]>('start_tunnels', { profileId, password, passphrase }),
  stopTunnels: (profileId: string) => invoke<void>('stop_tunnels', { profileId }),
  openRdp: (profileId: string, password?: string, passphrase?: string) => invoke<number>('open_rdp', { profileId, password, passphrase }),
};

export function readableError(error: unknown): AppError {
  if (typeof error === 'object' && error && 'message' in error) return error as AppError;
  if (typeof error === 'string') {
    try { return JSON.parse(error) as AppError; } catch { return { code: 'unknown', message: error }; }
  }
  return { code: 'unknown', message: 'Algo não saiu como esperado.' };
}
