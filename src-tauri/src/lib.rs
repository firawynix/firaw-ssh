mod bridge;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::{
    ExtendedData, FileStat, KeyboardInteractivePrompt, MethodType, OpenFlags, OpenType, Prompt,
    Session, Sftp,
};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;

const CREDENTIAL_SERVICE: &str = "FirawSSH";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppError {
    code: String,
    message: String,
    detail: Option<String>,
}

impl AppError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            detail: None,
        }
    }

    fn detail(code: &str, message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            detail: Some(detail.into()),
        }
    }
}

type AppResult<T> = Result<T, AppError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Profile {
    id: String,
    name: String,
    host: String,
    port: u16,
    username: String,
    auth_method: String,
    key_path: String,
    host_key_sha256: String,
    terminal_type: String,
    initial_directory: String,
    keep_alive: u64,
    auto_reconnect: bool,
    favorite: bool,
    color: String,
    notes: String,
    proxy_type: String,
    proxy_host: String,
    proxy_port: u16,
    proxy_profile_id: String,
    compression: bool,
    sftp_enabled: bool,
    terminal_enabled: bool,
    rdp_enabled: bool,
    rdp_host: String,
    rdp_port: u16,
    tunnels: Vec<TunnelRule>,
    key_passphrase_enabled: bool,
    account_password_enabled: bool,
    external_editor_enabled: bool,
    external_editor_path: String,
    bridge_enabled: bool,
    bridge_allow_command: bool,
    bridge_allow_sftp: bool,
    has_password: bool,
    has_passphrase: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct TunnelRule {
    name: String,
    kind: String,
    listen_host: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
    enabled: bool,
}

impl Default for TunnelRule {
    fn default() -> Self {
        Self {
            name: "Novo túnel".into(),
            kind: "local".into(),
            listen_host: "127.0.0.1".into(),
            listen_port: 8080,
            target_host: "127.0.0.1".into(),
            target_port: 80,
            enabled: true,
        }
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: "Novo servidor".into(),
            host: String::new(),
            port: 22,
            username: String::new(),
            auth_method: "password".into(),
            key_path: String::new(),
            host_key_sha256: String::new(),
            terminal_type: "xterm-256color".into(),
            initial_directory: String::new(),
            keep_alive: 30,
            auto_reconnect: true,
            favorite: false,
            color: "#22d3ee".into(),
            notes: String::new(),
            proxy_type: "none".into(),
            proxy_host: String::new(),
            proxy_port: 1080,
            proxy_profile_id: String::new(),
            compression: false,
            sftp_enabled: true,
            terminal_enabled: true,
            rdp_enabled: false,
            rdp_host: "127.0.0.1".into(),
            rdp_port: 3389,
            tunnels: Vec::new(),
            key_passphrase_enabled: true,
            account_password_enabled: true,
            external_editor_enabled: false,
            external_editor_path: String::new(),
            bridge_enabled: false,
            bridge_allow_command: false,
            bridge_allow_sftp: false,
            has_password: false,
            has_passphrase: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveProfileRequest {
    profile: Profile,
    password: Option<String>,
    passphrase: Option<String>,
    save_password: bool,
    save_passphrase: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostInspection {
    fingerprint: String,
    trusted: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalEvent {
    session_id: String,
    data: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalStatus {
    session_id: String,
    profile_id: String,
    status: String,
    message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferEvent {
    transfer_id: String,
    profile_id: String,
    direction: String,
    item: String,
    completed: u64,
    total: u64,
    status: String,
    message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalEditEvent {
    edit_id: String,
    profile_id: String,
    remote_path: String,
    status: String,
    message: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BridgeAuditEntry {
    timestamp: u64,
    profile_id: String,
    profile_name: String,
    action: String,
    status: String,
    summary: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortableProfile {
    profile: Profile,
    password: Option<String>,
    passphrase: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortableBackup {
    format: u8,
    created_at: u64,
    profiles: Vec<PortableProfile>,
}

enum TerminalCommand {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

enum TerminalEnd {
    Closed,
    Lost(String),
}

fn run_terminal_once(
    app: &AppHandle,
    profile: &Profile,
    session_id: &str,
    rx: &mpsc::Receiver<TerminalCommand>,
    password: Option<&str>,
    passphrase: Option<&str>,
    cols: &mut u32,
    rows: &mut u32,
) -> AppResult<TerminalEnd> {
    let session = connected_session(app, profile, password, passphrase)?;
    if profile.keep_alive > 0 {
        session.set_keepalive(true, profile.keep_alive.min(u32::MAX as u64) as u32);
    }
    let mut channel = session
        .channel_session()
        .map_err(|e| AppError::new("ssh", e.to_string()))?;
    channel
        .request_pty(
            &profile.terminal_type,
            None,
            Some(((*cols).max(20), (*rows).max(5), 0, 0)),
        )
        .map_err(|e| AppError::new("terminal", format!("PTY recusado: {e}")))?;
    channel
        .shell()
        .map_err(|e| AppError::new("terminal", format!("Shell recusado: {e}")))?;
    if !profile.initial_directory.trim().is_empty() {
        let escaped = profile.initial_directory.replace('\'', "'\"'\"'");
        channel
            .write_all(format!("cd -- '{escaped}'\n").as_bytes())
            .map_err(|e| AppError::new("terminal", e.to_string()))?;
    }
    session.set_blocking(false);
    let _ = app.emit(
        "terminal-status",
        TerminalStatus {
            session_id: session_id.into(),
            profile_id: profile.id.clone(),
            status: "connected".into(),
            message: format!("Conectado como {}", profile.username),
        },
    );
    let mut buffer = [0u8; 16384];
    let mut last_keepalive = Instant::now();
    loop {
        while let Ok(command) = rx.try_recv() {
            match command {
                TerminalCommand::Data(data) => {
                    let _ = channel.write_all(&data);
                    let _ = channel.flush();
                }
                TerminalCommand::Resize(c, r) => {
                    *cols = c;
                    *rows = r;
                    let _ = channel.request_pty_size(c.max(20), r.max(5), None, None);
                }
                TerminalCommand::Close => {
                    let _ = channel.close();
                    return Ok(TerminalEnd::Closed);
                }
            }
        }
        match channel.read(&mut buffer) {
            Ok(0) if channel.eof() => {
                return Ok(TerminalEnd::Lost("O servidor encerrou a sessão.".into()))
            }
            Ok(0) => thread::sleep(Duration::from_millis(8)),
            Ok(n) => {
                let _ = app.emit(
                    "terminal-output",
                    TerminalEvent {
                        session_id: session_id.into(),
                        data: STANDARD.encode(&buffer[..n]),
                    },
                );
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(8)),
            Err(e) => {
                return Ok(TerminalEnd::Lost(format!(
                    "A conexão foi interrompida: {e}"
                )))
            }
        }
        if profile.keep_alive > 0
            && last_keepalive.elapsed() >= Duration::from_secs(profile.keep_alive)
        {
            if let Err(error) = session.keepalive_send() {
                return Ok(TerminalEnd::Lost(format!("Keep-alive falhou: {error}")));
            }
            last_keepalive = Instant::now();
        }
    }
}

struct AppState {
    sessions: Mutex<HashMap<String, mpsc::Sender<TerminalCommand>>>,
    tunnels: Mutex<HashMap<String, Vec<mpsc::Sender<()>>>>,
    transfers: Mutex<HashMap<String, Arc<TransferControl>>>,
}

struct TransferControl {
    paused: AtomicBool,
    cancelled: AtomicBool,
}

impl TransferControl {
    fn new() -> Self {
        Self {
            paused: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn append_bridge_audit(
    app: &AppHandle,
    profile: &Profile,
    action: &str,
    status: &str,
    summary: impl Into<String>,
) {
    let entry = BridgeAuditEntry {
        timestamp: unix_now(),
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        action: action.into(),
        status: status.into(),
        summary: summary.into(),
    };
    if let (Ok(path), Ok(line)) = (
        data_dir(app).map(|p| p.join("bridge-audit.jsonl")),
        serde_json::to_string(&entry),
    ) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }
}

fn bridge_request_summary(action: &str, request: &serde_json::Value) -> String {
    match action {
        "exec" => {
            let command = request
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let program = command.split_whitespace().next().unwrap_or("comando");
            let hash = format!("{:x}", Sha256::digest(command.as_bytes()));
            format!("{} · referência {}", program, &hash[..12])
        }
        "upload" => format!(
            "{} item(ns) enviado(s)",
            request
                .get("localPaths")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len)
        ),
        "download" => format!(
            "{} item(ns) baixado(s)",
            request
                .get("remotePaths")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len)
        ),
        _ => action.into(),
    }
}

fn bridge_error(code: &str, message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({"ok": false, "error": code, "message": message.into()})
}

fn bridge_profile<'a>(
    profiles: &'a [Profile],
    profile_id: &str,
) -> Result<&'a Profile, serde_json::Value> {
    profiles
        .iter()
        .find(|profile| profile.id == profile_id)
        .filter(|profile| profile.bridge_enabled)
        .ok_or_else(|| {
            bridge_error(
                "forbidden",
                "Perfil inexistente ou não autorizado para automação local.",
            )
        })
}

fn handle_bridge_request(app: &AppHandle, request: serde_json::Value) -> serde_json::Value {
    let action = request
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if action == "ping" {
        return serde_json::json!({"ok": true, "service": "Firaw SSH Bridge", "version": 1});
    }
    let profiles = match read_profiles(app) {
        Ok(profiles) => profiles,
        Err(error) => return bridge_error(&error.code, error.message),
    };
    if action == "list" {
        let allowed = profiles
            .iter()
            .filter(|profile| profile.bridge_enabled)
            .map(|profile| {
                serde_json::json!({
                    "id": profile.id,
                    "name": profile.name,
                    "host": profile.host,
                    "port": profile.port,
                    "username": profile.username,
                    "scopes": {
                        "command": profile.bridge_allow_command,
                        "sftp": profile.bridge_allow_sftp
                    }
                })
            })
            .collect::<Vec<_>>();
        return serde_json::json!({"ok": true, "profiles": allowed});
    }
    let profile_id = request
        .get("profileId")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let profile = match bridge_profile(&profiles, profile_id) {
        Ok(profile) => profile.clone(),
        Err(error) => return error,
    };
    let audit_summary = bridge_request_summary(action, &request);
    append_bridge_audit(app, &profile, action, "started", &audit_summary);
    let _ = app.emit(
        "bridge-event",
        serde_json::json!({"profileId": profile.id, "action": action, "status": "started", "message": "Automação local iniciada."}),
    );
    let result = match action {
        "exec" => {
            if !profile.bridge_allow_command {
                return bridge_error("forbidden", "Comandos não estão autorizados neste perfil.");
            }
            let command = request
                .get("command")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .trim();
            if command.is_empty() || command.len() > 8192 {
                return bridge_error(
                    "validation",
                    "Informe um comando entre 1 e 8192 caracteres.",
                );
            }
            (|| -> AppResult<serde_json::Value> {
                let session = connected_session(app, &profile, None, None)?;
                let mut channel = session.channel_session().map_err(|e| {
                    AppError::new("bridge", format!("Não foi possível abrir o canal: {e}"))
                })?;
                channel
                    .handle_extended_data(ExtendedData::Merge)
                    .map_err(|e| AppError::new("bridge", e.to_string()))?;
                channel
                    .exec(command)
                    .map_err(|e| AppError::new("bridge", format!("Comando recusado: {e}")))?;
                let mut output = String::new();
                channel
                    .read_to_string(&mut output)
                    .map_err(|e| AppError::new("bridge", format!("Falha ao ler a saída: {e}")))?;
                channel
                    .wait_close()
                    .map_err(|e| AppError::new("bridge", e.to_string()))?;
                let exit_code = channel.exit_status().unwrap_or(-1);
                Ok(serde_json::json!({"exitCode": exit_code, "output": output}))
            })()
        }
        "download" => {
            if !profile.bridge_allow_sftp {
                return bridge_error("forbidden", "SFTP não está autorizado neste perfil.");
            }
            let remote_paths = request
                .get("remotePaths")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let local_root = PathBuf::from(
                request
                    .get("localDirectory")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            );
            (|| -> AppResult<serde_json::Value> {
                if remote_paths.is_empty() || !local_root.is_dir() {
                    return Err(AppError::new(
                        "validation",
                        "Informe caminhos remotos e uma pasta local válida.",
                    ));
                }
                let session = connected_session(app, &profile, None, None)?;
                let sftp = session
                    .sftp()
                    .map_err(|e| AppError::new("sftp", e.to_string()))?;
                let transfer_id = uuid::Uuid::new_v4().to_string();
                let control = TransferControl::new();
                for item in remote_paths {
                    let remote = PathBuf::from(item);
                    let name = remote
                        .file_name()
                        .ok_or_else(|| AppError::new("sftp", "Caminho remoto inválido."))?;
                    download_tree(
                        app,
                        &sftp,
                        &transfer_id,
                        &profile.id,
                        &remote,
                        &local_root.join(name),
                        &control,
                    )?;
                }
                Ok(serde_json::json!({"transferId": transfer_id}))
            })()
        }
        "upload" => {
            if !profile.bridge_allow_sftp {
                return bridge_error("forbidden", "SFTP não está autorizado neste perfil.");
            }
            let local_paths = request
                .get("localPaths")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let remote_directory = request
                .get("remoteDirectory")
                .and_then(|value| value.as_str())
                .unwrap_or(".");
            (|| -> AppResult<serde_json::Value> {
                if local_paths.is_empty() {
                    return Err(AppError::new(
                        "validation",
                        "Informe ao menos um caminho local.",
                    ));
                }
                let session = connected_session(app, &profile, None, None)?;
                let sftp = session
                    .sftp()
                    .map_err(|e| AppError::new("sftp", e.to_string()))?;
                let remote_root = sftp
                    .realpath(Path::new(remote_directory))
                    .map_err(|e| AppError::new("sftp", e.to_string()))?;
                let transfer_id = uuid::Uuid::new_v4().to_string();
                let control = TransferControl::new();
                for item in local_paths {
                    let local = PathBuf::from(item);
                    let name = local
                        .file_name()
                        .ok_or_else(|| AppError::new("storage", "Caminho local inválido."))?;
                    upload_tree(
                        app,
                        &sftp,
                        &transfer_id,
                        &profile.id,
                        &local,
                        &remote_root.join(name),
                        &control,
                    )?;
                }
                Ok(serde_json::json!({"transferId": transfer_id}))
            })()
        }
        _ => return bridge_error("unknown_action", "Ação desconhecida."),
    };
    match result {
        Ok(data) => {
            append_bridge_audit(app, &profile, action, "completed", &audit_summary);
            let _ = app.emit(
                "bridge-event",
                serde_json::json!({"profileId": profile.id, "action": action, "status": "completed", "message": "Automação local concluída."}),
            );
            notify(
                app,
                "Firaw SSH",
                &format!("Automação concluída em {}", profile.name),
            );
            serde_json::json!({"ok": true, "data": data})
        }
        Err(error) => {
            append_bridge_audit(
                app,
                &profile,
                action,
                "failed",
                format!("{} · {}", audit_summary, error.message),
            );
            let _ = app.emit(
                "bridge-event",
                serde_json::json!({"profileId": profile.id, "action": action, "status": "failed", "message": error.message}),
            );
            notify(app, "Firaw SSH — automação falhou", &error.message);
            bridge_error(&error.code, error.message)
        }
    }
}

fn data_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let path = app
        .path()
        .app_local_data_dir()
        .map_err(|e| AppError::new("storage", e.to_string()))?;
    fs::create_dir_all(&path).map_err(|e| AppError::new("storage", e.to_string()))?;
    Ok(path)
}

fn profiles_path(app: &AppHandle) -> AppResult<PathBuf> {
    Ok(data_dir(app)?.join("profiles.json"))
}

fn read_profiles(app: &AppHandle) -> AppResult<Vec<Profile>> {
    let path = profiles_path(app)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|e| AppError::new("storage", e.to_string()))?;
    let mut profiles: Vec<Profile> = serde_json::from_str(&text)
        .map_err(|e| AppError::new("storage", format!("Perfis inválidos: {e}")))?;
    migrate_legacy_profiles(&mut profiles);
    Ok(profiles)
}

fn migrate_legacy_profiles(profiles: &mut [Profile]) {
    for profile in profiles {
        if profile.auth_method == "password"
            && !profile.key_path.trim().is_empty()
            && profile.has_passphrase
        {
            profile.auth_method = "key".into();
            profile.key_passphrase_enabled = true;
            profile.account_password_enabled = profile.has_password;
        }
    }
}

fn write_profiles(app: &AppHandle, profiles: &[Profile]) -> AppResult<()> {
    let path = profiles_path(app)?;
    let text = serde_json::to_string_pretty(profiles)
        .map_err(|e| AppError::new("storage", e.to_string()))?;
    fs::write(&path, text).map_err(|e| AppError::new("storage", e.to_string()))
}

fn derive_backup_key(password: &str, salt: &[u8]) -> AppResult<[u8; 32]> {
    if password.chars().count() < 8 {
        return Err(AppError::new(
            "backup_password",
            "Use uma senha de backup com pelo menos 8 caracteres.",
        ));
    }
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| {
            AppError::new(
                "backup_crypto",
                format!("Não foi possível proteger o backup: {e}"),
            )
        })?;
    Ok(key)
}

#[tauri::command]
fn export_profiles(app: AppHandle, password: String) -> AppResult<String> {
    let profiles = read_profiles(&app)?;
    if profiles.is_empty() {
        return Err(AppError::new("backup", "Não há perfis para exportar."));
    }
    let portable = profiles
        .into_iter()
        .map(|profile| {
            let password = get_secret(&profile.id, "password").ok().flatten();
            let passphrase = get_secret(&profile.id, "passphrase").ok().flatten();
            PortableProfile {
                profile,
                password,
                passphrase,
            }
        })
        .collect();
    let payload = PortableBackup {
        format: 1,
        created_at: unix_now(),
        profiles: portable,
    };
    let plain = serde_json::to_vec(&payload).map_err(|e| AppError::new("backup", e.to_string()))?;
    let salt_uuid = uuid::Uuid::new_v4();
    let nonce_uuid = uuid::Uuid::new_v4();
    let salt = salt_uuid.as_bytes();
    let nonce_bytes = &nonce_uuid.as_bytes()[..12];
    let key = derive_backup_key(&password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::new("backup_crypto", e.to_string()))?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(nonce_bytes), plain.as_ref())
        .map_err(|_| AppError::new("backup_crypto", "Não foi possível criptografar o backup."))?;
    let destination = app
        .dialog()
        .file()
        .add_filter("Backup criptografado do Firaw SSH", &["firawssh"])
        .set_file_name(format!("Firaw-SSH-backup-{}.firawssh", unix_now()))
        .blocking_save_file()
        .and_then(|f| f.into_path().ok())
        .ok_or_else(|| AppError::new("cancelled", "Exportação cancelada."))?;
    let mut output = Vec::with_capacity(36 + encrypted.len());
    output.extend_from_slice(b"FIRAWBK1");
    output.extend_from_slice(salt);
    output.extend_from_slice(nonce_bytes);
    output.extend_from_slice(&encrypted);
    fs::write(&destination, output)
        .map_err(|e| AppError::new("backup", format!("Não foi possível salvar o backup: {e}")))?;
    Ok(destination.to_string_lossy().into_owned())
}

#[tauri::command]
fn import_profiles(app: AppHandle, password: String) -> AppResult<usize> {
    let source = app
        .dialog()
        .file()
        .add_filter("Backup criptografado do Firaw SSH", &["firawssh"])
        .blocking_pick_file()
        .and_then(|f| f.into_path().ok())
        .ok_or_else(|| AppError::new("cancelled", "Importação cancelada."))?;
    let bytes = fs::read(&source)
        .map_err(|e| AppError::new("backup", format!("Não foi possível ler o backup: {e}")))?;
    if bytes.len() < 37 || &bytes[..8] != b"FIRAWBK1" {
        return Err(AppError::new(
            "backup_format",
            "Este arquivo não é um backup válido do Firaw SSH.",
        ));
    }
    let key = derive_backup_key(&password, &bytes[8..24])?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::new("backup_crypto", e.to_string()))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&bytes[24..36]), &bytes[36..])
        .map_err(|_| {
            AppError::new(
                "backup_password",
                "Senha incorreta ou arquivo de backup danificado.",
            )
        })?;
    let backup: PortableBackup = serde_json::from_slice(&plain)
        .map_err(|_| AppError::new("backup_format", "O conteúdo do backup é inválido."))?;
    if backup.format != 1 {
        return Err(AppError::new(
            "backup_format",
            "Versão de backup ainda não suportada.",
        ));
    }
    let mut current = read_profiles(&app)?;
    let count = backup.profiles.len();
    for item in backup.profiles {
        validate_profile(&item.profile)?;
        let id = item.profile.id.clone();
        match current.iter().position(|p| p.id == id) {
            Some(index) => current[index] = item.profile,
            None => current.push(item.profile),
        }
        if let Some(secret) = item.password.as_deref() {
            let _ = set_secret(&id, "password", Some(secret), true)?;
        }
        if let Some(secret) = item.passphrase.as_deref() {
            let _ = set_secret(&id, "passphrase", Some(secret), true)?;
        }
    }
    write_profiles(&app, &current)?;
    Ok(count)
}

#[tauri::command]
fn list_bridge_audit(app: AppHandle) -> AppResult<Vec<BridgeAuditEntry>> {
    let path = data_dir(&app)?.join("bridge-audit.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|e| AppError::new("audit", e.to_string()))?;
    let mut entries = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect::<Vec<_>>();
    if entries.len() > 300 {
        entries.drain(..entries.len() - 300);
    }
    Ok(entries)
}

#[tauri::command]
fn choose_update_installer(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .add_filter("Instalador do Firaw SSH", &["exe"])
        .blocking_pick_file()
        .and_then(|f| f.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
}

fn parse_release_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.').map(|part| part.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

fn installer_release_version(name: &str) -> Option<(u64, u64, u64)> {
    let version = name.strip_prefix("firaw ssh_")?.split('_').next()?;
    parse_release_version(version)
}

#[tauri::command]
fn install_local_update(app: AppHandle, path: String) -> AppResult<()> {
    let installer = PathBuf::from(path);
    let name = installer
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    let selected_version = installer_release_version(&name);
    if !installer.is_file()
        || installer
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("exe"))
        || selected_version.is_none()
    {
        return Err(AppError::new(
            "update",
            "Escolha um instalador válido do Firaw SSH.",
        ));
    }
    let current_version = parse_release_version(env!("CARGO_PKG_VERSION"))
        .ok_or_else(|| AppError::new("update", "A versão atual é inválida."))?;
    if selected_version.expect("validated above") <= current_version {
        return Err(AppError::new(
            "update",
            format!(
                "Escolha uma versão mais nova que {}.",
                env!("CARGO_PKG_VERSION")
            ),
        ));
    }
    let mut command = Command::new(&installer);
    command.arg("/S");
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000);
    command.spawn().map_err(|e| {
        AppError::new(
            "update",
            format!("Não foi possível iniciar a atualização: {e}"),
        )
    })?;
    app.exit(0);
    Ok(())
}

fn credential(profile_id: &str, kind: &str) -> AppResult<Entry> {
    Entry::new(CREDENTIAL_SERVICE, &format!("{profile_id}:{kind}"))
        .map_err(|e| AppError::new("credential", format!("Cofre seguro do sistema indisponível: {e}")))
}

fn get_secret(profile_id: &str, kind: &str) -> AppResult<Option<String>> {
    match credential(profile_id, kind)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AppError::new(
            "credential",
            format!("Não foi possível ler o cofre: {e}"),
        )),
    }
}

fn set_secret(profile_id: &str, kind: &str, value: Option<&str>, keep: bool) -> AppResult<bool> {
    let entry = credential(profile_id, kind)?;
    if keep {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            entry.set_password(value).map_err(|e| {
                AppError::new(
                    "credential",
                    format!("Não foi possível proteger a credencial: {e}"),
                )
            })?;
            return Ok(true);
        }
        return Ok(entry.get_password().is_ok());
    }
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(AppError::new(
            "credential",
            format!("Não foi possível remover a credencial: {e}"),
        )),
    }
}

fn profile_by_id(app: &AppHandle, id: &str) -> AppResult<Profile> {
    read_profiles(app)?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::new("profile", "Perfil não encontrado."))
}

fn validate_profile(profile: &Profile) -> AppResult<()> {
    if profile.name.trim().is_empty() {
        return Err(AppError::new("validation", "Dê um nome ao perfil."));
    }
    if profile.host.trim().is_empty() {
        return Err(AppError::new("validation", "Informe o servidor."));
    }
    if profile.username.trim().is_empty() {
        return Err(AppError::new("validation", "Informe o usuário."));
    }
    if profile.port == 0 {
        return Err(AppError::new(
            "validation",
            "A porta deve estar entre 1 e 65535.",
        ));
    }
    if profile.auth_method == "key" && profile.key_path.trim().is_empty() {
        return Err(AppError::new(
            "validation",
            "Escolha o arquivo da chave privada.",
        ));
    }
    if matches!(profile.proxy_type.as_str(), "http" | "socks5")
        && (profile.proxy_host.trim().is_empty() || profile.proxy_port == 0)
    {
        return Err(AppError::new(
            "validation",
            "Informe o servidor e a porta do proxy.",
        ));
    }
    if profile.proxy_type == "ssh" && profile.proxy_profile_id.trim().is_empty() {
        return Err(AppError::new(
            "validation",
            "Escolha o perfil intermediário SSH.",
        ));
    }
    Ok(())
}

#[tauri::command]
fn list_profiles(app: AppHandle) -> AppResult<Vec<Profile>> {
    read_profiles(&app)
}

#[tauri::command]
fn save_profile(app: AppHandle, request: SaveProfileRequest) -> AppResult<Profile> {
    let mut profile = request.profile;
    if profile.id.is_empty() {
        profile.id = uuid::Uuid::new_v4().to_string();
    }
    profile.name = profile.name.trim().to_string();
    profile.host = profile.host.trim().to_string();
    profile.username = profile.username.trim().to_string();
    if profile.auth_method == "key" && !profile.key_path.trim().is_empty() {
        profile.key_path = normalize_selected_key_path(Path::new(&profile.key_path))
            .to_string_lossy()
            .into_owned();
    }
    validate_profile(&profile)?;
    let keep_account_password = request.save_password
        && (profile.auth_method == "password"
            || (profile.auth_method == "key" && profile.account_password_enabled));
    let keep_key_passphrase =
        request.save_passphrase && profile.auth_method == "key" && profile.key_passphrase_enabled;
    profile.has_password = set_secret(
        &profile.id,
        "password",
        request.password.as_deref(),
        keep_account_password,
    )?;
    profile.has_passphrase = set_secret(
        &profile.id,
        "passphrase",
        request.passphrase.as_deref(),
        keep_key_passphrase,
    )?;
    let mut profiles = read_profiles(&app)?;
    match profiles.iter().position(|p| p.id == profile.id) {
        Some(index) => profiles[index] = profile.clone(),
        None => profiles.push(profile.clone()),
    }
    write_profiles(&app, &profiles)?;
    Ok(profile)
}

#[tauri::command]
fn delete_profile(app: AppHandle, profile_id: String) -> AppResult<()> {
    let mut profiles = read_profiles(&app)?;
    profiles.retain(|p| p.id != profile_id);
    write_profiles(&app, &profiles)?;
    let _ = set_secret(&profile_id, "password", None, false);
    let _ = set_secret(&profile_id, "passphrase", None, false);
    Ok(())
}

#[tauri::command]
fn duplicate_profile(app: AppHandle, profile_id: String) -> AppResult<Profile> {
    let mut profile = profile_by_id(&app, &profile_id)?;
    profile.id = uuid::Uuid::new_v4().to_string();
    profile.name = format!("{} (cópia)", profile.name);
    profile.has_password = false;
    profile.has_passphrase = false;
    let mut profiles = read_profiles(&app)?;
    profiles.push(profile.clone());
    write_profiles(&app, &profiles)?;
    Ok(profile)
}

#[tauri::command]
fn choose_key_file(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .blocking_pick_file()
        .and_then(|f| f.into_path().ok())
        .map(|p| {
            normalize_selected_key_path(&p)
                .to_string_lossy()
                .into_owned()
        })
}

#[tauri::command]
fn choose_editor_file(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .add_filter(
            if cfg!(target_os = "linux") { "Aplicativo" } else { "Aplicativo Windows" },
            if cfg!(target_os = "linux") { &["AppImage", "appimage", "bin"][..] } else { &["exe"][..] },
        )
        .blocking_pick_file()
        .and_then(|f| f.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
}

#[tauri::command]
fn choose_local_files(app: AppHandle) -> Vec<String> {
    app.dialog()
        .file()
        .blocking_pick_files()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| f.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

#[tauri::command]
fn choose_local_directory(app: AppHandle) -> Option<String> {
    app.dialog()
        .file()
        .blocking_pick_folder()
        .and_then(|f| f.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
}

fn normalize_selected_key_path(selected: &Path) -> PathBuf {
    if selected
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pub"))
    {
        let private = selected.with_extension("");
        if private.is_file() {
            return private;
        }
    }
    selected.to_path_buf()
}

fn key_files(selected: &Path) -> AppResult<(PathBuf, Option<PathBuf>)> {
    let selected_is_public = selected
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pub"));
    let private = if selected_is_public {
        selected.with_extension("")
    } else {
        selected.to_path_buf()
    };
    if !private.is_file() {
        let message = if selected_is_public {
            format!(
                "O arquivo .pub é somente a chave pública. Coloque a chave privada correspondente em “{}” ou selecione-a diretamente.",
                private.display()
            )
        } else {
            format!(
                "A chave privada não foi encontrada em “{}”.",
                private.display()
            )
        };
        return Err(AppError::new("private_key_missing", message));
    }
    let public = if selected_is_public {
        selected.is_file().then(|| selected.to_path_buf())
    } else {
        let mut public_name = selected.as_os_str().to_os_string();
        public_name.push(".pub");
        let candidate = PathBuf::from(public_name);
        candidate.is_file().then_some(candidate)
    };
    Ok((private, public))
}

fn connect_direct(host: &str, port: u16) -> AppResult<TcpStream> {
    let address = format!("{host}:{port}");
    let socket = address
        .to_socket_addrs()
        .map_err(|e| AppError::new("network", format!("Servidor não encontrado: {e}")))?
        .next()
        .ok_or_else(|| AppError::new("network", "Servidor não encontrado."))?;
    let tcp = TcpStream::connect_timeout(&socket, Duration::from_secs(15)).map_err(|e| {
        AppError::new(
            "network",
            format!("Não foi possível conectar a {address}: {e}"),
        )
    })?;
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();
    Ok(tcp)
}

fn connect_http_proxy(profile: &Profile) -> AppResult<TcpStream> {
    let mut tcp = connect_direct(&profile.proxy_host, profile.proxy_port)?;
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        profile.host, profile.port, profile.host, profile.port
    );
    tcp.write_all(request.as_bytes())
        .map_err(|e| AppError::new("proxy", format!("Proxy HTTP indisponível: {e}")))?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while response.len() < 16384 && !response.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).map_err(|e| {
            AppError::new("proxy", format!("Resposta incompleta do proxy HTTP: {e}"))
        })?;
        response.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&response);
    if !status
        .lines()
        .next()
        .is_some_and(|line| line.contains(" 200 "))
    {
        return Err(AppError::new(
            "proxy",
            format!(
                "O proxy HTTP recusou a conexão: {}",
                status.lines().next().unwrap_or("resposta inválida")
            ),
        ));
    }
    Ok(tcp)
}

fn connect_socks5_proxy(profile: &Profile) -> AppResult<TcpStream> {
    let mut tcp = connect_direct(&profile.proxy_host, profile.proxy_port)?;
    tcp.write_all(&[5, 1, 0])
        .map_err(|e| AppError::new("proxy", e.to_string()))?;
    let mut greeting = [0u8; 2];
    tcp.read_exact(&mut greeting)
        .map_err(|e| AppError::new("proxy", format!("Proxy SOCKS5 não respondeu: {e}")))?;
    if greeting != [5, 0] {
        return Err(AppError::new(
            "proxy",
            "O proxy SOCKS5 exige autenticação não configurada.",
        ));
    }
    let host = profile.host.as_bytes();
    if host.len() > 255 {
        return Err(AppError::new(
            "proxy",
            "Nome do servidor longo demais para SOCKS5.",
        ));
    }
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&profile.port.to_be_bytes());
    tcp.write_all(&request)
        .map_err(|e| AppError::new("proxy", e.to_string()))?;
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head)
        .map_err(|e| AppError::new("proxy", format!("Proxy SOCKS5 não respondeu: {e}")))?;
    if head[1] != 0 {
        return Err(AppError::new(
            "proxy",
            format!("O proxy SOCKS5 recusou o destino (código {}).", head[1]),
        ));
    }
    let address_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0];
            tcp.read_exact(&mut len)
                .map_err(|e| AppError::new("proxy", e.to_string()))?;
            len[0] as usize
        }
        _ => return Err(AppError::new("proxy", "Resposta SOCKS5 inválida.")),
    };
    let mut discard = vec![0u8; address_len + 2];
    tcp.read_exact(&mut discard)
        .map_err(|e| AppError::new("proxy", e.to_string()))?;
    Ok(tcp)
}

fn pump_socket_channel(
    mut socket: TcpStream,
    session: &Session,
    mut channel: ssh2::Channel,
) -> AppResult<()> {
    socket
        .set_nonblocking(true)
        .map_err(|e| AppError::new("tunnel", e.to_string()))?;
    session.set_blocking(false);
    let mut to_remote = VecDeque::<u8>::new();
    let mut to_local = VecDeque::<u8>::new();
    let mut local_eof = false;
    let mut remote_eof = false;
    let mut buffer = [0u8; 32768];
    loop {
        if !local_eof {
            match socket.read(&mut buffer) {
                Ok(0) => {
                    local_eof = true;
                    let _ = channel.send_eof();
                }
                Ok(n) => to_remote.extend(&buffer[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(AppError::new("tunnel", e.to_string())),
            }
        }
        if !remote_eof {
            match channel.read(&mut buffer) {
                Ok(0) if channel.eof() => remote_eof = true,
                Ok(0) => {}
                Ok(n) => to_local.extend(&buffer[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(AppError::new("tunnel", e.to_string())),
            }
        }
        if !to_remote.is_empty() {
            let (first, _) = to_remote.as_slices();
            match channel.write(first) {
                Ok(n) => {
                    to_remote.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(AppError::new("tunnel", e.to_string())),
            }
        }
        if !to_local.is_empty() {
            let (first, _) = to_local.as_slices();
            match socket.write(first) {
                Ok(n) => {
                    to_local.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(AppError::new("tunnel", e.to_string())),
            }
        }
        if local_eof && remote_eof && to_remote.is_empty() && to_local.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(3));
    }
    let _ = channel.close();
    Ok(())
}

fn connect_ssh_jump(app: &AppHandle, profile: &Profile) -> AppResult<TcpStream> {
    if profile.proxy_profile_id.is_empty() || profile.proxy_profile_id == profile.id {
        return Err(AppError::new(
            "proxy",
            "Escolha outro perfil como servidor intermediário SSH.",
        ));
    }
    let jump = profile_by_id(app, &profile.proxy_profile_id)?;
    if jump.proxy_type == "ssh" {
        return Err(AppError::new(
            "proxy",
            "O perfil intermediário não pode depender de outro salto SSH.",
        ));
    }
    let session = connected_session(app, &jump, None, None)?;
    let channel = session
        .channel_direct_tcpip(&profile.host, profile.port, None)
        .map_err(|e| {
            AppError::new(
                "proxy",
                format!("O servidor intermediário recusou o destino: {e}"),
            )
        })?;
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| AppError::new("proxy", e.to_string()))?;
    let address = listener
        .local_addr()
        .map_err(|e| AppError::new("proxy", e.to_string()))?;
    thread::spawn(move || {
        if let Ok((socket, _)) = listener.accept() {
            let _ = pump_socket_channel(socket, &session, channel);
        }
    });
    connect_direct("127.0.0.1", address.port())
}

fn tcp_and_handshake(app: &AppHandle, profile: &Profile) -> AppResult<Session> {
    let tcp = match profile.proxy_type.as_str() {
        "none" | "" => connect_direct(&profile.host, profile.port)?,
        "http" => connect_http_proxy(profile)?,
        "socks5" => connect_socks5_proxy(profile)?,
        "ssh" => connect_ssh_jump(app, profile)?,
        _ => return Err(AppError::new("proxy", "Tipo de proxy desconhecido.")),
    };
    let mut session = Session::new().map_err(|e| AppError::new("ssh", e.to_string()))?;
    session.set_compress(profile.compression);
    session
        .method_pref(
            MethodType::HostKey,
            "rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521",
        )
        .map_err(|e| AppError::new("ssh", format!("Falha ao configurar a identidade SSH: {e}")))?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|e| AppError::new("ssh", format!("Falha na negociação SSH: {e}")))?;
    Ok(session)
}

fn fingerprint(session: &Session) -> AppResult<String> {
    let (key, _) = session.host_key().ok_or_else(|| {
        AppError::new(
            "host_key",
            "O servidor não apresentou uma chave de identidade.",
        )
    })?;
    Ok(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(key))
    ))
}

fn same_fingerprint(left: &str, right: &str) -> bool {
    left.trim_end_matches('=') == right.trim_end_matches('=')
}

fn verify_host(profile: &Profile, session: &Session) -> AppResult<String> {
    let current = fingerprint(session)?;
    if profile.host_key_sha256.is_empty() {
        return Err(AppError::detail(
            "host_unknown",
            "Primeira conexão: confirme a identidade do servidor.",
            current,
        ));
    }
    if !same_fingerprint(&profile.host_key_sha256, &current) {
        return Err(AppError::detail(
            "host_mismatch",
            "A identidade do servidor mudou. A conexão foi bloqueada.",
            current,
        ));
    }
    Ok(current)
}

fn authenticate(
    profile: &Profile,
    session: &Session,
    password: Option<&str>,
    passphrase: Option<&str>,
) -> AppResult<()> {
    match profile.auth_method.as_str() {
        "password" => {
            let password = password.ok_or_else(|| {
                AppError::new("password_required", "Digite ou salve a senha deste perfil.")
            })?;
            authenticate_password_factor(session, &profile.username, password, None)?;
        }
        "key" => {
            let (private_key, public_key) = key_files(Path::new(&profile.key_path))?;
            if profile.key_passphrase_enabled && passphrase.is_none() {
                return Err(AppError::new(
                    "key_passphrase_required",
                    "Esta chave está marcada como protegida. Digite ou salve a senha da chave.",
                ));
            }
            let key_result = session.userauth_pubkey_file(
                &profile.username,
                public_key.as_deref(),
                &private_key,
                passphrase,
            );
            if !session.authenticated() {
                let remaining = session
                    .auth_methods(&profile.username)
                    .unwrap_or_default()
                    .to_string();
                let accepts_second_factor = remaining
                    .split(',')
                    .any(|method| method == "password" || method == "keyboard-interactive");
                let key_still_offered = remaining.split(',').any(|method| method == "publickey");
                if key_result.is_err() && key_still_offered {
                    let detail = key_result
                        .err()
                        .map(|error| error.to_string())
                        .unwrap_or_default();
                    return Err(AppError::new(
                        "authentication",
                        format!(
                            "Não foi possível assinar com a chave privada. {} Confirme a opção “Esta chave possui senha” e a senha informada. Detalhe: {detail}",
                            private_key.display()
                        ),
                    ));
                }
                if accepts_second_factor && profile.account_password_enabled {
                    let password = password.ok_or_else(|| {
                        AppError::new(
                            "root_password_required",
                            format!(
                                "A chave foi processada, mas o servidor também exige a senha do usuário {}. Digite-a ou salve-a no cofre seguro do sistema.",
                                profile.username
                            ),
                        )
                    })?;
                    authenticate_password_factor(
                        session,
                        &profile.username,
                        password,
                        Some(&remaining),
                    )?;
                } else if accepts_second_factor {
                    return Err(AppError::new(
                        "account_password_disabled",
                        format!(
                            "O servidor exige a senha do usuário {} depois da chave. Volte ao perfil e ative essa etapa.",
                            profile.username
                        ),
                    ));
                } else {
                    let detail = key_result
                        .err()
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "o servidor não ofereceu a próxima etapa".into());
                    return Err(AppError::new(
                        "authentication",
                        format!(
                            "A chave privada foi recusada. Confirme a senha da chave e se “{}” corresponde ao arquivo .pub instalado no servidor. Detalhe: {detail}",
                            private_key.display()
                        ),
                    ));
                }
            }
        }
        "agent" => {
            session.userauth_agent(&profile.username).map_err(|e| {
                AppError::new(
                    "authentication",
                    format!("Nenhuma chave aceita no agente SSH: {e}"),
                )
            })?;
        }
        _ => {
            return Err(AppError::new(
                "authentication",
                "Método de autenticação desconhecido.",
            ))
        }
    }
    if !session.authenticated() {
        return Err(AppError::new(
            "authentication",
            "O servidor não autenticou este usuário.",
        ));
    }
    Ok(())
}

struct PasswordPrompter<'a> {
    password: &'a str,
}

impl KeyboardInteractivePrompt for PasswordPrompter<'_> {
    fn prompt<'a>(
        &mut self,
        _username: &str,
        _instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String> {
        prompts.iter().map(|_| self.password.to_string()).collect()
    }
}

fn authenticate_password_factor(
    session: &Session,
    username: &str,
    password: &str,
    offered_methods: Option<&str>,
) -> AppResult<()> {
    let available = match offered_methods {
        Some(methods) => methods.to_string(),
        None => session
            .auth_methods(username)
            .unwrap_or_default()
            .to_string(),
    };
    let allows =
        |method: &str| available.is_empty() || available.split(',').any(|item| item == method);
    let mut errors = Vec::new();
    if allows("password") {
        if let Err(error) = session.userauth_password(username, password) {
            errors.push(format!("senha: {error}"));
        }
    }
    if !session.authenticated() && allows("keyboard-interactive") {
        let mut prompter = PasswordPrompter { password };
        if let Err(error) = session.userauth_keyboard_interactive(username, &mut prompter) {
            errors.push(format!("interativa: {error}"));
        }
    }
    if session.authenticated() {
        return Ok(());
    }
    let detail = if errors.is_empty() {
        format!("métodos oferecidos pelo servidor: {available}")
    } else {
        errors.join("; ")
    };
    Err(AppError::new(
        "authentication",
        format!("A senha do usuário {username} foi recusada. {detail}"),
    ))
}

fn connected_session(
    app: &AppHandle,
    profile: &Profile,
    transient_password: Option<&str>,
    transient_passphrase: Option<&str>,
) -> AppResult<Session> {
    let session = tcp_and_handshake(app, profile)?;
    verify_host(profile, &session)?;
    let stored_password = get_secret(&profile.id, "password")?;
    let stored_passphrase = get_secret(&profile.id, "passphrase")?;
    let password_enabled = profile.auth_method == "password"
        || (profile.auth_method == "key" && profile.account_password_enabled);
    let password = password_enabled
        .then(|| {
            transient_password
                .filter(|v| !v.is_empty())
                .or(stored_password.as_deref())
        })
        .flatten();
    let passphrase = (profile.auth_method == "key" && profile.key_passphrase_enabled)
        .then(|| {
            transient_passphrase
                .filter(|v| !v.is_empty())
                .or(stored_passphrase.as_deref())
        })
        .flatten();
    authenticate(profile, &session, password, passphrase)?;
    Ok(session)
}

#[tauri::command]
fn inspect_host(app: AppHandle, profile_id: String) -> AppResult<HostInspection> {
    let profile = profile_by_id(&app, &profile_id)?;
    let session = tcp_and_handshake(&app, &profile)?;
    let current = fingerprint(&session)?;
    Ok(HostInspection {
        trusted: !profile.host_key_sha256.is_empty()
            && same_fingerprint(&profile.host_key_sha256, &current),
        fingerprint: current,
    })
}

#[tauri::command]
fn trust_host(app: AppHandle, profile_id: String, fingerprint: String) -> AppResult<Profile> {
    if !fingerprint.starts_with("SHA256:") {
        return Err(AppError::new("host_key", "Impressão digital inválida."));
    }
    let mut profiles = read_profiles(&app)?;
    let profile = profiles
        .iter_mut()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| AppError::new("profile", "Perfil não encontrado."))?;
    profile.host_key_sha256 = fingerprint;
    let saved = profile.clone();
    write_profiles(&app, &profiles)?;
    Ok(saved)
}

#[tauri::command]
fn connect_terminal(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    mut cols: u32,
    mut rows: u32,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<String> {
    let profile = profile_by_id(&app, &profile_id)?;
    validate_profile(&profile)?;
    let session_id = uuid::Uuid::new_v4().to_string();
    let thread_session_id = session_id.clone();
    let (tx, rx) = mpsc::channel::<TerminalCommand>();
    state
        .sessions
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das sessões indisponível."))?
        .insert(session_id.clone(), tx);
    let app_thread = app.clone();
    thread::spawn(move || {
        let emit_status = |status: &str, message: String| {
            let _ = app_thread.emit(
                "terminal-status",
                TerminalStatus {
                    session_id: thread_session_id.clone(),
                    profile_id: profile.id.clone(),
                    status: status.into(),
                    message,
                },
            );
        };
        emit_status(
            "connecting",
            format!("Conectando a {}:{}…", profile.host, profile.port),
        );
        let mut attempt = 0u32;
        loop {
            match run_terminal_once(
                &app_thread,
                &profile,
                &thread_session_id,
                &rx,
                password.as_deref(),
                passphrase.as_deref(),
                &mut cols,
                &mut rows,
            ) {
                Ok(TerminalEnd::Closed) => {
                    emit_status("disconnected", "Sessão encerrada.".into());
                    break;
                }
                Ok(TerminalEnd::Lost(reason)) if profile.auto_reconnect => {
                    attempt += 1;
                    let wait = (attempt * 2).min(30);
                    emit_status("connecting", format!("{reason} Reconectando em {wait}s…"));
                    let deadline = Instant::now() + Duration::from_secs(wait as u64);
                    let mut closed = false;
                    while Instant::now() < deadline {
                        match rx.recv_timeout(Duration::from_millis(200)) {
                            Ok(TerminalCommand::Close) => {
                                closed = true;
                                break;
                            }
                            Ok(TerminalCommand::Resize(c, r)) => {
                                cols = c;
                                rows = r
                            }
                            _ => {}
                        }
                    }
                    if closed {
                        emit_status("disconnected", "Sessão encerrada.".into());
                        break;
                    }
                }
                Ok(TerminalEnd::Lost(reason)) => {
                    emit_status(
                        "error",
                        serde_json::to_string(&AppError::new("terminal", reason)).unwrap(),
                    );
                    break;
                }
                Err(error) => {
                    emit_status(
                        "error",
                        serde_json::to_string(&error).unwrap_or(error.message),
                    );
                    break;
                }
            }
        }
        if let Ok(mut sessions) = app_thread.state::<AppState>().sessions.lock() {
            sessions.remove(&thread_session_id);
        }
    });
    Ok(session_id)
}

#[tauri::command]
fn terminal_input(state: State<'_, AppState>, session_id: String, data: String) -> AppResult<()> {
    let bytes = STANDARD
        .decode(data)
        .map_err(|e| AppError::new("terminal", e.to_string()))?;
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das sessões indisponível."))?;
    sessions
        .get(&session_id)
        .ok_or_else(|| AppError::new("session", "A sessão já terminou."))?
        .send(TerminalCommand::Data(bytes))
        .map_err(|_| AppError::new("session", "A sessão já terminou."))
}

#[tauri::command]
fn terminal_resize(
    state: State<'_, AppState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> AppResult<()> {
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das sessões indisponível."))?;
    sessions
        .get(&session_id)
        .ok_or_else(|| AppError::new("session", "A sessão já terminou."))?
        .send(TerminalCommand::Resize(cols, rows))
        .map_err(|_| AppError::new("session", "A sessão já terminou."))
}

#[tauri::command]
fn disconnect_terminal(state: State<'_, AppState>, session_id: String) -> AppResult<()> {
    if let Some(sender) = state
        .sessions
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das sessões indisponível."))?
        .remove(&session_id)
    {
        let _ = sender.send(TerminalCommand::Close);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteEntry {
    name: String,
    path: String,
    is_directory: bool,
    size: u64,
    modified: u64,
    permissions: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalEntry {
    name: String,
    path: String,
    is_directory: bool,
    size: u64,
    modified: u64,
}

fn modified_seconds(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn display_local_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_string()
}

#[tauri::command]
fn local_list(path: String) -> AppResult<Vec<LocalEntry>> {
    let requested = if path.trim().is_empty() {
        PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_else(|| "C:\\".into()))
    } else {
        PathBuf::from(path.trim())
    };
    let real = requested
        .canonicalize()
        .map_err(|e| AppError::new("local_files", format!("Pasta local inacessível: {e}")))?;
    let mut entries = fs::read_dir(&real)
        .map_err(|e| AppError::new("local_files", format!("Não foi possível listar: {e}")))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            Some(LocalEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: display_local_path(&entry.path()),
                is_directory: metadata.is_dir(),
                size: metadata.len(),
                modified: modified_seconds(&metadata),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        b.is_directory
            .cmp(&a.is_directory)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

#[tauri::command]
fn local_home() -> String {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string())
}

fn emit_transfer(
    app: &AppHandle,
    transfer_id: &str,
    profile_id: &str,
    direction: &str,
    item: &Path,
    completed: u64,
    total: u64,
    status: &str,
    message: impl Into<String>,
) {
    let _ = app.emit(
        "transfer-progress",
        TransferEvent {
            transfer_id: transfer_id.into(),
            profile_id: profile_id.into(),
            direction: direction.into(),
            item: item.to_string_lossy().into_owned(),
            completed,
            total,
            status: status.into(),
            message: message.into(),
        },
    );
}

fn wait_transfer(control: &TransferControl) -> AppResult<()> {
    while control.paused.load(Ordering::SeqCst) {
        if control.cancelled.load(Ordering::SeqCst) {
            return Err(AppError::new(
                "transfer_cancelled",
                "Transferência cancelada; o arquivo parcial foi mantido para retomar depois.",
            ));
        }
        thread::sleep(Duration::from_millis(120));
    }
    if control.cancelled.load(Ordering::SeqCst) {
        return Err(AppError::new(
            "transfer_cancelled",
            "Transferência cancelada; o arquivo parcial foi mantido para retomar depois.",
        ));
    }
    Ok(())
}

fn upload_tree(
    app: &AppHandle,
    sftp: &Sftp,
    transfer_id: &str,
    profile_id: &str,
    local: &Path,
    remote: &Path,
    control: &TransferControl,
) -> AppResult<()> {
    wait_transfer(control)?;
    let metadata = fs::symlink_metadata(local)
        .map_err(|e| AppError::new("storage", format!("{}: {e}", local.display())))?;
    if metadata.is_dir() {
        if sftp.stat(remote).is_err() {
            sftp.mkdir(remote, 0o755).map_err(|e| {
                AppError::new(
                    "sftp",
                    format!("Não foi possível criar {}: {e}", remote.display()),
                )
            })?;
        }
        for entry in fs::read_dir(local)
            .map_err(|e| AppError::new("storage", format!("{}: {e}", local.display())))?
        {
            let entry = entry.map_err(|e| AppError::new("storage", e.to_string()))?;
            upload_tree(
                app,
                sftp,
                transfer_id,
                profile_id,
                &entry.path(),
                &remote.join(entry.file_name()),
                control,
            )?;
        }
        return Ok(());
    }
    let total = metadata.len();
    emit_transfer(
        app,
        transfer_id,
        profile_id,
        "upload",
        local,
        0,
        total,
        "started",
        "Enviando…",
    );
    let mut source = fs::File::open(local)
        .map_err(|e| AppError::new("storage", format!("{}: {e}", local.display())))?;
    let remote_size = sftp.stat(remote).ok().and_then(|s| s.size);
    if remote_size == Some(total) {
        emit_transfer(
            app,
            transfer_id,
            profile_id,
            "upload",
            local,
            total,
            total,
            "completed",
            "Arquivo já estava completo",
        );
        return Ok(());
    }
    let resume_at = remote_size.filter(|size| *size < total).unwrap_or(0);
    if resume_at > 0 {
        source
            .seek(SeekFrom::Start(resume_at))
            .map_err(|e| AppError::new("storage", e.to_string()))?;
    }
    let flags = if resume_at > 0 {
        OpenFlags::WRITE | OpenFlags::APPEND
    } else {
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
    };
    let mut target = sftp
        .open_mode(remote, flags, 0o644, OpenType::File)
        .map_err(|e| {
            AppError::new(
                "sftp",
                format!("Não foi possível criar {}: {e}", remote.display()),
            )
        })?;
    let mut buffer = [0u8; 65536];
    let mut completed = resume_at;
    loop {
        wait_transfer(control)?;
        let read = source
            .read(&mut buffer)
            .map_err(|e| AppError::new("storage", e.to_string()))?;
        if read == 0 {
            break;
        }
        target
            .write_all(&buffer[..read])
            .map_err(|e| AppError::new("sftp", format!("Envio falhou: {e}")))?;
        completed += read as u64;
        emit_transfer(
            app,
            transfer_id,
            profile_id,
            "upload",
            local,
            completed,
            total,
            "progress",
            "Enviando…",
        );
    }
    emit_transfer(
        app,
        transfer_id,
        profile_id,
        "upload",
        local,
        total,
        total,
        "completed",
        "Enviado",
    );
    Ok(())
}

fn download_tree(
    app: &AppHandle,
    sftp: &Sftp,
    transfer_id: &str,
    profile_id: &str,
    remote: &Path,
    local: &Path,
    control: &TransferControl,
) -> AppResult<()> {
    wait_transfer(control)?;
    let stat = sftp
        .lstat(remote)
        .map_err(|e| AppError::new("sftp", format!("{}: {e}", remote.display())))?;
    if stat.perm.unwrap_or(0) & 0o170000 == 0o040000 {
        fs::create_dir_all(local)
            .map_err(|e| AppError::new("storage", format!("{}: {e}", local.display())))?;
        for (child, _) in sftp
            .readdir(remote)
            .map_err(|e| AppError::new("sftp", format!("{}: {e}", remote.display())))?
        {
            let name = child.file_name().unwrap_or_default();
            download_tree(
                app,
                sftp,
                transfer_id,
                profile_id,
                &child,
                &local.join(name),
                control,
            )?;
        }
        return Ok(());
    }
    let total = stat.size.unwrap_or(0);
    emit_transfer(
        app,
        transfer_id,
        profile_id,
        "download",
        remote,
        0,
        total,
        "started",
        "Baixando…",
    );
    let mut source = sftp
        .open(remote)
        .map_err(|e| AppError::new("sftp", format!("{}: {e}", remote.display())))?;
    let local_size = fs::metadata(local).ok().map(|m| m.len());
    if local_size == Some(total) {
        emit_transfer(
            app,
            transfer_id,
            profile_id,
            "download",
            remote,
            total,
            total,
            "completed",
            "Arquivo já estava completo",
        );
        return Ok(());
    }
    let resume_at = local_size.filter(|size| *size < total).unwrap_or(0);
    if resume_at > 0 {
        source
            .seek(SeekFrom::Start(resume_at))
            .map_err(|e| AppError::new("sftp", format!("Retomada falhou: {e}")))?;
    }
    let mut target = OpenOptions::new()
        .create(true)
        .write(true)
        .append(resume_at > 0)
        .truncate(resume_at == 0)
        .open(local)
        .map_err(|e| AppError::new("storage", format!("{}: {e}", local.display())))?;
    let mut buffer = [0u8; 65536];
    let mut completed = resume_at;
    loop {
        wait_transfer(control)?;
        let read = source
            .read(&mut buffer)
            .map_err(|e| AppError::new("sftp", format!("Download falhou: {e}")))?;
        if read == 0 {
            break;
        }
        target
            .write_all(&buffer[..read])
            .map_err(|e| AppError::new("storage", e.to_string()))?;
        completed += read as u64;
        emit_transfer(
            app,
            transfer_id,
            profile_id,
            "download",
            remote,
            completed,
            total,
            "progress",
            "Baixando…",
        );
    }
    emit_transfer(
        app,
        transfer_id,
        profile_id,
        "download",
        remote,
        total,
        total,
        "completed",
        "Baixado",
    );
    Ok(())
}

fn finish_transfer(
    app: &AppHandle,
    transfer_id: &str,
    profile: &Profile,
    direction: &str,
    result: AppResult<()>,
) {
    if let Ok(mut transfers) = app.state::<AppState>().transfers.lock() {
        transfers.remove(transfer_id);
    }
    match result {
        Ok(()) => {
            emit_transfer(
                app,
                transfer_id,
                &profile.id,
                direction,
                Path::new(""),
                1,
                1,
                "completed",
                "Transferência concluída.",
            );
            let _ = app
                .notification()
                .builder()
                .title("Firaw SSH")
                .body(format!("Transferência concluída em {}", profile.name))
                .show();
        }
        Err(error) => {
            let cancelled = error.code == "transfer_cancelled";
            emit_transfer(
                app,
                transfer_id,
                &profile.id,
                direction,
                Path::new(""),
                0,
                0,
                if cancelled { "cancelled" } else { "failed" },
                &error.message,
            );
            if !cancelled {
                let _ = app
                    .notification()
                    .builder()
                    .title("Firaw SSH — transferência falhou")
                    .body(error.message)
                    .show();
            }
        }
    }
}

#[tauri::command]
fn sftp_upload_paths(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    remote_directory: String,
    local_paths: Vec<String>,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<String> {
    if local_paths.is_empty() {
        return Err(AppError::new(
            "validation",
            "Selecione ao menos um item local.",
        ));
    }
    let profile = profile_by_id(&app, &profile_id)?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let thread_id = transfer_id.clone();
    let control = Arc::new(TransferControl::new());
    state
        .transfers
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das transferências indisponível."))?
        .insert(transfer_id.clone(), control.clone());
    thread::spawn(move || {
        let result = (|| {
            let session =
                connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
            let sftp = session
                .sftp()
                .map_err(|e| AppError::new("sftp", e.to_string()))?;
            let remote_root = sftp
                .realpath(Path::new(&remote_directory))
                .map_err(|e| AppError::new("sftp", format!("Pasta remota inacessível: {e}")))?;
            for item in local_paths {
                let local = PathBuf::from(item);
                let name = local
                    .file_name()
                    .ok_or_else(|| AppError::new("storage", "Item local inválido."))?;
                upload_tree(
                    &app,
                    &sftp,
                    &thread_id,
                    &profile.id,
                    &local,
                    &remote_root.join(name),
                    &control,
                )?;
            }
            Ok(())
        })();
        finish_transfer(&app, &thread_id, &profile, "upload", result);
    });
    Ok(transfer_id)
}

#[tauri::command]
fn sftp_download_paths(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    remote_paths: Vec<String>,
    local_directory: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<String> {
    if remote_paths.is_empty() {
        return Err(AppError::new(
            "validation",
            "Selecione ao menos um item remoto.",
        ));
    }
    let local_root = PathBuf::from(local_directory);
    if !local_root.is_dir() {
        return Err(AppError::new(
            "local_files",
            "Escolha uma pasta local válida.",
        ));
    }
    let profile = profile_by_id(&app, &profile_id)?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let thread_id = transfer_id.clone();
    let control = Arc::new(TransferControl::new());
    state
        .transfers
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das transferências indisponível."))?
        .insert(transfer_id.clone(), control.clone());
    thread::spawn(move || {
        let result = (|| {
            let session =
                connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
            let sftp = session
                .sftp()
                .map_err(|e| AppError::new("sftp", e.to_string()))?;
            for item in remote_paths {
                let remote = PathBuf::from(item);
                let name = remote
                    .file_name()
                    .ok_or_else(|| AppError::new("sftp", "Item remoto inválido."))?;
                download_tree(
                    &app,
                    &sftp,
                    &thread_id,
                    &profile.id,
                    &remote,
                    &local_root.join(name),
                    &control,
                )?;
            }
            Ok(())
        })();
        finish_transfer(&app, &thread_id, &profile, "download", result);
    });
    Ok(transfer_id)
}

#[tauri::command]
fn pause_transfer(state: State<'_, AppState>, transfer_id: String) -> AppResult<()> {
    let transfers = state
        .transfers
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das transferências indisponível."))?;
    let control = transfers
        .get(&transfer_id)
        .ok_or_else(|| AppError::new("transfer", "A transferência já terminou."))?;
    control.paused.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
fn resume_transfer(state: State<'_, AppState>, transfer_id: String) -> AppResult<()> {
    let transfers = state
        .transfers
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das transferências indisponível."))?;
    let control = transfers
        .get(&transfer_id)
        .ok_or_else(|| AppError::new("transfer", "A transferência já terminou."))?;
    control.paused.store(false, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
fn cancel_transfer(state: State<'_, AppState>, transfer_id: String) -> AppResult<()> {
    let transfers = state
        .transfers
        .lock()
        .map_err(|_| AppError::new("internal", "Estado das transferências indisponível."))?;
    let control = transfers
        .get(&transfer_id)
        .ok_or_else(|| AppError::new("transfer", "A transferência já terminou."))?;
    control.cancelled.store(true, Ordering::SeqCst);
    control.paused.store(false, Ordering::SeqCst);
    Ok(())
}

fn emit_external_edit(
    app: &AppHandle,
    edit_id: &str,
    profile_id: &str,
    remote_path: &Path,
    status: &str,
    message: impl Into<String>,
) {
    let _ = app.emit(
        "external-edit-status",
        ExternalEditEvent {
            edit_id: edit_id.into(),
            profile_id: profile_id.into(),
            remote_path: remote_path.to_string_lossy().replace('\\', "/"),
            status: status.into(),
            message: message.into(),
        },
    );
}

fn local_modified(path: &Path) -> AppResult<SystemTime> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|e| {
            AppError::new(
                "editor",
                format!("Não foi possível observar o arquivo: {e}"),
            )
        })
}

fn remote_revision(stat: &FileStat) -> (Option<u64>, Option<u64>) {
    (stat.size, stat.mtime)
}

fn editor_backup_dir(app: &AppHandle, profile_id: &str, remote_path: &Path) -> AppResult<PathBuf> {
    let hash = format!(
        "{:x}",
        Sha256::digest(remote_path.to_string_lossy().as_bytes())
    );
    let dir = data_dir(app)?
        .join("editor-backups")
        .join(profile_id)
        .join(hash);
    fs::create_dir_all(&dir).map_err(|e| AppError::new("editor_backup", e.to_string()))?;
    Ok(dir)
}

fn backup_remote_file(
    app: &AppHandle,
    profile: &Profile,
    sftp: &Sftp,
    remote_path: &Path,
) -> AppResult<PathBuf> {
    let dir = editor_backup_dir(app, &profile.id, remote_path)?;
    let filename = remote_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let backup = dir.join(format!(
        "{}-{}-{}",
        unix_now(),
        uuid::Uuid::new_v4(),
        filename
    ));
    let mut source = sftp.open(remote_path).map_err(|e| {
        AppError::new(
            "editor_backup",
            format!("Não foi possível criar a cópia de segurança: {e}"),
        )
    })?;
    let mut target =
        fs::File::create(&backup).map_err(|e| AppError::new("editor_backup", e.to_string()))?;
    std::io::copy(&mut source, &mut target)
        .map_err(|e| AppError::new("editor_backup", e.to_string()))?;
    let mut entries = fs::read_dir(&dir)
        .map_err(|e| AppError::new("editor_backup", e.to_string()))?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|e| {
        e.metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    let remove_count = entries.len().saturating_sub(20);
    for old in entries.into_iter().take(remove_count) {
        let _ = fs::remove_file(old.path());
    }
    Ok(backup)
}

fn sync_external_file(
    app: &AppHandle,
    edit_id: &str,
    profile: &Profile,
    remote_path: &Path,
    local_path: &Path,
    password: Option<&str>,
    passphrase: Option<&str>,
    baseline: &mut FileStat,
) -> AppResult<()> {
    emit_external_edit(
        app,
        edit_id,
        &profile.id,
        remote_path,
        "syncing",
        "Enviando alteração ao servidor…",
    );
    let session = connected_session(app, profile, password, passphrase)?;
    let sftp = session
        .sftp()
        .map_err(|e| AppError::new("editor", format!("SFTP indisponível: {e}")))?;
    let current = sftp
        .stat(remote_path)
        .map_err(|e| AppError::new("editor", format!("Arquivo remoto inacessível: {e}")))?;
    if remote_revision(&current) != remote_revision(baseline) {
        emit_external_edit(
            app,
            edit_id,
            &profile.id,
            remote_path,
            "conflict",
            "O arquivo mudou no servidor. A cópia local não foi enviada.",
        );
        return Err(AppError::new(
            "editor_conflict",
            "O arquivo foi alterado no servidor durante a edição.",
        ));
    }
    backup_remote_file(app, profile, &sftp, remote_path)?;
    let mut source = fs::File::open(local_path)
        .map_err(|e| AppError::new("editor", format!("Cópia local inacessível: {e}")))?;
    let mut target = sftp.create(remote_path).map_err(|e| {
        AppError::new(
            "editor",
            format!("Não foi possível gravar no servidor: {e}"),
        )
    })?;
    std::io::copy(&mut source, &mut target)
        .map_err(|e| AppError::new("editor", format!("Sincronização falhou: {e}")))?;
    drop(target);
    if let Some(permissions) = baseline.perm {
        let _ = sftp.setstat(
            remote_path,
            FileStat {
                size: None,
                uid: None,
                gid: None,
                perm: Some(permissions),
                atime: None,
                mtime: None,
            },
        );
    }
    *baseline = sftp.stat(remote_path).map_err(|e| {
        AppError::new(
            "editor",
            format!("Não foi possível confirmar o salvamento: {e}"),
        )
    })?;
    emit_external_edit(
        app,
        edit_id,
        &profile.id,
        remote_path,
        "saved",
        "Arquivo salvo no servidor.",
    );
    notify(
        app,
        "Firaw SSH — arquivo sincronizado",
        &format!("{} foi salvo em {}", remote_path.display(), profile.name),
    );
    Ok(())
}

#[tauri::command]
fn restore_editor_backup(
    app: AppHandle,
    profile_id: String,
    remote_path: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<String> {
    let profile = profile_by_id(&app, &profile_id)?;
    let remote = PathBuf::from(remote_path.trim());
    let dir = editor_backup_dir(&app, &profile.id, &remote)?;
    let mut backups = fs::read_dir(&dir)
        .map_err(|e| AppError::new("editor_backup", e.to_string()))?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    backups.sort_by_key(|e| {
        e.metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    let latest = backups
        .last()
        .ok_or_else(|| {
            AppError::new(
                "editor_backup",
                "Ainda não existe cópia de segurança deste arquivo.",
            )
        })?
        .path();
    let session = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    let sftp = session
        .sftp()
        .map_err(|e| AppError::new("editor_backup", e.to_string()))?;
    let permissions = sftp.stat(&remote).ok().and_then(|s| s.perm);
    let mut source =
        fs::File::open(&latest).map_err(|e| AppError::new("editor_backup", e.to_string()))?;
    let mut target = sftp
        .create(&remote)
        .map_err(|e| AppError::new("editor_backup", format!("Não foi possível restaurar: {e}")))?;
    std::io::copy(&mut source, &mut target)
        .map_err(|e| AppError::new("editor_backup", e.to_string()))?;
    drop(target);
    if let Some(perm) = permissions {
        let _ = sftp.setstat(
            &remote,
            FileStat {
                size: None,
                uid: None,
                gid: None,
                perm: Some(perm),
                atime: None,
                mtime: None,
            },
        );
    }
    notify(
        &app,
        "Firaw SSH — arquivo restaurado",
        &format!("{} voltou para a versão anterior.", remote.display()),
    );
    Ok(format!(
        "Versão anterior restaurada em {}.",
        remote.display()
    ))
}

fn run_external_editor(
    app: AppHandle,
    edit_id: String,
    profile: Profile,
    requested_remote: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<()> {
    let editor = PathBuf::from(&profile.external_editor_path);
    if !editor.is_file() {
        return Err(AppError::new(
            "editor_missing",
            "O editor configurado não foi encontrado. Escolha novamente o executável no perfil.",
        ));
    }
    let session = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    let sftp = session
        .sftp()
        .map_err(|e| AppError::new("editor", format!("SFTP indisponível: {e}")))?;
    let remote = sftp
        .realpath(Path::new(requested_remote.trim()))
        .map_err(|e| AppError::new("editor", format!("Arquivo remoto não encontrado: {e}")))?;
    let mut baseline = sftp
        .stat(&remote)
        .map_err(|e| AppError::new("editor", format!("Não foi possível ler os metadados: {e}")))?;
    if baseline.perm.unwrap_or(0) & 0o170000 == 0o040000 {
        return Err(AppError::new(
            "editor",
            "Selecione um arquivo remoto, não uma pasta.",
        ));
    }
    let edit_dir = data_dir(&app)?.join("external-edit").join(&edit_id);
    fs::create_dir_all(&edit_dir).map_err(|e| {
        AppError::new(
            "editor",
            format!("Não foi possível criar a área temporária: {e}"),
        )
    })?;
    let local = edit_dir.join(remote.file_name().unwrap_or_default());
    let mut source = sftp
        .open(&remote)
        .map_err(|e| AppError::new("editor", format!("Não foi possível baixar o arquivo: {e}")))?;
    let mut target = fs::File::create(&local).map_err(|e| {
        AppError::new(
            "editor",
            format!("Não foi possível criar a cópia local: {e}"),
        )
    })?;
    std::io::copy(&mut source, &mut target)
        .map_err(|e| AppError::new("editor", format!("Download para edição falhou: {e}")))?;
    drop(target);
    let mut command = Command::new(&editor);
    if editor
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase()
        .contains("notepad++")
    {
        command.args(["-multiInst", "-nosession"]);
    }
    command.arg(&local);
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000);
    let mut child = command
        .spawn()
        .map_err(|e| AppError::new("editor", format!("Não foi possível abrir o editor: {e}")))?;
    emit_external_edit(
        &app,
        &edit_id,
        &profile.id,
        &remote,
        "watching",
        "Editor aberto; salve normalmente para sincronizar.",
    );
    let mut seen = local_modified(&local)?;
    let mut conflict = false;
    loop {
        thread::sleep(Duration::from_millis(500));
        let changed = local_modified(&local)
            .map(|modified| modified > seen)
            .unwrap_or(false);
        if changed && !conflict {
            thread::sleep(Duration::from_millis(350));
            let modified = local_modified(&local)?;
            match sync_external_file(
                &app,
                &edit_id,
                &profile,
                &remote,
                &local,
                password.as_deref(),
                passphrase.as_deref(),
                &mut baseline,
            ) {
                Ok(()) => seen = modified,
                Err(error) if error.code == "editor_conflict" => conflict = true,
                Err(error) => {
                    emit_external_edit(
                        &app,
                        &edit_id,
                        &profile.id,
                        &remote,
                        "failed",
                        &error.message,
                    );
                }
            }
        }
        if child
            .try_wait()
            .map_err(|e| AppError::new("editor", format!("Falha ao acompanhar o editor: {e}")))?
            .is_some()
        {
            break;
        }
    }
    emit_external_edit(
        &app,
        &edit_id,
        &profile.id,
        &remote,
        "closed",
        "Edição externa encerrada.",
    );
    let _ = fs::remove_dir_all(&edit_dir);
    Ok(())
}

#[tauri::command]
fn open_remote_editor(
    app: AppHandle,
    profile_id: String,
    remote_path: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<String> {
    let profile = profile_by_id(&app, &profile_id)?;
    if !profile.external_editor_enabled {
        return Err(AppError::new(
            "editor_disabled",
            "Habilite o editor externo neste perfil.",
        ));
    }
    if remote_path.trim().is_empty() {
        return Err(AppError::new(
            "validation",
            "Informe o arquivo remoto para editar.",
        ));
    }
    let edit_id = uuid::Uuid::new_v4().to_string();
    let thread_id = edit_id.clone();
    thread::spawn(move || {
        emit_external_edit(
            &app,
            &thread_id,
            &profile.id,
            Path::new(&remote_path),
            "opening",
            "Preparando editor externo…",
        );
        if let Err(error) = run_external_editor(
            app.clone(),
            thread_id.clone(),
            profile.clone(),
            remote_path,
            password,
            passphrase,
        ) {
            emit_external_edit(
                &app,
                &thread_id,
                &profile.id,
                Path::new(""),
                "failed",
                &error.message,
            );
            notify(&app, "Firaw SSH — editor externo", &error.message);
        }
    });
    Ok(edit_id)
}

#[tauri::command]
fn sftp_list(
    app: AppHandle,
    profile_id: String,
    path: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<Vec<RemoteEntry>> {
    let profile = profile_by_id(&app, &profile_id)?;
    let session = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    let sftp = session
        .sftp()
        .map_err(|e| AppError::new("sftp", format!("SFTP indisponível: {e}")))?;
    let requested = if path.trim().is_empty() {
        "."
    } else {
        path.trim()
    };
    let real = sftp
        .realpath(Path::new(requested))
        .map_err(|e| AppError::new("sftp", format!("Pasta inacessível: {e}")))?;
    let mut entries = sftp
        .readdir(&real)
        .map_err(|e| AppError::new("sftp", format!("Não foi possível listar: {e}")))?
        .into_iter()
        .map(|(path, stat)| {
            let permissions = stat.perm.unwrap_or(0);
            RemoteEntry {
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                path: path.to_string_lossy().replace('\\', "/"),
                is_directory: permissions & 0o170000 == 0o040000,
                size: stat.size.unwrap_or(0),
                modified: stat.mtime.unwrap_or(0),
                permissions,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        b.is_directory
            .cmp(&a.is_directory)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

#[tauri::command]
fn sftp_upload(
    app: AppHandle,
    profile_id: String,
    remote_directory: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<String> {
    let local = app
        .dialog()
        .file()
        .blocking_pick_file()
        .and_then(|f| f.into_path().ok())
        .ok_or_else(|| AppError::new("cancelled", "Envio cancelado."))?;
    let name = local
        .file_name()
        .ok_or_else(|| AppError::new("sftp", "Arquivo local inválido."))?;
    let remote = Path::new(&remote_directory).join(name);
    let profile = profile_by_id(&app, &profile_id)?;
    let session = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    let sftp = session
        .sftp()
        .map_err(|e| AppError::new("sftp", e.to_string()))?;
    let mut source = fs::File::open(&local).map_err(|e| AppError::new("storage", e.to_string()))?;
    let mut target = sftp.create(&remote).map_err(|e| {
        AppError::new(
            "sftp",
            format!("Não foi possível criar o arquivo remoto: {e}"),
        )
    })?;
    std::io::copy(&mut source, &mut target)
        .map_err(|e| AppError::new("sftp", format!("Envio falhou: {e}")))?;
    Ok(remote.to_string_lossy().replace('\\', "/"))
}

#[tauri::command]
fn sftp_download(
    app: AppHandle,
    profile_id: String,
    remote_path: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<String> {
    let suggested = Path::new(&remote_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let local = app
        .dialog()
        .file()
        .set_file_name(suggested.as_ref())
        .blocking_save_file()
        .and_then(|f| f.into_path().ok())
        .ok_or_else(|| AppError::new("cancelled", "Download cancelado."))?;
    let profile = profile_by_id(&app, &profile_id)?;
    let session = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    let sftp = session
        .sftp()
        .map_err(|e| AppError::new("sftp", e.to_string()))?;
    let mut source = sftp.open(Path::new(&remote_path)).map_err(|e| {
        AppError::new(
            "sftp",
            format!("Não foi possível abrir o arquivo remoto: {e}"),
        )
    })?;
    let mut target =
        fs::File::create(&local).map_err(|e| AppError::new("storage", e.to_string()))?;
    std::io::copy(&mut source, &mut target)
        .map_err(|e| AppError::new("sftp", format!("Download falhou: {e}")))?;
    Ok(local.to_string_lossy().into_owned())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TunnelStarted {
    name: String,
    listen_host: String,
    listen_port: u16,
    target: String,
}

fn pump_forward(
    app: &AppHandle,
    socket: TcpStream,
    profile: Profile,
    target_host: String,
    target_port: u16,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<()> {
    let session = connected_session(app, &profile, password.as_deref(), passphrase.as_deref())?;
    let channel = session
        .channel_direct_tcpip(&target_host, target_port, None)
        .map_err(|e| AppError::new("tunnel", format!("Destino recusou o túnel: {e}")))?;
    pump_socket_channel(socket, &session, channel)
}

fn launch_local_forward(
    app: AppHandle,
    profile: Profile,
    rule: TunnelRule,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<(TunnelStarted, mpsc::Sender<()>)> {
    let listener =
        TcpListener::bind((rule.listen_host.as_str(), rule.listen_port)).map_err(|e| {
            AppError::new(
                "tunnel",
                format!(
                    "Não foi possível abrir {}:{}: {e}",
                    rule.listen_host, rule.listen_port
                ),
            )
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|e| AppError::new("tunnel", e.to_string()))?;
    let local = listener
        .local_addr()
        .map_err(|e| AppError::new("tunnel", e.to_string()))?;
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let started = TunnelStarted {
        name: rule.name.clone(),
        listen_host: rule.listen_host.clone(),
        listen_port: local.port(),
        target: format!("{}:{}", rule.target_host, rule.target_port),
    };
    thread::spawn(move || loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((socket, _)) => {
                let p = profile.clone();
                let host = rule.target_host.clone();
                let pw = password.clone();
                let pp = passphrase.clone();
                let app_connection = app.clone();
                let rule_name = rule.name.clone();
                thread::spawn(move || {
                    if let Err(error) =
                        pump_forward(&app_connection, socket, p, host, rule.target_port, pw, pp)
                    {
                        let _ = app_connection
                            .emit("tunnel-error", format!("{rule_name}: {}", error.message));
                    }
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(40)),
            Err(e) => {
                let _ = app.emit("tunnel-error", format!("{}: {e}", rule.name));
                break;
            }
        }
    });
    Ok((started, stop_tx))
}

fn socks5_target(socket: &mut TcpStream) -> AppResult<(String, u16)> {
    socket.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut head = [0u8; 2];
    socket
        .read_exact(&mut head)
        .map_err(|e| AppError::new("socks", format!("Cliente SOCKS5 inválido: {e}")))?;
    if head[0] != 5 {
        return Err(AppError::new("socks", "Somente SOCKS5 é aceito."));
    }
    let mut methods = vec![0u8; head[1] as usize];
    socket
        .read_exact(&mut methods)
        .map_err(|e| AppError::new("socks", e.to_string()))?;
    if !methods.contains(&0) {
        let _ = socket.write_all(&[5, 255]);
        return Err(AppError::new(
            "socks",
            "O cliente exige autenticação SOCKS não suportada.",
        ));
    }
    socket
        .write_all(&[5, 0])
        .map_err(|e| AppError::new("socks", e.to_string()))?;
    let mut req = [0u8; 4];
    socket
        .read_exact(&mut req)
        .map_err(|e| AppError::new("socks", e.to_string()))?;
    if req[0] != 5 || req[1] != 1 {
        return Err(AppError::new(
            "socks",
            "O túnel SOCKS aceita somente conexões TCP.",
        ));
    }
    let host = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            socket
                .read_exact(&mut b)
                .map_err(|e| AppError::new("socks", e.to_string()))?;
            Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0u8; 16];
            socket
                .read_exact(&mut b)
                .map_err(|e| AppError::new("socks", e.to_string()))?;
            Ipv6Addr::from(b).to_string()
        }
        3 => {
            let mut n = [0u8];
            socket
                .read_exact(&mut n)
                .map_err(|e| AppError::new("socks", e.to_string()))?;
            let mut b = vec![0u8; n[0] as usize];
            socket
                .read_exact(&mut b)
                .map_err(|e| AppError::new("socks", e.to_string()))?;
            String::from_utf8(b).map_err(|_| AppError::new("socks", "Destino SOCKS inválido."))?
        }
        _ => return Err(AppError::new("socks", "Tipo de endereço SOCKS inválido.")),
    };
    let mut port = [0u8; 2];
    socket
        .read_exact(&mut port)
        .map_err(|e| AppError::new("socks", e.to_string()))?;
    socket
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .map_err(|e| AppError::new("socks", e.to_string()))?;
    socket.set_read_timeout(None).ok();
    Ok((host, u16::from_be_bytes(port)))
}

fn launch_dynamic_forward(
    app: AppHandle,
    profile: Profile,
    rule: TunnelRule,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<(TunnelStarted, mpsc::Sender<()>)> {
    let listener =
        TcpListener::bind((rule.listen_host.as_str(), rule.listen_port)).map_err(|e| {
            AppError::new(
                "tunnel",
                format!(
                    "Não foi possível abrir o SOCKS {}:{}: {e}",
                    rule.listen_host, rule.listen_port
                ),
            )
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|e| AppError::new("tunnel", e.to_string()))?;
    let local = listener
        .local_addr()
        .map_err(|e| AppError::new("tunnel", e.to_string()))?;
    let (stop_tx, stop_rx) = mpsc::channel();
    let started = TunnelStarted {
        name: rule.name.clone(),
        listen_host: rule.listen_host.clone(),
        listen_port: local.port(),
        target: "SOCKS5 dinâmico".into(),
    };
    thread::spawn(move || loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((mut socket, _)) => {
                let p = profile.clone();
                let pw = password.clone();
                let pp = passphrase.clone();
                let app2 = app.clone();
                let name = rule.name.clone();
                thread::spawn(move || {
                    let result = (|| {
                        let (host, port) = socks5_target(&mut socket)?;
                        pump_forward(&app2, socket, p, host, port, pw, pp)
                    })();
                    if let Err(e) = result {
                        let _ = app2.emit("tunnel-error", format!("{name}: {}", e.message));
                    }
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(40)),
            Err(e) => {
                let _ = app.emit("tunnel-error", format!("{}: {e}", rule.name));
                break;
            }
        }
    });
    Ok((started, stop_tx))
}

fn launch_remote_forward(
    app: AppHandle,
    profile: Profile,
    rule: TunnelRule,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<(TunnelStarted, mpsc::Sender<()>)> {
    let session = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    let host = if rule.listen_host.trim().is_empty() {
        None
    } else {
        Some(rule.listen_host.as_str())
    };
    let (mut listener, bound) = session
        .channel_forward_listen(rule.listen_port, host, None)
        .map_err(|e| {
            AppError::new(
                "tunnel",
                format!("O servidor recusou o encaminhamento remoto: {e}"),
            )
        })?;
    session.set_blocking(false);
    let (stop_tx, stop_rx) = mpsc::channel();
    let started = TunnelStarted {
        name: rule.name.clone(),
        listen_host: rule.listen_host.clone(),
        listen_port: bound,
        target: format!("{}:{} (neste PC)", rule.target_host, rule.target_port),
    };
    thread::spawn(move || loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok(channel) => match connect_direct(&rule.target_host, rule.target_port) {
                Ok(socket) => {
                    if let Err(e) = pump_socket_channel(socket, &session, channel) {
                        let _ = app.emit("tunnel-error", format!("{}: {}", rule.name, e.message));
                    }
                }
                Err(e) => {
                    let _ = app.emit("tunnel-error", format!("{}: {}", rule.name, e.message));
                }
            },
            Err(_) => thread::sleep(Duration::from_millis(40)),
        }
    });
    Ok((started, stop_tx))
}

#[tauri::command]
fn start_tunnels(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<Vec<TunnelStarted>> {
    let profile = profile_by_id(&app, &profile_id)?;
    validate_profile(&profile)?;
    let active_rules = profile
        .tunnels
        .iter()
        .filter(|r| r.enabled)
        .cloned()
        .collect::<Vec<_>>();
    if active_rules.is_empty() {
        return Err(AppError::new(
            "tunnel",
            "Este perfil não tem encaminhamentos ativos.",
        ));
    }
    for rule in &active_rules {
        if rule.listen_host.trim().is_empty()
            || (rule.kind != "dynamic"
                && (rule.target_host.trim().is_empty() || rule.target_port == 0))
        {
            return Err(AppError::new(
                "tunnel",
                format!(
                    "Revise os endereços e a porta de destino da regra “{}”.",
                    rule.name
                ),
            ));
        }
    }
    // Falha cedo para não anunciar um listener que só descobriria credenciais
    // inválidas quando o primeiro programa tentasse usá-lo.
    let _preflight = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    if let Some(old) = state
        .tunnels
        .lock()
        .map_err(|_| AppError::new("internal", "Estado dos túneis indisponível."))?
        .remove(&profile_id)
    {
        for stop in old {
            let _ = stop.send(());
        }
    }
    let mut started = Vec::new();
    let mut controls = Vec::new();
    for rule in active_rules {
        let launched = match rule.kind.as_str() {
            "local" => launch_local_forward(
                app.clone(),
                profile.clone(),
                rule,
                password.clone(),
                passphrase.clone(),
            ),
            "dynamic" => launch_dynamic_forward(
                app.clone(),
                profile.clone(),
                rule,
                password.clone(),
                passphrase.clone(),
            ),
            "remote" => launch_remote_forward(
                app.clone(),
                profile.clone(),
                rule,
                password.clone(),
                passphrase.clone(),
            ),
            _ => Err(AppError::new(
                "tunnel",
                "Tipo de encaminhamento desconhecido.",
            )),
        };
        match launched {
            Ok((info, stop)) => {
                started.push(info);
                controls.push(stop);
            }
            Err(error) => {
                for stop in controls {
                    let _ = stop.send(());
                }
                return Err(error);
            }
        }
    }
    state
        .tunnels
        .lock()
        .map_err(|_| AppError::new("internal", "Estado dos túneis indisponível."))?
        .insert(profile_id, controls);
    Ok(started)
}

#[tauri::command]
fn stop_tunnels(state: State<'_, AppState>, profile_id: String) -> AppResult<()> {
    if let Some(controls) = state
        .tunnels
        .lock()
        .map_err(|_| AppError::new("internal", "Estado dos túneis indisponível."))?
        .remove(&profile_id)
    {
        for stop in controls {
            let _ = stop.send(());
        }
    }
    Ok(())
}

#[tauri::command]
fn open_rdp(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    password: Option<String>,
    passphrase: Option<String>,
) -> AppResult<u16> {
    let profile = profile_by_id(&app, &profile_id)?;
    validate_profile(&profile)?;
    if !profile.rdp_enabled {
        return Err(AppError::new(
            "rdp",
            "Ative a Área de trabalho remota neste perfil.",
        ));
    }
    if profile.rdp_host.trim().is_empty() || profile.rdp_port == 0 {
        return Err(AppError::new("rdp", "Informe o computador e a porta RDP."));
    }
    let _preflight = connected_session(&app, &profile, password.as_deref(), passphrase.as_deref())?;
    let rule = TunnelRule {
        name: "Área de trabalho remota".into(),
        kind: "local".into(),
        listen_host: "127.0.0.1".into(),
        listen_port: 0,
        target_host: profile.rdp_host.clone(),
        target_port: profile.rdp_port,
        enabled: true,
    };
    let (started, stop) = launch_local_forward(app, profile, rule, password, passphrase)?;
    let key = format!("rdp:{profile_id}");
    if let Some(old) = state
        .tunnels
        .lock()
        .map_err(|_| AppError::new("internal", "Estado dos túneis indisponível."))?
        .insert(key, vec![stop])
    {
        for item in old {
            let _ = item.send(());
        }
    }
    #[cfg(target_os = "windows")]
    let cliente = Command::new("mstsc.exe")
        .arg(format!("/v:127.0.0.1:{}", started.listen_port))
        .spawn();
    #[cfg(target_os = "linux")]
    let cliente = Command::new("xfreerdp")
        .arg(format!("/v:127.0.0.1:{}", started.listen_port))
        .spawn();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let cliente = Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "RDP não disponível neste sistema"));
    cliente
        .map_err(|e| {
            AppError::new(
                "rdp",
                format!("Não foi possível abrir a Área de Trabalho Remota: {e}"),
            )
        })?;
    Ok(started.listen_port)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(AppState {
            sessions: Mutex::new(HashMap::new()),
            tunnels: Mutex::new(HashMap::new()),
            transfers: Mutex::new(HashMap::new()),
        })
        .setup(|app| {
            let handle = app.handle().clone();
            bridge::start(move |request| handle_bridge_request(&handle, request));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            save_profile,
            delete_profile,
            duplicate_profile,
            choose_key_file,
            choose_editor_file,
            choose_local_files,
            choose_local_directory,
            inspect_host,
            trust_host,
            connect_terminal,
            terminal_input,
            terminal_resize,
            disconnect_terminal,
            sftp_list,
            sftp_upload,
            sftp_download,
            local_home,
            local_list,
            sftp_upload_paths,
            sftp_download_paths,
            pause_transfer,
            resume_transfer,
            cancel_transfer,
            open_remote_editor,
            restore_editor_backup,
            start_tunnels,
            stop_tunnels,
            open_rdp,
            list_bridge_audit,
            export_profiles,
            import_profiles,
            choose_update_installer,
            install_local_update,
        ])
        .run(tauri::generate_context!())
        .expect("falha ao iniciar o Firaw SSH");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_profile() -> Profile {
        Profile {
            host: "server.example".into(),
            username: "deploy".into(),
            ..Profile::default()
        }
    }

    #[test]
    fn rejects_missing_host() {
        let error = validate_profile(&Profile::default()).unwrap_err();
        assert_eq!(error.code, "validation");
        assert!(error.message.contains("servidor"));
    }

    #[test]
    fn accepts_password_profile() {
        assert!(validate_profile(&valid_profile()).is_ok());
    }

    #[test]
    fn key_auth_requires_private_key_path() {
        let mut profile = valid_profile();
        profile.auth_method = "key".into();
        let error = validate_profile(&profile).unwrap_err();
        assert!(error.message.contains("chave privada"));
    }

    #[test]
    fn public_key_selection_uses_matching_private_key() {
        let private = std::env::temp_dir().join(format!("firaw-key-{}", uuid::Uuid::new_v4()));
        let mut public_name = private.as_os_str().to_os_string();
        public_name.push(".pub");
        let public = PathBuf::from(public_name);
        fs::write(&private, "private").unwrap();
        fs::write(&public, "public").unwrap();

        assert_eq!(normalize_selected_key_path(&public), private);
        let (resolved_private, resolved_public) = key_files(&public).unwrap();
        assert_eq!(resolved_private, private);
        assert_eq!(resolved_public, Some(public.clone()));

        fs::remove_file(private).unwrap();
        fs::remove_file(public).unwrap();
    }

    #[test]
    fn public_key_without_private_pair_has_actionable_error() {
        let private = std::env::temp_dir().join(format!("firaw-key-{}", uuid::Uuid::new_v4()));
        let mut public_name = private.as_os_str().to_os_string();
        public_name.push(".pub");
        let public = PathBuf::from(public_name);
        fs::write(&public, "public").unwrap();

        let error = key_files(&public).unwrap_err();
        assert_eq!(error.code, "private_key_missing");
        assert!(error.message.contains("somente a chave pública"));

        fs::remove_file(public).unwrap();
    }

    #[test]
    fn legacy_profiles_keep_both_key_password_steps_enabled() {
        let mut value = serde_json::to_value(valid_profile()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("keyPassphraseEnabled");
        object.remove("accountPasswordEnabled");

        let restored: Profile = serde_json::from_value(value).unwrap();
        assert!(restored.key_passphrase_enabled);
        assert!(restored.account_password_enabled);
    }

    #[test]
    fn fingerprint_comparison_accepts_legacy_base64_padding() {
        assert!(same_fingerprint("SHA256:abc=", "SHA256:abc"));
        assert!(!same_fingerprint("SHA256:abc", "SHA256:def"));
    }

    #[test]
    fn legacy_key_profile_marked_as_password_is_recovered() {
        let mut profile = valid_profile();
        profile.auth_method = "password".into();
        profile.key_path = "C:\\keys\\server".into();
        profile.has_password = true;
        profile.has_passphrase = true;
        profile.key_passphrase_enabled = false;
        profile.account_password_enabled = false;

        migrate_legacy_profiles(std::slice::from_mut(&mut profile));

        assert_eq!(profile.auth_method, "key");
        assert!(profile.key_passphrase_enabled);
        assert!(profile.account_password_enabled);
    }

    #[test]
    fn updater_accepts_only_newer_semantic_release() {
        assert_eq!(
            installer_release_version("firaw ssh_1.4.2_x64-setup.exe"),
            Some((1, 4, 2))
        );
        assert_eq!(installer_release_version("outro-programa.exe"), None);
        assert!(parse_release_version("0.3.1").unwrap() > parse_release_version("0.3.0").unwrap());
    }

    #[test]
    fn backup_key_is_deterministic_and_password_specific() {
        let salt = b"0123456789abcdef";
        let first = derive_backup_key("senha-segura", salt).unwrap();
        let repeated = derive_backup_key("senha-segura", salt).unwrap();
        let different = derive_backup_key("outra-senha", salt).unwrap();
        assert_eq!(first, repeated);
        assert_ne!(first, different);
        assert_eq!(
            derive_backup_key("curta", salt).unwrap_err().code,
            "backup_password"
        );
    }
}
