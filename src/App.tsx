import { Files, TerminalSquare } from 'lucide-react';
import { listen } from '@tauri-apps/api/event';
import { relaunch } from '@tauri-apps/plugin-process';
import { check } from '@tauri-apps/plugin-updater';
import { useEffect, useState } from 'react';
import { api, blankProfile, readableError, type BridgeAuditEntry, type ExternalEditEvent, type Profile, type TransferEvent } from './api';
import ProfileEditor from './ProfileEditor';
import ProfileList from './ProfileList';
import SftpView from './SftpView';
import TerminalView, { type TerminalTabInfo } from './TerminalView';
import TitleBar from './TitleBar';

type View = 'profile'|'terminal'|'sftp';
type SessionTab = TerminalTabInfo & {password?:string;passphrase?:string};
type Pending = {profile:Profile;target:'terminal'|'sftp';password?:string;passphrase?:string;fingerprint:string};
type BackupAction = 'export'|'import';

export default function App(){
  const [profiles,setProfiles]=useState<Profile[]>([]);const [current,setCurrent]=useState<Profile>(blankProfile());const [view,setView]=useState<View>('profile');
  const [password,setPassword]=useState('');const [passphrase,setPassphrase]=useState('');const [savePassword,setSavePassword]=useState(true);const [savePassphrase,setSavePassphrase]=useState(true);
  const [busy,setBusy]=useState(false);const [toast,setToast]=useState<string>();const [log,setLog]=useState<string[]>([]);const [pending,setPending]=useState<Pending>();
  const [audit,setAudit]=useState<BridgeAuditEntry[]>([]);
  const [backupAction,setBackupAction]=useState<BackupAction>();const [backupSecret,setBackupSecret]=useState('');
  const [terminalTabs,setTerminalTabs]=useState<SessionTab[]>([]);const [activeTab,setActiveTab]=useState('');const [showSessionPicker,setShowSessionPicker]=useState(false);
  const addLog=(text:string)=>setLog(old=>[...old.slice(-199),text]);
  const refresh=async(selectId?:string)=>{try{const list=await api.listProfiles();setProfiles(list);if(selectId){const p=list.find(x=>x.id===selectId);if(p)setCurrent(p)}else if(!current.id&&list[0])setCurrent(list[0])}catch(e){setToast(readableError(e).message)}};
  const refreshAudit=async()=>{try{setAudit(await api.listBridgeAudit())}catch{}};
  useEffect(()=>{void refresh();void refreshAudit()},[]);
  useEffect(()=>{void (async()=>{try{const update=await check();if(update){setToast(`Atualizando o Firaw SSH para ${update.version}…`);await update.downloadAndInstall();await relaunch()}}catch{}})()},[]);
  useEffect(()=>{const transfer=listen<TransferEvent>('transfer-progress',e=>{if(['completed','failed','cancelled'].includes(e.payload.status))setToast(e.payload.message)});const editor=listen<ExternalEditEvent>('external-edit-status',e=>{if(e.payload.status==='saved'||e.payload.status==='conflict'||e.payload.status==='failed')setToast(e.payload.message)});const bridge=listen<{status:string;message:string}>('bridge-event',e=>{void refreshAudit();if(e.payload.status!=='started')setToast(e.payload.message)});return()=>{void transfer.then(fn=>fn());void editor.then(fn=>fn());void bridge.then(fn=>fn())}},[]);
  const loadCredentials=(p:Profile)=>{setPassword('');setPassphrase('');setSavePassword(p.hasPassword);setSavePassphrase(p.hasPassphrase)};
  const selectForEdit=(p:Profile)=>{setCurrent(p);loadCredentials(p);setView('profile')};
  const selectProfile=(p:Profile)=>{
    setCurrent(p);loadCredentials(p);
    if(view==='terminal'){
      const existing=terminalTabs.find(t=>t.profile.id===p.id);
      if(existing)setActiveTab(existing.id);else void prepareConnection(p,'terminal');
    }else if(view==='sftp')void prepareConnection(p,'sftp');
  };
  const save=async()=>{setBusy(true);try{const saved=await api.saveProfile({profile:current,password:password||undefined,passphrase:passphrase||undefined,savePassword,savePassphrase});setCurrent(saved);await refresh(saved.id);setToast('Perfil salvo com segurança.');addLog(`${new Date().toLocaleTimeString()} · Perfil “${saved.name}” salvo.`);return saved}catch(e){setToast(readableError(e).message)}finally{setBusy(false)}};
  const openConnection=async(target:'terminal'|'sftp')=>{setBusy(true);try{const saved=await api.saveProfile({profile:current,password:password||undefined,passphrase:passphrase||undefined,savePassword,savePassphrase});setCurrent(saved);await refresh(saved.id);await prepareConnection(saved,target,password||undefined,passphrase||undefined)}catch(e){showError(e)}finally{setBusy(false)}};
  const prepareConnection=async(profile:Profile,target:'terminal'|'sftp',pwd?:string,phrase?:string)=>{setBusy(true);try{const inspection=await api.inspectHost(profile.id);if(!inspection.trusted){setPending({profile,target,password:pwd,passphrase:phrase,fingerprint:inspection.fingerprint});return}activate(profile,target,pwd,phrase)}catch(e){showError(e)}finally{setBusy(false)}};
  const activate=(profile:Profile,target:'terminal'|'sftp',pwd?:string,phrase?:string)=>{setCurrent(profile);if(target==='sftp'){setView('sftp');return}const tab={id:crypto.randomUUID(),profile,password:pwd,passphrase:phrase};setTerminalTabs(old=>[...old,tab]);setActiveTab(tab.id);setView('terminal');setShowSessionPicker(false)};
  const confirmTrust=async()=>{if(!pending)return;setBusy(true);try{const saved=await api.trustHost(pending.profile.id,pending.fingerprint);await refresh(saved.id);setPending(undefined);activate(saved,pending.target,pending.password,pending.passphrase);addLog(`${new Date().toLocaleTimeString()} · Identidade confirmada: ${pending.fingerprint}`)}catch(e){showError(e)}finally{setBusy(false)}};
  const closeTab=(id:string)=>{setTerminalTabs(old=>{const index=old.findIndex(t=>t.id===id);const next=old.filter(t=>t.id!==id);if(id===activeTab){const replacement=next[Math.min(index,next.length-1)];setActiveTab(replacement?.id||'');if(!replacement)setView('profile')}return next})};
  const remove=async(p:Profile)=>{if(!confirm(`Excluir o perfil “${p.name}” e suas credenciais salvas?`))return;try{await api.deleteProfile(p.id);const left=profiles.filter(x=>x.id!==p.id);setProfiles(left);setCurrent(left[0]||blankProfile());setToast('Perfil excluído.')}catch(e){setToast(readableError(e).message)}};
  const duplicate=async(p:Profile)=>{try{const copy=await api.duplicateProfile(p.id);await refresh(copy.id);setCurrent(copy);setView('profile');setToast('Perfil duplicado; informe as credenciais.')}catch(e){setToast(readableError(e).message)}};
  const showError=(error:unknown)=>{const err=readableError(error);setToast(err.message);addLog(`${new Date().toLocaleTimeString()} · ${err.message}`)};
  const openBackup=(action:BackupAction)=>{setBackupSecret('');setBackupAction(action)};
  const confirmBackup=async()=>{if(!backupAction)return;if(backupSecret.length<8){setToast('Use uma senha de backup com pelo menos 8 caracteres.');return}setBusy(true);try{if(backupAction==='export'){const path=await api.exportProfiles(backupSecret);setToast(`Backup salvo em ${path}`)}else{const count=await api.importProfiles(backupSecret);await refresh();setToast(`${count} perfil(is) restaurado(s) com as credenciais.`)}setBackupAction(undefined);setBackupSecret('')}catch(e){showError(e)}finally{setBusy(false)}};
  const updateLocal=async()=>{try{const path=await api.chooseUpdateInstaller();if(!path)return;if(confirm('O Firaw SSH será fechado e o instalador selecionado será executado. Continuar?'))await api.installLocalUpdate(path)}catch(e){showError(e)}};
  const fullLog=[...audit.map(a=>`${new Date(a.timestamp*1000).toLocaleString()} · Ponte · ${a.profileName} · ${a.action} · ${a.status} · ${a.summary}`),...log];
  const sftpProfile=current;
  return <div className="app-shell"><TitleBar/><div className="workspace"><ProfileList profiles={profiles} selected={current.id} onSelect={selectProfile} onNew={()=>selectForEdit(blankProfile())} onDuplicate={p=>void duplicate(p)} onDelete={p=>void remove(p)} onExport={()=>openBackup('export')} onImport={()=>openBackup('import')} onUpdate={()=>void updateLocal()}/><main className="main-workspace">
    {view==='profile'&&<><ProfileEditor profile={current} profiles={profiles} onChange={setCurrent} password={password} passphrase={passphrase} onPassword={setPassword} onPassphrase={setPassphrase} savePassword={savePassword} savePassphrase={savePassphrase} setSavePassword={setSavePassword} setSavePassphrase={setSavePassphrase} onSave={save} onConnect={()=>void openConnection('terminal')} busy={busy} log={fullLog}/>{current.id&&<div className="quick-rail"><button title="Abrir terminal" onClick={()=>void openConnection('terminal')}><TerminalSquare size={19}/></button><button title="Abrir SFTP" onClick={()=>void openConnection('sftp')}><Files size={19}/></button></div>}</>}
    {terminalTabs.map(tab=><TerminalView key={tab.id} tabId={tab.id} profile={tab.profile} password={tab.password} passphrase={tab.passphrase} isActive={view==='terminal'&&activeTab===tab.id} tabs={terminalTabs} onSelectTab={id=>{setActiveTab(id);setView('terminal');const selected=terminalTabs.find(t=>t.id===id);if(selected)setCurrent(selected.profile)}} onCloseTab={closeTab} onNewTab={()=>setShowSessionPicker(true)} onBack={()=>setView('profile')} onLog={addLog}/>)}
    {view==='sftp'&&<SftpView key={sftpProfile.id} profile={sftpProfile} password={password||undefined} passphrase={passphrase||undefined} onBack={()=>setView('profile')}/>} </main></div>
    {toast&&<div className="toast" onAnimationEnd={()=>setToast(undefined)}>{toast}</div>}
    {pending&&<div className="modal-backdrop"><div className="trust-modal"><span className="shield">✓</span><small>PRIMEIRA CONEXÃO</small><h2>Confirme este servidor</h2><p>Compare esta impressão digital com a informada pelo administrador. Ela será usada para bloquear servidores falsos nas próximas conexões.</p><code>{pending.fingerprint}</code><div className="modal-actions"><button className="btn secondary" onClick={()=>setPending(undefined)}>Cancelar</button><button className="btn primary" disabled={busy} onClick={()=>void confirmTrust()}>Confiar e conectar</button></div></div></div>}
    {backupAction&&<div className="modal-backdrop"><form className="trust-modal backup-modal" onSubmit={e=>{e.preventDefault();void confirmBackup()}}><span className="shield">✓</span><small>BACKUP PROTEGIDO</small><h2>{backupAction==='export'?'Salvar perfis e credenciais':'Restaurar perfis e credenciais'}</h2><p>{backupAction==='export'?'Crie uma senha exclusiva. Ela será necessária para restaurar este backup.':'Digite a senha usada quando este backup foi criado.'}</p><label className="field">Senha do backup<input autoFocus type="password" autoComplete="new-password" minLength={8} value={backupSecret} onChange={e=>setBackupSecret(e.target.value)} placeholder="Mínimo de 8 caracteres"/></label><div className="modal-actions"><button type="button" className="btn secondary" onClick={()=>setBackupAction(undefined)}>Cancelar</button><button type="submit" className="btn primary" disabled={busy||backupSecret.length<8}>{busy?'Aguarde…':backupAction==='export'?'Escolher onde salvar':'Escolher backup'}</button></div></form></div>}
    {showSessionPicker&&<div className="modal-backdrop"><div className="session-picker"><small>NOVA SESSÃO</small><h2>Escolha um servidor</h2><p>Você pode abrir outra sessão do mesmo servidor ou usar outro perfil sem encerrar as conexões atuais.</p><div>{profiles.map(p=><button key={p.id} onClick={()=>void prepareConnection(p,'terminal')}><span className="server-icon" style={{'--profile-color':p.color} as React.CSSProperties}><TerminalSquare size={16}/></span><span><strong>{p.name}</strong><small>{p.username}@{p.host}:{p.port}</small></span></button>)}</div><div className="modal-actions"><button className="btn secondary" onClick={()=>setShowSessionPicker(false)}>Cancelar</button></div></div></div>}
  </div>;
}
