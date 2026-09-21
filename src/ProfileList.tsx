import { Copy, Download, MoreHorizontal, Plus, RefreshCw, Search, Server, Star, Trash2, Upload } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { Profile } from './api';

export default function ProfileList({ profiles, selected, onSelect, onNew, onDuplicate, onDelete, onExport, onImport, onUpdate }: {
  profiles: Profile[]; selected?: string; onSelect: (p: Profile) => void; onNew: () => void;
  onDuplicate: (p: Profile) => void; onDelete: (p: Profile) => void;
  onExport:()=>void; onImport:()=>void; onUpdate:()=>void;
}) {
  const [search, setSearch] = useState('');
  const [menu, setMenu] = useState<string>();
  const visible = useMemo(() => profiles.filter(p => `${p.name} ${p.host} ${p.username}`.toLowerCase().includes(search.toLowerCase()))
    .sort((a,b) => Number(b.favorite)-Number(a.favorite) || a.name.localeCompare(b.name, 'pt-BR')), [profiles, search]);
  return <aside className="profiles">
    <div className="profiles-head"><div><small>CONEXÕES</small><strong>Seus servidores</strong></div><button className="icon primary" onClick={onNew} title="Novo perfil"><Plus size={18}/></button></div>
    <label className="search"><Search size={15}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Buscar perfil…"/></label>
    <div className="profile-scroll">
      {visible.map(p => <div key={p.id} className={`profile-item ${selected===p.id?'active':''}`} onClick={()=>onSelect(p)}>
        <span className="server-icon" style={{'--profile-color':p.color} as React.CSSProperties}><Server size={17}/></span>
        <span className="profile-text"><strong>{p.name}</strong><small>{p.username || 'usuário'}@{p.host || 'servidor'}:{p.port}</small></span>
        {p.favorite && <Star size={13} className="favorite" fill="currentColor"/>}
        <button className="more" onClick={e=>{e.stopPropagation();setMenu(menu===p.id?undefined:p.id)}}><MoreHorizontal size={16}/></button>
        {menu===p.id && <div className="mini-menu">
          <button onClick={e=>{e.stopPropagation();onDuplicate(p);setMenu(undefined)}}><Copy size={14}/>Duplicar</button>
          <button className="danger" onClick={e=>{e.stopPropagation();onDelete(p);setMenu(undefined)}}><Trash2 size={14}/>Excluir</button>
        </div>}
      </div>)}
      {!visible.length && <div className="empty-list"><Server size={30}/><span>Nenhum perfil</span><small>Crie sua primeira conexão.</small></div>}
    </div>
    <div className="profile-tools"><button title="Exportar backup criptografado" onClick={onExport}><Upload size={14}/>Backup</button><button title="Importar backup criptografado" onClick={onImport}><Download size={14}/>Restaurar</button><button title="Instalar atualização" onClick={onUpdate}><RefreshCw size={14}/>Atualizar</button></div>
    <div className="vault-note"><span>●</span><div><strong>Cofre do sistema</strong><small>Senhas ficam protegidas neste computador</small></div></div>
  </aside>;
}
