import { getCurrentWindow } from '@tauri-apps/api/window';
import { Minus, Square, TerminalSquare, X } from 'lucide-react';

export default function TitleBar() {
  return <header className="titlebar" data-tauri-drag-region>
    <div className="brand" data-tauri-drag-region><TerminalSquare size={17}/><span>Firaw<span>SSH</span></span><small>0.3.0</small></div>
    <div className="window-actions">
      <button aria-label="Minimizar" onClick={() => void getCurrentWindow().minimize()}><Minus size={16}/></button>
      <button aria-label="Maximizar" onClick={() => void getCurrentWindow().toggleMaximize()}><Square size={13}/></button>
      <button className="close" aria-label="Fechar" onClick={() => void getCurrentWindow().close()}><X size={16}/></button>
    </div>
  </header>;
}
