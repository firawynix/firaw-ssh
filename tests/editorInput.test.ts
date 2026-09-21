import assert from 'node:assert/strict';
import test from 'node:test';
import { extractEditorTarget, extractNanoPath, normalizeRemoteEditorInput, trackExternalEditorInput } from '../src/editorInput.ts';

test('aceita caminho puro e comandos dos editores suportados', () => {
  assert.equal(normalizeRemoteEditorInput('/home/ksdev/config.lua'), '/home/ksdev/config.lua');
  assert.equal(normalizeRemoteEditorInput('nano /home/ksdev/config.lua'), '/home/ksdev/config.lua');
  assert.equal(normalizeRemoteEditorInput('sudo vim "/home/ksdev/meu arquivo.lua"'), '/home/ksdev/meu arquivo.lua');
  assert.equal(extractEditorTarget('vi -R /etc/hosts'), '/etc/hosts');
});

test('intercepta comando colado de uma vez antes que o nano abra', () => {
  const result = trackExternalEditorInput('nano /home/ksdev/config.lua\r', { line: '', escapeState: 0 });
  assert.deepEqual(result.targets, ['/home/ksdev/config.lua']);
  assert.equal(result.outgoing, 'nano /home/ksdev/config.lua\x15\r');
  assert.equal(result.line, '');
});

test('intercepta comando digitado e ignora marcadores de colagem do terminal', () => {
  const pasted = trackExternalEditorInput('\x1b[200~nano /etc/hosts\x1b[201~', { line: '', escapeState: 0 });
  assert.equal(pasted.line, 'nano /etc/hosts');
  const enter = trackExternalEditorInput('\r', pasted);
  assert.deepEqual(enter.targets, ['/etc/hosts']);
  assert.equal(enter.outgoing, '\x15\r');
});

test('intercepta comando enviado pelo botão de colar antes do Enter', () => {
  const pasted = trackExternalEditorInput('nano /home/ksdev/crystalserver/config.lua', { line: '', escapeState: 0 });
  const enter = trackExternalEditorInput('\r', pasted);
  assert.deepEqual(enter.targets, ['/home/ksdev/crystalserver/config.lua']);
});

test('recupera o caminho exibido pelo nano quando ele chegou a abrir', () => {
  assert.equal(
    extractNanoPath('GNU nano 7.2                         /home/ksdev/crystalserver/config.lua'),
    '/home/ksdev/crystalserver/config.lua',
  );
});
