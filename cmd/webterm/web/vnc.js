'use strict';

/* VNC panes: noVNC in a split-pane session. WebTerm logs in to the VNC server itself, so the browser's
   noVNC talks to a stream that asks for no login and the password never reaches the browser.
   Depends on workspace.js (el, setState, showOverlay, onControl, onClosed, ...) and vendor/novnc. */

function newVncSession(host, wtab) {
  const pane = el('div', 'pane');
  pane.innerHTML = `
    <div class="phead"><span class="dot"></span><span class="pname"></span><span class="grow"></span>
      <button type="button" class="quiet" data-act="kbd" hidden>${icon('keyboard')}Keyboard</button>
      <button type="button" class="quiet" data-act="cad" title="Send Ctrl+Alt+Delete to the remote desktop">Ctrl+Alt+Del</button>
      ${iconButton('clipboard', 'Clipboard', 'data-act="clip"')}
      ${iconButton('layout-columns', 'Split right', 'data-act="split-row"')}
      ${iconButton('layout-rows', 'Split down', 'data-act="split-col"')}
      ${iconButton('x', 'Close pane', 'data-act="close"')}</div>
    <div class="rdpwrap">
      <div class="vncscreen"></div>
      <textarea class="sink" aria-label="Remote desktop keyboard input" autocapitalize="off" autocomplete="off" autocorrect="off" spellcheck="false"></textarea>
      <div class="popover clip" hidden>
        <div class="section-head"><h3>Clipboard</h3>${iconButton('x', 'Close', 'data-clip="close"')}</div>
        <p class="small muted">Text copied on the remote desktop shows up here. To paste into it, type or paste here and send.</p>
        <textarea class="cliptext" rows="5" aria-label="Clipboard text"></textarea>
        <div class="actions"><button type="button" class="primary sm" data-clip="send">Send to remote</button>
          <button type="button" class="sm" data-clip="copy">${icon('copy')}Copy</button></div>
      </div>
    </div>
    <div class="tover" hidden></div>`;
  const sess = {
    kind: 'vnc', host, wtab, pane, head: pane.querySelector('.phead'),
    holder: pane.querySelector('.rdpwrap'), screen: pane.querySelector('.vncscreen'), sink: pane.querySelector('.sink'),
    clipPanel: pane.querySelector('.popover.clip'), clipArea: pane.querySelector('.cliptext'), overlay: pane.querySelector('.tover'),
    rfb: null, sock: null, state: 'connecting', retries: 0, timer: null, closed: false, connectedBefore: false, opened: true,
  };
  if (matchMedia('(pointer: coarse)').matches) pane.querySelector('[data-act=kbd]').hidden = false;

  pane.addEventListener('pointerdown', () => focusSession(sess), true);
  pane.addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    switch (b.dataset.act) {
      case 'close': closeSession(sess); break;
      case 'split-row': splitSession(sess, 'row'); break;
      case 'split-col': splitSession(sess, 'col'); break;
      case 'kbd': sess.sink.focus(); break;
      case 'cad': if (sess.rfb && sess.state === 'live') { sess.rfb.sendCtrlAltDel(); vncFocus(sess); } break;
      case 'clip': sess.clipPanel.hidden = !sess.clipPanel.hidden; b.classList.remove('news'); if (sess.clipPanel.hidden) vncFocus(sess); break;
      default: break;
    }
  });
  sess.clipPanel.addEventListener('click', ev => {
    const b = ev.target.closest('[data-clip]');
    if (!b) return;
    if (b.dataset.clip === 'close') { sess.clipPanel.hidden = true; vncFocus(sess); }
    if (b.dataset.clip === 'send' && sess.rfb) { sess.rfb.clipboardPasteFrom(sess.clipArea.value); toast('Sent to the remote desktop'); }
    if (b.dataset.clip === 'copy') navigator.clipboard.writeText(sess.clipArea.value).then(() => toast('Copied'), () => toast('Could not copy', 'err'));
  });
  bindVncKeyboard(sess);
  updateHead(sess);
  return sess;
}

// A phone has no keyboard until one is asked for: the text box takes what is typed and sends it as keys.
function bindVncKeyboard(sess) {
  const special = { Backspace: 0xFF08, Enter: 0xFF0D, Tab: 0xFF09, Escape: 0xFF1B, ArrowLeft: 0xFF51, ArrowUp: 0xFF52, ArrowRight: 0xFF53, ArrowDown: 0xFF54, Delete: 0xFFFF };
  const keysym = ch => { const c = ch.codePointAt(0); return c < 0x100 ? c : 0x01000000 + c; };
  sess.sink.addEventListener('keydown', ev => {
    if (special[ev.key] && sess.rfb) { ev.preventDefault(); sess.rfb.sendKey(special[ev.key], ev.code); }
  });
  sess.sink.addEventListener('input', () => {
    if (sess.rfb) for (const ch of sess.sink.value) sess.rfb.sendKey(keysym(ch));
    sess.sink.value = '';
  });
}

const vncFocus = sess => { if (sess.rfb) sess.rfb.focus({ preventScroll: true }); };

function vncDrop(sess) {
  const { rfb, sock } = sess;
  sess.rfb = sess.sock = null; // so the events these two raise next are ignored
  if (rfb) { try { rfb.disconnect(); } catch (e) { /* already closed */ } }
  if (sock) { try { sock.close(); } catch (e) { /* already closed */ } }
}

function vncConnect(sess) {
  clearTimeout(sess.timer);
  vncDrop(sess);
  setState(sess, 'connecting');
  showOverlay(sess, { title: 'Connecting…' });
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const sock = new WebSocket(`${proto}://${location.host}/api/ws/vnc/${encodeURIComponent(sess.host.id)}`);
  sock.binaryType = 'arraybuffer';
  sess.sock = sock;
  let attached = false;
  // Until WebTerm has logged in, the socket carries only JSON: a certificate to check, an error, or "ready".
  sock.onmessage = ev => {
    if (sess.sock !== sock || attached || typeof ev.data !== 'string') return;
    const m = JSON.parse(ev.data);
    if (m.type === 'ready') { attached = true; vncAttach(sess, sock); } else onControl(sess, m);
  };
  sock.onclose = ev => { if (sess.sock === sock && !sess.closed && !attached) onClosed(sess, ev); };
}

// Hands the logged-in stream to noVNC.
async function vncAttach(sess, sock) {
  let RFB;
  try { RFB = (await import('/vendor/novnc/core/rfb.js')).default; } catch (e) {
    setState(sess, 'fatal');
    showOverlay(sess, { tone: 'danger', title: 'The VNC viewer did not load', text: 'The page could not load its VNC code. Reload the page and try again.', buttons: [closeButton(sess)] });
    return;
  }
  if (sess.closed || sess.sock !== sock) return;
  const rfb = new RFB(sess.screen, sock, { shared: true });
  rfb.scaleViewport = true;
  rfb.resizeSession = false; // do not change the other machine's screen size
  sess.rfb = rfb;
  sock.send(JSON.stringify({ type: 'attach' }));
  rfb.addEventListener('connect', () => {
    if (sess.rfb !== rfb) return;
    sess.connectedBefore = true;
    sess.retries = 0;
    hideOverlay(sess);
    setState(sess, 'live');
    if (WS.active && WS.active.active === sess) vncFocus(sess);
  });
  rfb.addEventListener('disconnect', ev => {
    if (sess.rfb !== rfb || sess.closed) return;
    sess.rfb = null;
    onClosed(sess, { code: ev.detail.clean ? 1000 : 1006 });
  });
  rfb.addEventListener('securityfailure', ev => {
    if (sess.rfb !== rfb) return;
    setState(sess, 'fatal');
    showOverlay(sess, { tone: 'danger', title: `Could not connect to ${esc(sess.host.name)}`, text: esc((ev.detail && ev.detail.reason) || 'The VNC server refused the connection.'), buttons: [{ label: 'Retry', cls: 'primary', fn: () => { sess.retries = 0; connect(sess); } }, closeButton(sess)] });
  });
  rfb.addEventListener('clipboard', ev => {
    sess.clipArea.value = ev.detail.text;
    if (sess.clipPanel.hidden) sess.head.querySelector('[data-act=clip]').classList.add('news');
  });
}

function vncTeardown(sess) {
  sess.closed = true;
  clearTimeout(sess.timer);
  vncDrop(sess);
  sess.pane.remove();
}
