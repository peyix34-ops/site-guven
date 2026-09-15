const dns = require('dns').promises;
const fetch = require('node-fetch');
const cheerio = require('cheerio');

// 02 - DNS cozumleme
async function resolveDns(hostname) {
  try {
    const [a, aaaa] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname)
    ]);
    return {
      checked: true,
      a: a.status === 'fulfilled' ? a.value : [],
      aaaa: aaaa.status === 'fulfilled' ? aaaa.value : []
    };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

// 04/05 - HTTP analiz + yonlendirme zinciri (elle takip edilir, otomatik redirect kapali)
async function fetchWithRedirects(url, maxHops = 10) {
  const chain = [];
  let current = url;
  let res;
  for (let i = 0; i < maxHops; i++) {
    res = await fetch(current, { redirect: 'manual', timeout: 8000 });
    chain.push({ url: current, status: res.status });
    if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.get('location')) {
      current = new URL(res.headers.get('location'), current).toString();
      continue;
    }
    break;
  }
  const html = res.status < 400 ? await res.text() : '';
  return { chain, finalUrl: current, status: res.status, headers: res.headers, html };
}

// 06 - Guvenlik basliklari
function checkSecurityHeaders(headers) {
  const wanted = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy'
  ];
  const present = {};
  wanted.forEach(h => { present[h] = headers.get(h) || null; });
  const missing = wanted.filter(h => !present[h]);
  return { checked: true, present, missing };
}

// 07 - Cerez analizi
function analyzeCookies(headers) {
  const raw = headers.raw ? headers.raw()['set-cookie'] : null;
  if (!raw || raw.length === 0) return { checked: true, count: 0, issues: [] };
  const issues = [];
  raw.forEach(c => {
    if (!/secure/i.test(c)) issues.push('Secure bayragi eksik bir cerez var');
    if (!/httponly/i.test(c)) issues.push('HttpOnly bayragi eksik bir cerez var');
    if (!/samesite/i.test(c)) issues.push('SameSite bayragi eksik bir cerez var');
  });
  return { checked: true, count: raw.length, issues: [...new Set(issues)] };
}

// 08 - Form analizi
function analyzeForms(html, baseUrl) {
  const $ = cheerio.load(html);
  const forms = [];
  $('form').each((i, el) => {
    const action = $(el).attr('action') || '';
    const method = ($(el).attr('method') || 'get').toUpperCase();
    const hasPassword = $(el).find('input[type="password"]').length > 0;
    let actionHost = null;
    try { actionHost = new URL(action, baseUrl).hostname; } catch {}
    forms.push({ method, hasPassword, actionHost });
  });
  const risky = forms.filter(f => f.hasPassword && baseUrl.startsWith('http://'));
  return { checked: true, count: forms.length, forms, riskyOverHttp: risky.length };
}

// 09 - JavaScript referanslari
function analyzeScripts(html, baseUrl) {
  const $ = cheerio.load(html);
  const external = [];
  let inlineCount = 0;
  $('script').each((i, el) => {
    const src = $(el).attr('src');
    if (src) {
      try { external.push(new URL(src, baseUrl).hostname); } catch {}
    } else {
      inlineCount++;
    }
  });
  return { checked: true, externalDomains: [...new Set(external)], inlineCount };
}

// 10 - Kaynaklar (resim, css, script)
function analyzeResources(html, baseUrl) {
  const $ = cheerio.load(html);
  const domains = new Set();
  let count = 0;
  $('img[src], script[src], link[href]').each((i, el) => {
    const src = $(el).attr('src') || $(el).attr('href');
    count++;
    try { domains.add(new URL(src, baseUrl).hostname); } catch {}
  });
  return { checked: true, count, externalDomains: [...domains] };
}

// 11 - Gizlilik yuzeyi: ucuncu taraf alan adlari (cerez + kaynak + form birlesimi)
function privacySurface(hostname, scripts, resources, forms) {
  const thirdParty = new Set([...scripts.externalDomains, ...resources.externalDomains]
    .filter(d => d && d !== hostname));
  return { checked: true, thirdPartyDomainCount: thirdParty.size, thirdPartyDomains: [...thirdParty] };
}

// 12 - Sitemap kontrolu
async function checkSitemap(baseUrl) {
  try {
    const url = new URL('/sitemap.xml', baseUrl).toString();
    const res = await fetch(url, { timeout: 5000 });
    return { checked: true, found: res.status === 200, url };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

module.exports = {
  resolveDns,
  fetchWithRedirects,
  checkSecurityHeaders,
  analyzeCookies,
  analyzeForms,
  analyzeScripts,
  analyzeResources,
  privacySurface,
  checkSitemap
};

// ================== KAPSAMLI (DERIN) MOD FONKSIYONLARI ==================
// Bunlar gercekten calisan, gercek sure alan ek kontrollerdir - sahte gecikme yok.

const net = require('net');
const tls = require('tls');

// Port taramasi - yaygin servis portlarini kontrol eder (salt okunur TCP baglanti denemesi)
const COMMON_PORTS = [21, 22, 23, 25, 53, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017];
const PORT_NAMES = { 21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',110:'pop3',143:'imap',443:'https',445:'smb',1433:'mssql',3306:'mysql',3389:'rdp',5432:'postgres',6379:'redis',8080:'http-alt',8443:'https-alt',27017:'mongodb' };

function checkPort(hostname, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => { done = true; socket.destroy(); resolve({ port, open: true }); });
    socket.once('timeout', () => { if (!done) { done = true; socket.destroy(); resolve({ port, open: false }); } });
    socket.once('error', () => { if (!done) { done = true; resolve({ port, open: false }); } });
    socket.connect(port, hostname);
  });
}

// Kibarca, siralı taranir (hedefi bogmamak icin) - bu yuzden gercekten zaman alir
async function portScan(hostname, onEach) {
  const results = [];
  for (const port of COMMON_PORTS) {
    const r = await checkPort(hostname, port);
    if (onEach) onEach(r);
    results.push(r);
  }
  const open = results.filter(r => r.open).map(r => `${r.port}/${PORT_NAMES[r.port]}`);
  return { checked: true, scanned: results.length, open };
}

// Alt alan adi kesfi - yaygin on ekleri DNS ile kontrol eder
const COMMON_SUBS = ['www','mail','ftp','admin','api','dev','staging','test','blog','shop','portal','vpn','webmail','cpanel','ns1','ns2'];

async function subdomainEnum(rootHost, onEach) {
  const found = [];
  for (const sub of COMMON_SUBS) {
    const host = `${sub}.${rootHost}`;
    try {
      const addrs = await dns.resolve4(host);
      found.push(host);
      if (onEach) onEach({ host, found: true });
    } catch {
      if (onEach) onEach({ host, found: false });
    }
  }
  return { checked: true, scanned: COMMON_SUBS.length, found };
}

// Hassas dosya/klasor sizintisi kontrolu - sadece HEAD istegi, icerik indirilmez
const SENSITIVE_PATHS = ['/.env', '/.git/config', '/wp-config.php.bak', '/config.php.bak', '/backup.zip', '/.DS_Store', '/phpinfo.php', '/.htpasswd'];

async function sensitiveFileCheck(baseUrl, onEach) {
  const exposed = [];
  for (const p of SENSITIVE_PATHS) {
    try {
      const url = new URL(p, baseUrl).toString();
      const res = await fetch(url, { method: 'HEAD', timeout: 4000 });
      const isExposed = res.status === 200;
      if (isExposed) exposed.push(p);
      if (onEach) onEach({ path: p, exposed: isExposed });
    } catch {
      if (onEach) onEach({ path: p, exposed: false });
    }
  }
  return { checked: true, scanned: SENSITIVE_PATHS.length, exposed };
}

// TLS protokol destegi - eski/guvensiz protokoller (TLS 1.0/1.1) hala acik mi diye bakar
const TLS_VERSIONS = [
  { name: 'TLSv1', min: 'TLSv1', max: 'TLSv1' },
  { name: 'TLSv1.1', min: 'TLSv1.1', max: 'TLSv1.1' },
  { name: 'TLSv1.2', min: 'TLSv1.2', max: 'TLSv1.2' },
  { name: 'TLSv1.3', min: 'TLSv1.3', max: 'TLSv1.3' }
];

function tryTlsVersion(hostname, version) {
  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, {
      servername: hostname, minVersion: version.min, maxVersion: version.max, timeout: 4000
    }, () => { resolve({ version: version.name, supported: true }); socket.end(); });
    socket.on('error', () => resolve({ version: version.name, supported: false }));
    socket.on('timeout', () => { socket.destroy(); resolve({ version: version.name, supported: false }); });
  });
}

async function tlsProtocolScan(hostname, onEach) {
  const results = [];
  for (const v of TLS_VERSIONS) {
    const r = await tryTlsVersion(hostname, v);
    if (onEach) onEach(r);
    results.push(r);
  }
  const weak = results.filter(r => r.supported && (r.version === 'TLSv1' || r.version === 'TLSv1.1'));
  return { checked: true, results, weakProtocolsSupported: weak.map(w => w.version) };
}

// Ek sayfa taramasi - ana sayfadaki ic linklerden birkacini daha indirip
// form/script/cerez analizini genisletir
function extractInternalLinks(html, baseUrl, hostname, limit = 3) {
  const $ = cheerio.load(html);
  const links = new Set();
  $('a[href]').each((i, el) => {
    if (links.size >= limit * 3) return;
    const href = $(el).attr('href');
    try {
      const u = new URL(href, baseUrl);
      if (u.hostname === hostname && u.pathname !== '/' && !u.pathname.match(/\.(jpg|png|gif|pdf|zip|css|js)$/i)) {
        links.add(u.toString());
      }
    } catch {}
  });
  return [...links].slice(0, limit);
}

async function crawlExtraPages(html, baseUrl, hostname, onEach) {
  const links = extractInternalLinks(html, baseUrl, hostname, 3);
  let totalForms = 0, totalExternalScripts = 0, pagesChecked = 0;
  for (const link of links) {
    try {
      const res = await fetch(link, { timeout: 6000 });
      const pageHtml = await res.text();
      const forms = analyzeForms(pageHtml, link);
      const scripts = analyzeScripts(pageHtml, link);
      totalForms += forms.count;
      totalExternalScripts += scripts.externalDomains.length;
      pagesChecked++;
      if (onEach) onEach({ url: link, ok: true });
    } catch {
      if (onEach) onEach({ url: link, ok: false });
    }
  }
  return { checked: true, pagesChecked, totalForms, totalExternalScripts, links };
}

module.exports.portScan = portScan;
module.exports.subdomainEnum = subdomainEnum;
module.exports.sensitiveFileCheck = sensitiveFileCheck;
module.exports.tlsProtocolScan = tlsProtocolScan;
module.exports.crawlExtraPages = crawlExtraPages;

// --- KAPSAMLI MOD icin ek fonksiyonlar ---

// 14 - robots.txt kontrolu
async function checkRobots(baseUrl) {
  try {
    const url = new URL('/robots.txt', baseUrl).toString();
    const res = await fetch(url, { timeout: 6000 });
    if (res.status !== 200) return { checked: true, found: false };
    const text = await res.text();
    const disallowed = (text.match(/Disallow:\s*(\S+)/g) || []).length;
    return { checked: true, found: true, disallowedCount: disallowed };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

// 15 - Sertifika Seffafligi (Certificate Transparency) - crt.sh uzerinden alt alan adi tespiti
async function checkCertTransparency(hostname) {
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`;
    const res = await fetch(url, { timeout: 12000 });
    if (!res.ok) return { checked: false, reason: 'crt.sh yanit vermedi' };
    const data = await res.json();
    const names = new Set();
    data.forEach(entry => {
      (entry.name_value || '').split('\n').forEach(n => names.add(n.trim().toLowerCase()));
    });
    return { checked: true, subdomainCount: names.size, subdomains: [...names].slice(0, 25) };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

// 16 - E-posta guvenligi: SPF ve DMARC kayitlari (sahtecilige acik mi)
async function checkEmailSecurity(hostname) {
  const dns = require('dns').promises;
  const result = { checked: true, spf: false, dmarc: false };
  try {
    const txt = await dns.resolveTxt(hostname);
    result.spf = txt.some(r => r.join('').toLowerCase().startsWith('v=spf1'));
  } catch {}
  try {
    const dmarcTxt = await dns.resolveTxt('_dmarc.' + hostname);
    result.dmarc = dmarcTxt.some(r => r.join('').toLowerCase().startsWith('v=dmarc1'));
  } catch {}
  return result;
}

// 17 - Ic sayfa taramasi: anasayfadaki ic linkleri bulup her birini gercekten ziyaret eder
function extractInternalLinks(html, baseUrl, hostname, limit = 6) {
  const $ = cheerio.load(html);
  const links = new Set();
  $('a[href]').each((i, el) => {
    const href = $(el).attr('href');
    try {
      const u = new URL(href, baseUrl);
      if (u.hostname === hostname && u.protocol.startsWith('http') && !links.has(u.toString())) {
        links.add(u.toString());
      }
    } catch {}
  });
  return [...links].slice(0, limit);
}

// Tek bir ic sayfayi ziyaret edip karisik icerik (mixed content) ve form kontrolu yapar
async function crawlPage(url) {
  try {
    const res = await fetch(url, { timeout: 8000, redirect: 'follow' });
    const html = res.status < 400 ? await res.text() : '';
    const isHttps = url.startsWith('https://');
    let mixedContent = 0;
    if (isHttps && html) {
      const matches = html.match(/(?:src|href)=["']http:\/\/[^"']+["']/g) || [];
      mixedContent = matches.length;
    }
    const forms = html ? analyzeForms(html, url) : { count: 0, riskyOverHttp: 0 };
    return { url, status: res.status, mixedContent, forms: forms.count, formsRisky: forms.riskyOverHttp, checked: true };
  } catch (err) {
    return { url, checked: false, reason: err.message };
  }
}

module.exports.checkRobots = checkRobots;
module.exports.checkCertTransparency = checkCertTransparency;
module.exports.checkEmailSecurity = checkEmailSecurity;
module.exports.extractInternalLinks = extractInternalLinks;
module.exports.crawlPage = crawlPage;
                 
