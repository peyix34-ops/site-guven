const express = require('express');
const router = express.Router();

const { checkSafeBrowsing } = require('../services/safeBrowsing');
const { checkSSL } = require('../services/sslCheck');
const { checkDomainAge } = require('../services/domainAge');
const {
  resolveDns, fetchWithRedirects, checkSecurityHeaders,
  analyzeCookies, analyzeForms, analyzeScripts,
  analyzeResources, privacySurface, checkSitemap
} = require('../services/analyze');

// GET /api/check-stream?url=... - EventSource ile gercek zamanli akis
// Her modul GERCEKTEN tamamlandigi anda event olarak gonderilir - sahte gecikme yok
router.get('/', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).end();

  let hostname;
  try { hostname = new URL(url).hostname; }
  catch { return res.status(400).end(); }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const t0 = Date.now();
  const elapsed = () => Date.now() - t0;

  try {
    send('log', { text: `hedef alındı: ${url}`, ms: elapsed() });

    // Once sayfayi cek - digerlerinin cogu buna bagli, bu yuzden once bu bitmeli
    send('log', { text: 'sunucuya bağlanılıyor...', ms: elapsed() });
    const fetched = await fetchWithRedirects(url);
    const finalHost = new URL(fetched.finalUrl).hostname;

    send('module', { id: 'domain', done: true, ms: elapsed(), result: `host: ${finalHost}` });
    send('module', { id: 'http', done: true, ms: elapsed(), result: `${fetched.status} · ${fetched.chain.length} hop` });
    send('module', { id: 'redirect', done: true, ms: elapsed(), result: fetched.chain.length > 1 ? `${fetched.chain.length} adım` : 'yönlendirme yok' });
    send('log', { text: `http yanıtı alındı: ${fetched.status}`, ms: elapsed() });

    // Bundan sonraki kontroller birbirinden bagimsiz - GERCEKTEN paralel calisir,
    // her biri bittigi anda kendi eventini gonderir (kim once biterse o once gorunur)
    const tasks = [];

    tasks.push(checkSafeBrowsing(url).then(r => {
      send('module', { id: 'threat_partial', done: true, ms: elapsed(), safeBrowsing: r });
      send('log', { text: r.checked ? (r.clean ? 'kara listede kayıt yok' : 'tehdit tespit edildi!') : 'kara liste kontrol edilemedi', ms: elapsed(), level: r.checked && !r.clean ? 'bad' : null });
      return r;
    }));

    tasks.push(checkSSL(hostname).then(r => {
      send('module', { id: 'tls', done: true, ms: elapsed(), result: r.valid ? `geçerli, ${r.issuer || ''}` : 'geçersiz/tespit edilemedi', raw: r });
      send('log', { text: r.valid ? 'ssl sertifikası geçerli' : 'ssl sertifikası sorunlu', ms: elapsed(), level: r.valid ? null : 'warn' });
      return r;
    }));

    tasks.push(checkDomainAge(hostname).then(r => {
      send('log', { text: r.checked ? `domain yaşı: ${r.ageDays} gün` : 'domain yaşı tespit edilemedi', ms: elapsed(), level: r.risky ? 'warn' : null });
      return r;
    }));

    tasks.push(resolveDns(hostname).then(r => {
      send('module', { id: 'dns', done: true, ms: elapsed(), result: r.checked ? `${r.a.length} A kaydı` : 'çözümlenemedi' });
      send('log', { text: r.checked ? 'dns kayıtları çözümlendi' : 'dns hatası', ms: elapsed(), level: r.checked ? null : 'warn' });
      return r;
    }));

    tasks.push(checkSitemap(fetched.finalUrl).then(r => {
      send('module', { id: 'sitemap', done: true, ms: elapsed(), result: r.checked ? (r.found ? 'bulundu' : 'bulunamadı') : 'kontrol edilemedi' });
      return r;
    }));

    // Bunlar zaten indirilmis HTML uzerinde calisiyor, gercekten hizli ama yine de gercek islem
    const headers = checkSecurityHeaders(fetched.headers);
    send('module', { id: 'headers', done: true, ms: elapsed(), result: `${headers.missing.length} eksik başlık` });
    send('log', { text: headers.missing.length > 0 ? `eksik başlıklar: ${headers.missing.join(', ')}` : 'tüm güvenlik başlıkları mevcut', ms: elapsed(), level: headers.missing.length > 0 ? 'warn' : null });

    const cookies = analyzeCookies(fetched.headers);
    send('module', { id: 'cookies', done: true, ms: elapsed(), result: `${cookies.count} çerez, ${cookies.issues.length} uyarı` });

    const scripts = analyzeScripts(fetched.html, fetched.finalUrl);
    send('module', { id: 'js', done: true, ms: elapsed(), result: `${scripts.externalDomains.length} dış script kaynağı` });

    const resources = analyzeResources(fetched.html, fetched.finalUrl);
    send('module', { id: 'resources', done: true, ms: elapsed(), result: `${resources.count} kaynak, ${resources.externalDomains.length} dış alan` });

    const forms = analyzeForms(fetched.html, fetched.finalUrl);
    send('module', { id: 'forms', done: true, ms: elapsed(), result: `${forms.count} form${forms.riskyOverHttp > 0 ? ' · HTTP üzerinden şifre!' : ''}` });
    if (forms.riskyOverHttp > 0) send('log', { text: 'şifre formu HTTPS olmadan tespit edildi!', ms: elapsed(), level: 'bad' });

    const privacy = privacySurface(finalHost, scripts, resources, forms);
    send('module', { id: 'privacy', done: true, ms: elapsed(), result: `${privacy.thirdPartyDomainCount} üçüncü taraf alan` });

    // Paralel gorevlerin GERCEKTEN bitmesini bekle
    const [safeBrowsing, ssl, domainAge] = await Promise.all(tasks);

    const threats = [];
    if (safeBrowsing.checked && !safeBrowsing.clean) threats.push({ level: 'bad', text: 'Kara listede tehdit tespit edildi' });
    if (ssl.checked && !ssl.valid) threats.push({ level: 'bad', text: 'SSL sertifikasi gecersiz' });
    if (domainAge.checked && domainAge.risky) threats.push({ level: 'mid', text: 'Domain cok yeni acilmis (30 gunden az)' });
    if (headers.missing.length >= 3) threats.push({ level: 'mid', text: 'Onemli guvenlik basliklari eksik' });
    if (forms.riskyOverHttp > 0) threats.push({ level: 'bad', text: 'Sifre formu HTTPS olmadan gonderiliyor' });
    if (cookies.issues.length > 0) threats.push({ level: 'mid', text: 'Cerezlerde guvenlik bayragi eksikleri var' });
    if (fetched.chain.length > 3) threats.push({ level: 'mid', text: 'Cok sayida yonlendirme zinciri' });

    send('module', { id: 'threat', done: true, ms: elapsed(), result: `${threats.length} bulgu` });
    threats.forEach(f => send('log', { text: f.text, ms: elapsed(), level: f.level }));

    let score = 100;
    if (safeBrowsing.checked && !safeBrowsing.clean) score -= 40;
    if (ssl.checked && !ssl.valid) score -= 20;
    if (domainAge.checked && domainAge.risky) score -= 10;
    if (headers.missing.length >= 3) score -= 10;
    if (forms.riskyOverHttp > 0) score -= 15;
    if (cookies.issues.length > 0) score -= 5;
    score = Math.max(score, 0);

    send('final', {
      hostname: finalHost,
      score,
      ssl, domainAge, safeBrowsing,
      headersMissing: headers.missing.length,
      formsRisky: forms.riskyOverHttp
    });
    send('log', { text: `tarama tamamlandı (${(elapsed() / 1000).toFixed(1)}s)`, ms: elapsed() });
    send('done', {});
  } catch (err) {
    send('log', { text: 'hata: ' + err.message, ms: elapsed(), level: 'bad' });
    send('error', { message: err.message });
  }

  res.end();
});

module.exports = router;
