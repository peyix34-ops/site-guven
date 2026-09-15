const express = require('express');
const router = express.Router();

const { checkSafeBrowsing } = require('../services/safeBrowsing');
const { checkSSL } = require('../services/sslCheck');
const { checkDomainAge } = require('../services/domainAge');
const {
  resolveDns, fetchWithRedirects, checkSecurityHeaders,
  analyzeCookies, analyzeForms, analyzeScripts,
  analyzeResources, privacySurface, checkSitemap,
  checkRobots, checkCertTransparency, checkEmailSecurity,
  extractInternalLinks, crawlPage
} = require('../services/analyze');

// GET /api/check-stream?url=... - EventSource ile gercek zamanli akis
// Her modul GERCEKTEN tamamlandigi anda event olarak gonderilir - sahte gecikme yok
router.get('/', async (req, res) => {
  const url = req.query.url;
  const level = req.query.level === 'kapsamli' ? 'kapsamli' : 'temel';
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

    let deepScore = score;
    let deepFormsRisky = forms.riskyOverHttp;

    if (level === 'kapsamli') {
      send('log', { text: 'kapsamlı mod: ek kontroller başlıyor (bu daha uzun sürer)...', ms: elapsed() });

      // 14 - robots.txt
      const robots = await checkRobots(fetched.finalUrl);
      send('module', { id: 'robots', done: true, ms: elapsed(), result: robots.checked ? (robots.found ? `bulundu, ${robots.disallowedCount} kısıtlama` : 'bulunamadı') : 'kontrol edilemedi' });

      // 15 - sertifika seffafligi (crt.sh sorgusu gercekten birkaç saniye surer)
      send('log', { text: 'sertifika şeffaflık kayıtları sorgulanıyor (crt.sh)...', ms: elapsed() });
      const certT = await checkCertTransparency(finalHost);
      send('module', { id: 'subdomains', done: true, ms: elapsed(), result: certT.checked ? `${certT.subdomainCount} alt alan adı kaydı` : 'sorgulanamadı' });
      if (certT.checked) send('log', { text: `${certT.subdomainCount} alt alan adı sertifika kayıtlarında bulundu`, ms: elapsed() });

      // 16 - e-posta guvenligi (SPF/DMARC)
      const emailSec = await checkEmailSecurity(finalHost);
      send('module', { id: 'email_security', done: true, ms: elapsed(), result: `SPF: ${emailSec.spf ? 'var' : 'yok'} · DMARC: ${emailSec.dmarc ? 'var' : 'yok'}` });
      if (!emailSec.spf || !emailSec.dmarc) send('log', { text: 'e-posta sahteciliğine karşı koruma eksik (SPF/DMARC)', ms: elapsed(), level: 'warn' });

      // 17 - ic sayfa taramasi: bulunan ic linkleri GERCEKTEN teker teker ziyaret et
      const internalLinks = extractInternalLinks(fetched.html, fetched.finalUrl, finalHost, 6);
      send('log', { text: `${internalLinks.length} iç sayfa bulundu, tek tek ziyaret ediliyor...`, ms: elapsed() });

      let crawledCount = 0;
      let totalMixed = 0;
      let totalRiskyForms = 0;
      for (const link of internalLinks) {
        const pageResult = await crawlPage(link);
        crawledCount++;
        if (pageResult.checked) {
          totalMixed += pageResult.mixedContent;
          totalRiskyForms += pageResult.formsRisky;
          send('log', { text: `iç sayfa tarandı (${crawledCount}/${internalLinks.length}): ${link} · ${pageResult.status}`, ms: elapsed() });
        } else {
          send('log', { text: `iç sayfa taranamadı: ${link}`, ms: elapsed(), level: 'warn' });
        }
      }
      send('module', { id: 'crawl', done: true, ms: elapsed(), result: `${crawledCount} sayfa tarandı, ${totalMixed} karışık içerik uyarısı` });
      if (totalMixed > 0) send('log', { text: `${totalMixed} karışık içerik (http kaynak, https sayfa) tespit edildi`, ms: elapsed(), level: 'warn' });

      deepFormsRisky += totalRiskyForms;
      if (!emailSec.spf || !emailSec.dmarc) deepScore -= 5;
      if (totalMixed > 0) deepScore -= 10;
      if (totalRiskyForms > 0) deepScore -= 10;
      deepScore = Math.max(deepScore, 0);
    }

    send('final', {
      hostname: finalHost,
      score: deepScore,
      ssl, domainAge, safeBrowsing,
      headersMissing: headers.missing.length,
      formsRisky: deepFormsRisky,
      level
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
