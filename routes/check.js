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

router.post('/', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url alani zorunlu' });

  let hostname;
  try { hostname = new URL(url).hostname; }
  catch { return res.status(400).json({ error: 'gecersiz url' }); }

  try {
    const fetched = await fetchWithRedirects(url);
    const finalHost = new URL(fetched.finalUrl).hostname;

    const [
      safeBrowsing, ssl, domainAge, dnsResult, sitemap
    ] = await Promise.all([
      checkSafeBrowsing(url),
      checkSSL(hostname),
      checkDomainAge(hostname),
      resolveDns(hostname),
      checkSitemap(fetched.finalUrl)
    ]);

    const headers = checkSecurityHeaders(fetched.headers);
    const cookies = analyzeCookies(fetched.headers);
    const scripts = analyzeScripts(fetched.html, fetched.finalUrl);
    const resources = analyzeResources(fetched.html, fetched.finalUrl);
    const forms = analyzeForms(fetched.html, fetched.finalUrl);
    const privacy = privacySurface(finalHost, scripts, resources, forms);

    const threats = [];
    if (safeBrowsing.checked && !safeBrowsing.clean) threats.push({ level: 'bad', text: 'Kara listede tehdit tespit edildi' });
    if (ssl.checked && !ssl.valid) threats.push({ level: 'bad', text: 'SSL sertifikasi gecersiz' });
    if (domainAge.checked && domainAge.risky) threats.push({ level: 'mid', text: 'Domain cok yeni acilmis (30 gunden az)' });
    if (headers.missing.length >= 3) threats.push({ level: 'mid', text: 'Onemli guvenlik basliklari eksik' });
    if (forms.riskyOverHttp > 0) threats.push({ level: 'bad', text: 'Sifre formu HTTPS olmadan gonderiliyor' });
    if (cookies.issues.length > 0) threats.push({ level: 'mid', text: 'Cerezlerde guvenlik bayragi eksikleri var' });
    if (fetched.chain.length > 3) threats.push({ level: 'mid', text: 'Cok sayida yonlendirme zinciri' });

    let score = 100;
    if (safeBrowsing.checked && !safeBrowsing.clean) score -= 40;
    if (ssl.checked && !ssl.valid) score -= 20;
    if (domainAge.checked && domainAge.risky) score -= 10;
    if (headers.missing.length >= 3) score -= 10;
    if (forms.riskyOverHttp > 0) score -= 15;
    if (cookies.issues.length > 0) score -= 5;
    score = Math.max(score, 0);

    res.json({
      url,
      hostname,
      finalUrl: fetched.finalUrl,
      score,
      modules: {
        domain: { hostname, finalHost },
        dns: dnsResult,
        tls: ssl,
        http: { status: fetched.status, hops: fetched.chain.length },
        redirect: { chain: fetched.chain },
        headers,
        cookies,
        forms,
        js: scripts,
        resources,
        privacy,
        sitemap,
        threat: { checked: true, findings: threats }
      },
      layer1: { safeBrowsing, ssl, domainAge }
    });
  } catch (err) {
    res.status(500).json({ error: 'tarama sirasinda hata olustu: ' + err.message });
  }
});

module.exports = router;
