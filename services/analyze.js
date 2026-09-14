const dns = require('dns').promises;
const fetch = require('node-fetch');
const cheerio = require('cheerio');

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

function privacySurface(hostname, scripts, resources, forms) {
  const thirdParty = new Set([...scripts.externalDomains, ...resources.externalDomains]
    .filter(d => d && d !== hostname));
  return { checked: true, thirdPartyDomainCount: thirdParty.size, thirdPartyDomains: [...thirdParty] };
}

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
