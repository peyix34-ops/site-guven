const fetch = require('node-fetch');

function encodeUrlForVT(url) {
  return Buffer.from(url).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function formatStats(stats) {
  return {
    checked: true,
    pending: false,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)
  };
}

// Yeni gonderilen bir taramanin sonucunu gercekten bekler (polling).
// maxAttempts * intervalMs kadar gercekten bekleyip tekrar tekrar sorar.
async function pollAnalysis(analysisId, apiKey, maxAttempts, intervalMs, onProgress) {
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(intervalMs);
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey },
        timeout: 10000
      });
      if (!res.ok) continue;
      const data = await res.json();
      const status = data.data?.attributes?.status;
      if (onProgress) onProgress(i + 1, maxAttempts, status);
      if (status === 'completed') {
        return formatStats(data.data.attributes.stats || {});
      }
    } catch {}
  }
  return null; // zaman asimi - gercekten sonuc gelmedi
}

// level: 'temel' -> en fazla ~25sn bekler, 'kapsamli' -> en fazla ~55sn bekler (gercek bekleme, sahte degil)
async function checkVirusTotal(url, level, onProgress) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { checked: false, reason: 'API key tanimli degil' };

  const maxAttempts = level === 'kapsamli' ? 11 : 5;
  const intervalMs = 5000;

  try {
    const urlId = encodeUrlForVT(url);
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 10000
    });

    if (res.status === 404) {
      // VT bu URL'i daha once hic gormemis - taramaya gonder, sonra GERCEKTEN bekleyip sonucu sor
      const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`,
        timeout: 10000
      });
      if (!submitRes.ok) return { checked: false, reason: 'VT taramaya gonderilemedi' };
      const submitData = await submitRes.json();
      const analysisId = submitData.data?.id;
      if (!analysisId) return { checked: false, reason: 'analiz kimligi alinamadi' };

      const result = await pollAnalysis(analysisId, apiKey, maxAttempts, intervalMs, onProgress);
      if (result) return result;
      return { checked: true, pending: true, timedOut: true, malicious: 0, suspicious: 0, harmless: 0, total: 0 };
    }

    if (!res.ok) return { checked: false, reason: `VT hata: ${res.status}` };

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    return formatStats(stats);
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

module.exports = { checkVirusTotal };
