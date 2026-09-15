const fetch = require('node-fetch');

// VirusTotal API v3 - ucretsiz tier: dakikada 4 istek, gunde 500 istek
// URL'i once base64 ile kodlamak gerekiyor (VT'nin kendi formati)
function encodeUrlForVT(url) {
  return Buffer.from(url).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { checked: false, reason: 'API key tanimli degil' };
  }

  try {
    const urlId = encodeUrlForVT(url);
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 10000
    });

    if (res.status === 404) {
      // VT bu URL'i daha once hic taramamis - yeni tarama gonder
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
      return { checked: true, pending: true, malicious: 0, suspicious: 0, harmless: 0, total: 0 };
    }

    if (!res.ok) return { checked: false, reason: `VT hata: ${res.status}` };

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    return {
      checked: true,
      pending: false,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)
    };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

module.exports = { checkVirusTotal };
