const fetch = require('node-fetch');

async function checkSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) {
    return { checked: false, reason: 'API key tanimli degil (.env dosyasina ekle)' };
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const body = {
    client: { clientId: 'site-guven', clientVersion: '0.1.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    const matches = data.matches || [];
    return {
      checked: true,
      clean: matches.length === 0,
      threats: matches.map(m => m.threatType)
    };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

module.exports = { checkSafeBrowsing };
