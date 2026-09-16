const fetch = require('node-fetch');

// Gemini API - Google Search grounding ile GERCEKTEN web aramasi yapar
// Ucretsiz kota: ayda 5000 grounded prompt (gemini-2.5-flash uzerinden)
async function analyzeWithAI(url, hostname, scanSummary) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return { checked: false, reason: 'API key tanimli degil' };

  const prompt = `Sen bir web guvenlik analistisin. Asagidaki site hakkinda Google'da arama yaparak bilgi topla ve degerlendir:

Site: ${url}
Alan adi: ${hostname}

Bizim otomatik tarama sistemimizin bulgulari:
${scanSummary}

Gorevin:
1. Bu alan adiyla ilgili bilinen bir dolandiricilik, veri ihlali, kotu niyetli faaliyet ya da sikayet var mi diye Google'da ara.
2. Yukaridaki tarama bulgularini da dikkate alarak, sade bir Turkce ile (2-4 cumle) bu sitenin genel guvenilirligi hakkinda bir degerlendirme yaz.
3. Kesin yargidan kacin, "kesinlikle guvenlidir/degildir" deme; bulgulara dayali, olculu bir dil kullan.
4. Eger internette bir sikayet/olay bulamadiysan bunu da belirt, "bulunamadi" onemli bir bilgidir.

Cevabini sadece degerlendirme metni olarak ver, baslik ya da madde isareti kullanma, duz paragraf yaz.`;

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          tools: [{ google_search: {} }]
        }),
        timeout: 25000
      }
    );

    if (!res.ok) {
      const errText = await res.text();
      return { checked: false, reason: `Gemini hata: ${res.status} ${errText.slice(0, 150)}` };
    }

    const data = await res.json();
    const text = data.candidates?.[0]?.content?.parts?.map(p => p.text).join('') || '';
    const groundingUsed = !!data.candidates?.[0]?.groundingMetadata;

    if (!text) return { checked: false, reason: 'Gemini bos yanit dondu' };

    return { checked: true, text: text.trim(), groundingUsed };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

module.exports = { analyzeWithAI };
