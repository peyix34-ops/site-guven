const fetch = require('node-fetch');

const modelCandidates = ['gemini-flash-latest', 'gemini-3.8-flash', 'gemini-2.5-flash'];

async function callGemini(prompt, apiKey, useGrounding) {
  const allErrors = [];
  for (const model of modelCandidates) {
    try {
      const body = { contents: [{ parts: [{ text: prompt }] }] };
      if (useGrounding) body.tools = [{ google_search: {} }];

      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          timeout: 25000
        }
      );

      if (!res.ok) {
        const errText = await res.text();
        allErrors.push(`${model}: ${res.status} ${errText.slice(0, 100)}`);
        continue;
      }

      const data = await res.json();
      const text = data.candidates?.[0]?.content?.parts?.map(p => p.text).join('') || '';
      const groundingUsed = !!data.candidates?.[0]?.groundingMetadata;

      if (!text) { allErrors.push(`${model}: bos yanit`); continue; }

      return { checked: true, text: text.trim(), groundingUsed, modelUsed: model };
    } catch (err) {
      allErrors.push(`${model}: ${err.message}`);
    }
  }
  return { checked: false, reason: allErrors.join(' | ') };
}

async function analyzeWithAI(url, hostname, scanSummary) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return { checked: false, reason: 'API key tanimli degil' };

  const promptWithSearch = `Sen bir web guvenlik analistisin. Asagidaki site hakkinda Google'da arama yaparak bilgi topla ve degerlendir:

Site: ${url}
Alan adi: ${hostname}

Bizim otomatik tarama sistemimizin bulgulari:
${scanSummary}

Gorevin:
1. Bu alan adiyla ilgili bilinen bir dolandiricilik, veri ihlali, kotu niyetli faaliyet ya da sikayet var mi diye Google'da ara.
2. Yukaridaki tarama bulgularini da dikkate alarak, sade bir Turkce ile (2-4 cumle) bu sitenin genel guvenilirligi hakkinda bir degerlendirme yaz.
3. Kesin yargidan kacin, "kesinlikle guvenlidir/degildir" deme; bulgulara dayali, olculu bir dil kullan.
4. Eger internette bir sikayet/olay bulamadiysan bunu da belirt.

Cevabini sadece degerlendirme metni olarak ver, baslik ya da madde isareti kullanma, duz paragraf yaz.`;

  const promptNoSearch = `Sen bir web guvenlik analistisin. Asagidaki tarama bulgularina dayanarak, web aramasi YAPMADAN, sadece elindeki verilere gore degerlendirme yap:

Site: ${url}
Alan adi: ${hostname}

Tarama bulgulari:
${scanSummary}

Sade bir Turkce ile (2-4 cumle) bu bulgulara dayanarak sitenin genel guvenilirligi hakkinda olculu bir degerlendirme yaz. Kesin yargidan kacin. Baslik ya da madde isareti kullanma, duz paragraf yaz.`;

  // 1. once web aramali (grounding) dene - en degerli sonuc bu
  const withSearch = await callGemini(promptWithSearch, apiKey, true);
  if (withSearch.checked) return withSearch;

  // 2. grounding basarisizsa (kota vb.), web aramasi olmadan en azindan
  //    kendi topladigimiz veriyi yorumlayan bir sonuc uretmeyi dene
  const withoutSearch = await callGemini(promptNoSearch, apiKey, false);
  if (withoutSearch.checked) {
    return { ...withoutSearch, searchFailed: true, searchFailReason: withSearch.reason };
  }

  return { checked: false, reason: `Web aramali: ${withSearch.reason} || Aramasiz: ${withoutSearch.reason}` };
}

module.exports = { analyzeWithAI };
