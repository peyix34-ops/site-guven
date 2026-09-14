const whois = require('whois-json');

async function checkDomainAge(hostname) {
  try {
    const data = await whois(hostname);
    const created = data.creationDate || data.createdDate || data.registered;
    if (!created) {
      return { checked: false, reason: 'WHOIS verisi bulunamadi' };
    }
    const createdDate = new Date(created);
    const ageDays = Math.round((new Date() - createdDate) / (1000 * 60 * 60 * 24));
    return {
      checked: true,
      createdDate: created,
      ageDays,
      risky: ageDays < 30
    };
  } catch (err) {
    return { checked: false, reason: err.message };
  }
}

module.exports = { checkDomainAge };
