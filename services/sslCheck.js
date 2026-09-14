const tls = require('tls');

function checkSSL(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 5000 }, () => {
      const cert = socket.getPeerCertificate();
      const now = new Date();
      const validTo = new Date(cert.valid_to);
      const daysLeft = Math.round((validTo - now) / (1000 * 60 * 60 * 24));

      resolve({
        checked: true,
        valid: socket.authorized,
        issuer: cert.issuer ? cert.issuer.O : 'bilinmiyor',
        validTo: cert.valid_to,
        daysLeft
      });
      socket.end();
    });

    socket.on('error', (err) => {
      resolve({ checked: true, valid: false, reason: err.message });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ checked: true, valid: false, reason: 'baglanti zaman asimina ugradi' });
    });
  });
}

module.exports = { checkSSL };
