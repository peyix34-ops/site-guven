require('dotenv').config();
const express = require('express');
const cors = require('cors');
const checkRoute = require('./routes/check');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Ana tarama endpoint'i: POST /api/check  { "url": "https://ornek.com" }
app.use('/api/check', checkRoute);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Site Guven sunucusu ${PORT} portunda calisiyor`);
});
