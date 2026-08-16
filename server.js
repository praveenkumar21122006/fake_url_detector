'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');

const { analyzeURL } = require('./src/analyzer');
const store = require('./src/store');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false // the bundled frontend uses an inline <style>/<script>; tighten this if you split assets out
}));
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// Basic abuse protection on the API surface.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down and try again shortly.' }
});
app.use('/api/', apiLimiter);

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', env: NODE_ENV, time: new Date().toISOString() });
});

app.post('/api/analyze', (req, res) => {
  const { url } = req.body || {};

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Request body must include a "url" string.' });
  }
  if (url.length > 2048) {
    return res.status(400).json({ error: 'URL is too long (max 2048 characters).' });
  }

  try {
    const result = analyzeURL(url);
    store.recordScan(result);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: 'Could not parse that as a URL.', detail: err.message });
  }
});

app.get('/api/history', (req, res) => {
  res.json({ history: store.getHistory(req.query.limit) });
});

app.get('/api/stats', (req, res) => {
  res.json(store.getStats());
});

// Fallback to the SPA entry point for any non-API GET route.
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`URLGuard server listening on http://localhost:${PORT} [${NODE_ENV}]`);
});

module.exports = app;
