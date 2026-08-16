'use strict';

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const DATA_FILE = path.join(DATA_DIR, 'history.json');
const MAX_RECORDS = 500;

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');
}

function readAll() {
  ensureStore();
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('store: failed to read history file, resetting.', err.message);
    return [];
  }
}

function writeAll(records) {
  ensureStore();
  fs.writeFileSync(DATA_FILE, JSON.stringify(records, null, 2), 'utf8');
}

/**
 * Records a scan result. Stores only the hostname (not the full URL/query
 * string) to avoid persisting anything sensitive a user might paste.
 */
function recordScan(result) {
  const records = readAll();
  records.unshift({
    hostname: result.hostname,
    score: result.score,
    level: result.level,
    analyzedAt: result.analyzedAt
  });
  writeAll(records.slice(0, MAX_RECORDS));
}

function getHistory(limit = 20) {
  const n = Math.max(1, Math.min(100, Number(limit) || 20));
  return readAll().slice(0, n);
}

function getStats() {
  const records = readAll();
  const stats = { total: records.length, safe: 0, warn: 0, danger: 0 };
  for (const r of records) {
    if (stats[r.level] !== undefined) stats[r.level] += 1;
  }
  return stats;
}

module.exports = { recordScan, getHistory, getStats };
