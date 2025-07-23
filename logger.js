// logger.js
const fs = require('fs');
const path = require('path');

const LOG_PATH = path.join(__dirname, 'btc-payments.log');

function log(message) {
  const timestamp = new Date().toISOString();
  const fullMessage = `[${timestamp}] ${message}\n`;
  console.log(fullMessage.trim());
  fs.appendFileSync(LOG_PATH, fullMessage, 'utf8');
}

module.exports = { log };
