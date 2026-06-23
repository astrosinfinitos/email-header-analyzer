// js/api.js

const API_URL = 'https://email-header-analyzer-j40x.onrender.com/analyze';

async function analyzeHeader(rawHeader) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw_header: rawHeader }),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  return await response.json();
}