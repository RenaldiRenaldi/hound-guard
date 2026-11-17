// Hound Guard — a pre-signing transaction guard (zkVerify Agent Games, Wildcard track).
//
// What it does: before a wallet signs a transaction, POST the transaction's
// destination, calldata and value to /analyze. The guard decodes the calldata,
// flags the dangerous patterns (unlimited approvals, full NFT control,
// off-chain permits, bundled multicalls, unknown functions) and returns a
// deterministic 0-100 risk score plus a SAFE / CAUTION / BLOCK recommendation.
//
// Why it is verifiable: the analysis is a pure function of the transaction
// alone. No network calls, no model, no randomness, no hidden state. Anyone
// can re-run the same input through the same code and must get the same
// output — the verdict is checkable by a third party that does not take the
// guard's word for it. That is the same instinct zkVerify's Agent Games is
// built around: don't trust the agent, verify it.
//
// No dependencies. Node.js only (built-in http). No API keys, no secrets.

const http = require('http');

// --- Known function selectors (first 4 bytes of calldata) ---
const SELECTORS = {
  '0x095ea7b3': { name: 'approve', kind: 'approval' },
  '0xa22cb465': { name: 'setApprovalForAll', kind: 'approval' },
  '0xd505accf': { name: 'permit', kind: 'approval' },
  '0xa9059cbb': { name: 'transfer', kind: 'transfer' },
  '0x23b872dd': { name: 'transferFrom', kind: 'transfer' },
  '0xac9650d8': { name: 'multicall', kind: 'bundle' },
  '0x5ae401dc': { name: 'multicall', kind: 'bundle' },
  '0x38ed1739': { name: 'swapExactTokensForTokens', kind: 'swap' },
  '0x8803dbee': { name: 'swapTokensForExactTokens', kind: 'swap' },
  '0x7ff36ab5': { name: 'swapExactETHForTokens', kind: 'swap' },
  '0x18cbafe5': { name: 'swapExactTokensForETH', kind: 'swap' },
  '0xfb3bdb41': { name: 'swapExactTokensForTokensSupportingFeeOnTransferTokens', kind: 'swap' },
  '0xe8e33700': { name: 'addLiquidity', kind: 'liquidity' },
  '0xbaa2abde': { name: 'addLiquidityETH', kind: 'liquidity' },
  '0x02751cec': { name: 'removeLiquidity', kind: 'liquidity' },
};

// Unlimited approval threshold: 2^255. Anything at or above it is effectively infinite.
const UNLIMITED = 2n ** 255n;

function hexToBigInt(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length === 0) return null;
  return BigInt('0x' + clean);
}

function parseAddress(word) {
  // An address is the last 20 bytes of a 32-byte word.
  if (!word || word.length !== 64) return null;
  return '0x' + word.slice(24);
}

// Analyze one transaction. Pure function: same input -> same output, always.
function analyze(tx) {
  const flags = [];
  const checks = [];
  let score = 0;

  const to = (tx.to || '').toLowerCase();
  const data = (tx.data || '').toLowerCase();
  const value = tx.value ? hexToBigInt(String(tx.value)) : 0n;

  if (!to || !/^0x[0-9a-f]{40}$/.test(to)) {
    flags.push({ code: 'INVALID_DESTINATION', severity: 'high', detail: 'Destination address is missing or malformed.' });
    score += 40;
  }

  if (!data || data === '0x' || data === '') {
    // Plain value transfer, no calldata.
    checks.push({ check: 'no_calldata', result: 'pass', detail: 'Plain value transfer, no contract call.' });
    if (value > 0n) score += 5;
    return finish(score, flags, checks, 'plain_transfer');
  }

  const body = data.startsWith('0x') ? data.slice(2) : data;
  if (body.length < 8 || body.length % 2 !== 0) {
    flags.push({ code: 'MALFORMED_CALLDATA', severity: 'high', detail: 'Calldata is too short or not valid hex.' });
    score += 40;
    return finish(score, flags, checks, 'unknown');
  }

  const selector = '0x' + body.slice(0, 8);
  const fn = SELECTORS[selector];
  const fnName = fn ? fn.name : 'unknown_function';
  checks.push({ check: 'function_selector', result: fn ? 'known' : 'unknown', detail: selector + ' -> ' + fnName });

  if (!fn) {
    flags.push({ code: 'UNKNOWN_FUNCTION', severity: 'medium', detail: 'Function selector ' + selector + ' is not in the known set. The contract could do anything.' });
    score += 30;
    return finish(score, flags, checks, fnName);
  }

  const words = [];
  for (let i = 8; i + 64 <= body.length; i += 64) words.push(body.slice(i, i + 64));

  if (fn.name === 'approve' && words.length >= 2) {
    const spender = parseAddress(words[0]);
    const amount = hexToBigInt(words[1]);
    checks.push({ check: 'approve_spender', result: 'parsed', detail: 'spender ' + spender });
    if (amount !== null && amount >= UNLIMITED) {
      flags.push({ code: 'UNLIMITED_APPROVAL', severity: 'high', detail: 'approve() for an effectively infinite amount (' + amount.toString() + '). The spender can drain the full token balance at any time until the allowance is revoked.' });
      score += 70;
    } else if (amount !== null && amount > 0n) {
      flags.push({ code: 'TOKEN_APPROVAL', severity: 'low', detail: 'approve() for a bounded amount (' + amount.toString() + ').' });
      score += 10;
    }
  }

  if (fn.name === 'setApprovalForAll' && words.length >= 2) {
    const operator = parseAddress(words[0]);
    const approved = hexToBigInt(words[1]) === 1n;
    checks.push({ check: 'setApprovalForAll_operator', result: 'parsed', detail: 'operator ' + operator + ', approved=' + approved });
    if (approved) {
      flags.push({ code: 'FULL_NFT_CONTROL', severity: 'high', detail: 'setApprovalForAll(true) hands one operator control of ALL of the wallet\'s tokens in this collection. This is the permission behind most NFT drain scams.' });
      score += 70;
    }
  }

  if (fn.name === 'permit') {
    flags.push({ code: 'OFFCHAIN_APPROVAL', severity: 'medium', detail: 'permit() is an off-chain signature approval. Anyone holding the signature can submit it — it does not need the wallet to send a transaction.' });
    score += 30;
  }

  if (fn.kind === 'bundle') {
    flags.push({ code: 'BUNDLED_CALLS', severity: 'medium', detail: 'multicall() bundles several calls into one transaction. Each nested call must be checked on its own; a safe-looking outer call can hide a dangerous inner one.' });
    score += 15;
    // Best-effort: scan the calldata for known nested selectors.
    const nested = [];
    for (const [sel, info] of Object.entries(SELECTORS)) {
      if (body.slice(8).includes(sel.slice(2))) nested.push(info.name);
    }
    if (nested.length) checks.push({ check: 'nested_calls', result: 'found', detail: 'nested: ' + [...new Set(nested)].join(', ') });
  }

  if (fn.kind === 'swap' || fn.kind === 'liquidity') {
    checks.push({ check: 'dex_call', result: 'noted', detail: fnName + ' — verify the token addresses and the minimum-output (slippage) yourself before signing.' });
    score += 5;
  }

  if (value > 0n) {
    checks.push({ check: 'native_value', result: 'noted', detail: 'Transaction sends native currency (' + value.toString() + ' wei) along with the call.' });
    score += 5;
  }

  return finish(score, flags, checks, fnName);
}

function finish(score, flags, checks, fnName) {
  if (score > 100) score = 100;
  const recommendation = score >= 70 ? 'BLOCK' : score >= 30 ? 'CAUTION' : 'SAFE';
  return {
    function: fnName,
    riskScore: score,
    recommendation,
    flags,
    checks,
    verdict: recommendation === 'SAFE'
      ? 'No dangerous pattern detected. Still verify the destination address yourself.'
      : recommendation === 'CAUTION'
        ? 'Suspicious pattern detected. Review the flags before signing — do not sign blind.'
        : 'Dangerous pattern detected. Do not sign this transaction unless you fully understand and intend every flagged effect.',
  };
}

// --- HTTP server (no framework) ---
const server = http.createServer((req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };

  if (req.method === 'GET' && req.url === '/') {
    return send(200, {
      service: 'hound-guard',
      description: 'Pre-signing transaction guard. POST /analyze with {to, data, value} to get a deterministic risk score.',
      endpoints: ['GET /', 'GET /demo', 'POST /analyze'],
      track: 'zkVerify Agent Games Season 01 — Wildcard',
    });
  }

  if (req.method === 'GET' && req.url === '/demo') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!doctype html><html><head><meta charset="utf-8"><title>Hound Guard — demo</title></head><body style="font-family:sans-serif;max-width:640px;margin:40px auto">
<h1>Hound Guard</h1><p>Pre-signing transaction guard. Paste a transaction and check it before you sign — or try a preset below.</p>
<p><b>Try one:</b><br>
<button onclick="fill('unlimited')">Unlimited approval (BLOCK)</button>
<button onclick="fill('nft')">setApprovalForAll (BLOCK)</button>
<button onclick="fill('permit')">permit() (CAUTION)</button>
<button onclick="fill('safe')">Safe transfer (SAFE)</button></p>
<form onsubmit="return go(event)"><label>To (address)<br><input id="to" style="width:100%" value="0x0000000000000000000000000000000000000000"></label><br><br>
<label>Calldata (hex)<br><input id="data" style="width:100%" value="0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"></label><br><br>
<label>Value (wei, hex or 0)<br><input id="value" style="width:100%" value="0x0"></label><br><br>
<button type="submit">Analyze</button></form><pre id="out" style="background:#f4f4f4;padding:12px;white-space:pre-wrap"></pre>
<script>
const PRESETS={
unlimited:{to:'0x0000000000000000000000000000000000000000',data:'0x095ea7b3'+'0000000000000000000000001111111111111111111111111111111111111111'+'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',value:'0x0'},
nft:{to:'0x0000000000000000000000000000000000000000',data:'0xa22cb465'+'0000000000000000000000001111111111111111111111111111111111111111'+'0000000000000000000000000000000000000000000000000000000000000001',value:'0x0'},
permit:{to:'0x0000000000000000000000000000000000000000',data:'0xd505accf'+'0000000000000000000000001111111111111111111111111111111111111111'+'0000000000000000000000002222222222222222222222222222222222222222'+'00000000000000000000000000000000000000000000000000000000000003e8'+'00000000000000000000000000000000000000000000000000000000693d0000'+'000000000000000000000000000000000000000000000000000000000000001b'+'0000000000000000000000000000000000000000000000000000000000000000'+'0000000000000000000000000000000000000000000000000000000000000000',value:'0x0'},
safe:{to:'0x0000000000000000000000000000000000000000',data:'0xa9059cbb'+'0000000000000000000000002222222222222222222222222222222222222222'+'00000000000000000000000000000000000000000000000000000000000003e8',value:'0x0'}
};
function fill(k){const p=PRESETS[k];document.getElementById('to').value=p.to;document.getElementById('data').value=p.data;document.getElementById('value').value=p.value;go(new Event('submit'))}
async function go(e){e.preventDefault();const r=await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to:document.getElementById('to').value,data:document.getElementById('data').value,value:document.getElementById('value').value})});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);return false}</script>
<p>Unlimited approval = an <code>approve()</code> for the maximum uint256. The guard returns BLOCK with the UNLIMITED_APPROVAL flag. setApprovalForAll(true) hands one operator every NFT in the collection — also BLOCK. permit() is an off-chain approval — CAUTION. A bounded transfer is SAFE.</p></body></html>`);
  }

  if (req.method === 'POST' && req.url === '/analyze') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 65536) req.destroy(); });
    req.on('end', () => {
      let tx;
      try { tx = JSON.parse(body || '{}'); } catch { return send(400, { error: 'Invalid JSON body.' }); }
      if (typeof tx !== 'object' || tx === null) return send(400, { error: 'Body must be a JSON object {to, data, value}.' });
      return send(200, analyze(tx));
    });
    return;
  }

  return send(404, { error: 'Not found. Use GET / or POST /analyze.' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('hound-guard listening on port ' + PORT));
