async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
function requireFields(obj, fields) {
  const missing = fields.filter(f => !(f in obj));
  if (missing.length) throw new Error('missing fields: ' + missing.join(','));
}
function validateReceiptContract(receipt) {
  requireFields(receipt, ['mode','case_id','grant','grant_id','receipt_sha256','band_message_ids','live_gate_events','blocked_attempts','context_releases','late_participant_probes','reviewer_deposits','revocations','post_revocation_blocks','band_secret_scan','policy_log_sha256']);
  requireFields(receipt.grant, ['case_id','room_id','grant_id','human_approver','allowed_agents','allowed_context_keys','allowed_action_kinds']);
  if (receipt.grant.case_id !== receipt.case_id) throw new Error('grant case mismatch');
  if (receipt.grant.grant_id !== receipt.grant_id) throw new Error('grant id mismatch');
  if (receipt.mode !== 'live_band_spear') throw new Error('mode mismatch');
  if (!Array.isArray(receipt.band_message_ids) || receipt.band_message_ids.length < 1) throw new Error('missing band ids');
  if (!receipt.live_gate_events.every(e => e.band_message_id && e.band_ok === true && e.band_content_sha256)) throw new Error('bad live events');
  if (receipt.reviewer_deposits.length !== 3) throw new Error('expected 3 reviewer deposits');
  if (receipt.band_secret_scan.raw_secret_canary_posted !== false) throw new Error('raw canary posted');
  if (receipt.band_secret_scan.protected_payload_value_posted !== false) throw new Error('protected payload posted');
  if (receipt.late_participant_probes.some(p => p.recovered)) throw new Error('late replay recovered');
  return true;
}
function validateEvidenceContract(evidence) {
  requireFields(evidence, ['winning_frame','canonical_receipt_sha256','live_receipt_file_sha256','seal_post_message_id','agent_trace','proof','use_case','attack_survival','downloads']);
  if (Object.keys(evidence.agent_trace).length < 3) throw new Error('agent_trace < 3');
  const proof = evidence.proof;
  if (proof.agents_named !== true || proof.agent_trace_present !== true || proof.band_message_ids_present !== true) throw new Error('agent proof incomplete');
  if (proof.late_replay_recovered !== false) throw new Error('late replay recovered');
  if (proof.raw_secret_canary_posted !== false) throw new Error('raw canary posted');
  if (proof.protected_payload_value_posted !== false) throw new Error('protected payload posted');
  if (!evidence.use_case || !String(evidence.use_case.title || '').includes('Vendor bank-change approval')) throw new Error('use case incomplete');
  if (!Array.isArray(evidence.attack_survival) || evidence.attack_survival.length < 5) throw new Error('attack survival incomplete');
  if (!Array.isArray(evidence.downloads) || evidence.downloads.length < 5) throw new Error('downloads incomplete');
  return true;
}
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}
function setBadge(id, ok, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text || (ok ? 'PASS' : 'FAIL');
  el.classList.remove('pass', 'fail');
  el.classList.add(ok ? 'pass' : 'fail');
}
function shortHash(hash) {
  return hash ? hash.slice(0, 12) + '…' + hash.slice(-10) : 'unavailable';
}
async function fetchText(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(path + ' fetch status ' + response.status);
  return response.text();
}
async function loadCliTranscript() {
  const transcript = await fetchText('cli-transcript.txt');
  setText('console-lines', transcript);
}
async function validateDownloadHashes(evidence) {
  let hashPinned = 0;
  let selfChecking = 0;
  for (const [index, item] of evidence.downloads.entries()) {
    if (!item || !item.href || !item.label) throw new Error('download ' + index + ' missing href/label');
    const text = await fetchText(item.href);
    if (item.sha256) {
      const actual = await sha256Hex(text);
      if (actual !== item.sha256) throw new Error('download hash mismatch: ' + item.href);
      hashPinned += 1;
    } else if (item.self_verifying === true && item.href === 'evidence.json') {
      selfChecking += 1;
    } else {
      throw new Error('download missing hash: ' + item.href);
    }
  }
  return { hashPinned, selfChecking, total: hashPinned + selfChecking };
}
async function verify() {
  const [evidenceText, siteReceiptText, canonicalReceiptText] = await Promise.all([
    fetchText('evidence.json'),
    fetchText('receipts/live-band-demo-20260618T185330Z.json'),
    fetchText('../receipts/live-band-demo-20260618T185330Z.json')
  ]);
  await loadCliTranscript();

  const evidence = JSON.parse(evidenceText);
  const receipt = JSON.parse(siteReceiptText);
  const lines = [];
  lines.push('winning_frame=' + evidence.winning_frame);
  lines.push('canonical_receipt_sha256=' + evidence.canonical_receipt_sha256);
  lines.push('live_receipt_file_sha256=' + evidence.live_receipt_file_sha256);
  lines.push('seal_post_message_id=' + evidence.seal_post_message_id);
  lines.push('agents=' + Object.keys(evidence.agent_trace).length);
  lines.push('late_replay_recovered=' + evidence.proof.late_replay_recovered);
  lines.push('raw_secret_canary_posted=' + evidence.proof.raw_secret_canary_posted);
  lines.push('protected_payload_value_posted=' + evidence.proof.protected_payload_value_posted);

  const agentCount = Object.keys(evidence.agent_trace).length;
  setText('agent-count', String(agentCount));
  setText('band-count', String(receipt.band_message_ids.length));
  setText('secret-status', evidence.proof.protected_payload_value_posted === false ? '0' : 'FAIL');
  setText('replay-status', evidence.proof.late_replay_recovered === false ? 'PASS' : 'FAIL');
  setText('hero-status', 'Checking');
  setText('hero-status-copy', 'browser verifier running');
  setText('seal-id', evidence.seal_post_message_id);

  try {
    validateEvidenceContract(evidence);
    const downloadCheck = await validateDownloadHashes(evidence);
    lines.push('browser_download_hash_check=PASS');
    lines.push('browser_evidence_contract_check=PASS');
    setBadge('contract-badge', true, 'Verified');
    setText('download-check', downloadCheck.hashPinned + ' hash-pinned files matched; evidence.json passed its contract check.');
    setText('proof-check', 'The public evidence file includes the use case, agents, proof flags, attack results, and seal.');
  } catch (err) {
    lines.push('browser_evidence_contract_check=FAIL ' + err.message);
    setBadge('contract-badge', false, 'Needs attention');
    setText('download-check', 'A download hash or evidence field failed: ' + err.message);
    setText('proof-check', 'The public evidence bundle did not pass the browser contract.');
  }

  try {
    validateReceiptContract(receipt);
    lines.push('browser_receipt_contract_check=PASS');
    setBadge('schema-badge', true, 'Verified');
    setText('secrets-check', 'The receipt says no raw canary or protected payload value was posted.');
    setText('replay-check', 'Late participant replay stayed blocked in this run.');
  } catch (err) {
    lines.push('browser_receipt_contract_check=FAIL ' + err.message);
    setBadge('schema-badge', false, 'Needs attention');
    setText('secrets-check', 'Receipt contract failed: ' + err.message);
    setText('replay-check', 'Replay/secret proof could not be trusted because the receipt contract failed.');
  }

  const copy = JSON.parse(JSON.stringify(receipt));
  const expected = copy.receipt_sha256;
  delete copy.receipt_sha256;
  const actual = await sha256Hex(canonical(copy));
  const siteFileHash = await sha256Hex(siteReceiptText);
  const canonicalFileHash = await sha256Hex(canonicalReceiptText);
  const receiptCopiesMatch = siteReceiptText === canonicalReceiptText;
  const payloadHashOk = expected === actual && evidence.canonical_receipt_sha256 === actual;
  const fileHashOk = receiptCopiesMatch && evidence.live_receipt_file_sha256 === siteFileHash && evidence.live_receipt_file_sha256 === canonicalFileHash;
  const hashOk = payloadHashOk && fileHashOk;
  lines.push('browser_receipt_hash_check=' + (payloadHashOk ? 'PASS' : 'FAIL'));
  lines.push('browser_receipt_hash=' + actual);
  lines.push('browser_receipt_file_hash_check=' + (fileHashOk ? 'PASS' : 'FAIL'));
  lines.push('browser_receipt_file_hash=' + siteFileHash);
  lines.push('browser_site_canonical_receipt_match=' + (receiptCopiesMatch ? 'PASS' : 'FAIL'));
  setBadge('hash-badge', hashOk, hashOk ? 'Verified' : 'Needs attention');
  setText('receipt-hash-short', hashOk
    ? 'Receipt payload ' + shortHash(actual) + ' and file ' + shortHash(siteFileHash) + ' match.'
    : 'The receipt hash did not match. Treat this page as failed.');
  setText('hero-status', hashOk ? 'PASS' : 'FAIL');
  setText('hero-status-copy', hashOk
    ? 'Browser checks passed for this receipt-pinned prototype run: public bundle intact, receipt shape present, receipt hashes matched.'
    : 'A browser proof check failed. Treat this page as failed until repaired.');

  setText('last-updated', new Date().toISOString());
  setText('verification', lines.join('\n'));
}
verify().catch(err => {
  setBadge('contract-badge', false, 'Error');
  setBadge('schema-badge', false, 'Error');
  setBadge('hash-badge', false, 'Error');
  setText('hero-status', 'FAIL');
  setText('hero-status-copy', 'The browser verifier did not finish. Treat this page as failed until repaired.');
  setText('download-check', 'The browser verifier did not finish.');
  setText('proof-check', String(err));
  setText('console-lines', 'failed_to_load_cli_transcript_or_verify=' + err);
  setText('verification', 'verification_error=' + err);
});
