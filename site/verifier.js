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

const scopeGateDemoState = {
  requested: false,
  granted: false,
  reviewed: false,
  revoked: false,
  replayed: false,
  sealed: false,
  messages: []
};
function escapeHtml(value) {
  return String(value).replace(/[&<>"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]));
}
function addDemoMessage(actor, body, tone) {
  scopeGateDemoState.messages.push({ actor, body, tone: tone || '' });
}
function renderScopeGateDemo() {
  const badge = document.getElementById('demo-state-badge');
  const transcript = document.getElementById('demo-transcript');
  if (!badge || !transcript) return;
  let stateText = 'LOCKED';
  let stateClass = '';
  if (scopeGateDemoState.sealed) {
    stateText = 'SEALED / PASS';
    stateClass = 'sealed';
  } else if (scopeGateDemoState.revoked) {
    stateText = 'REVOKED';
    stateClass = 'revoked';
  } else if (scopeGateDemoState.granted) {
    stateText = 'SCOPED';
    stateClass = 'scoped';
  } else if (scopeGateDemoState.requested) {
    stateText = 'BLOCKED';
  }
  badge.textContent = stateText;
  badge.className = 'state-badge' + (stateClass ? ' ' + stateClass : '');
  transcript.innerHTML = scopeGateDemoState.messages.map(message => `
    <div class="message ${escapeHtml(message.tone)}">
      <span class="actor">${escapeHtml(message.actor)}</span>
      ${escapeHtml(message.body)}
    </div>
  `).join('');
  transcript.scrollTop = transcript.scrollHeight;
  setText('demo-secret-count', '0');
  setText('demo-replay-state', scopeGateDemoState.replayed ? 'BLOCKED' : (scopeGateDemoState.revoked ? 'ready' : 'not tested'));
  setText('demo-receipt-state', scopeGateDemoState.sealed ? 'sealed' : (scopeGateDemoState.revoked ? 'ready' : 'open'));
  document.querySelectorAll('[data-action]').forEach(button => {
    const action = button.getAttribute('data-action');
    button.disabled = (
      (action === 'request' && scopeGateDemoState.requested) ||
      (action === 'grant' && (!scopeGateDemoState.requested || scopeGateDemoState.granted)) ||
      (action === 'review' && (!scopeGateDemoState.granted || scopeGateDemoState.reviewed || scopeGateDemoState.revoked)) ||
      (action === 'revoke' && (!scopeGateDemoState.granted || scopeGateDemoState.revoked)) ||
      (action === 'late-replay' && (!scopeGateDemoState.revoked || scopeGateDemoState.replayed)) ||
      (action === 'seal' && (!scopeGateDemoState.revoked || scopeGateDemoState.sealed))
    );
  });
}
function handleScopeGateDemoAction(action) {
  if (action === 'request' && !scopeGateDemoState.requested) {
    scopeGateDemoState.requested = true;
    addDemoMessage('Requester agent', 'Supplier bank-change review requested: need evidence, risk, reviewer decision, and payment action in one Band room.', 'audit');
    addDemoMessage('ScopeGate', 'BLOCKED: no human grant yet. Raw account number, routing number, and secret canary stay out of shared room history. Protected values stay at 0.', 'blocked');
  } else if (action === 'grant' && scopeGateDemoState.requested && !scopeGateDemoState.granted) {
    scopeGateDemoState.granted = true;
    addDemoMessage('Finance lead', 'Grant Scope for CASE VENDOR-WIRE-1849: this case, these agents, safe fields only, today.', 'safe');
    addDemoMessage('ScopeGate', 'SCOPED: safe summaries, hashes, policy excerpt, and risk memo may enter the room. Raw banking values remain withheld.', 'safe');
  } else if (action === 'review' && scopeGateDemoState.granted && !scopeGateDemoState.reviewed && !scopeGateDemoState.revoked) {
    scopeGateDemoState.reviewed = true;
    addDemoMessage('Evidence agent', 'Vendor record hash matches known supplier; invoice summary and policy excerpt attached as safe context.', 'safe');
    addDemoMessage('Risk agent', 'Risk memo: bank-change request needs two reviewers; no protected payload was posted to the room.', 'safe');
    addDemoMessage('Reviewer agents', 'Reviewer A approves, Reviewer B requests second check, Auditor Gatekeeper records deposits.', 'audit');
  } else if (action === 'revoke' && scopeGateDemoState.granted && !scopeGateDemoState.revoked) {
    scopeGateDemoState.revoked = true;
    addDemoMessage('Finance lead', 'Revoke key after this review window. Future disclosure attempts must ask again.', 'blocked');
    addDemoMessage('ScopeGate', 'REVOKED: scoped access closed; post-revocation blocks are recorded for the receipt.', 'blocked');
  } else if (action === 'late-replay' && scopeGateDemoState.revoked && !scopeGateDemoState.replayed) {
    scopeGateDemoState.replayed = true;
    addDemoMessage('Late participant', 'I joined late. Replay the sensitive bank-change context from earlier messages.', 'blocked');
    addDemoMessage('ScopeGate', 'BLOCKED: late replay recovered nothing. Shared Band history contains no protected banking payload.', 'blocked');
  } else if (action === 'seal' && scopeGateDemoState.revoked && !scopeGateDemoState.sealed) {
    scopeGateDemoState.sealed = true;
    addDemoMessage('Auditor Gatekeeper', 'Receipt sealed: agents traced, Band message IDs witnessed, protected values posted = 0, late replay blocked.', 'audit');
    addDemoMessage('Browser verifier', 'Scroll down: this page now checks the sealed receipt, file hashes, and public evidence bundle in your browser.', 'safe');
  }
  renderScopeGateDemo();
}
function initScopeGateDemo() {
  if (!document.getElementById('demo-transcript')) return;
  scopeGateDemoState.messages = [
    { actor: 'RoomKey', body: 'This is the product surface: a room can coordinate work, but disclosure waits for a human-scoped key.', tone: 'audit' },
    { actor: 'Supplier event', body: 'A supplier asks finance to change where money gets sent before a wire release.', tone: '' }
  ];
  document.querySelectorAll('[data-action]').forEach(button => {
    button.addEventListener('click', () => handleScopeGateDemoAction(button.getAttribute('data-action')));
  });
  renderScopeGateDemo();
}

let currentBackendWorkflow = null;
let workflowStageIndex = 0;
let workflowTimer = null;
function shortId(value) {
  return value ? String(value).slice(0, 8) + '…' + String(value).slice(-6) : 'none';
}
function summarizeEventPayload(event) {
  const payload = event.payload || {};
  if (event.type === 'action.blocked') return `blocked ${payload.action_kind || 'action'}: ${payload.decision?.reason || 'denied'} / ${payload.decision?.state || 'state unknown'}`;
  if (event.type === 'grant.granted') return `grant ${payload.grant_id || ''}: ${payload.allowed_agents?.length || 0} agents, ${(payload.allowed_context_keys || []).join(', ')}`;
  if (event.type === 'grant.requested') return `requested ${(payload.requested_agents || []).length} agents and ${(payload.requested_context_keys || []).length} context keys`;
  if (event.type === 'participant.added') return `${payload.agent || 'agent'} added after ${payload.decision?.state || 'grant check'}`;
  if (event.type === 'context.released') return `${payload.context_key}: ${payload.value_chars} chars, raw posted = ${payload.raw_value_posted_to_band}, hash ${shortId(payload.value_sha256)}`;
  if (event.type === 'context.replay_blocked') return `${payload.participant || 'late participant'} recovered=${payload.recovered}; release_allowed=${payload.release_allowed}`;
  if (event.type === 'reviewer.deposit') return `${payload.reviewer || event.actor}: ${payload.verdict}, independent=${payload.independent}, raw posted=${payload.raw_value_posted_to_band}`;
  if (event.type === 'review_gate.adjudicated') return `${payload.final_outcome || 'outcome'} with ${payload.reviewer_count || 0} reviewers / ${payload.threshold_rule || 'threshold'}`;
  if (event.type === 'grant.revoked') return `grant ${payload.grant_id || ''} revoked: ${payload.reason || 'complete'}`;
  if (event.type === 'context.blocked') return `${payload.context_key || 'context'} blocked: ${payload.decision?.reason || 'denied'} / ${payload.decision?.state || 'state unknown'}`;
  if (event.type === 'receipt.sealed') return `receipt sealed for ${payload.case_id || 'case'} in ${payload.mode || 'mode'}`;
  if (event.type === 'naive.baseline') return `naive path would leak=${payload.would_leak_canary}; raw canary posted=${payload.raw_canary_posted_to_band}`;
  if (event.type === 'demo.started') return `case ${payload.case_id}; raw protected posted=${payload.raw_protected_payload_posted}`;
  return Object.keys(payload).slice(0, 4).join(', ') || 'receipt event';
}
function buildBackendWorkflow(receipt, evidence) {
  const events = (receipt.live_gate_events || []).map((event, index) => ({ ...event, index: index + 1 }));
  const preGrantBlocked = event => event.type === 'action.blocked' && event.payload?.phase === 'pre_grant';
  const postGrantBlocked = event => event.type === 'action.blocked' && event.payload?.phase === 'post_revocation';
  const stages = [
    {
      key: 'intake',
      title: '1. Intake + gate block',
      copy: 'The requester starts the supplier bank-change review. Before a human grant exists, the action agent is blocked and no protected payload enters Band.',
      accept: event => ['demo.started', 'naive.baseline'].includes(event.type) || preGrantBlocked(event),
      detail: () => ({ case_id: receipt.case_id, blocked_attempts: receipt.blocked_attempts?.filter(item => item.phase === 'pre_grant'), naive_leak_radius: receipt.naive_leak_radius, secret_canary_pre_grant_seen: receipt.secret_canary_pre_grant_seen })
    },
    {
      key: 'grant',
      title: '2. Human scope grant',
      copy: 'ScopeGate records a narrow grant: one case, named agents, allowed action kinds, and allowed context keys.',
      accept: event => ['grant.requested', 'grant.granted', 'participant.added'].includes(event.type),
      detail: () => ({ grant_id: receipt.grant_id, allowed_agents: receipt.grant?.allowed_agents, allowed_context_keys: receipt.grant?.allowed_context_keys, allowed_action_kinds: receipt.grant?.allowed_action_kinds, expires_at: receipt.grant?.expires_at })
    },
    {
      key: 'release',
      title: '3. Context releases + replay block',
      copy: 'The backend releases safe context as hashes/counts. A late unapproved participant asks for replay and recovers nothing.',
      accept: event => ['context.released', 'context.replay_blocked'].includes(event.type),
      detail: () => ({ context_releases: receipt.context_releases, late_participant_probes: receipt.late_participant_probes })
    },
    {
      key: 'review',
      title: '4. Reviewer deposits + adjudication',
      copy: 'Three reviewer agents deposit independent decisions tied to the scoped context. The review gate adjudicates the result.',
      accept: event => ['reviewer.deposit', 'review_gate.adjudicated'].includes(event.type),
      detail: () => ({ reviewer_deposits: receipt.reviewer_deposits, review_gate: receipt.review_gate })
    },
    {
      key: 'revoke',
      title: '5. Revoke + post-revocation blocks',
      copy: 'The operator revokes the grant. Later action/context attempts fail closed because the key is no longer valid.',
      accept: event => event.type === 'grant.revoked' || event.type === 'context.blocked' || postGrantBlocked(event),
      detail: () => ({ revocations: receipt.revocations, post_revocation_blocks: receipt.post_revocation_blocks })
    },
    {
      key: 'seal',
      title: '6. Receipt sealed + browser proof',
      copy: 'The run closes with a receipt hash, transcript hash, secret scan, and browser-verifiable public proof bundle.',
      accept: event => event.type === 'receipt.sealed',
      detail: () => ({ receipt_sha256: receipt.receipt_sha256, transcript_sha256: receipt.transcript_sha256, policy_log_sha256: receipt.policy_log_sha256, band_secret_scan: receipt.band_secret_scan, evidence_receipt_sha256: evidence.canonical_receipt_sha256 })
    }
  ].map(stage => ({ ...stage, events: events.filter(stage.accept), detail: stage.detail() }));
  return { receipt, evidence, events, stages };
}
function renderBackendWorkflow(workflow, index) {
  if (!workflow || !document.getElementById('workflow-stage-list')) return;
  currentBackendWorkflow = workflow;
  workflowStageIndex = Math.max(0, Math.min(index || 0, workflow.stages.length - 1));
  const stage = workflow.stages[workflowStageIndex];
  setText('workflow-band-count', String(workflow.receipt.band_message_ids?.length || 0));
  setText('workflow-gate-count', String(workflow.events.length));
  setText('workflow-context-count', String(workflow.receipt.context_releases?.length || 0));
  setText('workflow-reviewer-count', String(workflow.receipt.reviewer_deposits?.length || 0));
  setText('workflow-block-count', String(workflow.receipt.post_revocation_blocks?.length || 0));
  setText('workflow-stage-title', stage.title);
  setText('workflow-stage-copy', stage.copy);
  const stageList = document.getElementById('workflow-stage-list');
  stageList.innerHTML = workflow.stages.map((item, i) => `
    <button class="workflow-stage ${i === workflowStageIndex ? 'active' : ''}" type="button" data-workflow-stage="${i}">
      <strong>${escapeHtml(item.title)}</strong>
      <span>${item.events.length} receipt events</span>
    </button>
  `).join('');
  stageList.querySelectorAll('[data-workflow-stage]').forEach(button => {
    button.addEventListener('click', () => renderBackendWorkflow(workflow, Number(button.getAttribute('data-workflow-stage'))));
  });
  const stream = document.getElementById('workflow-event-stream');
  stream.innerHTML = stage.events.map(event => `
    <article class="event-row">
      <div class="event-top">
        <strong>#${event.index} ${escapeHtml(event.actor || 'System')}</strong>
        <span class="event-kind">${escapeHtml(event.type)}</span>
      </div>
      <p>${escapeHtml(summarizeEventPayload(event))}</p>
      <span class="meta">Band message ${escapeHtml(shortId(event.band_message_id))} · content hash ${escapeHtml(shortId(event.band_content_sha256))}</span>
    </article>
  `).join('') || '<article class="event-row"><p>No events for this stage.</p></article>';
  const detail = document.getElementById('workflow-object-detail');
  detail.textContent = JSON.stringify(stage.detail, null, 2);
}
function playActualReceiptRun() {
  if (!currentBackendWorkflow) return;
  window.clearInterval(workflowTimer);
  renderBackendWorkflow(currentBackendWorkflow, 0);
  workflowTimer = window.setInterval(() => {
    if (workflowStageIndex >= currentBackendWorkflow.stages.length - 1) {
      window.clearInterval(workflowTimer);
      return;
    }
    renderBackendWorkflow(currentBackendWorkflow, workflowStageIndex + 1);
  }, 900);
}
function setupBackendWorkflowControls() {
  const play = document.getElementById('workflow-play');
  const seal = document.getElementById('workflow-seal');
  if (play && !play.dataset.bound) {
    play.dataset.bound = 'true';
    play.addEventListener('click', playActualReceiptRun);
  }
  if (seal && !seal.dataset.bound) {
    seal.dataset.bound = 'true';
    seal.addEventListener('click', () => currentBackendWorkflow && renderBackendWorkflow(currentBackendWorkflow, currentBackendWorkflow.stages.length - 1));
  }
}
async function fetchText(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(path + ' fetch status ' + response.status);
  return response.text();
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
  setText('secret-status', evidence.proof.protected_payload_value_posted === false ? '0' : 'FAIL');
  setText('replay-status', evidence.proof.late_replay_recovered === false ? 'PASS' : 'FAIL');
  setText('hero-status', 'Checking');
  setText('hero-status-copy', 'The browser is checking the receipt, proof bundle, and pinned hashes now.');
  setText('seal-id', evidence.seal_post_message_id);
  const backendWorkflow = buildBackendWorkflow(receipt, evidence);
  renderBackendWorkflow(backendWorkflow, 0);
  setupBackendWorkflowControls();

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

  setText('band-count', String(receipt.band_message_ids.length));
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
initScopeGateDemo();
verify().catch(err => {
  setBadge('contract-badge', false, 'Error');
  setBadge('schema-badge', false, 'Error');
  setBadge('hash-badge', false, 'Error');
  setText('hero-status', 'FAIL');
  setText('hero-status-copy', 'The browser verifier did not finish. Treat this page as failed until repaired.');
  setText('download-check', 'The browser verifier did not finish.');
  setText('proof-check', String(err));
  setText('verification', 'verification_error=' + err);
});
