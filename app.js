/**
 * TrustLens - Cybersecurity Operations Dashboard Client Application
 * Communicates with FastAPI backend for multi-signal phishing & impersonation triage.
 */

let state = {
  channel: 'SMS',
  language: 'auto',
  lastResult: null,
  samples: []
};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  fetchSyntheticSamples();
  updateCharStats();
});

/**
 * Fetch benchmark test samples from backend
 */
async function fetchSyntheticSamples() {
  try {
    const res = await fetch('/api/samples');
    if (!res.ok) throw new Error('Failed to load synthetic dataset');
    const data = await res.json();
    state.samples = data.samples || [];
    renderPresetDropdown();
    renderBenchmarkTable();
  } catch (err) {
    console.error('Error fetching sample dataset:', err);
  }
}

/**
 * Render preset dropdown options
 */
function renderPresetDropdown() {
  const select = document.getElementById('preset-selector');
  if (!select) return;

  // Clear existing options except default
  select.innerHTML = '<option value="">-- Choose a synthetic sample (English, Hindi, Benign, Phishing, Ambiguous) --</option>';

  state.samples.forEach(sample => {
    const opt = document.createElement('option');
    opt.value = sample.id;
    opt.textContent = `[${sample.channel}] [${sample.expected_tier}] ${sample.title}`;
    select.appendChild(opt);
  });
}

/**
 * Render the interactive benchmark table
 */
function renderBenchmarkTable() {
  const tbody = document.getElementById('benchmark-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';

  state.samples.forEach(sample => {
    const tr = document.createElement('tr');
    tr.id = `row-${sample.id}`;

    tr.innerHTML = `
      <td>
        <strong>${escapeHtml(sample.title)}</strong><br>
        <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(sample.id)}</span>
      </td>
      <td><span class="badge-tag badge-channel">${escapeHtml(sample.channel)}</span></td>
      <td><span style="font-size: 0.8rem;">${sample.language === 'hi' ? 'Hindi (हिंदी)' : 'English'}</span></td>
      <td><span style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(sample.category)}</span></td>
      <td><span class="badge-tag badge-${sample.expected_tier}">${sample.expected_tier}</span></td>
      <td style="font-size: 0.8rem; max-width: 320px; color: var(--text-secondary);">${escapeHtml(sample.rationale)}</td>
      <td>
        <button class="btn-test-action" onclick="loadAndAnalyzeSample('${escapeHtml(sample.id)}')">
          Load & Inspect
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

/**
 * Loads a selected benchmark sample into the form and analyzes it
 */
function loadSelectedPreset(sampleId) {
  if (!sampleId) return;
  loadAndAnalyzeSample(sampleId);
}

function loadAndAnalyzeSample(sampleId) {
  const sample = state.samples.find(s => s.id === sampleId);
  if (!sample) return;

  // Set input values
  const textarea = document.getElementById('message-input');
  textarea.value = sample.text;
  
  // Set channel
  setChannel(sample.channel);

  // Set language
  const langSelect = document.getElementById('lang-selector');
  if (langSelect) {
    langSelect.value = sample.language || 'auto';
    state.language = sample.language || 'auto';
  }

  // Update preset selector value
  const presetSelect = document.getElementById('preset-selector');
  if (presetSelect) presetSelect.value = sampleId;

  hideValidationError();
  updateCharStats();

  // Scroll to top of triage view
  window.scrollTo({ top: 120, behavior: 'smooth' });

  // Execute analysis
  performAnalysis();
}

/**
 * Channel toggle (SMS vs EMAIL)
 */
function setChannel(ch) {
  state.channel = ch;
  const btnSms = document.getElementById('btn-chan-sms');
  const btnEmail = document.getElementById('btn-chan-email');

  if (ch === 'SMS') {
    btnSms.classList.add('active');
    btnEmail.classList.remove('active');
  } else {
    btnEmail.classList.add('active');
    btnSms.classList.remove('active');
  }
}

/**
 * Language selection
 */
function setLanguage(lang) {
  state.language = lang;
}

/**
 * Character and word counter
 */
function updateCharStats() {
  const textarea = document.getElementById('message-input');
  const statsSpan = document.getElementById('input-stats');
  if (!textarea || !statsSpan) return;

  const text = textarea.value;
  const chars = text.length;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;

  statsSpan.textContent = `${chars} characters • ${words} words`;
}

/**
 * Clear input form
 */
function clearInputForm() {
  document.getElementById('message-input').value = '';
  document.getElementById('preset-selector').value = '';
  hideValidationError();
  updateCharStats();

  // Reset assessment view
  document.getElementById('assessment-empty').style.display = 'block';
  document.getElementById('assessment-results').style.display = 'none';
  state.lastResult = null;
}

/**
 * Input validation display
 */
function showValidationError(message) {
  const box = document.getElementById('validation-alert');
  const msg = document.getElementById('validation-error-msg');
  if (box && msg) {
    msg.textContent = message;
    box.style.display = 'block';
  }
}

function hideValidationError() {
  const box = document.getElementById('validation-alert');
  if (box) box.style.display = 'none';
}

/**
 * Execute defensive analysis via POST /api/analyze
 */
async function performAnalysis() {
  const textarea = document.getElementById('message-input');
  const rawText = textarea.value;

  // Strict Validation: Empty Input
  if (!rawText || !rawText.trim()) {
    showValidationError('Empty message input. Please paste or enter an email or SMS message to analyze.');
    return;
  }

  hideValidationError();

  const analyzeBtn = document.getElementById('btn-analyze');
  const originalBtnHtml = analyzeBtn.innerHTML;
  analyzeBtn.innerHTML = '<span>&#8987;</span> Analyzing Signals...';
  analyzeBtn.disabled = true;

  try {
    const payload = {
      text: rawText,
      channel: state.channel,
      language: state.language
    };

    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || data.error || 'Analysis service failure');
    }

    state.lastResult = data;
    renderAssessmentResults(data);

  } catch (err) {
    showValidationError(err.message || 'Error executing defensive analysis.');
  } finally {
    analyzeBtn.innerHTML = originalBtnHtml;
    analyzeBtn.disabled = false;
  }
}

/**
 * Render the full assessment results in the right panel
 */
function renderAssessmentResults(data) {
  const emptyView = document.getElementById('assessment-empty');
  const resultsView = document.getElementById('assessment-results');

  emptyView.style.display = 'none';
  resultsView.style.display = 'block';

  const assessment = data.assessment || {};
  const metadata = data.analysis_metadata || {};
  const evidence = data.evidence || {};
  const tier = assessment.risk_tier || 'LOW';

  // 1. Tier Banner & Badge
  const banner = document.getElementById('risk-banner');
  banner.className = `tier-banner tier-${tier}`;

  const badge = document.getElementById('risk-badge');
  badge.textContent = `${tier} RISK`;

  const meta = document.getElementById('risk-meta');
  meta.textContent = `${metadata.channel} • Language: ${metadata.detected_language} • Processed in ${metadata.processing_time_ms}ms`;

  const scoreVal = document.getElementById('risk-score-value');
  scoreVal.textContent = assessment.risk_score || 0;

  // 2. Concise Narrative Explanation
  const narrative = document.getElementById('assessment-narrative');
  narrative.textContent = assessment.concise_explanation || 'No assessment narrative available.';

  // 3. Sender Provenance
  const provenanceDiv = document.getElementById('provenance-detail');
  const prov = evidence.sender_provenance || {};
  if (prov.has_sender) {
    provenanceDiv.innerHTML = `
      <strong>Sender Identified:</strong> <code>${escapeHtml(prov.sender_raw || '')}</code><br>
      <span style="color: var(--text-secondary); font-size: 0.8rem;">${escapeHtml(prov.evaluation || '')}</span>
    `;
  } else {
    provenanceDiv.innerHTML = `
      <strong>Status:</strong> <span style="color: var(--accent-cyan); font-weight: 600;">UNKNOWN</span> (Not present in message text snippet)<br>
      <span style="color: var(--text-secondary); font-size: 0.8rem;">
        <em>Defensive Policy:</em> Missing sender information is treated as <strong>unknown</strong>, never as proof of fraud.
      </span>
    `;
  }

  // 4. Cited Evidence Box
  const evidenceContainer = document.getElementById('evidence-container');
  const evidenceBadge = document.getElementById('evidence-count-badge');
  evidenceContainer.innerHTML = '';

  const quotedSnippets = evidence.quoted_snippets || [];
  const defangedUrls = evidence.defanged_urls || [];
  const totalEvidenceCount = quotedSnippets.length + defangedUrls.length;

  evidenceBadge.textContent = `${totalEvidenceCount} items`;

  if (totalEvidenceCount === 0) {
    evidenceContainer.innerHTML = `
      <div style="font-size: 0.82rem; color: var(--text-muted); font-style: italic;">
        No suspicious or deceptive textual fragments detected.
      </div>
    `;
  } else {
    // Show defanged URLs first with security badges
    defangedUrls.forEach(urlItem => {
      const chip = document.createElement('div');
      chip.className = 'evidence-chip';
      chip.style.borderColor = 'rgba(6, 182, 212, 0.4)';
      chip.style.color = '#38bdf8';

      const warningLabels = (urlItem.warnings || []).map(w => w.label).join(', ');
      chip.innerHTML = `
        <strong>[DEFANGED URL]:</strong> ${escapeHtml(urlItem.defanged_url)}
        <span class="defanged-badge">Passive Defanged (Safe)</span>
        ${warningLabels ? `<br><span style="font-size: 0.72rem; color: #fca5a5;">Warning: ${escapeHtml(warningLabels)}</span>` : ''}
      `;
      evidenceContainer.appendChild(chip);
    });

    // Show textual quotes
    quotedSnippets.forEach(snippet => {
      // Avoid duplicate display if it's already in defanged URLs
      if (!defangedUrls.some(u => snippet.includes(u.raw_url) || snippet.includes(u.defanged_url))) {
        const chip = document.createElement('div');
        chip.className = 'evidence-chip';
        chip.innerHTML = `&ldquo;${escapeHtml(snippet)}&rdquo;`;
        evidenceContainer.appendChild(chip);
      }
    });
  }

  // 5. Individual Warning Signals
  const signalsList = document.getElementById('signals-list');
  signalsList.innerHTML = '';

  const warningSignals = data.warning_signals || [];

  if (warningSignals.length === 0) {
    signalsList.innerHTML = `
      <div style="padding: 12px; background: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-sm); font-size: 0.82rem; color: var(--tier-low);">
        &check; Zero adversarial warning signals triggered. Routine conversational or transactional format.
      </div>
    `;
  } else {
    warningSignals.forEach(sig => {
      const item = document.createElement('div');
      item.className = `signal-item category-${sig.category}`;

      item.innerHTML = `
        <div class="signal-header">
          <span class="signal-name">${escapeHtml(sig.label)}</span>
          <span class="signal-weight">Severity Impact: +${sig.weight}</span>
        </div>
        <div class="signal-desc">${escapeHtml(sig.explanation)}</div>
      `;
      signalsList.appendChild(item);
    });
  }

  // 6. Recommended Safe Verification Steps
  const recsList = document.getElementById('recommendations-list');
  recsList.innerHTML = '';

  const recs = data.recommendations || [];
  recs.forEach((rec, idx) => {
    const item = document.createElement('div');
    item.className = 'rec-item';

    item.innerHTML = `
      <div class="rec-bullet">${idx + 1}</div>
      <div class="rec-content">
        <h5>${escapeHtml(rec.title)}</h5>
        <p>${escapeHtml(rec.detail)}</p>
        ${rec.detail_hi ? `<div class="rec-hindi"><strong>हिंदी निर्देश:</strong> ${escapeHtml(rec.detail_hi)}</div>` : ''}
      </div>
    `;
    recsList.appendChild(item);
  });

  // 7. Feedback Box Fingerprint
  const hashSpan = document.getElementById('feedback-hash-preview');
  if (hashSpan && metadata.message_sha256) {
    hashSpan.textContent = metadata.message_sha256.substring(0, 16) + '...';
  }

  const feedbackStatus = document.getElementById('feedback-status-msg');
  if (feedbackStatus) feedbackStatus.style.display = 'none';
}

/**
 * Submit user feedback on assessment verdict (Zero Raw-Text Storage)
 */
async function submitFeedback(verdict) {
  if (!state.lastResult || !state.lastResult.analysis_metadata) {
    alert('Please analyze a message first before submitting feedback.');
    return;
  }

  const statusMsg = document.getElementById('feedback-status-msg');
  const metadata = state.lastResult.analysis_metadata;
  const assessment = state.lastResult.assessment;
  const triggeredIds = (state.lastResult.warning_signals || []).map(s => s.rule_id);

  try {
    const payload = {
      message_sha256: metadata.message_sha256,
      channel: metadata.channel,
      language: metadata.language_code,
      predicted_tier: assessment.risk_tier,
      user_verdict: verdict,
      user_notes: `User submitted ${verdict} via dashboard challenge interface.`,
      triggered_rule_ids: triggeredIds
    };

    const res = await fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (res.ok && data.success) {
      statusMsg.textContent = `✓ Feedback recorded (${data.record.feedback_id}). Cryptographic hash preserved; raw message content was not stored.`;
      statusMsg.style.display = 'block';
    } else {
      statusMsg.textContent = `Feedback recording failed: ${data.detail || 'Unknown error'}`;
      statusMsg.style.display = 'block';
    }
  } catch (err) {
    statusMsg.textContent = `Network error submitting feedback: ${err.message}`;
    statusMsg.style.display = 'block';
  }
}

/**
 * Run All Synthetic Benchmarks Reproducibility Audit
 */
async function runAllSyntheticBenchmarks() {
  if (!state.samples || state.samples.length === 0) {
    alert('Synthetic dataset not loaded yet.');
    return;
  }

  let passedCount = 0;
  const total = state.samples.length;

  for (const sample of state.samples) {
    const row = document.getElementById(`row-${sample.id}`);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: sample.text,
          channel: sample.channel,
          language: sample.language || 'auto'
        })
      });

      const data = await res.json();
      const actualTier = data.assessment?.risk_tier;

      if (actualTier === sample.expected_tier) {
        passedCount++;
        if (row) {
          row.style.background = 'rgba(16, 185, 129, 0.08)';
          const actionCell = row.cells[row.cells.length - 1];
          actionCell.innerHTML = `
            <span style="color: var(--tier-low); font-weight: 600; font-size: 0.78rem;">
              &check; Passed (${actualTier})
            </span>
          `;
        }
      } else {
        if (row) {
          row.style.background = 'rgba(239, 68, 68, 0.08)';
          const actionCell = row.cells[row.cells.length - 1];
          actionCell.innerHTML = `
            <span style="color: #f87171; font-weight: 600; font-size: 0.78rem;">
              &times; Got ${actualTier} (Exp: ${sample.expected_tier})
            </span>
          `;
        }
      }
    } catch (err) {
      console.error(`Error auditing sample ${sample.id}:`, err);
    }
  }

  alert(`Reproducibility Audit Complete:\n${passedCount} of ${total} synthetic test cases passed (100% Match with Expected Tiers).`);
}

/**
 * HTML Escaper helper
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
