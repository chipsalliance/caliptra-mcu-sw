// Licensed under the Apache-2.0 license

import init, { parse_spdm_cert_chain, get_sample_ci_chain } from './pkg/dice_visualizer_wasm.js';

// Global state
let currentModel = null;
let activeCertIndex = 0;
let wasmReady = false;

// Global hook for Mermaid node clicks
window.selectCertTab = function(idx) {
  switchTab(idx);
};

// UI Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const btnLoadSample = document.getElementById('btn-load-sample');
const statusBar = document.getElementById('status-bar');
const statTotalCerts = document.getElementById('stat-total-certs');
const statSpdmHeader = document.getElementById('stat-spdm-header');
const statRootHash = document.getElementById('stat-root-hash');
const errorBanner = document.getElementById('error-banner');
const diagramSection = document.getElementById('diagram-section');
const mermaidGraph = document.getElementById('mermaid-graph');
const certViewerSection = document.getElementById('cert-viewer-section');
const certTabsBar = document.getElementById('cert-tabs-bar');
const tabPanel = document.getElementById('tab-panel');
const themeSelect = document.getElementById('theme-select');

// Theme palettes for Mermaid integration
const themeConfigs = {
  'slate': {
    primaryColor: '#1e293b',
    primaryTextColor: '#f8fafc',
    primaryBorderColor: '#38bdf8',
    lineColor: '#38bdf8',
  },
  'github-dark': {
    primaryColor: '#161b22',
    primaryTextColor: '#e6edf3',
    primaryBorderColor: '#58a6ff',
    lineColor: '#58a6ff',
  },
  'nord': {
    primaryColor: '#2e3440',
    primaryTextColor: '#eceff4',
    primaryBorderColor: '#88c0d0',
    lineColor: '#88c0d0',
  },
  'catppuccin': {
    primaryColor: '#1e1e2e',
    primaryTextColor: '#cdd6f4',
    primaryBorderColor: '#89b4fa',
    lineColor: '#89b4fa',
  },
  'tokyo-night': {
    primaryColor: '#24283b',
    primaryTextColor: '#c0caf5',
    primaryBorderColor: '#7aa2f7',
    lineColor: '#7aa2f7',
  }
};

function applyTheme(themeName) {
  if (!themeConfigs[themeName]) themeName = 'slate';
  document.documentElement.setAttribute('data-theme', themeName);
  if (document.body) document.body.setAttribute('data-theme', themeName);
  localStorage.setItem('caliptra-dice-theme', themeName);
  if (themeSelect) {
    themeSelect.value = themeName;
  }
  const cfg = themeConfigs[themeName];
  if (window.mermaid && cfg) {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'dark',
      securityLevel: 'loose',
      themeVariables: {
        primaryColor: cfg.primaryColor,
        primaryTextColor: cfg.primaryTextColor,
        primaryBorderColor: cfg.primaryBorderColor,
        lineColor: cfg.lineColor,
        fontSize: '13px'
      }
    });
    if (currentModel && currentModel.mermaid_diagram) {
      renderDiagram(currentModel.mermaid_diagram).catch(() => {});
    }
  }
}

// Hook for HTML inline onchange
window.onThemeChanged = applyTheme;

if (themeSelect) {
  themeSelect.addEventListener('change', (e) => {
    applyTheme(e.target.value);
  });
}

// Initial theme load
const savedTheme = localStorage.getItem('caliptra-dice-theme') || 'slate';
applyTheme(savedTheme);

// Initialize WebAssembly at module load time
try {
  await init();
  wasmReady = true;
  console.log("WebAssembly dice-visualizer loaded successfully.");
} catch (e) {
  console.error("WASM initialization error:", e);
  showError(`WebAssembly initialization failed: ${e.message}`);
}

// Event Listeners
btnLoadSample.addEventListener('click', async () => {
  hideError();
  try {
    let bytes;
    if (wasmReady && typeof get_sample_ci_chain === 'function') {
      bytes = get_sample_ci_chain();
    } else {
      // Fallback: fetch local copy in web directory
      const res = await fetch('./certificate_chain_slot_00.der');
      if (!res.ok) throw new Error("Could not load sample chain file");
      const buf = await res.arrayBuffer();
      bytes = new Uint8Array(buf);
    }
    processCertChainBytes(bytes);
  } catch (err) {
    showError(`Failed to load test certificate: ${err.message}`);
  }
});

fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) handleFile(file);
});

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length > 0) {
    handleFile(e.dataTransfer.files[0]);
  }
});

// Click event delegation on tabPanel (e.g. for copying measurement digests)
tabPanel.addEventListener('click', (e) => {
  const btn = e.target.closest('.btn-copy-digest');
  if (btn) {
    const digest = btn.getAttribute('data-digest');
    if (digest) {
      navigator.clipboard.writeText(digest).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '✓';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.innerHTML = orig;
          btn.classList.remove('copied');
        }, 1500);
      });
    }
  }
});

function handleFile(file) {
  hideError();
  const reader = new FileReader();
  reader.onload = (e) => {
    const bytes = new Uint8Array(e.target.result);
    processCertChainBytes(bytes);
  };
  reader.onerror = () => showError(`Failed to read file ${file.name}`);
  reader.readAsArrayBuffer(file);
}

function processCertChainBytes(bytes) {
  if (!wasmReady) {
    showError("WebAssembly decoder is still initializing or failed to load.");
    return;
  }

  try {
    const jsonStr = parse_spdm_cert_chain(bytes);
    const result = JSON.parse(jsonStr);

    if (!result.success) {
      showError(result.error || "Failed to decode certificate chain.");
      return;
    }

    renderVisualizer(result);
  } catch (err) {
    showError(`Decoder exception: ${err.message}`);
  }
}

function renderVisualizer(model) {
  currentModel = model;
  activeCertIndex = 0;

  // Status Bar
  statusBar.classList.remove('hidden');
  statTotalCerts.textContent = model.total_certs;
  statSpdmHeader.textContent = model.has_spdm_header ? "Yes (SPDM GET_CERTIFICATE)" : "Raw Concatenated DER";
  statRootHash.textContent = model.root_hash_hex ? `SHA-384 (${model.root_hash_hex.substring(0, 16)}...)` : "N/A";

  // 1. Render Tabs & Active Cert FIRST so certificates are always visible
  certViewerSection.classList.remove('hidden');
  renderTabs(model.certs);
  renderActiveCert(model.certs[0]);

  // 2. Render Mermaid Diagram safely
  if (model.mermaid_diagram) {
    renderDiagram(model.mermaid_diagram).catch(err => {
      console.warn("Mermaid diagram rendering error:", err);
    });
  }
}

async function renderDiagram(mermaidCode) {
  if (!window.mermaid || !mermaidCode) return;
  diagramSection.classList.remove('hidden');
  mermaidGraph.textContent = mermaidCode;
  mermaidGraph.removeAttribute('data-processed');
  try {
    await mermaid.run({ nodes: [mermaidGraph] });
  } catch (e) {
    console.warn("Mermaid run warning:", e);
  }
}

function renderTabs(certs) {
  certTabsBar.innerHTML = '';
  certs.forEach((cert, idx) => {
    const btn = document.createElement('button');
    btn.className = `tab-btn ${idx === activeCertIndex ? 'active' : ''}`;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', idx === activeCertIndex ? 'true' : 'false');
    btn.onclick = () => switchTab(idx);

    let badge = '';
    if (cert.dice && cert.dice.has_dice) {
      if (cert.dice.multi_tcb_info && cert.dice.multi_tcb_info.length > 0) {
        badge = `<span class="pill-badge">MultiTcb</span>`;
      } else if (cert.dice.tcb_info) {
        badge = `<span class="pill-badge">TcbInfo</span>`;
      } else if (cert.dice.ueid_hex) {
        badge = `<span class="pill-badge">UEID</span>`;
      }
    }

    btn.innerHTML = `<span>${idx + 1}. ${cert.tab_title}</span> ${badge}`;
    certTabsBar.appendChild(btn);
  });
}

function switchTab(index) {
  if (!currentModel || !currentModel.certs[index]) return;
  activeCertIndex = index;

  // Update tab buttons
  const buttons = certTabsBar.querySelectorAll('.tab-btn');
  buttons.forEach((btn, idx) => {
    btn.classList.toggle('active', idx === index);
    btn.setAttribute('aria-selected', idx === index ? 'true' : 'false');
  });

  renderActiveCert(currentModel.certs[index]);
}

function formatTcbType(typeStr) {
  if (!typeStr) return '<span class="text-muted">-</span>';
  // Known Caliptra 4-byte TCI types inverted by RISC-V little-endian u32 serialization
  const knownInverted = {
    'RMTR': 'RTMR',
    'VICC': 'CCIV',
    'VMOS': 'SOMV',
    'OMOS': 'SOMO',
    'WFCM': 'MCFW',
  };
  let displayStr = knownInverted[typeStr] || typeStr;
  if (displayStr === '0x00000000') {
    displayStr = '0x00000000 (FE State / Stashed)';
  }
  return `<code style="color:var(--accent-amber);white-space:nowrap">${displayStr}</code>`;
}

function formatSvn(tcb) {
  if (tcb.svn === null || tcb.svn === undefined) return '<span class="text-muted">-</span>';
  return `<code style="white-space:nowrap">${tcb.svn}</code>`;
}

function formatLayerIndex(tcb) {
  const parts = [];
  if (tcb.layer !== null && tcb.layer !== undefined) {
    parts.push(`<div><small class="text-muted">layer: </small><code>${tcb.layer}</code></div>`);
  }
  if (tcb.index !== null && tcb.index !== undefined) {
    parts.push(`<div><small class="text-muted">index: </small><code>${tcb.index}</code></div>`);
  }
  return parts.length > 0 ? `<div style="white-space:nowrap">${parts.join('')}</div>` : '<span class="text-muted">-</span>';
}

function formatComponent(t) {
  const parts = [];
  if (t.vendor) parts.push(`<div><strong>${t.vendor}</strong></div>`);
  if (t.model) parts.push(`<div><small class="text-muted">model: </small>${t.model}</div>`);
  if (t.version) parts.push(`<div><small class="text-muted">version: </small>${t.version}</div>`);
  return parts.length > 0 ? `<div style="white-space:nowrap">${parts.join('')}</div>` : '<span class="text-muted">-</span>';
}

function formatVendorInfo(t) {
  if (!t.vendor_info_hex) return '<span class="text-muted">-</span>';
  let html = `<div class="vendor-info-cell"><code>0x${t.vendor_info_hex}</code>`;
  if (t.vendor_info_hex.length === 8) {
    const loc = parseInt(t.vendor_info_hex, 16);
    html += `<span class="locality-badge">(DPE Locality: <code>${loc}</code>)</span>`;
  }
  html += `</div>`;
  return html;
}

function formatFlags(t) {
  if (!t.flags) {
    if (t.flags_mask_hex) {
      return `<div style="white-space:nowrap"><small class="text-muted">flagsMask: </small><code>0x${t.flags_mask_hex}</code></div>`;
    }
    return '<span class="text-muted">-</span>';
  }

  const activeFlags = [];
  if (t.flags.not_configured) activeFlags.push('<span class="badge-tag" style="border-color:var(--accent-amber);color:var(--accent-amber)">notConfigured</span>');
  if (t.flags.not_secure) activeFlags.push('<span class="badge-tag" style="border-color:var(--accent-red,#f87171);color:var(--accent-red,#f87171)">notSecure</span>');
  if (t.flags.recovery) activeFlags.push('<span class="badge-tag" style="border-color:var(--accent-amber);color:var(--accent-amber)">recovery</span>');
  if (t.flags.debug) activeFlags.push('<span class="badge-tag" style="border-color:var(--accent-cyan);color:var(--accent-cyan)">debug</span>');

  let html = `<div style="white-space:nowrap">`;
  html += activeFlags.length > 0 ? activeFlags.join(' ') : `<span class="badge-tag">None (0x${t.flags.raw_hex})</span>`;
  if (t.flags_mask_hex) {
    html += `<div style="margin-top:0.25rem"><small class="text-muted">flagsMask: </small><code>0x${t.flags_mask_hex}</code></div>`;
  }
  html += `</div>`;
  return html;
}

function formatMeasurements(t) {
  const items = [];
  if (t.fwids && t.fwids.length > 0) {
    t.fwids.forEach((f, fIdx) => {
      items.push(`
        <div class="measurement-box">
          <div class="measurement-header">
            <span class="badge-role" style="font-family:var(--font-mono);font-size:0.75rem;border-color:var(--accent-blue,#60a5fa);color:var(--accent-blue,#60a5fa)">
              fwids[${fIdx}]
            </span>
            <span class="badge-hash">${f.hash_alg}</span>
          </div>
          <div class="digest-container">
            <code class="digest-code">${f.digest_hex}</code>
            <button class="btn-copy-digest" data-digest="${f.digest_hex}" title="Copy SHA-384 digest">📋</button>
          </div>
        </div>
      `);
    });
  }
  if (t.integrity_registers && t.integrity_registers.length > 0) {
    t.integrity_registers.forEach((ir, rIdx) => {
      const regName = ir.name ? ir.name : (ir.num !== null && ir.num !== undefined ? `integrityRegisters[${ir.num}]` : `integrityRegisters[${rIdx}]`);
      ir.digests.forEach(d => {
        items.push(`
          <div class="measurement-box">
            <div class="measurement-header">
              <span class="badge-role" style="font-family:var(--font-mono);font-size:0.75rem;border-color:var(--accent-purple,#c084fc);color:var(--accent-purple,#c084fc)">
                ${regName}
              </span>
              <span class="badge-hash">${d.hash_alg}</span>
            </div>
            <div class="digest-container">
              <code class="digest-code">${d.digest_hex}</code>
              <button class="btn-copy-digest" data-digest="${d.digest_hex}" title="Copy SHA-384 digest">📋</button>
            </div>
          </div>
        `);
      });
    });
  }
  if (items.length === 0) {
    return '<span class="text-muted">No measurements</span>';
  }
  return items.join('');
}

function renderActiveCert(cert) {
  let diceHtml = '<p class="text-muted">No TCG DICE extensions present in this certificate.</p>';

  if (cert.dice && cert.dice.has_dice) {
    let sections = [];

    // UEID Section
    if (cert.dice.ueid_hex) {
      sections.push(`
        <div class="dice-subcard">
          <div class="dice-subcard-header">
            <h4>tcg-dice-Ueid</h4>
            <span class="oid-tag">OID: 2.23.133.5.4.4</span>
          </div>
          <div class="prop-row">
            <span class="prop-key">Unique Device ID:</span>
            <span class="prop-val" style="word-break:break-all;color:var(--accent-cyan);font-family:var(--font-mono)">${cert.dice.ueid_hex}</span>
          </div>
        </div>
      `);
    }

    // Key Purposes Section (EKU)
    if (cert.dice.key_purposes && cert.dice.key_purposes.length > 0) {
      sections.push(`
        <div class="dice-subcard">
          <div class="dice-subcard-header">
            <h4>tcg-dice-kp (Key Purposes)</h4>
            <span class="oid-tag">EKU: 2.5.29.37</span>
          </div>
          <div class="prop-row">
            <span class="prop-key">Declared Roles:</span>
            <div>
              ${cert.dice.key_purposes.map(kp => `<span class="badge-role">${kp}</span>`).join('')}
            </div>
          </div>
        </div>
      `);
    }

    // MultiTcbInfo or TcbInfo Section
    const isMulti = cert.dice.multi_tcb_info && cert.dice.multi_tcb_info.length > 0;
    const tcbs = isMulti ? cert.dice.multi_tcb_info : (cert.dice.tcb_info ? [cert.dice.tcb_info] : []);

    if (tcbs.length > 0) {
      const extTitle = isMulti ? 'tcg-dice-MultiTcbInfo' : 'tcg-dice-TcbInfo';
      const extOid = isMulti ? '2.23.133.5.4.5' : '2.23.133.5.4.1';
      const countBadge = isMulti ? `<span class="badge-count">${tcbs.length} TCB Entries</span>` : '';

      sections.push(`
        <div class="dice-subcard">
          <div class="dice-subcard-header">
            <h4>${extTitle}</h4>
            <div style="display:flex;gap:0.5rem;align-items:center;">
              ${countBadge}
              <span class="oid-tag">OID: ${extOid}</span>
            </div>
          </div>
          <div class="table-container">
            <table class="data-table dice-table">
              <thead>
                <tr>
                  <th style="width: 35px; text-align: center;">#</th>
                  <th style="min-width: 95px; white-space: nowrap;">layer / index</th>
                  <th style="min-width: 50px; white-space: nowrap;">svn</th>
                  <th style="min-width: 100px; white-space: nowrap;">type</th>
                  <th style="min-width: 140px; white-space: nowrap;">vendor / model / version</th>
                  <th style="min-width: 160px; white-space: nowrap;">vendorInfo</th>
                  <th style="min-width: 130px; white-space: nowrap;">flags / flagsMask</th>
                  <th style="min-width: 550px; white-space: nowrap;">fwids &amp; integrityRegisters</th>
                </tr>
              </thead>
              <tbody>
                ${tcbs.map((t, idx) => `
                  <tr>
                    <td style="text-align: center;"><code>${idx + 1}</code></td>
                    <td>${formatLayerIndex(t)}</td>
                    <td>${formatSvn(t)}</td>
                    <td>${formatTcbType(t.tcb_type)}</td>
                    <td>${formatComponent(t)}</td>
                    <td>${formatVendorInfo(t)}</td>
                    <td>${formatFlags(t)}</td>
                    <td>${formatMeasurements(t)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `);
    }

    diceHtml = sections.join('');
  }

  let spdmHtml = `
    <div class="dice-subcard" style="margin-top:0">
      <div class="dice-subcard-header">
        <h4>id-DMTF-hardware-identity</h4>
        <span class="oid-tag">OID: 1.3.6.1.4.1.412.274.2</span>
      </div>
      <div class="prop-row">
        <span class="prop-key">Status:</span>
        <span class="prop-val">${cert.spdm.has_hardware_identity 
          ? '<span class="badge-role" style="border-color:var(--accent-green);color:var(--accent-green)">Present</span>' 
          : '<span class="text-muted">Not present</span>'}</span>
      </div>
      <div class="prop-row">
        <span class="prop-key">Specification:</span>
        <span class="prop-val" style="font-size:0.8rem;color:var(--text-muted)">DSP0274 / OCP NVMe CERT-5 (IDevID)</span>
      </div>
    </div>
    <div class="dice-subcard">
      <div class="dice-subcard-header">
        <h4>id-DMTF-mutable-certificate</h4>
        <span class="oid-tag">OID: 1.3.6.1.4.1.412.274.5</span>
      </div>
      <div class="prop-row">
        <span class="prop-key">Status:</span>
        <span class="prop-val">${cert.spdm.is_mutable 
          ? '<span class="badge-role" style="border-color:var(--accent-green);color:var(--accent-green)">Present</span>' 
          : '<span class="text-muted">Not present</span>'}</span>
      </div>
      <div class="prop-row">
        <span class="prop-key">Specification:</span>
        <span class="prop-val" style="font-size:0.8rem;color:var(--text-muted)">DSP0274 / OCP NVMe CERT-6 (Alias Chains)</span>
      </div>
    </div>
  `;

  let standardExtsHtml = cert.standard_extensions && cert.standard_extensions.length > 0 ? `
    <div class="table-container">
      <table class="standard-exts-table">
        <thead>
          <tr>
            <th>Extension (RFC 5280)</th>
            <th>OID</th>
            <th>Critical</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          ${cert.standard_extensions.map(e => `
            <tr>
              <td><code>${e.name}</code></td>
              <td><code>${e.oid}</code></td>
              <td>${e.critical ? '<span style="color:var(--accent-red)">True</span>' : 'False'}</td>
              <td>${e.value_summary}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  ` : '<p class="text-muted">No standard extensions.</p>';

  tabPanel.innerHTML = `
    <!-- Top Grid: Identity & Standard Extensions -->
    <div class="grid-two-col">
      <!-- Summary Card -->
      <div class="info-card">
        <h3>Certificate Identity</h3>
        <div class="prop-list">
          <div class="prop-row">
            <span class="prop-key">Subject:</span>
            <span class="prop-val">${cert.subject}</span>
          </div>
          <div class="prop-row">
            <span class="prop-key">Issuer:</span>
            <span class="prop-val">${cert.issuer}</span>
          </div>
          <div class="prop-row">
            <span class="prop-key">Serial Number:</span>
            <span class="prop-val"><code>0x${cert.serial_hex}</code></span>
          </div>
          <div class="prop-row">
            <span class="prop-key">Validity:</span>
            <span class="prop-val">${cert.not_before} to ${cert.not_after}</span>
          </div>
          <div class="prop-row">
            <span class="prop-key">Signature Algorithm:</span>
            <span class="prop-val"><code>${cert.sig_alg}</code></span>
          </div>
          <div class="prop-row">
            <span class="prop-key">Public Key Algorithm:</span>
            <span class="prop-val"><code>${cert.public_key.algorithm}</code> ${cert.public_key.key_size_bits ? `<small class="text-muted">(${cert.public_key.key_size_bits} bits)</small>` : ''}</span>
          </div>
        </div>
      </div>

      <!-- Standard Extensions Card -->
      <div class="info-card">
        <h3>Standard X.509 Extensions</h3>
        ${standardExtsHtml}
      </div>
    </div>

    <!-- TCG DICE Card (Full Width) -->
    <div class="info-card full-width">
      <h3>TCG DICE Attestation Extensions</h3>
      ${diceHtml}
    </div>

    <!-- Bottom Grid: SPDM & Raw PEM -->
    <div class="grid-two-col">
      <!-- SPDM Card -->
      <div class="info-card">
        <h3>DMTF SPDM Extensions</h3>
        ${spdmHtml}
      </div>

      <!-- Raw PEM Card -->
      <div class="info-card">
        <h3>Raw Certificate (PEM)</h3>
        <div class="code-inspector">
          <button class="btn-copy" onclick="navigator.clipboard.writeText(currentModel.certs[${cert.index}].raw_pem)">Copy PEM</button>
          <code>${cert.raw_pem}</code>
        </div>
      </div>
    </div>
  `;
}

function showError(msg) {
  errorBanner.textContent = msg;
  errorBanner.classList.remove('hidden');
}

function hideError() {
  errorBanner.classList.add('hidden');
}

