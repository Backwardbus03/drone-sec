/**
 * Drone Forensic Toolkit (DFT) — Mobile Companion Apps & Wireless Forensics UI Module
 * Handles mobile companion artifact visualization, pilot identity extraction,
 * paired hardware serial numbers, operator phone GPS recovery, and wireless acquisition sessions.
 */

if (typeof window.escapeHtml !== 'function') {
  window.escapeHtml = function(text) {
    if (text === null || text === undefined) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
}

let cachedMobileData = null;
let cachedWirelessSessions = [];

async function initMobileTab() {
  await loadMobileCatalog();
  await loadMobileData();
}

async function loadMobileCatalog() {
  try {
    const res = await fetch('/api/mobile/supported-apps');
    if (!res.ok) return;
    const catalog = await res.json();
    renderMobileCatalog(catalog);
  } catch (err) {
    console.warn('Failed to load mobile catalog:', err);
  }
}

function renderMobileCatalog(catalog) {
  const container = document.getElementById('mobileCatalogGrid');
  if (!container) return;

  container.innerHTML = catalog.map(app => `
    <div class="bg-slate-900 border border-slate-800 hover:border-slate-700 p-3.5 rounded-xl transition flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between mb-1.5">
          <h5 class="text-xs font-bold text-white">${escapeHtml(app.app_name)}</h5>
          <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-sky-950 text-sky-300 border border-sky-800">${escapeHtml(app.platform)}</span>
        </div>
        <p class="text-[11px] font-mono text-slate-400 mb-2">${escapeHtml(app.package_id || 'mobile-pkg')}</p>
        <p class="text-[11px] text-slate-400 mb-2 line-clamp-2">${escapeHtml((app.supported_models || []).join(', '))}</p>
      </div>
      <div class="border-t border-slate-800/80 pt-2 text-[10px] text-slate-500">
        Key Files: <code class="text-sky-400">${escapeHtml((app.key_artifacts || []).slice(0, 2).join(', '))}</code>
      </div>
    </div>
  `).join('');
}

async function loadMobileData() {
  if (!activeCaseId) return;

  // Dynamically update mobile quick-upload portal URL to point to active case
  try {
    const portalLink = document.getElementById('mobilePortalLink');
    const portalBtn = document.getElementById('mobilePortalBtn');
    const host = window.location.hostname || '127.0.0.1';
    const port = window.location.port ? `:${window.location.port}` : '';
    const uploadUrl = `${window.location.protocol}//${host}${port}/upload?case=${encodeURIComponent(activeCaseId)}`;
    if (portalLink) {
      portalLink.href = uploadUrl;
      portalLink.textContent = uploadUrl;
    }
    if (portalBtn) {
      portalBtn.href = uploadUrl;
    }
  } catch (_) {}

  try {
    const [mobRes, wireRes] = await Promise.all([
      fetch(`/api/cases/${activeCaseId}/mobile`).catch(err => {
        console.warn('Mobile API fetch error:', err);
        return null;
      }),
      fetch(`/api/cases/${activeCaseId}/wireless`).catch(err => {
        console.warn('Wireless API fetch error:', err);
        return null;
      })
    ]);

    let data = { artifacts: [], apps_detected: [], total_flight_records: 0, extracted_telemetry_points_count: 0 };
    if (mobRes && mobRes.ok) {
      data = await mobRes.json();
      cachedMobileData = data;
    }

    let wirelessSessions = [];
    if (wireRes && wireRes.ok) {
      wirelessSessions = await wireRes.json();
      cachedWirelessSessions = wirelessSessions;
    }

    renderMobileUI(data, wirelessSessions);
  } catch (err) {
    console.error('Failed to load mobile companion or wireless data:', err);
  }
}

function renderMobileUI(data, wirelessSessions) {
  wirelessSessions = wirelessSessions || cachedWirelessSessions || [];
  data = data || cachedMobileData || { artifacts: [] };

  // 1. Stat cards
  const statApps = document.getElementById('mobStatApps');
  if (statApps) {
    const recognized = (data.apps_detected || []).filter(a => a && a !== 'Unknown Mobile App');
    if (recognized.length > 0) {
      statApps.textContent = recognized.join(', ');
    } else if (wirelessSessions.length > 0) {
      statApps.textContent = `${wirelessSessions.length} Wireless Session${wirelessSessions.length === 1 ? '' : 's'}`;
    } else {
      statApps.textContent = 'None';
    }
  }

  const statPilot = document.getElementById('mobStatPilot');
  const statPilotEmail = document.getElementById('mobStatPilotEmail');
  let firstPilot = null;
  let firstSN = null;

  (data.artifacts || []).forEach(art => {
    if (!firstPilot && art.pilot_account) {
      firstPilot = art.pilot_account;
    }
    if (!firstSN && art.paired_hardware && art.paired_hardware.aircraft_sn) {
      firstSN = art.paired_hardware.aircraft_sn;
    }
  });

  if (statPilot) {
    if (firstPilot) {
      statPilot.textContent = firstPilot.pilot_name || firstPilot.callsign || firstPilot.email || 'Identified';
    } else if (wirelessSessions.length > 0) {
      statPilot.textContent = 'Mobile Wireless Client';
    } else {
      statPilot.textContent = 'Not Identified';
    }
  }
  if (statPilotEmail) {
    if (firstPilot && firstPilot.email) {
      statPilotEmail.textContent = firstPilot.email;
    } else if (wirelessSessions.length > 0) {
      statPilotEmail.textContent = 'Live Wi-Fi Ingestion';
    } else {
      statPilotEmail.textContent = 'Email: --';
    }
  }

  const statSN = document.getElementById('mobStatSN');
  if (statSN) {
    if (firstSN) {
      statSN.textContent = firstSN;
    } else if (wirelessSessions.length > 0) {
      statSN.textContent = 'Direct Wi-Fi Uplink';
    } else {
      statSN.textContent = 'Not Bound';
    }
  }

  const statLogs = document.getElementById('mobStatLogs');
  if (statLogs) {
    if (data.total_flight_records > 0) {
      statLogs.textContent = `${data.total_flight_records} logs (${data.extracted_telemetry_points_count || 0} pts)`;
    } else if (wirelessSessions.length > 0) {
      const totalFiles = wirelessSessions.reduce((acc, s) => acc + (s.files_acquired ? s.files_acquired.length : 1), 0);
      statLogs.textContent = `${totalFiles} wireless file${totalFiles === 1 ? '' : 's'}`;
    } else {
      statLogs.textContent = '0 logs';
    }
  }

  // 2. Render Artifacts & Wireless Sessions
  renderMobileArtifacts(data.artifacts || [], wirelessSessions);
  renderWirelessSessions(wirelessSessions);
}

function renderMobileArtifacts(artifacts, wirelessSessions) {
  const container = document.getElementById('mobileArtifactsContainer');
  if (!container) return;

  wirelessSessions = wirelessSessions || cachedWirelessSessions || [];

  // Filter out empty placeholder artifacts
  const recognizedArtifacts = (artifacts || []).filter(art => {
    if (!art) return false;
    if (art.app_name === 'Unknown Mobile App') {
      const hasPilot = art.pilot_account && Object.keys(art.pilot_account).length > 0;
      const hasHw = art.paired_hardware && Object.keys(art.paired_hardware).length > 0;
      const hasLogs = art.flight_logs && art.flight_logs.length > 0;
      const hasOps = art.operator_locations && art.operator_locations.length > 0;
      return hasPilot || hasHw || hasLogs || hasOps;
    }
    return true;
  });

  let html = '';

  // If wireless uploads exist, display the wireless ingestion highlight banner
  if (wirelessSessions.length > 0) {
    const totalFiles = wirelessSessions.reduce((acc, s) => acc + (s.files_acquired ? s.files_acquired.length : 1), 0);
    const recentFiles = wirelessSessions.flatMap(s => s.files_acquired || []).slice(0, 6);

    html += `
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div class="flex items-center space-x-3">
            <span class="text-2xl">📲</span>
            <div>
              <h4 class="text-sm font-bold text-white">Direct Mobile Wireless Evidence Ingestion</h4>
              <p class="text-[11px] text-slate-400">Received wirelessly from suspect mobile device over local Wi-Fi • Dual-hashed & Write-Blocked</p>
            </div>
          </div>
          <span class="px-2.5 py-1 rounded text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center space-x-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>${wirelessSessions.length} Transfer Session${wirelessSessions.length === 1 ? '' : 's'} Logged</span>
          </span>
        </div>
        <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
          <div class="flex flex-wrap items-center gap-1.5">
            <span class="text-slate-400">Wirelessly Received Files (<strong class="text-white">${totalFiles}</strong>):</span>
            ${recentFiles.map(f => `<span class="bg-slate-950 text-sky-300 font-mono text-[11px] px-2 py-0.5 rounded border border-slate-800">📄 ${escapeHtml(f)}</span>`).join('')}
          </div>
          <button onclick="switchTab('evidenceTab')" class="text-sky-400 hover:text-sky-300 font-semibold text-xs flex items-center space-x-1 transition">
            <span>Inspect In Evidence Vault</span> <span>→</span>
          </button>
        </div>
      </div>
    `;
  }

  // If recognized drone companion apps exist, render full forensic cards
  if (recognizedArtifacts.length > 0) {
    html += recognizedArtifacts.map(art => {
      const pilot = art.pilot_account || {};
      const hw = art.paired_hardware || {};
      const configs = art.config_dumps || {};
      const ops = art.operator_locations || [];

      return `
        <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-4">
          <div class="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div class="flex items-center space-x-3">
              <span class="text-2xl">📱</span>
              <div>
                <h4 class="text-base font-bold text-white">${escapeHtml(art.app_name)}</h4>
                <p class="text-xs font-mono text-sky-400">${escapeHtml(art.package_id || 'Mobile App')} — Target Platform: <strong class="text-slate-200">${escapeHtml(art.target_platform)}</strong></p>
              </div>
            </div>
            <span class="px-2.5 py-1 rounded text-xs font-semibold bg-indigo-950 text-indigo-300 border border-indigo-800">Artifact ID: ${escapeHtml(art.app_id)}</span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <!-- Column 1: Pilot Account -->
            <div class="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/80 space-y-1.5">
              <h5 class="text-slate-300 font-bold uppercase tracking-wider text-[10px] flex items-center space-x-1">
                <span>👤</span> <span>Pilot Account & Identity</span>
              </h5>
              <p class="text-slate-400"><strong>Pilot / Nick:</strong> <span class="text-white">${escapeHtml(pilot.pilot_name || pilot.callsign || '--')}</span></p>
              <p class="text-slate-400"><strong>Registered Email:</strong> <span class="text-sky-300 font-mono">${escapeHtml(pilot.email || '--')}</span></p>
              <p class="text-slate-400"><strong>User ID:</strong> <span class="text-slate-300 font-mono">${escapeHtml(pilot.user_id || '--')}</span></p>
              ${pilot.phone ? `<p class="text-slate-400"><strong>Phone:</strong> <span class="text-slate-300">${escapeHtml(pilot.phone)}</span></p>` : ''}
            </div>

            <!-- Column 2: Paired Hardware -->
            <div class="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/80 space-y-1.5">
              <h5 class="text-slate-300 font-bold uppercase tracking-wider text-[10px] flex items-center space-x-1">
                <span>🚁</span> <span>Hardware Binding & Serial #</span>
              </h5>
              <p class="text-slate-400"><strong>Aircraft Serial:</strong> <span class="text-emerald-400 font-mono font-semibold">${escapeHtml(hw.aircraft_sn || '--')}</span></p>
              <p class="text-slate-400"><strong>Remote Controller SN:</strong> <span class="text-slate-300 font-mono">${escapeHtml(hw.controller_sn || '--')}</span></p>
              <p class="text-slate-400"><strong>Camera / Gimbal SN:</strong> <span class="text-slate-300 font-mono">${escapeHtml(hw.camera_sn || '--')}</span></p>
            </div>

            <!-- Column 3: Operator Geolocation -->
            <div class="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/80 space-y-1.5">
              <h5 class="text-slate-300 font-bold uppercase tracking-wider text-[10px] flex items-center space-x-1">
                <span>📍</span> <span>Smartphone Operator GPS</span>
              </h5>
              ${ops.length ? `
                <p class="text-emerald-300 font-mono font-semibold">${ops[0].latitude.toFixed(6)}, ${ops[0].longitude.toFixed(6)}</p>
                <p class="text-[11px] text-slate-400">${escapeHtml(ops[0].source || 'Phone GPS')}</p>
                <button onclick="flyToOperatorLocation(${ops[0].latitude}, ${ops[0].longitude})" class="mt-1 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 text-[11px] font-semibold px-2 py-1 rounded transition">
                  Show on Flight Map 🗺️
                </button>
              ` : '<p class="text-slate-500">No smartphone GPS fix recorded in this log.</p>'}
            </div>
          </div>

          <!-- Discovered Files & Configs -->
          <div class="bg-slate-950/40 p-3 rounded-lg border border-slate-800/60 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div class="flex items-center space-x-4">
              <span class="text-slate-400">Flight Records: <strong class="text-white">${(art.flight_logs || []).length}</strong></span>
              <span class="text-slate-400">Waypoints / Missions: <strong class="text-white">${(art.mission_plans || []).length}</strong></span>
              <span class="text-slate-400">Cached Media: <strong class="text-white">${(art.cached_media || []).length}</strong></span>
            </div>
            ${Object.keys(configs).length ? `
              <span class="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono text-[11px]">
                Config Backup: ${escapeHtml(configs.callsign ? `Callsign: ${configs.callsign}` : Object.keys(configs)[0])}
              </span>
            ` : ''}
          </div>
        </div>
      `;
    }).join('');
  }

  // If nothing was rendered at all
  if (!html) {
    html = `
      <div class="text-center py-10 bg-slate-900 border border-slate-800 rounded-xl">
        <span class="text-3xl block mb-2">📱</span>
        <p class="text-sm font-semibold text-slate-300">No Mobile Companion Artifacts Detected</p>
        <p class="text-xs text-slate-500 mt-1">Ingest a smartphone backup (.zip, .tar), companion database, or upload files from suspect device via the Direct Mobile Ingestion Portal.</p>
      </div>
    `;
  }

  container.innerHTML = html;
}

function renderWirelessSessions(sessions) {
  const tbody = document.getElementById('wirelessSessionsTableBody');
  if (!tbody) return;

  if (!sessions || !sessions.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="px-4 py-6 text-center text-xs text-slate-500">No wireless transfer sessions logged for this case.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = sessions.map(s => {
    const fileBadges = (s.files_acquired && s.files_acquired.length)
      ? s.files_acquired.map(f => `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-800 text-sky-300 border border-slate-700 mr-1 mb-1">📄 ${escapeHtml(f)}</span>`).join('')
      : '<span class="text-slate-500 italic">No files recorded</span>';

    const bytesFormatted = s.bytes_transferred >= 1048576
      ? (s.bytes_transferred / (1024 * 1024)).toFixed(2) + ' MB'
      : s.bytes_transferred >= 1024
        ? (s.bytes_transferred / 1024).toFixed(1) + ' KB'
        : (s.bytes_transferred || 0) + ' B';

    const protoBadge = s.protocol === 'LOCAL_HTTP_PORTAL'
      ? '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">📲 Mobile Web Portal</span>'
      : `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-sky-950 text-sky-300 border border-sky-800">${escapeHtml(s.protocol)}</span>`;

    const statusBadge = s.status === 'COMPLETED'
      ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">✓ COMPLETED</span>'
      : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">${escapeHtml(s.status)}</span>`;

    return `
      <tr class="hover:bg-slate-900/60 transition border-b border-slate-800/60">
        <td class="px-4 py-3 font-mono text-sky-400 font-bold text-xs">${escapeHtml(s.session_id)}</td>
        <td class="px-4 py-3">${protoBadge}</td>
        <td class="px-4 py-3 font-mono text-slate-300 text-xs">${escapeHtml(s.source_ip)}</td>
        <td class="px-4 py-3 text-slate-300 text-xs">${escapeHtml(s.target_device)}</td>
        <td class="px-4 py-3">
          <div class="flex flex-wrap items-center">${fileBadges}</div>
          <div class="text-[10px] font-mono text-slate-400 mt-0.5">${bytesFormatted} total (${(s.files_acquired || []).length} file${(s.files_acquired || []).length === 1 ? '' : 's'})</div>
        </td>
        <td class="px-4 py-3">${statusBadge}</td>
      </tr>
    `;
  }).join('');
}

async function triggerWirelessAcquisition() {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }

  const mode = document.getElementById('wirelessModeSelect').value;
  const ip = document.getElementById('wirelessIpInput').value.trim();
  const port = parseInt(document.getElementById('wirelessPortInput').value) || 21;
  const platform = document.getElementById('wirelessPlatformSelect').value;
  const statusEl = document.getElementById('wirelessStatusIndicator');

  if (statusEl) {
    statusEl.innerHTML = '<span class="text-amber-400 font-semibold animate-pulse">⏳ Executing Wireless Acquisition...</span>';
  }

  try {
    const res = await fetch(`/api/cases/${activeCaseId}/wireless/acquire`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: mode,
        target_ip: ip,
        port: port,
        platform_hint: platform,
        duration_sec: 2.0,
        actor: 'Forensic Investigator'
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Wireless acquisition failed.');
    }

    const session = await res.json();
    if (statusEl) {
      statusEl.innerHTML = `<span class="text-emerald-400 font-semibold">✓ Acquired ${session.files_acquired.length} file(s) wirelessly (${session.session_id})</span>`;
    }

    await loadMobileData();
    if (typeof loadCaseStats === 'function') await loadCaseStats(activeCaseId);
  } catch (err) {
    if (statusEl) {
      statusEl.innerHTML = `<span class="text-rose-400 font-semibold">✗ Error: ${escapeHtml(err.message)}</span>`;
    }
  }
}

async function uploadMobileEvidenceFile(file) {
  if (!activeCaseId || !file) return;

  const formData = new FormData();
  formData.append('file', file);
  formData.append('actor', 'Wireless Mobile Browser');

  const statusEl = document.getElementById('wirelessStatusIndicator');
  if (statusEl) statusEl.innerHTML = '<span class="text-sky-400 animate-pulse">📤 Uploading file wirelessly...</span>';

  try {
    const res = await fetch(`/api/cases/${activeCaseId}/wireless/upload-mobile`, {
      method: 'POST',
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Upload failed');
    }

    const result = await res.json();
    if (statusEl) {
      statusEl.innerHTML = `<span class="text-emerald-400 font-semibold">✓ Received ${escapeHtml(result.file_name)} wirelessly. Dual hashed.</span>`;
    }

    await loadMobileData();
    if (typeof loadCaseStats === 'function') await loadCaseStats(activeCaseId);
  } catch (err) {
    if (statusEl) statusEl.innerHTML = `<span class="text-rose-400 font-semibold">✗ Upload failed: ${escapeHtml(err.message)}</span>`;
  }
}

function flyToOperatorLocation(lat, lon) {
  if (typeof switchTab === 'function') {
    switchTab('mapTab');
  }
  setTimeout(() => {
    if (typeof map !== 'undefined' && map) {
      map.flyTo([lat, lon], 17);
      L.popup()
        .setLatLng([lat, lon])
        .setContent(`<div class="text-xs"><strong>📱 Operator Phone GPS</strong><br/>Lat: ${lat.toFixed(6)}<br/>Lon: ${lon.toFixed(6)}</div>`)
        .openOn(map);
    }
  }, 300);
}
