/**
 * Drone Forensic Toolkit (DFT) — Main Application Controller
 * Manages active case state, global navigation tabs, case lifecycle modals,
 * and coordinates data refreshes across all forensic modules.
 */

let activeCaseId = null;

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

function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
  const target = document.getElementById(tabId);
  if (target) target.classList.remove('hidden');

  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.remove('bg-slate-800', 'text-sky-400', 'border-sky-500/30', 'bg-sky-500/10');
    btn.classList.add('text-slate-300');
  });

  const activeBtns = document.querySelectorAll(`.nav-btn[onclick*="${tabId}"]`);
  activeBtns.forEach(activeBtn => {
    activeBtn.classList.remove('text-slate-300');
    activeBtn.classList.add('bg-slate-800', 'text-sky-400', 'border-sky-500/30', 'bg-sky-500/10');
  });

  // Update mobile bottom navigation bar active state
  document.querySelectorAll('.mobile-bottom-btn').forEach(btn => {
    btn.classList.remove('text-sky-400', 'font-bold');
    btn.classList.add('text-slate-400');
  });
  const activeBottomBtns = document.querySelectorAll(`.mobile-bottom-btn[onclick*="${tabId}"]`);
  activeBottomBtns.forEach(btn => {
    btn.classList.remove('text-slate-400');
    btn.classList.add('text-sky-400', 'font-bold');
  });

  // Auto-close mobile drawer on navigation
  closeMobileDrawer();

  // Invalidate Leaflet maps when becoming visible to avoid blank tiles
  if (tabId === 'mapTab' && leafletMap) {
    setTimeout(() => leafletMap.invalidateSize(), 150);
  } else if (tabId === 'geofenceTab') {
    if (typeof initGeoPreviewMap === 'function') initGeoPreviewMap();
    if (geoPreviewMap) setTimeout(() => geoPreviewMap.invalidateSize(), 150);
  } else if (tabId === 'gcsTab') {
    if (typeof initGcsMap === 'function') initGcsMap();
    if (gcsMap) setTimeout(() => gcsMap.invalidateSize(), 150);
  } else if (tabId === 'mobileTab') {
    if (typeof initMobileTab === 'function') initMobileTab();
  }
}

function openMobileDrawer() {
  const drawer = document.getElementById('mobileDrawer');
  const backdrop = document.getElementById('mobileDrawerBackdrop');
  if (drawer) {
    drawer.classList.remove('-translate-x-full');
    drawer.classList.add('translate-x-0');
  }
  if (backdrop) {
    backdrop.classList.remove('hidden', 'opacity-0', 'pointer-events-none');
    backdrop.classList.add('opacity-100');
  }
  document.body.classList.add('overflow-hidden');
}

function closeMobileDrawer() {
  const drawer = document.getElementById('mobileDrawer');
  const backdrop = document.getElementById('mobileDrawerBackdrop');
  if (drawer) {
    drawer.classList.remove('translate-x-0');
    drawer.classList.add('-translate-x-full');
  }
  if (backdrop) {
    backdrop.classList.remove('opacity-100');
    backdrop.classList.add('opacity-0', 'pointer-events-none');
    setTimeout(() => {
      if (backdrop && backdrop.classList.contains('opacity-0')) {
        backdrop.classList.add('hidden');
      }
    }, 300);
  }
  document.body.classList.remove('overflow-hidden');
}

function toggleMobileDrawer() {
  const drawer = document.getElementById('mobileDrawer');
  if (drawer && drawer.classList.contains('translate-x-0')) {
    closeMobileDrawer();
  } else {
    openMobileDrawer();
  }
}

function openNewCaseModal() {
  document.getElementById('newCaseModal').classList.remove('hidden');
}

function closeNewCaseModal() {
  document.getElementById('newCaseModal').classList.add('hidden');
}

function clearDashboardView() {
  const setElText = (id, txt) => {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
  };

  setElText('statPlatform', '--');
  setElText('statDistance', '0 m');
  setElText('statAltitude', '0 m');
  setElText('statViolations', '0');
  setElText('statArmed', '--');
  setElText('statDisarmed', '--');
  setElText('statDuration', '0 s');
  setElText('statTelemetry', '0');

  const cocBadge = document.getElementById('cocBadge');
  if (cocBadge) cocBadge.classList.add('hidden');

  if (flightPathLayer && leafletMap) {
    leafletMap.removeLayer(flightPathLayer);
    flightPathLayer = null;
  }
  if (zonesLayerGroup) zonesLayerGroup.clearLayers();
  if (geoPreviewDronePath && geoPreviewMap) {
    geoPreviewMap.removeLayer(geoPreviewDronePath);
    geoPreviewDronePath = null;
  }
  activeGeoJson = null;
  if (typeof clearGeofencePreview === 'function') clearGeofencePreview();

  const setHtml = (id, html) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  };

  setHtml('evidenceTableBody', '<tr><td colspan="6" class="p-4 text-center text-slate-500">No evidence ingested yet.</td></tr>');
  setHtml('mediaTableBody', '<tr><td colspan="7" class="p-4 text-center text-slate-500">No media assets ingested yet.</td></tr>');
  setElText('mediaCountBadge', '0 Media Items');
  setHtml('violationsTableBody', '<tr><td colspan="6" class="p-4 text-center text-slate-500">No geofence infringements detected.</td></tr>');
  setHtml('timelineTableBody', '<tr><td colspan="5" class="p-4 text-center text-slate-500">No timeline events recorded.</td></tr>');
  setHtml('anomaliesTableBody', '<tr><td colspan="5" class="p-4 text-center text-slate-500">No anomalies detected.</td></tr>');
  setHtml('auditTableBody', '<tr><td colspan="6" class="p-4 text-center text-slate-500">No audit records found.</td></tr>');
  setHtml('zonesTableBody', '<tr><td colspan="5" class="p-4 text-center text-slate-500">No geofence perimeters configured.</td></tr>');

  // GCS reset
  setElText('gcsStatPlatform', 'None');
  setElText('gcsStatFC', 'FC: --');
  setElText('gcsStatOperator', 'Not Identified');
  setElText('gcsStatOpSource', 'Source: --');
  setElText('gcsStatWaypoints', '0');
  setElText('gcsStatPlanDist', 'Planned Dist: 0 m');
  setElText('gcsStatAdherence', '-- %');
  setElText('gcsStatReached', '0 / 0 reached');
  setElText('gcsWaypointCountBadge', '0 waypoints');
  setHtml('gcsWaypointsTableBody', '<tr><td colspan="7" class="p-4 text-center text-slate-500">No GCS mission plan loaded for this case.</td></tr>');

  if (gcsMapLayers) gcsMapLayers.clearLayers();
  cachedGcsData = null;
}

async function loadCases() {
  try {
    const res = await fetch('/api/cases');
    const cases = await res.json();
    const selectors = [document.getElementById('caseSelector'), document.getElementById('mobileCaseSelector')].filter(Boolean);
    if (selectors.length === 0) return;
    
    selectors.forEach(sel => sel.innerHTML = '');
    if (cases.length === 0) {
      selectors.forEach(sel => sel.innerHTML = '<option value="">-- No Cases Found --</option>');
      activeCaseId = null;
      clearDashboardView();
      return;
    }
    cases.forEach(c => {
      selectors.forEach(sel => {
        const opt = document.createElement('option');
        opt.value = c.case_id;
        opt.textContent = `${c.case_id} — ${c.case_name}`;
        sel.appendChild(opt);
      });
    });
    if (!activeCaseId && cases.length > 0) {
      activeCaseId = cases[0].case_id;
    }
    selectors.forEach(sel => sel.value = activeCaseId);
    await refreshCaseData();
  } catch (e) {
    console.error('Error loading cases:', e);
  }
}

function onCaseChange(sourceEl) {
  const sel = (sourceEl && sourceEl.value !== undefined) ? sourceEl : (document.getElementById('caseSelector') || document.getElementById('mobileCaseSelector'));
  if (sel) {
    activeCaseId = sel.value;
    const s1 = document.getElementById('caseSelector');
    const s2 = document.getElementById('mobileCaseSelector');
    if (s1) s1.value = activeCaseId;
    if (s2) s2.value = activeCaseId;
    refreshCaseData();
  }
}

async function submitNewCase() {
  const cid = document.getElementById('modalCaseId').value.trim();
  const name = document.getElementById('modalCaseName').value.trim();
  const inv = document.getElementById('modalInvestigator').value.trim();
  const agency = document.getElementById('modalAgency').value.trim();
  const desc = document.getElementById('modalDesc').value.trim();

  if (!cid || !name) {
    alert('Please enter Case ID and Title');
    return;
  }

  try {
    const res = await fetch('/api/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        case_id: cid,
        case_name: name,
        investigator_name: inv || 'Examiner',
        agency_name: agency || 'Forensic Lab',
        description: desc
      })
    });

    if (res.ok) {
      closeNewCaseModal();
      activeCaseId = cid;
      await loadCases();

      // Clear form inputs
      document.getElementById('modalCaseId').value = '';
      document.getElementById('modalCaseName').value = '';
      document.getElementById('modalInvestigator').value = '';
      document.getElementById('modalAgency').value = '';
      document.getElementById('modalDesc').value = '';

      // Trigger the 3-Step Guided Ingestion Workflow!
      if (typeof startIngestionWorkflow === 'function') {
        startIngestionWorkflow(cid);
      }
    } else {
      const err = await res.json();
      alert('Error creating case: ' + err.detail);
    }
  } catch (e) {
    alert('Network error creating case: ' + e);
  }
}

async function refreshCaseData() {
  if (!activeCaseId) return;

  try {
    // 1. Fetch Case Overview
    const caseRes = await fetch(`/api/cases/${activeCaseId}`);
    if (caseRes.ok) {
      const caseInfo = await caseRes.json();
      const cocBadge = document.getElementById('cocBadge');
      if (cocBadge) {
        cocBadge.classList.toggle('hidden', !caseInfo.chain_of_custody_verified);
      }
    }

    // 2. Fetch Summary & Stats
    const sumRes = await fetch(`/api/cases/${activeCaseId}/summary`);
    if (sumRes.ok) {
      const summary = await sumRes.json();
      const setEl = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      };
      setEl('statPlatform', (summary.platform_detected || 'UNKNOWN').toUpperCase());
      setEl('statDistance', `${summary.total_distance_meters} m`);
      setEl('statAltitude', `${summary.max_altitude_m} m`);
      setEl('statViolations', summary.violations_count);
      setEl('statArmed', summary.arm_time_utc ? summary.arm_time_utc.replace('T', ' ').substring(0, 19) + ' UTC' : '--');
      setEl('statDisarmed', summary.disarm_time_utc ? summary.disarm_time_utc.replace('T', ' ').substring(0, 19) + ' UTC' : '--');
      setEl('statDuration', `${summary.total_duration_sec} s`);
      setEl('statTelemetry', summary.telemetry_count);
    }

    // 3. Render Flight Path on Map
    const geoRes = await fetch(`/api/cases/${activeCaseId}/geojson`);
    if (geoRes.ok) {
      const geoData = await geoRes.json();
      if (typeof renderMapData === 'function') {
        renderMapData(geoData);
      }
    }

    // 4. Populate Tables across modules
    if (typeof loadEvidenceTable === 'function') loadEvidenceTable();
    if (typeof loadMediaTable === 'function') loadMediaTable();
    if (typeof loadGeofenceTable === 'function') loadGeofenceTable();
    if (typeof loadViolationsTable === 'function') loadViolationsTable();
    if (typeof loadTimelineTable === 'function') loadTimelineTable();
    if (typeof loadAnomaliesTable === 'function') loadAnomaliesTable();
    if (typeof loadAuditTable === 'function') loadAuditTable();
    if (typeof loadGcsData === 'function') loadGcsData();
    if (typeof loadMobileData === 'function') loadMobileData();
  } catch (e) {
    console.error('Error refreshing case data:', e);
  }
}

// --- LIVE REAL-TIME DASHBOARD SYNCHRONIZATION ---
let liveSyncInterval = null;
let lastSyncState = {
  caseId: null,
  syncVersion: 0,
  evidenceCount: 0,
  telemetryCount: 0,
  mediaCount: 0,
  wirelessCount: 0
};

function showLiveSyncToast(msg) {
  let toast = document.getElementById('liveSyncToast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'liveSyncToast';
    toast.className = 'fixed bottom-5 right-5 z-50 bg-slate-900/95 border border-sky-500 text-sky-200 text-xs px-4 py-3 rounded-xl shadow-2xl flex items-center space-x-2.5 transition-all duration-300 transform translate-y-10 opacity-0 pointer-events-none';
    document.body.appendChild(toast);
  }
  toast.innerHTML = `<span class="text-base">📲</span> <span>${msg}</span>`;
  toast.classList.remove('translate-y-10', 'opacity-0', 'pointer-events-none');
  setTimeout(() => {
    toast.classList.add('translate-y-10', 'opacity-0', 'pointer-events-none');
  }, 4500);
}

async function checkSyncStatus() {
  if (!activeCaseId) return;

  try {
    const res = await fetch(`/api/cases/${activeCaseId}/sync-status`);
    if (!res.ok) return;
    const data = await res.json();

    const indicator = document.getElementById('syncIndicator');
    if (indicator) {
      indicator.innerHTML = `<span class="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse mr-1"></span> Live Sync Active`;
    }

    const stateChanged = (
      lastSyncState.caseId !== activeCaseId ||
      data.sync_version > lastSyncState.syncVersion ||
      data.evidence_count !== lastSyncState.evidenceCount ||
      data.telemetry_count !== lastSyncState.telemetryCount ||
      data.media_count !== lastSyncState.mediaCount ||
      data.wireless_count !== lastSyncState.wirelessCount
    );

    if (stateChanged) {
      const isInitial = (lastSyncState.caseId !== activeCaseId);
      const wasUpload = (!isInitial && (data.evidence_count > lastSyncState.evidenceCount || data.wireless_count > lastSyncState.wirelessCount));

      lastSyncState = {
        caseId: activeCaseId,
        syncVersion: data.sync_version,
        evidenceCount: data.evidence_count,
        telemetryCount: data.telemetry_count,
        mediaCount: data.media_count,
        wirelessCount: data.wireless_count
      };

      await refreshCaseData();

      if (wasUpload) {
        showLiveSyncToast(`Wireless evidence received & synchronized to laptop! (Total: ${data.evidence_count} items)`);
      }
    }
  } catch (err) {
    // Silent fail on background poll
  }
}

function startLiveSync() {
  if (liveSyncInterval) clearInterval(liveSyncInterval);
  checkSyncStatus();
  liveSyncInterval = setInterval(checkSyncStatus, 2500);
}

// Global Startup
window.onload = async () => {
  if (typeof initMap === 'function') initMap();
  await loadCases();
  if (typeof loadCatalog === 'function') await loadCatalog();
  startLiveSync();
};

// Auto-adjust Leaflet maps on window resize or mobile orientation change
window.addEventListener('resize', () => {
  if (typeof leafletMap !== 'undefined' && leafletMap) leafletMap.invalidateSize();
  if (typeof geoPreviewMap !== 'undefined' && geoPreviewMap) geoPreviewMap.invalidateSize();
  if (typeof gcsMap !== 'undefined' && gcsMap) gcsMap.invalidateSize();
});
window.addEventListener('orientationchange', () => {
  setTimeout(() => {
    if (typeof leafletMap !== 'undefined' && leafletMap) leafletMap.invalidateSize();
    if (typeof geoPreviewMap !== 'undefined' && geoPreviewMap) geoPreviewMap.invalidateSize();
    if (typeof gcsMap !== 'undefined' && gcsMap) gcsMap.invalidateSize();
  }, 250);
});

