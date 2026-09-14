/**
 * Drone Forensic Toolkit (DFT) — Timeline, Anomalies & Audit Ledger Module
 * Handles unified event timeline reconstruction, telemetry anomaly detection,
 * ISO/IEC 27037 chain-of-custody audit logs, and cryptographic hash verification.
 */

async function loadTimelineTable() {
  if (!activeCaseId) return;
  const tbody = document.getElementById('timelineTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  try {
    const res = await fetch(`/api/cases/${activeCaseId}/timeline`);
    if (!res.ok) return;
    const items = await res.json();

    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-500">No timeline events recorded.</td></tr>';
      return;
    }
    items.forEach(it => {
      const tr = document.createElement('tr');
      const evType = (it.event_type || '').toUpperCase();
      let typeBadge = '';
      let rowClass = '';

      if (evType === 'MEDIA_CAPTURE') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold uppercase">📷 MEDIA CAPTURE</span>`;
        rowClass = 'bg-cyan-950/20';
      } else if (evType === 'ARM' || evType === 'ARMED') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold uppercase">ARMED</span>`;
        rowClass = 'bg-emerald-950/20';
      } else if (evType === 'DISARM' || evType === 'DISARMED') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-700 font-bold uppercase">DISARMED</span>`;
        rowClass = 'bg-amber-950/20';
      } else if (evType === 'TAKEOFF') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-sky-950 text-sky-300 border border-sky-800 font-bold uppercase">TAKEOFF</span>`;
      } else if (evType === 'LANDING' || evType === 'LAND') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 font-bold uppercase">LANDING</span>`;
      } else if (it.category === 'GEOFENCE_BREACH') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800 font-bold uppercase">BREACH</span>`;
      } else if (it.category === 'ANOMALY') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-purple-950 text-purple-300 border border-purple-800 font-bold uppercase">ANOMALY</span>`;
      } else {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-sky-300 uppercase">${it.category || 'EVENT'}</span>`;
      }

      if (rowClass) tr.className = rowClass;

      tr.innerHTML = `
        <td class="p-2.5 font-mono text-slate-300">${it.timestamp_utc}</td>
        <td class="p-2.5">${typeBadge}</td>
        <td class="p-2.5"><span class="px-2 py-0.5 rounded text-[10px] ${it.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800 font-bold' : (it.severity === 'WARNING' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-slate-800 text-slate-400')}">${it.severity}</span></td>
        <td class="p-2.5 text-white font-medium">${it.description}</td>
        <td class="p-2.5 text-slate-400 font-mono">${it.latitude !== null && it.latitude !== undefined ? `${it.latitude.toFixed(5)}, ${it.longitude.toFixed(5)} (${it.altitude_m !== null && it.altitude_m !== undefined ? it.altitude_m.toFixed(1) : 0}m)` : 'System / Telemetry'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Error loading timeline table:', e);
  }
}

async function loadAnomaliesTable() {
  if (!activeCaseId) return;
  const tbody = document.getElementById('anomaliesTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  try {
    const res = await fetch(`/api/cases/${activeCaseId}/anomalies`);
    if (!res.ok) return;
    const anoms = await res.json();

    if (anoms.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-500">No anomalies detected. Integrity intact.</td></tr>';
      return;
    }
    anoms.forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="p-2.5 font-mono text-amber-400 font-bold">${a.anomaly_id}</td>
        <td class="p-2.5 text-white font-medium">${a.anomaly_type}</td>
        <td class="p-2.5"><span class="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 uppercase font-bold">${a.severity}</span></td>
        <td class="p-2.5 font-mono text-slate-400">${a.timestamp_utc || 'N/A'}</td>
        <td class="p-2.5 text-slate-300">${a.description}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Error loading anomalies table:', e);
  }
}

async function loadAuditTable() {
  if (!activeCaseId) return;
  const tbody = document.getElementById('auditTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  try {
    const res = await fetch(`/api/cases/${activeCaseId}/audit-trail`);
    if (!res.ok) return;
    const logs = await res.json();

    logs.forEach(l => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="p-2.5 font-mono text-slate-500">#${l.entry_id}</td>
        <td class="p-2.5 font-mono text-slate-400">${l.timestamp_utc}</td>
        <td class="p-2.5 font-medium text-white">${l.actor}</td>
        <td class="p-2.5 text-sky-400 font-semibold">${l.action}</td>
        <td class="p-2.5 text-slate-300">${l.details}</td>
        <td class="p-2.5 font-mono text-[10px] text-emerald-400">${l.signature ? l.signature.substring(0,16) : '--'}...</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Error loading audit table:', e);
  }
}

async function verifyChainOfCustody() {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  try {
    const res = await fetch(`/api/cases/${activeCaseId}`);
    const data = await res.json();
    if (data.chain_of_custody_verified) {
      alert('Chain-of-Custody Cryptographic Integrity: 100% UNCOMPROMISED.\nAll HMAC signatures and cryptographic pointers are valid.');
    } else {
      alert('Chain-of-Custody Compromised! ' + (data.chain_error || 'Hash mismatch detected.'));
    }
  } catch (e) {
    alert('Error verifying chain of custody: ' + e);
  }
}
