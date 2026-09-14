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
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-cyan-50 text-cyan-800 border border-cyan-200 font-bold uppercase">📷 MEDIA CAPTURE</span>`;
        rowClass = 'bg-cyan-50/40';
      } else if (evType === 'ARM' || evType === 'ARMED') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-800 border border-emerald-200 font-bold uppercase">ARMED</span>`;
        rowClass = 'bg-emerald-50/40';
      } else if (evType === 'DISARM' || evType === 'DISARMED') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-amber-50 text-amber-800 border border-amber-200 font-bold uppercase">DISARMED</span>`;
        rowClass = 'bg-amber-50/40';
      } else if (evType === 'TAKEOFF') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-sky-50 text-sky-800 border border-sky-200 font-bold uppercase">TAKEOFF</span>`;
      } else if (evType === 'LANDING' || evType === 'LAND') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-indigo-50 text-indigo-800 border border-indigo-200 font-bold uppercase">LANDING</span>`;
      } else if (it.category === 'GEOFENCE_BREACH') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-rose-50 text-rose-800 border border-rose-200 font-bold uppercase">BREACH</span>`;
        rowClass = 'bg-rose-50/30';
      } else if (it.category === 'ANOMALY') {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-purple-50 text-purple-800 border border-purple-200 font-bold uppercase">ANOMALY</span>`;
        rowClass = 'bg-purple-50/30';
      } else {
        typeBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-100 text-sky-800 uppercase font-semibold">${it.category || 'EVENT'}</span>`;
      }

      tr.className = `${rowClass || 'hover:bg-sky-50/50'} transition border-b border-slate-100`;

      tr.innerHTML = `
        <td class="p-2.5 font-mono text-slate-700">${it.timestamp_utc}</td>
        <td class="p-2.5">${typeBadge}</td>
        <td class="p-2.5"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${it.severity === 'CRITICAL' ? 'bg-rose-50 text-rose-700 border border-rose-200' : (it.severity === 'WARNING' ? 'bg-amber-50 text-amber-800 border border-amber-200' : 'bg-slate-100 text-slate-700 border border-slate-200')}">${it.severity}</span></td>
        <td class="p-2.5 text-slate-900 font-medium">${it.description}</td>
        <td class="p-2.5 text-slate-600 font-mono text-xs">${it.latitude !== null && it.latitude !== undefined ? `${it.latitude.toFixed(5)}, ${it.longitude.toFixed(5)} (${it.altitude_m !== null && it.altitude_m !== undefined ? it.altitude_m.toFixed(1) : 0}m)` : 'System / Telemetry'}</td>
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
      tr.className = 'hover:bg-amber-50/40 transition border-b border-amber-100/60 bg-amber-50/10';
      tr.innerHTML = `
        <td class="p-2.5 font-mono text-amber-800 font-bold">${a.anomaly_id}</td>
        <td class="p-2.5 text-slate-900 font-semibold">${a.anomaly_type}</td>
        <td class="p-2.5"><span class="px-2 py-0.5 rounded text-[10px] bg-amber-100 text-amber-800 border border-amber-300 uppercase font-bold">${a.severity}</span></td>
        <td class="p-2.5 font-mono text-slate-600 text-xs">${a.timestamp_utc || 'N/A'}</td>
        <td class="p-2.5 text-slate-700">${a.description}</td>
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
      tr.className = 'hover:bg-sky-50/50 transition border-b border-slate-100';
      tr.innerHTML = `
        <td class="p-2.5 font-mono text-slate-500 font-semibold">#${l.entry_id}</td>
        <td class="p-2.5 font-mono text-slate-600 text-xs">${l.timestamp_utc}</td>
        <td class="p-2.5 font-bold text-slate-900">${l.actor}</td>
        <td class="p-2.5 text-sky-700 font-bold">${l.action}</td>
        <td class="p-2.5 text-slate-700">${l.details}</td>
        <td class="p-2.5 font-mono text-[10px] text-emerald-700 font-semibold">${l.signature ? l.signature.substring(0,16) : '--'}...</td>
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
