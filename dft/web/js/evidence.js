/**
 * Drone Forensic Toolkit (DFT) — Physical & Logical Evidence Module
 * Handles evidence ingestion, multi-category sorting (Logs, Video/Images, GCS),
 * category filtering, one-click sample loading, and the cryptographic evidence ledger table.
 */

let currentEvidenceCategory = 'all';

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

function setEvidenceCategoryFilter(category) {
  currentEvidenceCategory = category;

  // Update button active styling
  const buttons = {
    all: document.getElementById('evFilterBtnAll'),
    logs: document.getElementById('evFilterBtnLogs'),
    video_images: document.getElementById('evFilterBtnMedia'),
    gcs: document.getElementById('evFilterBtnGcs')
  };

  Object.entries(buttons).forEach(([key, btn]) => {
    if (!btn) return;
    if (key === category) {
      btn.className = 'px-3 py-1 rounded font-bold transition bg-sky-600 text-white shadow-sm flex items-center space-x-1';
    } else {
      btn.className = 'px-3 py-1 rounded font-medium text-slate-400 hover:text-white transition flex items-center space-x-1';
    }
  });

  loadEvidenceTable();
}

async function loadEvidenceTable() {
  if (!activeCaseId) return;
  const tbody = document.getElementById('evidenceTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  try {
    const res = await fetch(`/api/cases/${activeCaseId}/evidence?category=${currentEvidenceCategory}`);
    if (!res.ok) return;
    const data = await res.json();

    // Update count badges
    if (data.counts) {
      const setEl = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      };
      setEl('evFilterCountAll', data.counts.total);
      setEl('evFilterCountLogs', data.counts.logs);
      setEl('evFilterCountMedia', data.counts.video_images);
      setEl('evFilterCountGcs', data.counts.gcs);
    }

    const items = data.items || [];
    if (items.length === 0) {
      const catLabel = currentEvidenceCategory === 'all' ? 'evidence items' : `${currentEvidenceCategory} evidence`;
      tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-slate-500">No ${catLabel} ingested for this case yet.</td></tr>`;
      return;
    }

    items.forEach(ev => {
      const tr = document.createElement('tr');
      const cat = ev.evidence_category || 'LOGS';

      let catBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">📋 Logs</span>';
      if (cat === 'VIDEO_IMAGES') {
        catBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">🎥 Video/Images</span>';
      } else if (cat === 'GCS') {
        catBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-950 text-sky-300 border border-sky-800">🎮 GCS</span>';
      }

      tr.innerHTML = `
        <td class="p-2.5 font-mono text-sky-400 font-bold">${ev.item_id}</td>
        <td class="p-2.5">${catBadge}</td>
        <td class="p-2.5 font-medium text-white">${escapeHtml(ev.file_name)}</td>
        <td class="p-2.5 text-slate-400">${(ev.file_size_bytes/1024).toFixed(1)} KB</td>
        <td class="p-2.5"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-bold uppercase">${ev.drone_platform || 'UNKNOWN'}</span></td>
        <td class="p-2.5 font-mono text-[11px] text-slate-300">
          <div><span class="text-slate-500">SHA256:</span> ${ev.hashes && ev.hashes.sha256 ? ev.hashes.sha256.substring(0,20) : '--'}...</div>
          <div><span class="text-slate-500">SHA3:</span> ${ev.hashes && ev.hashes.sha3_256 ? ev.hashes.sha3_256.substring(0,20) : '--'}...</div>
        </td>
        <td class="p-2.5 text-emerald-400 font-medium">✓ Verified</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Error loading evidence table:', e);
  }
}

async function uploadEvidence() {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  const fileInput = document.getElementById('evidenceFileInput');
  if (!fileInput.files || fileInput.files.length === 0) {
    alert('Please select an evidence file to ingest.');
    return;
  }
  const mode = document.getElementById('acqMode').value;
  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append('file', file);
  formData.append('acquisition_type', mode);
  formData.append('actor', 'Forensic Investigator');

  const res = await fetch(`/api/cases/${activeCaseId}/ingest`, {
    method: 'POST',
    body: formData
  });

  if (res.ok) {
    const data = await res.json();
    const catName = data.evidence_category === 'VIDEO_IMAGES' ? 'Video/Images' : (data.evidence_category === 'GCS' ? 'GCS' : 'Logs');
    alert(`Evidence successfully ingested, write-blocked, and sorted as [${catName}] into ${data.category_folder}/!`);
    fileInput.value = '';
    await refreshCaseData();

    // Hook into Guided Ingestion Workflow if active
    if (typeof onDroneLogIngested === 'function') {
      onDroneLogIngested();
    }
  } else {
    const err = await res.json();
    alert('Error ingesting evidence: ' + (err.detail || 'Upload failed'));
  }
}

async function loadSample(platform) {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  let sampleFile = '';
  if (platform === 'dji') sampleFile = 'dji_mavic3_telemetry.srt';
  else if (platform === 'ardupilot') sampleFile = 'ardupilot_flight.log';
  else if (platform === 'px4') sampleFile = 'px4_mission.csv';
  else if (platform === 'parrot') sampleFile = 'parrot_anafi_flight.json';
  else if (platform === 'betaflight') sampleFile = 'betaflight_blackbox.txt';

  const blobRes = await fetch(`/samples/${sampleFile}`);
  if (!blobRes.ok) {
    alert('Could not locate sample file: ' + sampleFile);
    return;
  }
  const blob = await blobRes.blob();
  const formData = new FormData();
  formData.append('file', blob, sampleFile);
  formData.append('acquisition_type', 'LOGICAL_EXTRACT');
  formData.append('actor', 'Automated Ingestion Worker');

  const res = await fetch(`/api/cases/${activeCaseId}/ingest`, {
    method: 'POST',
    body: formData
  });

  if (res.ok) {
    const data = await res.json();
    alert(`Sample evidence for ${platform.toUpperCase()} ingested and sorted as [${data.evidence_category}]!`);
    await refreshCaseData();

    // Hook into Guided Ingestion Workflow if active
    if (typeof onDroneLogIngested === 'function') {
      onDroneLogIngested();
    }
  } else {
    const err = await res.json();
    alert('Error loading sample: ' + (err.detail || 'Sample load failed'));
  }
}
