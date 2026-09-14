/**
 * Drone Forensic Toolkit (DFT) — Media & Visual Evidence Module
 * Handles payload video and imagery uploads (.mp4, .mov, .jpg), EXIF extraction,
 * temporal synchronization with flight telemetry, synchronized media tables, and lightbox inspection.
 */

async function uploadMediaFiles() {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  const input = document.getElementById('mediaFilesInput');
  if (!input.files || input.files.length === 0) {
    alert('Please select one or more media files (.mp4, .mov, .jpg, etc.) to ingest.');
    return;
  }

  const files = Array.from(input.files);
  const btn = document.getElementById('uploadMediaBtn');
  const spinner = document.getElementById('uploadMediaBtnSpinner');
  const alertBox = document.getElementById('mediaUploadAlert');

  btn.disabled = true;
  if (spinner) spinner.classList.remove('hidden');
  alertBox.className = 'p-3 rounded-lg text-xs bg-sky-950/80 border border-sky-800 text-sky-200 block';
  alertBox.textContent = `Ingesting, write-blocking and synchronizing ${files.length} media file(s)...`;

  let syncedCount = 0;
  let failedCount = 0;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const formData = new FormData();
    formData.append('file', file);
    if (file.lastModified) {
      formData.append('capture_timestamp', new Date(file.lastModified).toISOString());
    }
    formData.append('actor', 'Forensic Investigator');

    try {
      const res = await fetch(`/api/cases/${activeCaseId}/ingest-media`, {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        if (data.has_overlap) syncedCount++;
      } else {
        failedCount++;
      }
    } catch (e) {
      failedCount++;
    }
  }

  btn.disabled = false;
  if (spinner) spinner.classList.add('hidden');
  input.value = '';

  alertBox.className = 'p-3 rounded-lg text-xs bg-emerald-950/80 border border-emerald-800 text-emerald-200 block';
  alertBox.innerHTML = `✓ <strong>Media Processing Complete!</strong> Ingested <strong>${files.length - failedCount}</strong> file(s). <strong>${syncedCount}</strong> synchronized with flight telemetry and injected into the master timeline.`;

  await refreshCaseData();

  // Hook into Guided Ingestion Workflow if active
  if (typeof onMediaIngested === 'function') {
    onMediaIngested();
  }
}

async function loadMediaTable() {
  if (!activeCaseId) return;
  try {
    const res = await fetch(`/api/cases/${activeCaseId}/media`);
    if (!res.ok) return;
    const mediaList = await res.json();
    const tbody = document.getElementById('mediaTableBody');
    const badge = document.getElementById('mediaCountBadge');
    if (badge) badge.textContent = `${mediaList.length} Media Item${mediaList.length === 1 ? '' : 's'}`;
    if (!tbody) return;

    tbody.innerHTML = '';
    if (mediaList.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-500">No media assets ingested yet.</td></tr>';
      return;
    }

    mediaList.forEach(m => {
      const tr = document.createElement('tr');
      const isSynced = m.has_telemetry_overlap;
      const durText = m.duration_sec ? ` (${m.duration_sec}s)` : '';
      const thumbSrc = m.thumbnail_base64
        ? `data:image/jpeg;base64,${m.thumbnail_base64}`
        : `/api/cases/${activeCaseId}/media/${m.item_id}/thumbnail`;

      const typeBadgeClass = m.media_type === 'VIDEO'
        ? 'bg-purple-50 text-purple-800 border-purple-200'
        : 'bg-sky-50 text-sky-800 border-sky-200';

      const syncBadge = isSynced
        ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-300 font-bold">✓ SYNCHRONIZED</span>`
        : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-slate-100 text-slate-500 border border-slate-200">NO OVERLAP</span>`;

      const coordsText = (m.latitude !== null && m.latitude !== undefined && m.longitude !== null && m.longitude !== undefined)
        ? `<div class="font-mono text-[11px] text-sky-700 font-semibold">${m.latitude.toFixed(5)}, ${m.longitude.toFixed(5)}</div>
           <div class="text-[10px] text-slate-500">Alt: ${m.altitude_m !== null && m.altitude_m !== undefined ? m.altitude_m.toFixed(1) : 0}m AGL</div>`
        : `<span class="text-slate-400 text-xs">Outside telemetry</span>`;

      const deltaText = (m.sync_delta_seconds !== null && m.sync_delta_seconds !== undefined)
        ? `<span class="text-emerald-700 font-mono text-[11px] font-semibold">Δ ${Math.abs(m.sync_delta_seconds).toFixed(1)}s</span>`
        : `<span class="text-slate-400">--</span>`;

      tr.className = 'hover:bg-sky-50/50 transition border-b border-slate-100';
      tr.innerHTML = `
        <td class="p-2.5">
          <div class="w-14 h-10 bg-slate-100 rounded overflow-hidden border border-slate-200 flex items-center justify-center cursor-pointer hover:opacity-80 transition shadow-sm" onclick="openMediaLightbox('${m.item_id}')">
            ${m.thumbnail_base64 || m.media_type === 'IMAGE' || m.media_type === 'VIDEO' ? `<img src="${thumbSrc}" alt="Thumbnail" class="w-full h-full object-cover" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';" /><span class="hidden text-xs">${m.media_type === 'VIDEO' ? '🎥' : '📷'}</span>` : `<span class="text-xs">${m.media_type === 'VIDEO' ? '🎥' : '📷'}</span>`}
          </div>
        </td>
        <td class="p-2.5">
          <div class="font-bold text-slate-900 text-xs">${m.filename}</div>
          <div class="text-[10px] text-slate-500 font-mono">${(m.file_size_bytes / (1024 * 1024)).toFixed(2)} MB${durText}</div>
        </td>
        <td class="p-2.5 whitespace-nowrap">
          <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] border font-bold ${typeBadgeClass}">
            ${m.media_type === 'VIDEO' ? '🎥 VIDEO' : '📷 PHOTO'}
          </span>
        </td>
        <td class="p-2.5 whitespace-nowrap font-mono text-slate-600 text-xs">
          ${m.capture_timestamp_utc ? m.capture_timestamp_utc.replace('T', ' ').substring(0, 19) + ' UTC' : '<span class="text-slate-400">No EXIF time</span>'}
        </td>
        <td class="p-2.5 whitespace-nowrap">
          ${coordsText}
        </td>
        <td class="p-2.5 whitespace-nowrap">
          ${syncBadge}
          <div class="text-[10px] mt-0.5">${deltaText}</div>
        </td>
        <td class="p-2.5 text-right whitespace-nowrap">
          <button onclick="openMediaLightbox('${m.item_id}')" class="bg-white hover:bg-slate-100 text-sky-700 border border-slate-200 text-[11px] font-semibold px-2.5 py-1 rounded-lg transition shadow-sm">
            Inspect Frame
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Error loading media table:', e);
  }
}

async function openMediaLightbox(itemId) {
  if (!activeCaseId) return;
  try {
    const res = await fetch(`/api/cases/${activeCaseId}/media`);
    if (!res.ok) return;
    const mediaList = await res.json();
    const item = mediaList.find(m => m.item_id === itemId);
    if (!item) return;

    document.getElementById('modalMediaTitle').innerHTML = `<span>📷 ${item.filename}</span> <span class="text-slate-400 font-normal">(${item.media_type})</span>`;
    const imgEl = document.getElementById('modalMediaImg');
    imgEl.src = item.thumbnail_base64
      ? `data:image/jpeg;base64,${item.thumbnail_base64}`
      : `/api/cases/${activeCaseId}/media/${item.item_id}/thumbnail`;

    document.getElementById('modalMediaTimestamp').textContent = item.capture_timestamp_utc
      ? item.capture_timestamp_utc.replace('T', ' ').substring(0, 19) + ' UTC'
      : 'No timestamp';

    document.getElementById('modalMediaCoords').textContent = (item.latitude !== null && item.latitude !== undefined && item.longitude !== null && item.longitude !== undefined)
      ? `${item.latitude.toFixed(6)}, ${item.longitude.toFixed(6)} (Alt: ${item.altitude_m !== null && item.altitude_m !== undefined ? item.altitude_m.toFixed(1) : 0}m AGL)`
      : 'Outside flight telemetry window';

    document.getElementById('modalMediaDelta').textContent = (item.sync_delta_seconds !== null && item.sync_delta_seconds !== undefined)
      ? `Δ ${Math.abs(item.sync_delta_seconds).toFixed(2)} seconds from flight telemetry`
      : 'Not synchronized';

    document.getElementById('modalMediaHash').textContent = item.sha256 ? item.sha256 : '--';
    document.getElementById('modalMediaE01').textContent = item.e01_container_file ? item.e01_container_file : 'Pending packaging';

    document.getElementById('mediaLightboxModal').classList.remove('hidden');
  } catch (e) {
    console.error('Error opening lightbox:', e);
  }
}

function closeMediaLightbox() {
  document.getElementById('mediaLightboxModal').classList.add('hidden');
}

async function loadSampleMedia(mediaKey) {
  if (!activeCaseId) {
    alert('Please select or create an active case first. (Tip: You can load the DJI Mavic 3 sample flight log in the section above first!)');
    return;
  }
  let sampleFile = '';
  if (mediaKey === 'video') {
    sampleFile = 'sample_recon_video.mp4';
  } else if (mediaKey === 'photo') {
    sampleFile = 'sample_aerial_photo.jpg';
  } else if (mediaKey === 'unrelated') {
    sampleFile = 'sample_unrelated_photo.jpg';
  }

  const alertBox = document.getElementById('mediaUploadAlert');
  alertBox.className = 'p-3 rounded-lg text-xs bg-sky-950/80 border border-sky-800 text-sky-200 block';
  alertBox.textContent = `Fetching sample '${sampleFile}' and analyzing telemetry synchronization...`;

  try {
    const blobRes = await fetch(`/samples/${sampleFile}`);
    if (!blobRes.ok) {
      alert('Could not locate sample file: ' + sampleFile);
      return;
    }
    const blob = await blobRes.blob();
    const formData = new FormData();
    formData.append('file', blob, sampleFile);
    formData.append('actor', 'Forensic Examiner (Sample Benchmark)');

    const res = await fetch(`/api/cases/${activeCaseId}/ingest-media`, {
      method: 'POST',
      body: formData
    });

    if (res.ok) {
      const data = await res.json();
      alertBox.className = 'p-3 rounded-lg text-xs bg-emerald-950/80 border border-emerald-800 text-emerald-200 block';
      if (data.has_overlap) {
        alertBox.innerHTML = `✓ <strong>Sample Ingested & Synchronized!</strong> File <code>${sampleFile}</code> overlaps the telemetry window. Representative frame was extracted and a <strong>MEDIA_CAPTURE</strong> event was injected into the master timeline!`;
      } else {
        alertBox.innerHTML = `ℹ️ <strong>Sample Ingested (No Overlap)</strong> File <code>${sampleFile}</code> was write-blocked and hashed, but its timestamp falls outside the active flight window.`;
      }
      await refreshCaseData();

      // Hook into Guided Ingestion Workflow if active
      if (typeof onMediaIngested === 'function') {
        onMediaIngested();
      }
    } else {
      const err = await res.json();
      alert('Error ingesting sample media: ' + err.detail);
    }
  } catch (e) {
    alert('Error loading sample media: ' + e);
  }
}
