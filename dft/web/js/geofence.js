/**
 * Drone Forensic Toolkit (DFT) — Geofence & Airspace Module
 * Handles restricted airspace catalogs, custom zone construction, circle/polygon preview maps,
 * active zone tables, and geofence breach evaluations.
 */

let geoPreviewMap = null;
let geoPreviewDronePath = null;
let geoPreviewShapeLayer = null;
let geoPreviewMarker = null;
let polygonPoints = [];

let cachedCatalog = [];
let currentCatalogCategory = 'ALL';
let currentCatalogRegion = 'ALL';
let catalogSearchTerm = '';

function initGeoPreviewMap() {
  if (!geoPreviewMap) {
    const el = document.getElementById('geoPreviewMap');
    if (!el) return;
    geoPreviewMap = L.map('geoPreviewMap').setView([19.1334, 72.9133], 14);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap contributors',
      maxZoom: 19
    }).addTo(geoPreviewMap);
    geoPreviewMap.on('click', onGeoPreviewMapClick);
  }
}

function syncDronePathToPreviewMap() {
  if (!geoPreviewMap) return;
  if (geoPreviewDronePath) {
    geoPreviewMap.removeLayer(geoPreviewDronePath);
    geoPreviewDronePath = null;
  }
  if (activeGeoJson && activeGeoJson.features && activeGeoJson.features.length > 0) {
    geoPreviewDronePath = L.geoJSON(activeGeoJson, {
      style: { color: '#0284c7', weight: 4, opacity: 0.85 },
      pointToLayer: function(feature, latlng) {
        return L.circleMarker(latlng, { radius: 5, fillColor: '#38bdf8', color: '#fff', weight: 1.5, fillOpacity: 0.9 });
      }
    }).addTo(geoPreviewMap);
    geoPreviewMap.fitBounds(geoPreviewDronePath.getBounds(), { padding: [30, 30] });
  }
}

function centerPreviewOnDrone() {
  if (geoPreviewDronePath && geoPreviewMap) {
    geoPreviewMap.fitBounds(geoPreviewDronePath.getBounds(), { padding: [30, 30] });
  } else if (geoPreviewShapeLayer && geoPreviewMap) {
    if (geoPreviewShapeLayer.getBounds) {
      geoPreviewMap.fitBounds(geoPreviewShapeLayer.getBounds(), { padding: [30, 30] });
    }
  }
}

function onGeoPreviewMapClick(e) {
  const lat = e.latlng.lat;
  const lng = e.latlng.lng;
  const type = document.getElementById('geoZoneType').value;

  if (type === 'circle') {
    document.getElementById('geoCenterLat').value = lat.toFixed(6);
    document.getElementById('geoCenterLon').value = lng.toFixed(6);
    const radInput = document.getElementById('geoRadius');
    const radius = parseFloat(radInput.value) || 250;
    if (!radInput.value) radInput.value = radius;
    renderCirclePreview(lat, lng, radius);
  } else {
    polygonPoints.push([parseFloat(lat.toFixed(6)), parseFloat(lng.toFixed(6))]);
    document.getElementById('geoCoords').value = JSON.stringify(polygonPoints);
    document.getElementById('geoPolygonCount').textContent = `${polygonPoints.length} vertices`;
    renderPolygonPreview(polygonPoints);
  }
}

function renderCirclePreview(lat, lng, radius) {
  initGeoPreviewMap();
  if (geoPreviewShapeLayer) {
    geoPreviewMap.removeLayer(geoPreviewShapeLayer);
    geoPreviewShapeLayer = null;
  }
  if (geoPreviewMarker) {
    geoPreviewMap.removeLayer(geoPreviewMarker);
    geoPreviewMarker = null;
  }

  geoPreviewMarker = L.marker([lat, lng], { draggable: true }).addTo(geoPreviewMap);
  geoPreviewMarker.on('drag', function(ev) {
    const pos = ev.target.getLatLng();
    document.getElementById('geoCenterLat').value = pos.lat.toFixed(6);
    document.getElementById('geoCenterLon').value = pos.lng.toFixed(6);
    if (geoPreviewShapeLayer) {
      geoPreviewShapeLayer.setLatLng(pos);
    }
    document.getElementById('geoInstructionHint').textContent = `Center: ${pos.lat.toFixed(4)}, ${pos.lng.toFixed(4)} (Radius ${radius}m)`;
  });

  geoPreviewShapeLayer = L.circle([lat, lng], {
    radius: radius || 250,
    color: '#ef4444',
    fillColor: '#ef4444',
    fillOpacity: 0.25,
    weight: 2
  }).addTo(geoPreviewMap);

  document.getElementById('geoInstructionHint').textContent = `Center: ${lat.toFixed(4)}, ${lng.toFixed(4)} (Radius ${radius || 250}m)`;
}

function renderPolygonPreview(coords) {
  initGeoPreviewMap();
  if (geoPreviewShapeLayer) {
    geoPreviewMap.removeLayer(geoPreviewShapeLayer);
    geoPreviewShapeLayer = null;
  }
  if (geoPreviewMarker) {
    geoPreviewMap.removeLayer(geoPreviewMarker);
    geoPreviewMarker = null;
  }

  if (!coords || coords.length === 0) return;

  if (coords.length === 1) {
    geoPreviewMarker = L.circleMarker(coords[0], { radius: 6, color: '#ef4444', fillColor: '#ef4444', fillOpacity: 0.8 }).addTo(geoPreviewMap);
    document.getElementById('geoInstructionHint').textContent = '1 vertex placed. Click more points to close perimeter.';
  } else {
    geoPreviewShapeLayer = L.polygon(coords, {
      color: '#ef4444',
      fillColor: '#ef4444',
      fillOpacity: 0.25,
      weight: 2
    }).addTo(geoPreviewMap);
    document.getElementById('geoInstructionHint').textContent = `${coords.length} vertices placed. Ready to save zone.`;
  }
}

function updateCirclePreviewFromInputs() {
  const lat = parseFloat(document.getElementById('geoCenterLat').value);
  const lon = parseFloat(document.getElementById('geoCenterLon').value);
  const rad = parseFloat(document.getElementById('geoRadius').value) || 250;
  if (!isNaN(lat) && !isNaN(lon)) {
    renderCirclePreview(lat, lon, rad);
  }
}

function updatePolygonPreviewFromTextarea() {
  try {
    const parsed = JSON.parse(document.getElementById('geoCoords').value);
    if (Array.isArray(parsed) && parsed.length > 0) {
      polygonPoints = parsed;
      document.getElementById('geoPolygonCount').textContent = `${polygonPoints.length} vertices`;
      renderPolygonPreview(polygonPoints);
    }
  } catch (e) {
    // Typing in progress
  }
}

function clearGeofencePreview() {
  polygonPoints = [];
  document.getElementById('geoCenterLat').value = '';
  document.getElementById('geoCenterLon').value = '';
  document.getElementById('geoCoords').value = '';
  document.getElementById('geoPolygonCount').textContent = '0 vertices';
  if (geoPreviewShapeLayer && geoPreviewMap) {
    geoPreviewMap.removeLayer(geoPreviewShapeLayer);
    geoPreviewShapeLayer = null;
  }
  if (geoPreviewMarker && geoPreviewMap) {
    geoPreviewMap.removeLayer(geoPreviewMarker);
    geoPreviewMarker = null;
  }
  const type = document.getElementById('geoZoneType').value;
  document.getElementById('geoInstructionHint').textContent = type === 'circle' ? 'Click map to place Center' : 'Click map to place boundary perimeter points';
}

function toggleZoneInputs() {
  const type = document.getElementById('geoZoneType').value;
  if (type === 'circle') {
    document.getElementById('circleInputs').classList.remove('hidden');
    document.getElementById('polygonInputs').classList.add('hidden');
    document.getElementById('geoModeBadge').textContent = 'CIRCLE MODE';
    document.getElementById('geoInstructionHint').textContent = 'Click map to place Center';
  } else {
    document.getElementById('circleInputs').classList.add('hidden');
    document.getElementById('polygonInputs').classList.remove('hidden');
    document.getElementById('geoModeBadge').textContent = 'POLYGON MODE';
    document.getElementById('geoInstructionHint').textContent = 'Click map to place boundary perimeter points';
  }
  clearGeofencePreview();
}

async function loadCatalog() {
  try {
    const res = await fetch('/api/geofence/catalog');
    cachedCatalog = await res.json();
    const badge = document.getElementById('catalogCountBadge');
    if (badge) badge.textContent = `${cachedCatalog.length} Real-World Airspaces`;
    renderCatalogTable();
  } catch (e) {
    console.error('Error loading catalog:', e);
  }
}

function filterCatalogCategory(cat, btn) {
  currentCatalogCategory = cat;
  document.querySelectorAll('.catalog-filter-btn').forEach(b => {
    b.classList.remove('bg-sky-600', 'text-white', 'font-semibold');
    b.classList.add('bg-slate-800', 'text-slate-300');
  });
  if (btn) {
    btn.classList.add('bg-sky-600', 'text-white', 'font-semibold');
    btn.classList.remove('bg-slate-800', 'text-slate-300');
  }
  renderCatalogTable();
}

function onCatalogRegionChange() {
  currentCatalogRegion = document.getElementById('catalogRegionSelect').value;
  renderCatalogTable();
}

function onCatalogSearchInput() {
  catalogSearchTerm = document.getElementById('catalogSearchInput').value.trim().toLowerCase();
  renderCatalogTable();
}

function renderCatalogTable() {
  const tbody = document.getElementById('catalogTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const filtered = cachedCatalog.filter(item => {
    if (currentCatalogCategory !== 'ALL' && item.category !== currentCatalogCategory) return false;
    if (currentCatalogRegion !== 'ALL' && item.city_region !== currentCatalogRegion) return false;
    if (catalogSearchTerm) {
      const str = `${item.zone_id} ${item.name} ${item.category} ${item.authority} ${item.city_region} ${item.description}`.toLowerCase();
      if (!str.includes(catalogSearchTerm)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-500">No restricted airspaces match the selected filter.</td></tr>';
    return;
  }

  const catIcons = {
    'AIRPORT': '✈️',
    'AIRDROME': '🚁',
    'MILITARY_AIRFORCE': '⚔️',
    'GOVERNMENT': '🏛️',
    'STRATEGIC_NUCLEAR': '⚛️',
    'PRISON': '🔒',
    'CONTROLLED_BUFFER': '🟡'
  };

  filtered.forEach(z => {
    const tr = document.createElement('tr');
    const isRed = z.zone_class === 'RED' || z.max_altitude_m === 0;
    const icon = catIcons[z.category] || '🛡️';

    tr.innerHTML = `
      <td class="p-2.5 font-mono text-sky-400 font-semibold text-[11px] whitespace-nowrap">${z.zone_id}</td>
      <td class="p-2.5">
        <div class="font-medium text-white">${z.name}</div>
        <div class="text-[10px] text-slate-400 truncate max-w-xs" title="${z.description || ''}">${z.description || ''}</div>
      </td>
      <td class="p-2.5 whitespace-nowrap">
        <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-sky-300 font-medium">${icon} ${z.category}</span>
        <div class="text-[10px] text-slate-400 mt-0.5">${z.authority || '--'}</div>
      </td>
      <td class="p-2.5 text-slate-300 whitespace-nowrap text-[11px]">${z.city_region || '--'}</td>
      <td class="p-2.5 whitespace-nowrap">
        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isRed ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}">
          ${isRed ? 'RED ZONE (0m)' : `YELLOW (${z.max_altitude_m}m)`}
        </span>
      </td>
      <td class="p-2.5 text-slate-400 whitespace-nowrap text-[11px]">
        ${z.zone_type === 'circle' ? `${(z.radius_meters/1000).toFixed(1)} km radius` : `${z.coordinates.length} pts polygon`}
      </td>
      <td class="p-2.5 text-right whitespace-nowrap">
        <button onclick="importPresetIntoCase('${z.zone_id}')" class="bg-sky-700 hover:bg-sky-600 text-white text-[11px] font-semibold px-2.5 py-1 rounded transition shadow">
          + Add to Case
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function importPresetIntoCase(presetId) {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  try {
    const res = await fetch(`/api/cases/${activeCaseId}/geofence/import-preset/${presetId}`, {
      method: 'POST'
    });
    if (res.ok) {
      const data = await res.json();
      alert(`Imported '${data.zone.name}' into Case ${activeCaseId}!\nBreaches detected: ${data.violations_detected}`);
      await refreshCaseData();
    } else {
      const err = await res.json();
      alert('Failed to import preset: ' + err.detail);
    }
  } catch (e) {
    alert('Error importing preset: ' + e);
  }
}

async function loadAllPresetsIntoCase() {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  if (!confirm(`Are you sure you want to load all 35+ real-world restricted airspaces into Case ${activeCaseId}?`)) {
    return;
  }
  try {
    const res = await fetch(`/api/cases/${activeCaseId}/geofence/load-all-presets`, {
      method: 'POST'
    });
    if (res.ok) {
      const data = await res.json();
      alert(`Successfully imported ${data.added_count} real-world restricted airspaces!\nTotal zones in case: ${data.total_zones}\nTotal breaches detected: ${data.violations_detected}`);
      await refreshCaseData();
    } else {
      const err = await res.json();
      alert('Failed to load presets: ' + err.detail);
    }
  } catch (e) {
    alert('Error loading presets: ' + e);
  }
}

async function loadGeofenceTable() {
  if (!activeCaseId) return;
  const res = await fetch(`/api/cases/${activeCaseId}/geofence/zones`);
  const zones = await res.json();
  const tbody = document.getElementById('zonesTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const countBadge = document.getElementById('activeZonesCountBadge');
  if (countBadge) countBadge.textContent = `${zones.length} zones configured`;

  if (zonesLayerGroup) zonesLayerGroup.clearLayers();

  const catIcons = {
    'AIRPORT': '✈️',
    'AIRDROME': '🚁',
    'MILITARY_AIRFORCE': '⚔️',
    'GOVERNMENT': '🏛️',
    'STRATEGIC_NUCLEAR': '⚛️',
    'PRISON': '🔒',
    'CONTROLLED_BUFFER': '🟡'
  };

  zones.forEach(z => {
    const tr = document.createElement('tr');
    const isRed = z.zone_class === 'RED' || z.is_preconfigured_nofly || z.max_altitude_m === 0;
    const icon = catIcons[z.category] || '🛡️';

    tr.innerHTML = `
      <td class="p-2.5 font-mono text-sky-400 font-bold">${z.zone_id}</td>
      <td class="p-2.5">
        <div class="font-medium text-white">${z.name}</div>
        <div class="text-[10px] text-slate-400">${z.description || ''}</div>
      </td>
      <td class="p-2.5">
        <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-sky-300 font-medium">${icon} ${z.category || 'CUSTOM'}</span>
        <div class="text-[10px] text-slate-400 mt-0.5">${z.authority || (z.city_region || '--')}</div>
      </td>
      <td class="p-2.5 text-slate-300">${z.zone_type === 'circle' ? `${(z.radius_meters/1000).toFixed(1)} km radius` : `${z.coordinates.length} vertices polygon`}</td>
      <td class="p-2.5 text-slate-300 font-mono">${z.max_altitude_m !== null ? z.max_altitude_m + 'm' : 'Unlimited'}</td>
      <td class="p-2.5">
        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isRed ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}">
          ${isRed ? 'RED ZONE (0m)' : `YELLOW (${z.max_altitude_m}m)`}
        </span>
      </td>
    `;
    tbody.appendChild(tr);

    // Render zone on Leaflet map with rich popups
    if (zonesLayerGroup) {
      const color = isRed ? '#ef4444' : '#f59e0b';
      const popupHtml = `
        <div style="font-family: sans-serif; font-size: 11px; min-width: 180px; color: #0f172a;">
          <div style="font-weight: bold; font-size: 12px; margin-bottom: 2px;">${z.name}</div>
          <div style="margin-bottom: 4px;">
            <span style="background: ${isRed ? '#fee2e2' : '#fef3c7'}; color: ${isRed ? '#b91c1c' : '#b45309'}; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 10px;">
              ${isRed ? 'RED ZONE (0m NO-FLY)' : `YELLOW ZONE (${z.max_altitude_m}m)`}
            </span>
            <span style="color: #475569; font-weight: 600; margin-left: 4px;">${z.category || 'RESTRICTED'}</span>
          </div>
          ${z.authority ? `<div style="color: #475569; margin-bottom: 2px;">Authority: <strong>${z.authority}</strong></div>` : ''}
          <div style="color: #64748b;">Max Ceiling: <strong>${z.max_altitude_m !== null ? z.max_altitude_m + 'm AGL' : 'Unlimited'}</strong></div>
          <div style="color: #64748b; font-size: 10px; margin-top: 3px;">${z.description || ''}</div>
        </div>
      `;

      if (z.zone_type === 'circle' && z.center_lat && z.center_lon) {
        L.circle([z.center_lat, z.center_lon], { radius: z.radius_meters, color: color, fillColor: color, fillOpacity: 0.18, weight: 2 }).bindPopup(popupHtml).addTo(zonesLayerGroup);
      } else if (z.zone_type === 'polygon' && z.coordinates && z.coordinates.length > 0) {
        L.polygon(z.coordinates, { color: color, fillColor: color, fillOpacity: 0.18, weight: 2 }).bindPopup(popupHtml).addTo(zonesLayerGroup);
      }
    }
  });
}

async function loadViolationsTable() {
  if (!activeCaseId) return;
  const res = await fetch(`/api/cases/${activeCaseId}/geofence/violations`);
  const vios = await res.json();
  const tbody = document.getElementById('violationsTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const badge = document.getElementById('violationsCountBadge');
  if (badge) badge.textContent = `${vios.length} breaches`;

  if (vios.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-500">No airspace or geofence infringements detected.</td></tr>';
    return;
  }
  vios.forEach(v => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="p-2.5 font-mono text-red-400 font-bold">${v.violation_id}</td>
      <td class="p-2.5 font-medium text-white">${v.zone_name}</td>
      <td class="p-2.5 whitespace-nowrap">
        <span class="px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 font-semibold uppercase">${v.category || 'RESTRICTED'}</span>
        <div class="text-[10px] text-slate-400 mt-0.5">${v.authority || '--'}</div>
      </td>
      <td class="p-2.5 text-slate-400 font-mono whitespace-nowrap">${v.timestamp_utc}</td>
      <td class="p-2.5 text-slate-300 font-mono whitespace-nowrap">${v.latitude.toFixed(5)}, ${v.longitude.toFixed(5)}</td>
      <td class="p-2.5 text-amber-300 font-semibold font-mono whitespace-nowrap">${v.altitude_m.toFixed(1)} m</td>
      <td class="p-2.5 text-red-300 font-medium">
        <span class="px-1.5 py-0.5 rounded text-[10px] bg-red-900/60 text-red-200 font-bold mr-1">${v.violation_type}</span>
        ${v.details}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function submitNewGeofence() {
  if (!activeCaseId) { alert('Select an active case first.'); return; }
  const name = document.getElementById('geoName').value.trim();
  const type = document.getElementById('geoZoneType').value;
  const maxAlt = document.getElementById('geoMaxAlt').value ? parseFloat(document.getElementById('geoMaxAlt').value) : null;

  if (!name) { alert('Enter zone name'); return; }

  let payload = { name: name, zone_type: type, max_altitude_m: maxAlt };

  if (type === 'circle') {
    payload.center_lat = parseFloat(document.getElementById('geoCenterLat').value);
    payload.center_lon = parseFloat(document.getElementById('geoCenterLon').value);
    payload.radius_meters = parseFloat(document.getElementById('geoRadius').value);
  } else {
    try {
      payload.coordinates = JSON.parse(document.getElementById('geoCoords').value);
    } catch (e) {
      alert('Invalid coordinates JSON'); return;
    }
  }

  const res = await fetch(`/api/cases/${activeCaseId}/geofence/zones`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (res.ok) {
    alert('Geofence zone added and evaluated!');
    clearGeofencePreview();
    document.getElementById('geoName').value = '';
    refreshCaseData();
  }
}
