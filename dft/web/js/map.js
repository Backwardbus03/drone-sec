/**
 * Drone Forensic Toolkit (DFT) — Map & Flight Trajectory Module
 * Manages the primary Leaflet map, flight path rendering, and trajectory markers.
 */

let leafletMap = null;
let flightPathLayer = null;
let zonesLayerGroup = null;
let activeGeoJson = null;

function initMap() {
  if (!leafletMap) {
    leafletMap = L.map('map').setView([19.1334, 72.9133], 14);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap contributors',
      maxZoom: 19
    }).addTo(leafletMap);
    zonesLayerGroup = L.layerGroup().addTo(leafletMap);
  }
}

function renderMapData(geojson) {
  activeGeoJson = geojson;
  initMap();
  if (flightPathLayer) {
    leafletMap.removeLayer(flightPathLayer);
  }

  if (geojson.features && geojson.features.length > 0) {
    flightPathLayer = L.geoJSON(geojson, {
      style: { color: '#38bdf8', weight: 4, opacity: 0.9 },
      pointToLayer: function(feature, latlng) {
        return L.circleMarker(latlng, { radius: 6, fillColor: '#f59e0b', color: '#fff', weight: 2, fillOpacity: 1.0 });
      }
    }).addTo(leafletMap);

    leafletMap.fitBounds(flightPathLayer.getBounds(), { padding: [50, 50] });
  }

  // Synchronize path to geofence preview map if present
  if (typeof syncDronePathToPreviewMap === 'function') {
    syncDronePathToPreviewMap();
  }
}
