/**
 * Drone Forensic Toolkit (DFT) — Forensic Reporting Module
 * Handles ISO/IEC 27042 compliant court-admissible forensic reporting export (HTML, JSON, KML, DFXML, PDF, CSV).
 */

function downloadReport(format) {
  if (!activeCaseId) {
    alert('Please select or create an active case first.');
    return;
  }
  if (format === 'html') {
    window.open(`/api/cases/${activeCaseId}/report/html`, '_blank');
  } else if (format === 'json') {
    window.open(`/api/cases/${activeCaseId}/report/json`, '_blank');
  } else if (format === 'kml') {
    window.open(`/api/cases/${activeCaseId}/kml`, '_blank');
  } else if (format === 'dfxml') {
    window.open(`/api/cases/${activeCaseId}/report/dfxml`, '_blank');
  } else if (format === 'pdf') {
    window.open(`/api/cases/${activeCaseId}/report/pdf`, '_blank');
  } else if (format === 'csv') {
    window.open(`/api/cases/${activeCaseId}/telemetry/csv`, '_blank');
  }
}
