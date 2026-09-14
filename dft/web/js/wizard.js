/**
 * Drone Forensic Toolkit (DFT) — Guided Evidence Ingestion Workflow Module
 * Orchestrates the 3-step evidence ingestion flow when a case is created:
 *   Step 1: Ground Control Station (GCS) — Skippable
 *   Step 2: Drone Flight Logs — Mandatory (Skip Not Allowed)
 *   Step 3: Visual Evidence / Payload Media — Skippable
 */

const wizardState = {
  active: false,
  step: 0,
  caseId: null,
  gcsIngested: false,
  droneIngested: false,
  mediaIngested: false
};

function startIngestionWorkflow(caseId) {
  wizardState.active = true;
  wizardState.step = 1;
  wizardState.caseId = caseId || activeCaseId;
  wizardState.gcsIngested = false;
  wizardState.droneIngested = false;
  wizardState.mediaIngested = false;

  const banner = document.getElementById('ingestionWizardBanner');
  if (banner) {
    banner.classList.remove('hidden');
  }

  setWizardStep(1);
}

function setWizardStep(step) {
  wizardState.step = step;
  const banner = document.getElementById('ingestionWizardBanner');
  if (!banner) return;
  banner.classList.remove('hidden');

  if (step === 1) {
    // 1. Take user to GCS tab
    if (typeof switchTab === 'function') {
      switchTab('gcsTab');
    }
    renderStep1Banner();
  } else if (step === 2) {
    // 2. Take user to Drone Logs (Evidence tab)
    if (typeof switchTab === 'function') {
      switchTab('evidenceTab');
    }
    const droneSection = document.getElementById('droneLogsSection');
    if (droneSection) {
      droneSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    renderStep2Banner();
  } else if (step === 3) {
    // 3. Take user to Media Ingestion (Evidence tab)
    if (typeof switchTab === 'function') {
      switchTab('evidenceTab');
    }
    const mediaSection = document.getElementById('mediaSection');
    if (mediaSection) {
      mediaSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    renderStep3Banner();
  }
}

function renderStep1Banner() {
  const banner = document.getElementById('ingestionWizardBanner');
  if (!banner) return;

  const gcsDone = wizardState.gcsIngested;

  banner.innerHTML = `
    <div class="bg-gradient-to-r from-white/95 via-sky-50/90 to-white/95 border-2 border-sky-400 rounded-xl p-3.5 sm:p-4 shadow-lg space-y-3 wizard-active-panel text-slate-800">
      <!-- Progress Bar & Stepper -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-200 gap-2">
        <div class="flex items-center space-x-2">
          <span class="text-[10px] sm:text-xs font-black tracking-wider uppercase text-sky-800 bg-sky-100 border border-sky-300 px-2 py-0.5 rounded">Guided Ingestion Flow</span>
          <span class="text-xs text-slate-600 font-medium truncate max-w-[200px]">Active Case: <strong class="text-slate-900 font-mono">${escapeHtml(wizardState.caseId)}</strong></span>
        </div>
        <div class="flex flex-wrap items-center gap-1 text-[11px] sm:text-xs">
          <span class="px-2 py-0.5 rounded-full font-bold bg-sky-600 text-white shadow-sm">1. GCS</span>
          <span class="text-slate-400 font-bold">──</span>
          <span class="px-2 py-0.5 rounded-full font-medium bg-slate-100 text-slate-600 border border-slate-200">2. Drone Logs</span>
          <span class="text-slate-400 font-bold">──</span>
          <span class="px-2 py-0.5 rounded-full font-medium bg-slate-100 text-slate-600 border border-slate-200">3. Media</span>
          <button onclick="dismissWizardBanner()" title="Exit Guided Flow" class="ml-2 text-slate-400 hover:text-slate-700 text-sm font-bold px-1.5 py-0.5 rounded hover:bg-slate-200">✕</button>
        </div>
      </div>

      <!-- Step Content -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
              <span>🎮 Step 1 of 3: Ground Control Station (GCS) Ingestion</span>
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-50 text-sky-700 border border-sky-200 uppercase">Optional — Skippable</span>
          </div>
          <p class="text-xs text-slate-600 leading-relaxed">
            Upload Ground Control Station mission plans (<code class="text-sky-700 font-semibold">.plan</code>, <code class="text-sky-700 font-semibold">.waypoints</code>, <code class="text-sky-700 font-semibold">.kml</code>) or telemetry (<code class="text-sky-700 font-semibold">.tlog</code>) to identify operator launch location and pre-planned paths. If no GCS device was recovered, you may skip this step.
          </p>
        </div>

        <!-- Action Controls -->
        <div class="flex flex-wrap items-center gap-2 shrink-0 pt-2 md:pt-0">
          ${gcsDone ? `
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-xs font-bold text-emerald-700 flex items-center space-x-1 bg-emerald-50 border border-emerald-200 px-2.5 py-1.5 rounded-lg">
                <span>✓</span> <span>GCS Ingested</span>
              </span>
              <button onclick="setWizardStep(2)" class="bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold px-3.5 py-2 rounded-lg transition shadow-md flex items-center space-x-1">
                <span>Proceed to Drone Logs</span> <span>→</span>
              </button>
            </div>
          ` : `
            <button onclick="skipGcsStep()" class="bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs font-semibold px-3.5 py-2 rounded-lg transition shadow-sm flex items-center space-x-1">
              <span>Skip GCS Evidence</span> <span>→</span>
            </button>
          `}
        </div>
      </div>
    </div>
  `;
}

function renderStep2Banner() {
  const banner = document.getElementById('ingestionWizardBanner');
  if (!banner) return;

  const droneDone = wizardState.droneIngested;

  banner.innerHTML = `
    <div class="bg-gradient-to-r from-white/95 via-amber-50/90 to-white/95 border-2 border-amber-400 rounded-xl p-3.5 sm:p-4 shadow-lg space-y-3 wizard-active-panel text-slate-800">
      <!-- Progress Bar & Stepper -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-200 gap-2">
        <div class="flex items-center space-x-2">
          <span class="text-[10px] sm:text-xs font-black tracking-wider uppercase text-amber-800 bg-amber-100 border border-amber-300 px-2 py-0.5 rounded">Guided Ingestion Flow</span>
          <span class="text-xs text-slate-600 font-medium truncate max-w-[200px]">Active Case: <strong class="text-slate-900 font-mono">${escapeHtml(wizardState.caseId)}</strong></span>
        </div>
        <div class="flex flex-wrap items-center gap-1 text-[11px] sm:text-xs">
          <span class="px-2 py-0.5 rounded-full font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">✓ 1. GCS</span>
          <span class="text-slate-400 font-bold">──</span>
          <span class="px-2 py-0.5 rounded-full font-bold bg-amber-500 text-white shadow-sm animate-pulse">2. Drone Logs (Mandatory)</span>
          <span class="text-slate-400 font-bold">──</span>
          <span class="px-2 py-0.5 rounded-full font-medium bg-slate-100 text-slate-600 border border-slate-200">3. Media</span>
          <button onclick="dismissWizardBanner()" title="Exit Guided Flow" class="ml-2 text-slate-400 hover:text-slate-700 text-sm font-bold px-1.5 py-0.5 rounded hover:bg-slate-200">✕</button>
        </div>
      </div>

      <!-- Step Content -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
              <span>🛰️ Step 2 of 3: Primary Drone Flight Logs Ingestion</span>
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300 uppercase animate-pulse">⚠️ Mandatory — Cannot Skip</span>
          </div>
          <p class="text-xs text-slate-600 leading-relaxed">
            Primary UAV blackbox logs (<code class="text-amber-700 font-semibold">.BIN</code>, <code class="text-amber-700 font-semibold">.ulg</code>, <code class="text-amber-700 font-semibold">.txt</code>, <code class="text-amber-700 font-semibold">.csv</code>) <strong>must be ingested</strong> to extract flight telemetry, arming lifecycle, and GPS coordinates. Use the file upload form below or choose a sample flight log.
          </p>
        </div>

        <!-- Action Controls -->
        <div class="flex flex-wrap items-center gap-2 shrink-0 pt-2 md:pt-0">
          ${droneDone ? `
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-xs font-bold text-emerald-700 flex items-center space-x-1 bg-emerald-50 border border-emerald-200 px-2.5 py-1.5 rounded-lg">
                <span>✓</span> <span>Telemetry Ingested</span>
              </span>
              <button onclick="setWizardStep(3)" class="bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold px-3.5 py-2 rounded-lg transition shadow-md flex items-center space-x-1">
                <span>Proceed to Payload Media</span> <span>→</span>
              </button>
            </div>
          ` : `
            <div class="flex items-center space-x-2 bg-rose-50 border border-rose-200 px-3 py-1.5 rounded-lg text-xs text-rose-700">
              <span class="font-bold">⛔ Skip Disabled</span>
              <span class="text-[11px] text-slate-500">(Flight logs required)</span>
            </div>
          `}
        </div>
      </div>
    </div>
  `;
}

function renderStep3Banner() {
  const banner = document.getElementById('ingestionWizardBanner');
  if (!banner) return;

  const mediaDone = wizardState.mediaIngested;

  banner.innerHTML = `
    <div class="bg-gradient-to-r from-white/95 via-purple-50/90 to-white/95 border-2 border-purple-400 rounded-xl p-3.5 sm:p-4 shadow-lg space-y-3 wizard-active-panel text-slate-800">
      <!-- Progress Bar & Stepper -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-200 gap-2">
        <div class="flex items-center space-x-2">
          <span class="text-[10px] sm:text-xs font-black tracking-wider uppercase text-purple-800 bg-purple-100 border border-purple-300 px-2 py-0.5 rounded">Guided Ingestion Flow</span>
          <span class="text-xs text-slate-600 font-medium truncate max-w-[200px]">Active Case: <strong class="text-slate-900 font-mono">${escapeHtml(wizardState.caseId)}</strong></span>
        </div>
        <div class="flex flex-wrap items-center gap-1 text-[11px] sm:text-xs">
          <span class="px-2 py-0.5 rounded-full font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">✓ 1. GCS</span>
          <span class="text-slate-400 font-bold">──</span>
          <span class="px-2 py-0.5 rounded-full font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">✓ 2. Drone Logs</span>
          <span class="text-slate-400 font-bold">──</span>
          <span class="px-2 py-0.5 rounded-full font-bold bg-purple-600 text-white shadow-sm">3. Media</span>
          <button onclick="dismissWizardBanner()" title="Exit Guided Flow" class="ml-2 text-slate-400 hover:text-slate-700 text-sm font-bold px-1.5 py-0.5 rounded hover:bg-slate-200">✕</button>
        </div>
      </div>

      <!-- Step Content -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
              <span>📷 Step 3 of 3: Visual Evidence & Payload Media</span>
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200 uppercase">Optional — Skippable</span>
          </div>
          <p class="text-xs text-slate-600 leading-relaxed">
            Ingest drone payload videos (<code class="text-purple-700 font-semibold">.mp4</code>, <code class="text-purple-700 font-semibold">.mov</code>) or aerial photos (<code class="text-purple-700 font-semibold">.jpg</code>). The system automatically extracts timestamps and synchronizes each capture with the reconstructed flight telemetry.
          </p>
        </div>

        <!-- Action Controls -->
        <div class="flex flex-wrap items-center gap-2 shrink-0 pt-2 md:pt-0">
          ${mediaDone ? `
            <button onclick="finishIngestionWorkflow()" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold px-4 py-2 rounded-lg transition shadow-md flex items-center space-x-1.5">
              <span>✓ Complete & View Trajectory</span>
            </button>
          ` : `
            <button onclick="skipMediaStep()" class="bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs font-semibold px-3.5 py-2 rounded-lg transition shadow-sm flex items-center space-x-1">
              <span>Skip Media & Finish</span> <span>→</span>
            </button>
          `}
        </div>
      </div>
    </div>
  `;
}

function skipGcsStep() {
  wizardState.gcsIngested = false;
  setWizardStep(2);
}

function onGcsIngested() {
  if (wizardState.active && wizardState.step === 1) {
    wizardState.gcsIngested = true;
    renderStep1Banner();
  }
}

function onDroneLogIngested() {
  if (wizardState.active && wizardState.step === 2) {
    wizardState.droneIngested = true;
    renderStep2Banner();
  }
}

function skipMediaStep() {
  wizardState.mediaIngested = false;
  finishIngestionWorkflow();
}

function onMediaIngested() {
  if (wizardState.active && wizardState.step === 3) {
    wizardState.mediaIngested = true;
    renderStep3Banner();
  }
}

async function finishIngestionWorkflow() {
  wizardState.active = false;
  const banner = document.getElementById('ingestionWizardBanner');

  if (banner) {
    banner.innerHTML = `
      <div class="bg-gradient-to-r from-emerald-50 via-white to-emerald-50 border-2 border-emerald-400 rounded-xl p-4 shadow-lg flex items-center justify-between text-slate-800">
        <div class="flex items-center space-x-3">
          <span class="text-2xl">🎉</span>
          <div>
            <h4 class="text-sm font-bold text-slate-900">Investigation Ingestion Workflow Completed!</h4>
            <p class="text-xs text-emerald-700">All evidence items hashed, write-blocked, and processed into case <strong class="font-mono text-slate-900">${wizardState.caseId}</strong>. Flight telemetry is ready for analysis.</p>
          </div>
        </div>
        <button onclick="dismissWizardBanner()" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold px-3.5 py-1.5 rounded-lg transition shadow-sm">
          Dismiss
        </button>
      </div>
    `;

    setTimeout(() => {
      dismissWizardBanner();
    }, 4500);
  }

  // Switch to Flight Trajectory map & refresh all data
  if (typeof switchTab === 'function') {
    switchTab('mapTab');
  }
  if (typeof refreshCaseData === 'function') {
    await refreshCaseData();
  }
}

function dismissWizardBanner() {
  const banner = document.getElementById('ingestionWizardBanner');
  if (banner) {
    banner.classList.add('hidden');
    banner.innerHTML = '';
  }
}

function isWizardActive() {
  return wizardState.active;
}
