/**
 * Drone Forensic Toolkit (DFT) — AI Forensic Analyst (RAG) Controller
 * Interacts with /api/cases/{case_id}/ask and /api/cases/{case_id}/rag/ingest
 * Provides a responsive chat UI with evidence citations and model provider badges.
 */

let ragCurrentCaseId = null;
let ragIsQuerying = false;
let ragMsgCounter = 0;

function ragOnCaseChanged(caseId) {
  ragCurrentCaseId = caseId;
  ragCheckStatus();
  const chatWin = document.getElementById('ragChatWindow');
  if (chatWin && (!chatWin.children.length || chatWin.dataset.caseId !== caseId)) {
    chatWin.dataset.caseId = caseId;
    chatWin.innerHTML = `
      <div class="p-4 rounded-xl bg-sky-50/70 border border-sky-100 text-xs text-sky-800 space-y-1">
        <div class="font-bold flex items-center space-x-1.5 text-sm text-sky-900">
          <span>🤖</span> <span>AI Forensic Assistant Ready</span>
        </div>
        <p>Analyzing active case: <strong class="font-mono text-sky-950">${escapeHtml(caseId)}</strong></p>
        <p class="text-[11px] text-sky-700">Ask questions about flight telemetry, geofence breaches, sensor anomalies, chain-of-custody, or DGCA/FAA regulation compliance.</p>
      </div>
    `;
  }
}

function ragCheckStatus() {
  const caseId = activeCaseId || ragCurrentCaseId;
  const statusEl = document.getElementById('ragStatusBar');
  const badgeEl = document.getElementById('ragIndexBadge');
  if (!caseId) {
    if (statusEl) statusEl.textContent = "Select an active case to begin analysis.";
    if (badgeEl) badgeEl.classList.add('hidden');
    return;
  }

  fetch(`/api/cases/${encodeURIComponent(caseId)}/rag/status`)
    .then(r => r.json())
    .then(data => {
      if (statusEl) {
        if (data.ready) {
          statusEl.innerHTML = `<span class="text-emerald-600 font-semibold">● Indexed</span> &mdash; ${data.indexed_chunks} evidence chunks vectorized in case collection.`;
        } else {
          statusEl.innerHTML = `<span class="text-amber-600 font-semibold">○ Not Indexed</span> &mdash; Click "⚡ Index Case Evidence" to build vector index.`;
        }
      }
      if (badgeEl) {
        badgeEl.textContent = `${data.indexed_chunks} Chunks`;
        badgeEl.classList.remove('hidden');
      }
    })
    .catch(() => {
      if (statusEl) statusEl.textContent = "Status verification pending.";
    });
}

function ragIngestCase() {
  const caseId = activeCaseId || ragCurrentCaseId;
  if (!caseId) {
    alert("Please select or create an active forensic case first.");
    return;
  }

  const btn = document.getElementById('ragIngestBtn');
  const statusEl = document.getElementById('ragStatusBar');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="inline-block animate-spin mr-1">⏳</span> Vectorizing Evidence...`;
  }
  if (statusEl) {
    statusEl.innerHTML = `<span class="text-sky-600 font-mono animate-pulse">Computing dense vector embeddings and populating ChromaDB...</span>`;
  }

  fetch(`/api/cases/${encodeURIComponent(caseId)}/rag/ingest`, {
    method: 'POST'
  })
    .then(r => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then(data => {
      if (statusEl) {
        statusEl.innerHTML = `<span class="text-emerald-600 font-semibold">✓ Indexing Complete</span> &mdash; ${data.chunks_indexed} forensic chunks ready for retrieval.`;
      }
      ragCheckStatus();
    })
    .catch(err => {
      if (statusEl) {
        statusEl.innerHTML = `<span class="text-rose-600 font-semibold">✕ Indexing error:</span> ${escapeHtml(err.message)}`;
      }
    })
    .finally(() => {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span>⚡</span> <span>Index Case Evidence</span>`;
      }
    });
}

function ragSetQuestion(promptText) {
  const input = document.getElementById('ragQuestionInput');
  if (input) {
    input.value = promptText;
    input.focus();
  }
}

function ragClearChat() {
  const chatWin = document.getElementById('ragChatWindow');
  const caseId = activeCaseId || ragCurrentCaseId || "--";
  if (chatWin) {
    chatWin.innerHTML = `
      <div class="p-4 rounded-xl bg-sky-50/70 border border-sky-100 text-xs text-sky-800 space-y-1">
        <div class="font-bold flex items-center space-x-1.5 text-sm text-sky-900">
          <span>🤖</span> <span>Chat History Cleared</span>
        </div>
        <p>Active Case: <strong class="font-mono text-sky-950">${escapeHtml(caseId)}</strong></p>
      </div>
    `;
  }
}

function ragAsk() {
  if (ragIsQuerying) return;
  const caseId = activeCaseId || ragCurrentCaseId;
  if (!caseId) {
    alert("Please select an active case first.");
    return;
  }

  const input = document.getElementById('ragQuestionInput');
  const question = input ? input.value.trim() : "";
  if (!question) return;

  if (input) input.value = "";
  ragAppendUserMessage(question);
  const thinkingId = ragAppendThinkingMessage();

  ragIsQuerying = true;
  const sendBtn = document.getElementById('ragSendBtn');
  if (sendBtn) sendBtn.disabled = true;

  fetch(`/api/cases/${encodeURIComponent(caseId)}/ask`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      question: question,
      top_k: 10
    })
  })
    .then(r => {
      if (!r.ok) throw new Error(`Server returned HTTP ${r.status}`);
      return r.json();
    })
    .then(data => {
      ragReplaceAssistantMessage(thinkingId, data);
      ragUpdateProviderBadge(data.provider);
    })
    .catch(err => {
      ragReplaceAssistantMessage(thinkingId, {
        answer: `❌ Analysis error occurred: ${err.message}`,
        sources: [],
        provider: "error",
        chunks_retrieved: 0
      });
    })
    .finally(() => {
      ragIsQuerying = false;
      if (sendBtn) sendBtn.disabled = false;
    });
}

function ragAppendUserMessage(text) {
  const win = document.getElementById('ragChatWindow');
  if (!win) return;
  const id = `rag-msg-${++ragMsgCounter}`;

  const div = document.createElement('div');
  div.id = id;
  div.className = "flex justify-end gap-2 animate-fadeIn";
  div.innerHTML = `
    <div class="max-w-[85%] rounded-2xl rounded-tr-none px-4 py-3 bg-gradient-to-r from-sky-600 to-indigo-600 text-white text-xs sm:text-sm leading-relaxed shadow-md shadow-sky-600/10 whitespace-pre-wrap font-sans">
      ${escapeHtml(text)}
    </div>
  `;
  win.appendChild(div);
  win.scrollTop = win.scrollHeight;
}

function ragAppendThinkingMessage() {
  const win = document.getElementById('ragChatWindow');
  if (!win) return null;
  const id = `rag-msg-${++ragMsgCounter}`;

  const div = document.createElement('div');
  div.id = id;
  div.className = "flex justify-start gap-2.5 animate-fadeIn";
  div.innerHTML = `
    <div class="w-7 h-7 rounded-lg bg-sky-100 text-sky-700 flex items-center justify-center shrink-0 text-xs font-bold border border-sky-200">
      🤖
    </div>
    <div class="max-w-[85%] rounded-2xl rounded-tl-none px-4 py-3 bg-white border border-slate-200 shadow-sm text-xs sm:text-sm text-slate-500 italic flex items-center space-x-2">
      <span class="inline-block w-2 h-2 rounded-full bg-sky-500 animate-ping mr-1"></span>
      <span>Retrieving vector embeddings & reasoning over case evidence...</span>
    </div>
  `;
  win.appendChild(div);
  win.scrollTop = win.scrollHeight;
  return id;
}

function renderMarkdownToHtml(markdownText) {
  if (!markdownText) return "";

  let html = "";
  // 1. Primary: Use marked.js if loaded from CDN
  if (typeof marked !== 'undefined' && typeof marked.parse === 'function') {
    try {
      html = marked.parse(markdownText, { breaks: true, gfm: true });
    } catch (e) {
      html = "";
    }
  }

  // 2. Offline / Air-Gapped Fallback Parser
  if (!html) {
    let text = escapeHtml(markdownText);

    // Code blocks
    text = text.replace(/```([a-z0-9_\-]*)?\n([\s\S]*?)```/gim, '<pre><code>$2</code></pre>');
    text = text.replace(/`([^`]+)`/gim, '<code>$1</code>');

    // Headings
    text = text.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    text = text.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    text = text.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Bold and Italic
    text = text.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
    text = text.replace(/\*(.*?)\*/gim, '<em>$1</em>');

    // Ordered lists
    text = text.replace(/^\s*(\d+)\.\s+(.*)$/gim, '<li>$2</li>');
    // Unordered lists
    text = text.replace(/^\s*[\-\*]\s+(.*)$/gim, '<li>$1</li>');

    // Wrap consecutive <li> into <ol> or <ul>
    text = text.replace(/(<li>[\s\S]*?<\/li>)/gim, '<ol>$1</ol>');

    // Paragraphs
    const blocks = text.split(/\n\n+/);
    html = blocks.map(b => {
      const trimmed = b.trim();
      if (!trimmed) return "";
      if (trimmed.startsWith('<h') || trimmed.startsWith('<pre') || trimmed.startsWith('<ol') || trimmed.startsWith('<ul')) {
        return trimmed;
      }
      return `<p>${trimmed.replace(/\n/g, '<br/>')}</p>`;
    }).filter(Boolean).join('');
  }

  // 3. Domain-Specific Forensic Highlights & Status Badges
  html = html
    .replace(/\bRED ZONE\b/gi, '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-rose-100 text-rose-800 border border-rose-200">🛑 RED ZONE</span>')
    .replace(/\bYELLOW ZONE\b/gi, '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-amber-100 text-amber-800 border border-amber-200">⚠️ YELLOW ZONE</span>')
    .replace(/\bGREEN ZONE\b/gi, '<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">✅ GREEN ZONE</span>')
    .replace(/\b(CRITICAL)\b/g, '<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">CRITICAL</span>')
    .replace(/\b(WARNING)\b/g, '<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200">WARNING</span>');

  return html;
}

function ragReplaceAssistantMessage(msgId, data) {
  const el = document.getElementById(msgId);
  if (!el) return;

  const answerText = data.answer || "No response generated.";
  const sources = data.sources || [];
  const provider = data.provider || "groq";

  let providerBadgeClass = "bg-sky-50 text-sky-700 border-sky-200";
  let providerLabel = "Groq LLaMA-3.3";
  if (provider === "ollama") {
    providerBadgeClass = "bg-emerald-50 text-emerald-700 border-emerald-200";
    providerLabel = "Local Ollama";
  } else if (provider === "offline-evidence-match") {
    providerBadgeClass = "bg-amber-50 text-amber-700 border-amber-200";
    providerLabel = "Direct Vector Match";
  }

  // Generate citations accordion
  let citationsHtml = "";
  if (sources.length > 0) {
    const citationsList = sources.slice(0, 8).map((s, idx) => {
      const meta = s.metadata || {};
      const type = meta.chunk_type || "evidence";
      return `
        <div class="p-2.5 rounded-lg bg-slate-50 border border-slate-200/80 text-[11px] text-slate-700 space-y-1">
          <div class="flex items-center justify-between text-[10px] text-slate-500 font-semibold uppercase">
            <span class="text-sky-700 font-bold">[Citation #${idx + 1}] &bull; ${escapeHtml(type)}</span>
            <span class="font-mono">Match: ${(s.relevance_score * 100).toFixed(0)}%</span>
          </div>
          <div class="text-slate-800 text-[11px] font-sans leading-relaxed">${escapeHtml(s.text)}</div>
        </div>
      `;
    }).join("");

    citationsHtml = `
      <details class="mt-3 pt-2.5 border-t border-slate-100 text-xs">
        <summary class="cursor-pointer text-[11px] font-semibold text-slate-600 hover:text-sky-700 select-none flex items-center space-x-1.5 py-1">
          <span>📚</span> <span>View ${sources.length} Retrieved Forensic Citations</span>
        </summary>
        <div class="mt-2.5 space-y-2 max-h-56 overflow-y-auto pr-1">
          ${citationsList}
        </div>
      </details>
    `;
  }

  el.innerHTML = `
    <div class="w-8 h-8 rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 text-white flex items-center justify-center shrink-0 text-sm font-bold shadow-md shadow-sky-500/20 mt-1">
      🤖
    </div>
    <div class="max-w-[94%] sm:max-w-[88%] rounded-2xl rounded-tl-none p-4 sm:p-5 bg-white border border-slate-200/90 shadow-sm text-slate-800 font-sans space-y-3 leading-relaxed">
      <div class="flex items-center justify-between gap-2 pb-2 border-b border-slate-100">
        <div class="flex items-center space-x-2">
          <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span class="text-[11px] font-bold text-slate-700 uppercase tracking-wider">Forensic Investigation Analysis</span>
        </div>
        <span class="text-[11px] px-2.5 py-0.5 rounded-md font-mono font-medium border ${providerBadgeClass}">
          ${providerLabel}
        </span>
      </div>
      <div class="rag-markdown">${renderMarkdownToHtml(answerText)}</div>
      ${citationsHtml}
    </div>
  `;

  const win = document.getElementById('ragChatWindow');
  if (win) win.scrollTop = win.scrollHeight;
}

function ragUpdateProviderBadge(provider) {
  const badge = document.getElementById('ragProviderIndicator');
  if (!badge) return;
  if (!provider || provider === "none") {
    badge.classList.add('hidden');
    return;
  }
  badge.classList.remove('hidden');
  if (provider === "groq") {
    badge.textContent = "⚡ Groq Active";
    badge.className = "text-[10px] bg-sky-50 text-sky-700 border border-sky-200 px-2 py-0.5 rounded font-mono font-semibold";
  } else if (provider === "ollama") {
    badge.textContent = "🦙 Ollama Local";
    badge.className = "text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded font-mono font-semibold";
  } else {
    badge.textContent = "🔍 Vector Match";
    badge.className = "text-[10px] bg-amber-50 text-amber-700 border border-amber-200 px-2 py-0.5 rounded font-mono font-semibold";
  }
}
