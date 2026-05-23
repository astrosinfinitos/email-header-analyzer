const ACCEPTED_FORMATS = ['.eml', '.msg', '.txt', '.mht', '.mhtml'];

/* ── Drag & drop ── */
function onDragOver(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.add('drag-over');
}

function onDragLeave() {
  document.getElementById('drop-zone').classList.remove('drag-over');
}

function onDrop(e) {
  e.preventDefault();
  onDragLeave();
  const file = e.dataTransfer.files[0];
  if (file) onFileSelected(file);
}

/* ── Selección de archivo ── */
function onFileSelected(file) {
  if (!file) return;

  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!ACCEPTED_FORMATS.includes(ext)) {
    showError(`Formato no soportado: ${ext}. Usa .eml, .msg, .txt o .mht`);
    return;
  }

  showFilePill(file.name);

  const reader = new FileReader();
  reader.onload = (e) => {
    const header = extractHeader(e.target.result);
    document.getElementById('header-input').value = header;
    onInputChange();
    clearResults();
    analyze();
  };
  reader.readAsText(file, 'utf-8');
}

/* ── Extracción de cabecera RFC 2822 ── */
function extractHeader(raw) {
  const sepCRLF = raw.indexOf('\r\n\r\n');
  const sepLF   = raw.indexOf('\n\n');

  let end = -1;
  if (sepCRLF !== -1 && sepLF !== -1) end = Math.min(sepCRLF, sepLF);
  else if (sepCRLF !== -1) end = sepCRLF;
  else if (sepLF   !== -1) end = sepLF;

  return end !== -1 ? raw.slice(0, end).trim() : raw.trim();
}

/* ── File pill ── */
function showFilePill(filename) {
  document.getElementById('file-pill-wrap').innerHTML = `
    <div class="file-pill">
      📄 ${filename}
      <span class="pill-x" id="pill-clear">✕</span>
    </div>`;

  document.getElementById('pill-clear').addEventListener('click', (e) => {
    e.stopPropagation();
    clearFile();
  });
}

function clearFile() {
  document.getElementById('file-pill-wrap').innerHTML = '';
  document.getElementById('file-input').value = '';
  document.getElementById('header-input').value = '';
  onInputChange();
  clearResults();
}

/* ── Inicialización ── */
function initUpload() {
  const dropZone  = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const browse    = document.getElementById('drop-browse');

  dropZone.addEventListener('dragover',  onDragOver);
  dropZone.addEventListener('dragleave', onDragLeave);
  dropZone.addEventListener('drop',      onDrop);
  dropZone.addEventListener('click',     () => fileInput.click());

  browse.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  fileInput.addEventListener('change', (e) => {
    onFileSelected(e.target.files[0]);
  });
}

