// MailBackup Studio Web Application
let state = {
  accounts: [],
  selectedAccountId: null,
  selectedFolderId: null,
  selectedMessageId: null,
  messages: [],
  folders: [],
  currentSort: 'newest',
};

// DOM Elements
const el = {
  accountsList: document.getElementById('accounts-list'),
  foldersList: document.getElementById('folders-list'),
  folderCountBadge: document.getElementById('folder-count-badge'),
  currentFolderTitle: document.getElementById('current-folder-title'),
  folderMsgCount: document.getElementById('folder-msg-count'),
  emailItemsContainer: document.getElementById('email-items-container'),
  sortSelect: document.getElementById('sort-select'),
  globalSearch: document.getElementById('global-search'),
  statsSummary: document.getElementById('stats-summary'),
  btnSyncAll: document.getElementById('btn-sync-all'),
  btnOpenSettings: document.getElementById('btn-open-settings'),
  btnAddAccountQuick: document.getElementById('btn-add-account-quick'),
  settingsModal: document.getElementById('settings-modal'),
  btnCloseModal: document.getElementById('btn-close-modal'),
  exportModal: document.getElementById('export-modal'),
  btnOpenExport: document.getElementById('btn-export-mbox-dialog'),
  btnCloseExport: document.getElementById('btn-close-export'),
  exportAccountSelect: document.getElementById('export-account-select'),
  exportFolderSelect: document.getElementById('export-folder-select'),
  exportForm: document.getElementById('export-form'),
  readerEmpty: document.getElementById('reader-empty'),
  readerContent: document.getElementById('reader-content'),
  viewSubject: document.getElementById('view-subject'),
  viewFrom: document.getElementById('view-from'),
  viewTo: document.getElementById('view-to'),
  viewAvatar: document.getElementById('view-avatar'),
  viewFolderTag: document.getElementById('view-folder-tag'),
  viewDateTag: document.getElementById('view-date-tag'),
  viewAttachmentsBar: document.getElementById('view-attachments-bar'),
  viewAttCount: document.getElementById('view-att-count'),
  viewAttachmentsList: document.getElementById('view-attachments-list'),
  viewBodyFrame: document.getElementById('view-body-frame'),
  viewBodyPlain: document.getElementById('view-body-plain'),
  btnDownloadRawEml: document.getElementById('btn-download-raw-eml'),
  modalAccountsList: document.getElementById('modal-accounts-list'),
  addAccountForm: document.getElementById('add-account-form'),
  formProvider: document.getElementById('form-provider'),
  formServer: document.getElementById('form-server'),
  formPort: document.getElementById('form-port'),
  btnTestAccount: document.getElementById('btn-test-account'),
  toast: document.getElementById('toast'),
  toastMessage: document.getElementById('toast-message'),

  // Edit Account Modal Elements
  editAccountModal: document.getElementById('edit-account-modal'),
  btnCloseEditModal: document.getElementById('btn-close-edit-modal'),
  btnCancelEdit: document.getElementById('btn-cancel-edit'),
  editAccountForm: document.getElementById('edit-account-form'),
  editAccountId: document.getElementById('edit-account-id'),
  editEmail: document.getElementById('edit-email'),
  editName: document.getElementById('edit-name'),
  editServer: document.getElementById('edit-server'),
  editPort: document.getElementById('edit-port'),
  editUsername: document.getElementById('edit-username'),
  editPassword: document.getElementById('edit-password'),
  editRetention: document.getElementById('edit-retention'),
  editSchedule: document.getElementById('edit-schedule'),
  editEnabled: document.getElementById('edit-enabled'),

  // Settings Tab Elements
  settingsStorageForm: document.getElementById('settings-storage-form'),
  settingsDataDir: document.getElementById('settings-data-dir'),
  settingsMoveExisting: document.getElementById('settings-move-existing'),
  settingsDbPath: document.getElementById('settings-db-path'),
  settingsCurrentStorage: document.getElementById('settings-current-storage'),
  btnSaveStorage: document.getElementById('btn-save-storage'),
};

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  loadStats();
  loadAccounts();
  loadSettings();
});

function initEventListeners() {
  // Navigation & Modals
  el.btnOpenSettings.addEventListener('click', () => {
    openModal(el.settingsModal);
    loadSettings();
  });
  el.btnAddAccountQuick.addEventListener('click', () => {
    openModal(el.settingsModal);
    switchTab('tab-add');
  });
  el.btnCloseModal.addEventListener('click', () => closeModal(el.settingsModal));
  
  el.btnOpenExport.addEventListener('click', () => {
    populateExportModal();
    openModal(el.exportModal);
  });
  el.btnCloseExport.addEventListener('click', () => closeModal(el.exportModal));

  // Edit Account Modal
  if (el.btnCloseEditModal) el.btnCloseEditModal.addEventListener('click', () => closeModal(el.editAccountModal));
  if (el.btnCancelEdit) el.btnCancelEdit.addEventListener('click', () => closeModal(el.editAccountModal));
  if (el.editAccountForm) el.editAccountForm.addEventListener('submit', handleSaveAccountEdit);

  // Storage Settings Form
  if (el.settingsStorageForm) el.settingsStorageForm.addEventListener('submit', handleSaveStorageSettings);

  // Tab switching in settings modal
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Sorting
  if (el.sortSelect) {
    el.sortSelect.addEventListener('change', (e) => {
      state.currentSort = e.target.value;
      renderMessages(state.messages);
    });
  }

  // Provider presets
  el.formProvider.addEventListener('change', (e) => {
    const val = e.target.value;
    if (val === 'gmail') {
      el.formServer.value = 'imap.gmail.com';
      el.formPort.value = 993;
    } else if (val === 'outlook') {
      el.formServer.value = 'outlook.office365.com';
      el.formPort.value = 993;
    } else if (val === 'icloud') {
      el.formServer.value = 'imap.mail.me.com';
      el.formPort.value = 993;
    } else if (val === 'yahoo') {
      el.formServer.value = 'imap.mail.yahoo.com';
      el.formPort.value = 993;
    }
  });

  // Forms
  el.addAccountForm.addEventListener('submit', handleAddAccount);
  el.btnTestAccount.addEventListener('click', handleTestAccount);
  el.exportForm.addEventListener('submit', handleExportMbox);

  // Sync All button
  el.btnSyncAll.addEventListener('click', handleSyncAll);

  // Search
  let debounceTimeout = null;
  el.globalSearch.addEventListener('input', (e) => {
    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(() => {
      const q = e.target.value.trim();
      if (q.length > 1) {
        performSearch(q);
      } else if (q.length === 0 && state.selectedFolderId) {
        loadFolderMessages(state.selectedFolderId);
      }
    }, 250);
  });

  // Download raw .eml button
  el.btnDownloadRawEml.addEventListener('click', () => {
    if (state.selectedMessageId) {
      window.open(`/api/messages/${state.selectedMessageId}/download`, '_blank');
    }
  });

  // Keyboard shortcut: Cmd/Ctrl + K to focus search
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      el.globalSearch.focus();
    }
  });
}

function showToast(msg, duration = 3000) {
  el.toastMessage.textContent = msg;
  el.toast.style.display = 'flex';
  setTimeout(() => {
    el.toast.style.display = 'none';
  }, duration);
}

function openModal(modal) {
  modal.style.display = 'flex';
}

function closeModal(modal) {
  modal.style.display = 'none';
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.toggle('active', c.id === tabId);
  });
  if (tabId === 'tab-settings') {
    loadSettings();
  }
}

// Sorting logic
function applySort(messages) {
  if (!messages || messages.length === 0) return [];
  const list = [...messages];

  if (state.currentSort === 'newest') {
    list.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
  } else if (state.currentSort === 'oldest') {
    list.sort((a, b) => new Date(a.date || 0) - new Date(b.date || 0));
  } else if (state.currentSort === 'sender') {
    list.sort((a, b) => (a.from_addr || '').localeCompare(b.from_addr || ''));
  } else if (state.currentSort === 'subject') {
    list.sort((a, b) => (a.subject || '').localeCompare(b.subject || ''));
  }

  return list;
}

// API Calls
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const stats = await res.json();
    const mb = (stats.total_bytes / (1024 * 1024)).toFixed(1);
    el.statsSummary.textContent = `${stats.total_messages.toLocaleString()} msgs • ${mb} MB`;
    if (el.settingsCurrentStorage) {
      el.settingsCurrentStorage.textContent = `${stats.total_messages.toLocaleString()} messages (${mb} MB across accounts)`;
    }
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

async function loadAccounts() {
  try {
    const res = await fetch('/api/accounts');
    if (!res.ok) return;
    state.accounts = await res.json();
    renderAccounts();
    renderModalAccounts();

    if (state.accounts.length > 0 && !state.selectedAccountId) {
      selectAccount(state.accounts[0].id);
    }
  } catch (err) {
    console.error('Failed to load accounts:', err);
  }
}

function renderAccounts() {
  el.accountsList.innerHTML = '';
  if (state.accounts.length === 0) {
    el.accountsList.innerHTML = `<div class="empty-state-hint" style="padding: 8px;">No accounts yet. Click + to add.</div>`;
    return;
  }

  state.accounts.forEach(acc => {
    const item = document.createElement('div');
    item.className = `account-item ${acc.id === state.selectedAccountId ? 'active' : ''}`;
    item.innerHTML = `
      <div class="account-info">
        <span class="account-title">${escapeHtml(acc.name)}</span>
        <span class="account-email">${escapeHtml(acc.email)}</span>
      </div>
      <span class="account-status-dot" style="background: ${acc.enabled ? 'var(--accent-emerald)' : 'var(--text-dim)'};" title="${acc.enabled ? 'Active' : 'Disabled'}"></span>
    `;
    item.addEventListener('click', () => selectAccount(acc.id));
    el.accountsList.appendChild(item);
  });
}

function renderModalAccounts() {
  el.modalAccountsList.innerHTML = '';
  if (state.accounts.length === 0) {
    el.modalAccountsList.innerHTML = `<p style="color: var(--text-dim);">No accounts configured yet.</p>`;
    return;
  }

  state.accounts.forEach(acc => {
    const row = document.createElement('div');
    row.className = 'account-table-row';
    const retentionText = acc.retention_days ? `${acc.retention_days} days` : 'Forever';
    const scheduleText = acc.schedule || 'Default (Daily)';
    const statusText = acc.enabled ? '<span style="color: var(--accent-emerald); font-weight: 600;">Enabled</span>' : '<span style="color: var(--text-dim);">Disabled</span>';

    row.innerHTML = `
      <div>
        <strong>${escapeHtml(acc.name)}</strong> (${escapeHtml(acc.email)}) - ${statusText}
        <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 2px;">
          Server: ${escapeHtml(acc.imap_server)}:${acc.imap_port} • Schedule: <code>${escapeHtml(scheduleText)}</code> • Retention: ${retentionText}
        </div>
      </div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-sm btn-secondary" onclick="openEditAccount('${acc.id}')">Edit</button>
        <button class="btn btn-sm btn-ghost" style="color: var(--accent-rose);" onclick="deleteAccount('${acc.id}')">Remove</button>
      </div>
    `;
    el.modalAccountsList.appendChild(row);
  });
}

// Edit Account Handlers
window.openEditAccount = function(accountId) {
  const acc = state.accounts.find(a => a.id === accountId);
  if (!acc) return;

  el.editAccountId.value = acc.id;
  el.editEmail.value = `${acc.name} <${acc.email}>`;
  el.editName.value = acc.name;
  el.editServer.value = acc.imap_server;
  el.editPort.value = acc.imap_port;
  el.editUsername.value = acc.username;
  el.editPassword.value = '';
  el.editRetention.value = acc.retention_days || 0;
  el.editSchedule.value = acc.schedule || '0 0 * * *';
  el.editEnabled.checked = acc.enabled !== false;

  openModal(el.editAccountModal);
};

async function handleSaveAccountEdit(e) {
  e.preventDefault();
  const accountId = el.editAccountId.value;
  const payload = {
    name: el.editName.value.trim(),
    server: el.editServer.value.trim(),
    port: parseInt(el.editPort.value),
    username: el.editUsername.value.trim(),
    password: el.editPassword.value || null,
    retention_days: parseInt(el.editRetention.value) || null,
    schedule: el.editSchedule.value.trim() || '0 0 * * *',
    enabled: el.editEnabled.checked,
  };

  try {
    const res = await fetch(`/api/accounts/${accountId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      showToast('Account settings updated successfully! ✅');
      closeModal(el.editAccountModal);
      await loadAccounts();
    } else {
      const err = await res.text();
      showToast(`Update failed: ${err}`);
    }
  } catch (err) {
    showToast(`Network error: ${err}`);
  }
}

async function selectAccount(accountId) {
  state.selectedAccountId = accountId;
  renderAccounts();
  await loadFolders(accountId);
}

async function loadFolders(accountId) {
  try {
    const res = await fetch(`/api/accounts/${accountId}/folders`);
    if (!res.ok) return;
    state.folders = await res.json();
    renderFolders();

    if (state.folders.length > 0) {
      selectFolder(state.folders[0]);
    } else {
      el.currentFolderTitle.textContent = 'No folders';
      el.folderMsgCount.textContent = '0 messages';
      el.emailItemsContainer.innerHTML = `<div class="empty-state"><h3>No folders synced</h3><p>Click "Sync Now" to download mailboxes.</p></div>`;
    }
  } catch (err) {
    console.error('Failed to load folders:', err);
  }
}

function renderFolders() {
  el.foldersList.innerHTML = '';
  el.folderCountBadge.textContent = state.folders.length;

  state.folders.forEach(f => {
    const item = document.createElement('div');
    item.className = `folder-item ${f.id === state.selectedFolderId ? 'active' : ''}`;
    item.innerHTML = `
      <span>📁 ${escapeHtml(f.remote_name)}</span>
      <span class="count-badge">${f.message_count}</span>
    `;
    item.addEventListener('click', () => selectFolder(f));
    el.foldersList.appendChild(item);
  });
}

async function selectFolder(folder) {
  state.selectedFolderId = folder.id;
  el.currentFolderTitle.textContent = folder.remote_name;
  el.folderMsgCount.textContent = `${folder.message_count} messages`;
  renderFolders();
  await loadFolderMessages(folder.id);
}

async function loadFolderMessages(folderId) {
  el.emailItemsContainer.innerHTML = `<div class="empty-state"><p>Loading messages...</p></div>`;
  try {
    const res = await fetch(`/api/folders/${folderId}/messages`);
    if (!res.ok) return;
    state.messages = await res.json();
    renderMessages(state.messages);
  } catch (err) {
    console.error('Failed to load messages:', err);
  }
}

function renderMessages(messages) {
  el.emailItemsContainer.innerHTML = '';
  if (!messages || messages.length === 0) {
    el.emailItemsContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        <h3>No emails in this folder</h3>
        <p>This folder is currently empty.</p>
      </div>
    `;
    return;
  }

  const sorted = applySort(messages);

  sorted.forEach(msg => {
    const card = document.createElement('div');
    card.className = `email-card ${msg.id === state.selectedMessageId ? 'active' : ''}`;
    
    const sender = msg.from_addr || 'Unknown Sender';
    const subject = msg.subject || '(No Subject)';
    const dateStr = msg.date ? new Date(msg.date).toLocaleDateString() : '';

    card.innerHTML = `
      <div class="card-top-row">
        <span class="card-sender">${escapeHtml(sender)}</span>
        <span class="card-date">${dateStr}</span>
      </div>
      <div class="card-subject">${escapeHtml(subject)}</div>
    `;
    card.addEventListener('click', () => selectMessage(msg.id));
    el.emailItemsContainer.appendChild(card);
  });
}

async function selectMessage(messageId) {
  state.selectedMessageId = messageId;
  document.querySelectorAll('.email-card').forEach(c => c.classList.remove('active'));

  try {
    const res = await fetch(`/api/messages/${messageId}`);
    if (!res.ok) return;
    const msg = await res.json();

    el.readerEmpty.style.display = 'none';
    el.readerContent.style.display = 'flex';

    el.viewSubject.textContent = msg.subject || '(No Subject)';
    el.viewFrom.textContent = msg.from_addr || 'Unknown';
    el.viewTo.textContent = msg.to_addrs || 'Undisclosed recipients';
    el.viewFolderTag.textContent = msg.folder_name || 'MAILBOX';
    el.viewDateTag.textContent = msg.date ? new Date(msg.date).toLocaleString() : '';

    const firstLetter = (msg.from_addr || 'U')[0].toUpperCase();
    el.viewAvatar.textContent = firstLetter;

    // Attachments
    if (msg.attachments && msg.attachments.length > 0) {
      el.viewAttachmentsBar.style.display = 'flex';
      el.viewAttCount.textContent = msg.attachments.length;
      el.viewAttachmentsList.innerHTML = '';
      msg.attachments.forEach(att => {
        const chip = document.createElement('div');
        chip.className = 'att-chip';
        const kb = (att.size_bytes / 1024).toFixed(1);
        chip.innerHTML = `📎 ${escapeHtml(att.filename)} (${kb} KB)`;
        chip.title = `MIME: ${att.mime_type}`;
        el.viewAttachmentsList.appendChild(chip);
      });
    } else {
      el.viewAttachmentsBar.style.display = 'none';
    }

    // Body
    if (msg.body_html) {
      el.viewBodyFrame.style.display = 'block';
      el.viewBodyPlain.style.display = 'none';
      el.viewBodyFrame.srcdoc = msg.body_html;
    } else {
      el.viewBodyFrame.style.display = 'none';
      el.viewBodyPlain.style.display = 'block';
      el.viewBodyPlain.textContent = msg.body_text || '(Empty Message Body)';
    }
  } catch (err) {
    console.error('Failed to fetch message details:', err);
  }
}

async function performSearch(query) {
  el.currentFolderTitle.textContent = `Search: "${query}"`;
  el.emailItemsContainer.innerHTML = `<div class="empty-state"><p>Searching across all archives...</p></div>`;

  try {
    const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
    if (!res.ok) return;
    const results = await res.json();
    el.folderMsgCount.textContent = `${results.length} matches`;

    el.emailItemsContainer.innerHTML = '';
    if (results.length === 0) {
      el.emailItemsContainer.innerHTML = `<div class="empty-state"><div class="empty-icon">🔍</div><h3>No matches found</h3><p>Try searching for a different keyword.</p></div>`;
      return;
    }

    const sortedResults = applySort(results);

    sortedResults.forEach(item => {
      const card = document.createElement('div');
      card.className = `email-card ${item.message_id === state.selectedMessageId ? 'active' : ''}`;
      const dateStr = item.date ? new Date(item.date).toLocaleDateString() : '';

      card.innerHTML = `
        <div class="card-top-row">
          <span class="card-sender">${escapeHtml(item.from_addr)}</span>
          <span class="card-date">${dateStr}</span>
        </div>
        <div class="card-subject">${escapeHtml(item.subject || '(No Subject)')}</div>
        <div class="card-snippet">${item.snippet}</div>
      `;
      card.addEventListener('click', () => selectMessage(item.message_id));
      el.emailItemsContainer.appendChild(card);
    });
  } catch (err) {
    console.error('Search error:', err);
  }
}

async function handleSyncAll() {
  if (state.accounts.length === 0) {
    showToast('No accounts configured yet.');
    return;
  }

  el.btnSyncAll.disabled = true;
  el.btnSyncAll.innerHTML = `<span class="stats-dot" style="animation: pulse 1s infinite;"></span> Syncing...`;
  showToast('Initiating background sync...');

  for (const acc of state.accounts) {
    try {
      await fetch(`/api/sync/${acc.id}`, { method: 'POST' });
    } catch (err) {
      console.error('Sync error:', err);
    }
  }

  setTimeout(async () => {
    el.btnSyncAll.disabled = false;
    el.btnSyncAll.innerHTML = `
      <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
      </svg>
      Sync Now
    `;
    showToast('Sync complete!');
    await loadStats();
    if (state.selectedAccountId) {
      await loadFolders(state.selectedAccountId);
    }
  }, 2500);
}

async function handleAddAccount(e) {
  e.preventDefault();
  const payload = {
    provider: el.formProvider.value,
    name: document.getElementById('form-name').value.trim(),
    email: document.getElementById('form-email').value.trim(),
    server: el.formServer.value.trim(),
    port: parseInt(el.formPort.value),
    username: document.getElementById('form-username').value.trim(),
    password: document.getElementById('form-password').value,
    retention_days: parseInt(document.getElementById('form-retention').value) || null,
    schedule: document.getElementById('form-schedule').value.trim() || '0 0 * * *',
  };

  try {
    const res = await fetch('/api/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      showToast('Account added successfully! ✅');
      closeModal(el.settingsModal);
      el.addAccountForm.reset();
      await loadAccounts();
    } else {
      const err = await res.text();
      showToast(`Error: ${err}`);
    }
  } catch (err) {
    showToast(`Network error: ${err}`);
  }
}

async function handleTestAccount() {
  const payload = {
    provider: el.formProvider.value,
    email: document.getElementById('form-email').value.trim(),
    server: el.formServer.value.trim(),
    port: parseInt(el.formPort.value),
    username: document.getElementById('form-username').value.trim(),
    password: document.getElementById('form-password').value,
  };

  if (!payload.password || !payload.server) {
    showToast('Please enter server and password to test.');
    return;
  }

  el.btnTestAccount.disabled = true;
  el.btnTestAccount.textContent = 'Testing...';

  try {
    const res = await fetch('/api/accounts/test-direct', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      showToast('Connection & authentication successful! ✅');
    } else {
      const err = await res.text();
      showToast(`Test failed: ${err}`);
    }
  } catch (err) {
    showToast(`Test error: ${err}`);
  } finally {
    el.btnTestAccount.disabled = false;
    el.btnTestAccount.textContent = 'Test Connection';
  }
}

async function deleteAccount(accountId) {
  if (!confirm(`Are you sure you want to remove account '${accountId}'?`)) return;

  try {
    const res = await fetch(`/api/accounts/${accountId}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Account removed.');
      await loadAccounts();
    }
  } catch (err) {
    showToast('Failed to remove account.');
  }
}

function populateExportModal() {
  el.exportAccountSelect.innerHTML = '';
  state.accounts.forEach(acc => {
    const opt = document.createElement('option');
    opt.value = acc.id;
    opt.textContent = `${acc.name} (${acc.email})`;
    el.exportAccountSelect.appendChild(opt);
  });

  el.exportFolderSelect.innerHTML = '<option value="ALL">All Folders</option>';
  state.folders.forEach(f => {
    const opt = document.createElement('option');
    opt.value = f.id;
    opt.textContent = f.remote_name;
    el.exportFolderSelect.appendChild(opt);
  });

  const timestamp = new Date().toISOString().split('T')[0];
  document.getElementById('export-output-path').value = `backup_${timestamp}.mbox`;
}

async function handleExportMbox(e) {
  e.preventDefault();
  const payload = {
    account_id: el.exportAccountSelect.value,
    folder_id: el.exportFolderSelect.value === 'ALL' ? null : el.exportFolderSelect.value,
    output_path: document.getElementById('export-output-path').value.trim(),
  };

  try {
    const res = await fetch('/api/export/mbox', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      const result = await res.json();
      showToast(`Exported ${result.exported_count} messages to .mbox! ✅`);
      closeModal(el.exportModal);
    } else {
      const err = await res.text();
      showToast(`Export failed: ${err}`);
    }
  } catch (err) {
    showToast(`Export error: ${err}`);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function loadSettings() {
  try {
    const res = await fetch('/api/settings');
    if (!res.ok) return;
    const data = await res.json();
    if (el.settingsDataDir) {
      el.settingsDataDir.value = data.data_dir;
    }
    if (el.settingsDbPath) {
      el.settingsDbPath.textContent = data.db_path;
    }
  } catch (err) {
    console.error('Failed to load settings:', err);
  }
}

async function handleSaveStorageSettings(e) {
  e.preventDefault();
  const newDir = el.settingsDataDir.value.trim();
  if (!newDir) {
    showToast('Please enter a valid directory path');
    return;
  }

  const moveExisting = el.settingsMoveExisting ? el.settingsMoveExisting.checked : true;
  const btn = el.btnSaveStorage;
  const originalHtml = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="stats-dot" style="animation: pulse 1s infinite;"></span> Saving...`;
  }

  try {
    const res = await fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data_dir: newDir,
        move_existing: moveExisting,
      }),
    });

    if (res.ok) {
      const data = await res.json();
      if (el.settingsDataDir) el.settingsDataDir.value = data.data_dir;
      showToast(`Storage updated! ${data.migrated_files} file(s) migrated. ✅`);
      await loadStats();
      if (state.selectedAccountId) {
        await loadFolders(state.selectedAccountId);
      }
    } else {
      const errText = await res.text();
      showToast(`Failed to update storage: ${errText}`);
    }
  } catch (err) {
    showToast(`Error updating storage: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}
