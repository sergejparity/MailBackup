// MailBackup Studio Web Application
let state = {
  accounts: [],
  expandedAccounts: new Set(),
  accountFolders: {}, // accountId -> array of folders
  selectedAccountId: null,
  selectedFolderId: null,
  selectedMessageId: null,
  messages: [],
  currentSort: 'newest',
};

// DOM Elements
const el = {
  accountsList: document.getElementById('accounts-list'),
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

  // Advanced Search Elements
  btnOpenAdvancedSearch: document.getElementById('btn-open-advanced-search'),
  advancedSearchModal: document.getElementById('advanced-search-modal'),
  btnCloseAdvancedSearch: document.getElementById('btn-close-advanced-search'),
  btnCancelAdvancedSearch: document.getElementById('btn-cancel-advanced-search'),
  btnResetAdvancedSearch: document.getElementById('btn-reset-advanced-search'),
  advancedSearchForm: document.getElementById('advanced-search-form'),
  advSearchFrom: document.getElementById('adv-search-from'),
  advSearchTo: document.getElementById('adv-search-to'),
  advSearchCc: document.getElementById('adv-search-cc'),
  advSearchSubject: document.getElementById('adv-search-subject'),
  advSearchKeywords: document.getElementById('adv-search-keywords'),
  advSearchExclude: document.getElementById('adv-search-exclude'),
  advSearchDateFrom: document.getElementById('adv-search-date-from'),
  advSearchDateTo: document.getElementById('adv-search-date-to'),
  advSearchAccount: document.getElementById('adv-search-account'),
  advSearchFolder: document.getElementById('adv-search-folder'),
  advSearchAttName: document.getElementById('adv-search-att-name'),
  advSearchAttType: document.getElementById('adv-search-att-type'),
  advSearchMinSize: document.getElementById('adv-search-min-size'),
  advSearchHasAtt: document.getElementById('adv-search-has-att'),
  advSearchIncludeDeleted: document.getElementById('adv-search-include-deleted'),

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
  settingsDbPathInput: document.getElementById('settings-db-path-input'),
  settingsMoveDbExisting: document.getElementById('settings-move-db-existing'),
  settingsCurrentStorage: document.getElementById('settings-current-storage'),
  btnSaveStorage: document.getElementById('btn-save-storage'),
  settingsCloseToTray: document.getElementById('settings-close-to-tray'),
  traySettingStatus: document.getElementById('tray-setting-status'),
  settingsAutostart: document.getElementById('settings-autostart'),
  autostartSettingStatus: document.getElementById('autostart-setting-status'),
  settingsRunAsService: document.getElementById('settings-run-as-service'),
  serviceSettingStatus: document.getElementById('service-setting-status'),
  serviceDetailsBox: document.getElementById('service-details-box'),
  serviceTypeLabel: document.getElementById('service-type-label'),
  serviceDetailsText: document.getElementById('service-details-text'),
  serviceManualCmd: document.getElementById('service-manual-cmd'),
  btnCopyServiceCmd: document.getElementById('btn-copy-service-cmd'),

  // Header & Logs Elements
  syncProgressBanner: document.getElementById('sync-progress-banner'),
  syncStatusTitle: document.getElementById('sync-status-title'),
  syncStatusSubtitle: document.getElementById('sync-status-subtitle'),
  syncProgressBarFill: document.getElementById('sync-progress-bar-fill'),
  btnOpenLogs: document.getElementById('btn-open-logs'),
  logsFilter: document.getElementById('logs-filter'),
  btnRefreshLogs: document.getElementById('btn-refresh-logs'),
  btnDownloadLogs: document.getElementById('btn-download-logs'),
  btnClearLogs: document.getElementById('btn-clear-logs'),
  logsEntriesList: document.getElementById('logs-entries-list'),
  logsFilePath: document.getElementById('logs-file-path'),
  logsEntryCount: document.getElementById('logs-entry-count'),
};

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  initSplitterResizing();
  initModalResizing();
  initEventListeners();
  loadStats();
  loadAccounts();
  loadSettings();
});

// Workspace Panes Draggable Splitters
function initSplitterResizing() {
  const sidebar = document.getElementById('sidebar-pane');
  const resizerSidebar = document.getElementById('resizer-sidebar');
  const msgList = document.getElementById('email-list-pane');
  const resizerMsgList = document.getElementById('resizer-msglist');

  if (!sidebar || !resizerSidebar || !msgList || !resizerMsgList) return;

  // Restore saved widths from localStorage
  const savedSidebar = localStorage.getItem('mailbackup_sidebar_width');
  if (savedSidebar) {
    const w = parseInt(savedSidebar, 10);
    if (!isNaN(w) && w >= 180 && w <= 480) {
      sidebar.style.width = `${w}px`;
    }
  }

  const savedMsgList = localStorage.getItem('mailbackup_msglist_width');
  if (savedMsgList) {
    const w = parseInt(savedMsgList, 10);
    if (!isNaN(w) && w >= 240 && w <= 850) {
      msgList.style.width = `${w}px`;
    }
  }

  // 1. Sidebar Resizer
  resizerSidebar.addEventListener('mousedown', (e) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = sidebar.getBoundingClientRect().width;
    document.body.classList.add('is-resizing');
    resizerSidebar.classList.add('is-active');

    function onMouseMove(moveEvent) {
      const delta = moveEvent.clientX - startX;
      let newWidth = startWidth + delta;
      const maxAllowed = Math.min(480, window.innerWidth - 550);
      newWidth = Math.max(180, Math.min(newWidth, Math.max(180, maxAllowed)));
      sidebar.style.width = `${newWidth}px`;
    }

    function onMouseUp() {
      document.body.classList.remove('is-resizing');
      resizerSidebar.classList.remove('is-active');
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      localStorage.setItem('mailbackup_sidebar_width', Math.round(sidebar.getBoundingClientRect().width));
    }

    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
  });

  // Double click sidebar resizer to reset to default 260px
  resizerSidebar.addEventListener('dblclick', () => {
    sidebar.style.width = '260px';
    localStorage.removeItem('mailbackup_sidebar_width');
  });

  // 2. Message List Resizer
  resizerMsgList.addEventListener('mousedown', (e) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = msgList.getBoundingClientRect().width;
    document.body.classList.add('is-resizing');
    resizerMsgList.classList.add('is-active');

    function onMouseMove(moveEvent) {
      const delta = moveEvent.clientX - startX;
      let newWidth = startWidth + delta;
      const sidebarW = sidebar.getBoundingClientRect().width;
      const maxAllowed = Math.min(850, window.innerWidth - sidebarW - 320);
      newWidth = Math.max(240, Math.min(newWidth, Math.max(240, maxAllowed)));
      msgList.style.width = `${newWidth}px`;
    }

    function onMouseUp() {
      document.body.classList.remove('is-resizing');
      resizerMsgList.classList.remove('is-active');
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      localStorage.setItem('mailbackup_msglist_width', Math.round(msgList.getBoundingClientRect().width));
    }

    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
  });

  // Double click message list resizer to reset to default 380px
  resizerMsgList.addEventListener('dblclick', () => {
    msgList.style.width = '380px';
    localStorage.removeItem('mailbackup_msglist_width');
  });

  // Keep panes responsive if window is shrunk
  window.addEventListener('resize', () => {
    const totalW = window.innerWidth;
    const sidebarW = sidebar.getBoundingClientRect().width;
    const msgListW = msgList.getBoundingClientRect().width;
    if (sidebarW + msgListW + 300 > totalW) {
      const excess = (sidebarW + msgListW + 300) - totalW;
      const newMsgW = Math.max(240, msgListW - excess);
      msgList.style.width = `${newMsgW}px`;
    }
  });
}

// Modal Resizing & Maximize/Restore
function initModalResizing() {
  setupModalResizing({
    cardId: 'settings-modal-card',
    headerId: 'settings-modal-header',
    maxBtnId: 'btn-maximize-modal',
    storageKey: 'mailbackup_settings_modal_size',
    defaultWidth: 720,
    defaultHeight: 580,
  });

  setupModalResizing({
    cardId: 'edit-account-modal-card',
    headerId: 'edit-account-modal-header',
    maxBtnId: 'btn-maximize-edit-modal',
    storageKey: 'mailbackup_edit_modal_size',
    defaultWidth: 640,
    defaultHeight: 540,
  });
}

function setupModalResizing(options) {
  const { cardId, headerId, maxBtnId, storageKey, defaultWidth, defaultHeight } = options;
  const card = document.getElementById(cardId);
  const header = document.getElementById(headerId);
  const maxBtn = document.getElementById(maxBtnId);

  if (!card) return;

  let isMaximized = false;
  let preMaxWidth = `${defaultWidth}px`;
  let preMaxHeight = `${defaultHeight}px`;

  // Restore saved preferences from localStorage
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey));
    if (saved) {
      if (saved.width) {
        const w = Math.min(Math.max(saved.width, 480), Math.round(window.innerWidth * 0.96));
        card.style.width = `${w}px`;
        preMaxWidth = `${w}px`;
      }
      if (saved.height) {
        const h = Math.min(Math.max(saved.height, 380), Math.round(window.innerHeight * 0.94));
        card.style.height = `${h}px`;
        preMaxHeight = `${h}px`;
      }
      if (saved.maximized) {
        toggleMaximize(true);
      }
    }
  } catch (e) {
    // Ignore JSON errors
  }

  function updateMaxBtnUI(maximized) {
    if (!maxBtn) return;
    const maxIcon = maxBtn.querySelector('.maximize-icon');
    const restoreIcon = maxBtn.querySelector('.restore-icon');
    if (maxIcon) maxIcon.style.display = maximized ? 'none' : 'block';
    if (restoreIcon) restoreIcon.style.display = maximized ? 'block' : 'none';
    maxBtn.title = maximized ? 'Restore window size' : 'Maximize window';
  }

  function toggleMaximize(forceState) {
    isMaximized = typeof forceState === 'boolean' ? forceState : !isMaximized;
    if (isMaximized) {
      if (!card.classList.contains('is-maximized')) {
        preMaxWidth = card.style.width || `${card.offsetWidth}px`;
        preMaxHeight = card.style.height || `${card.offsetHeight}px`;
      }
      card.classList.add('is-maximized');
    } else {
      card.classList.remove('is-maximized');
      card.style.width = preMaxWidth;
      card.style.height = preMaxHeight;
    }
    updateMaxBtnUI(isMaximized);
    saveModalState();
  }

  function saveModalState() {
    try {
      localStorage.setItem(storageKey, JSON.stringify({
        width: Math.round(parseFloat(preMaxWidth) || card.offsetWidth),
        height: Math.round(parseFloat(preMaxHeight) || card.offsetHeight),
        maximized: isMaximized,
      }));
    } catch (e) {}
  }

  if (maxBtn) {
    maxBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleMaximize();
    });
  }

  if (header) {
    header.addEventListener('dblclick', (e) => {
      if (e.target.closest('button')) return;
      toggleMaximize();
    });
  }

  // Handle drag resizing via corner grip or edges
  const handles = card.querySelectorAll('.modal-resize-handle');
  handles.forEach(handle => {
    handle.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const dir = handle.dataset.direction || 'se';
      const startX = e.clientX;
      const startY = e.clientY;
      const startW = card.offsetWidth;
      const startH = card.offsetHeight;

      // If maximized, smoothly unmaximize to current size
      if (isMaximized) {
        card.classList.remove('is-maximized');
        isMaximized = false;
        updateMaxBtnUI(false);
      }

      card.classList.add('no-transition');
      document.body.classList.add('is-modal-resizing');
      handle.classList.add('is-dragging');

      function onMouseMove(moveEvent) {
        if (dir.includes('e')) {
          const deltaX = moveEvent.clientX - startX;
          let newW = startW + deltaX;
          newW = Math.max(480, Math.min(newW, window.innerWidth * 0.96));
          card.style.width = `${newW}px`;
          preMaxWidth = `${newW}px`;
        }
        if (dir.includes('s')) {
          const deltaY = moveEvent.clientY - startY;
          let newH = startH + deltaY;
          newH = Math.max(380, Math.min(newH, window.innerHeight * 0.94));
          card.style.height = `${newH}px`;
          preMaxHeight = `${newH}px`;
        }
      }

      function onMouseUp() {
        card.classList.remove('no-transition');
        handle.classList.remove('is-dragging');
        setTimeout(() => {
          document.body.classList.remove('is-modal-resizing');
        }, 50); // delay removal to prevent modal click dismissal
        window.removeEventListener('mousemove', onMouseMove);
        window.removeEventListener('mouseup', onMouseUp);
        saveModalState();
      }

      window.addEventListener('mousemove', onMouseMove);
      window.addEventListener('mouseup', onMouseUp);
    });

    // Double-click on corner grip resets to default size
    if (handle.dataset.direction === 'se') {
      handle.addEventListener('dblclick', (e) => {
        e.stopPropagation();
        card.classList.remove('is-maximized');
        isMaximized = false;
        card.style.width = `${defaultWidth}px`;
        card.style.height = `${defaultHeight}px`;
        preMaxWidth = `${defaultWidth}px`;
        preMaxHeight = `${defaultHeight}px`;
        updateMaxBtnUI(false);
        saveModalState();
      });
    }
  });
}

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

  // Advanced Search Modal
  if (el.btnOpenAdvancedSearch) el.btnOpenAdvancedSearch.addEventListener('click', openAdvancedSearchModal);
  if (el.btnCloseAdvancedSearch) el.btnCloseAdvancedSearch.addEventListener('click', () => closeModal(el.advancedSearchModal));
  if (el.btnCancelAdvancedSearch) el.btnCancelAdvancedSearch.addEventListener('click', () => closeModal(el.advancedSearchModal));
  if (el.btnResetAdvancedSearch) el.btnResetAdvancedSearch.addEventListener('click', handleResetAdvancedSearch);
  if (el.advancedSearchForm) el.advancedSearchForm.addEventListener('submit', handleAdvancedSearchSubmit);
  if (el.advSearchAccount) el.advSearchAccount.addEventListener('change', updateAdvSearchFolders);

  // Date preset buttons
  document.querySelectorAll('.btn-date-preset').forEach(btn => {
    btn.addEventListener('click', (e) => handleDatePresetClick(e.currentTarget));
  });
  if (el.advSearchDateFrom) {
    el.advSearchDateFrom.addEventListener('input', () => {
      document.querySelectorAll('.btn-date-preset').forEach(b => b.classList.remove('active'));
    });
  }
  if (el.advSearchDateTo) {
    el.advSearchDateTo.addEventListener('input', () => {
      document.querySelectorAll('.btn-date-preset').forEach(b => b.classList.remove('active'));
    });
  }

  // Backdrop click to dismiss modals
  [el.settingsModal, el.editAccountModal, el.exportModal, el.advancedSearchModal].forEach(modal => {
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal && !document.body.classList.contains('is-modal-resizing')) {
          closeModal(modal);
        }
      });
    }
  });

  // Storage Settings Form
  if (el.settingsStorageForm) el.settingsStorageForm.addEventListener('submit', handleSaveStorageSettings);
  if (el.settingsCloseToTray) el.settingsCloseToTray.addEventListener('change', handleToggleCloseToTray);
  if (el.settingsAutostart) el.settingsAutostart.addEventListener('change', handleToggleAutostart);
  if (el.settingsRunAsService) el.settingsRunAsService.addEventListener('change', handleToggleService);
  if (el.btnCopyServiceCmd) el.btnCopyServiceCmd.addEventListener('click', handleCopyServiceCmd);

  // Logs Actions & Direct Nav
  if (el.btnOpenLogs) {
    el.btnOpenLogs.addEventListener('click', () => {
      openModal(el.settingsModal);
      switchTab('tab-logs');
    });
  }
  if (el.logsFilter) el.logsFilter.addEventListener('change', () => renderLogs(cachedLogs));
  if (el.btnRefreshLogs) el.btnRefreshLogs.addEventListener('click', loadLogs);
  if (el.btnDownloadLogs) el.btnDownloadLogs.addEventListener('click', handleDownloadLogs);
  if (el.btnClearLogs) el.btnClearLogs.addEventListener('click', handleClearLogs);

  // Tab switching in settings modal
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Start live sync progress background poller
  startSyncProgressPolling();

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
  if (el.exportForm) el.exportForm.addEventListener('submit', handleExportMbox);
  if (el.exportAccountSelect) el.exportAccountSelect.addEventListener('change', updateExportDefaultPath);
  const btnDownloadBrowser = document.getElementById('btn-download-browser');
  if (btnDownloadBrowser) btnDownloadBrowser.addEventListener('click', handleDownloadMboxBrowser);

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

  // Keyboard shortcut: Cmd/Ctrl + K to focus search, Escape to close modals
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      el.globalSearch.focus();
    }
    if (e.key === 'Escape') {
      if (el.settingsModal && el.settingsModal.style.display === 'flex') closeModal(el.settingsModal);
      if (el.editAccountModal && el.editAccountModal.style.display === 'flex') closeModal(el.editAccountModal);
      if (el.exportModal && el.exportModal.style.display === 'flex') closeModal(el.exportModal);
      if (el.advancedSearchModal && el.advancedSearchModal.style.display === 'flex') closeModal(el.advancedSearchModal);
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
  } else if (tabId === 'tab-logs') {
    loadLogs();
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
    // Container for the account row and its nested folders
    const container = document.createElement('div');
    container.className = 'account-tree-node';

    const isExpanded = state.expandedAccounts.has(acc.id);

    const item = document.createElement('div');
    item.className = `account-item ${acc.id === state.selectedAccountId ? 'active' : ''}`;
    
    // Chevron icon
    const chevron = document.createElement('span');
    chevron.className = `account-chevron ${isExpanded ? 'expanded' : ''}`;
    chevron.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>`;
    chevron.style.marginRight = '8px';
    chevron.style.transition = 'transform 0.2s';
    if (isExpanded) chevron.style.transform = 'rotate(90deg)';

    const info = document.createElement('div');
    info.className = 'account-info';
    info.innerHTML = `
      <span class="account-title">${escapeHtml(acc.name)}</span>
      <span class="account-email">${escapeHtml(acc.email)}</span>
    `;

    const statusDot = document.createElement('span');
    statusDot.className = 'account-status-dot';
    statusDot.style.background = acc.enabled ? 'var(--accent-emerald)' : 'var(--text-dim)';
    statusDot.title = acc.enabled ? 'Active' : 'Disabled';

    item.appendChild(chevron);
    item.appendChild(info);
    item.appendChild(statusDot);

    item.addEventListener('click', () => toggleAccountExpansion(acc.id));
    container.appendChild(item);

    // Render nested folders if expanded
    if (isExpanded) {
      const foldersContainer = document.createElement('div');
      foldersContainer.className = 'nested-folders';
      
      const folders = state.accountFolders[acc.id];
      if (folders) {
        if (folders.length === 0) {
          foldersContainer.innerHTML = '<div class="empty-state-hint" style="padding: 4px 16px;">No folders found</div>';
        } else {
          folders.forEach(f => {
            const fItem = document.createElement('div');
            fItem.className = `folder-item nested ${f.id === state.selectedFolderId ? 'active' : ''}`;
            fItem.innerHTML = `
              <span>📁 ${escapeHtml(f.remote_name)}</span>
              <span class="count-badge">${f.message_count}</span>
            `;
            fItem.addEventListener('click', (e) => {
              e.stopPropagation();
              state.selectedAccountId = acc.id;
              selectFolder(f);
            });
            foldersContainer.appendChild(fItem);
          });
        }
      } else {
        foldersContainer.innerHTML = '<div class="empty-state-hint" style="padding: 4px 16px;">Loading folders...</div>';
      }
      container.appendChild(foldersContainer);
    }

    el.accountsList.appendChild(container);
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

async function toggleAccountExpansion(accountId) {
  if (state.expandedAccounts.has(accountId)) {
    state.expandedAccounts.delete(accountId);
    renderAccounts();
  } else {
    state.expandedAccounts.add(accountId);
    renderAccounts();
    if (!state.accountFolders[accountId]) {
      await loadFolders(accountId);
    }
  }
}

async function loadFolders(accountId) {
  try {
    const res = await fetch(`/api/accounts/${accountId}/folders`);
    if (!res.ok) return;
    const folders = await res.json();
    state.accountFolders[accountId] = folders;
    renderAccounts();
  } catch (err) {
    console.error('Failed to load folders:', err);
  }
}

async function selectFolder(folder) {
  state.selectedFolderId = folder.id;
  el.currentFolderTitle.textContent = folder.remote_name;
  el.folderMsgCount.textContent = `${folder.message_count} messages`;
  renderAccounts();
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

function formatMailDateTime(rawDate) {
  if (!rawDate) return '';
  const d = new Date(rawDate);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
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
    const dateStr = formatMailDateTime(msg.date);
    const fullDateTitle = msg.date ? new Date(msg.date).toLocaleString() : '';

    card.innerHTML = `
      <div class="card-top-row">
        <span class="card-sender" title="${escapeHtml(sender)}">${escapeHtml(sender)}</span>
        <span class="card-date" title="${escapeHtml(fullDateTitle)}">${dateStr}</span>
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

    // Auto-focus the account/folder for this message
    if (msg.account_id && msg.folder_id) {
      let needsRender = false;
      
      if (state.selectedAccountId !== msg.account_id || state.selectedFolderId !== msg.folder_id) {
        state.selectedAccountId = msg.account_id;
        state.selectedFolderId = msg.folder_id;
        needsRender = true;
      }
      
      if (!state.expandedAccounts.has(msg.account_id)) {
        state.expandedAccounts.add(msg.account_id);
        needsRender = true;
      }

      if (needsRender) {
        if (!state.accountFolders[msg.account_id]) {
          await loadFolders(msg.account_id);
        } else {
          renderAccounts();
        }
        
        setTimeout(() => {
          const activeFolder = document.querySelector('.folder-item.active');
          if (activeFolder) {
            activeFolder.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }, 50);
      }
    }

    el.readerEmpty.style.display = 'none';
    el.readerContent.style.display = 'flex';

    el.viewSubject.textContent = msg.subject || '(No Subject)';
    el.viewFrom.textContent = msg.from_addr || 'Unknown';
    el.viewTo.textContent = msg.to_addrs || 'Undisclosed recipients';
    let folderName = msg.folder_name || 'MAILBOX';
    if (msg.account_id && msg.folder_id && state.accountFolders[msg.account_id]) {
      const matchedFolder = state.accountFolders[msg.account_id].find(f => f.id === msg.folder_id);
      if (matchedFolder) {
        folderName = matchedFolder.remote_name;
      }
    }
    el.viewFolderTag.textContent = folderName;
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
      const dateStr = formatMailDateTime(item.date);
      const fullDateTitle = item.date ? new Date(item.date).toLocaleString() : '';

      card.innerHTML = `
        <div class="card-top-row">
          <span class="card-sender" title="${escapeHtml(item.from_addr)}">${escapeHtml(item.from_addr)}</span>
          <span class="card-date" title="${escapeHtml(fullDateTitle)}">${dateStr}</span>
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

async function openAdvancedSearchModal() {
  if (!el.advancedSearchModal) return;
  await populateAdvancedSearchAccounts();

  // If user had something typed in the quick search bar, seed keywords if empty
  if (el.globalSearch && el.globalSearch.value.trim() && el.advSearchKeywords && !el.advSearchKeywords.value) {
    el.advSearchKeywords.value = el.globalSearch.value.trim();
  }

  openModal(el.advancedSearchModal);
  if (el.advSearchFrom) el.advSearchFrom.focus();
}

async function populateAdvancedSearchAccounts() {
  if (!el.advSearchAccount) return;
  const currentVal = el.advSearchAccount.value;
  el.advSearchAccount.innerHTML = '<option value="ALL">All Accounts</option>';
  state.accounts.forEach(acc => {
    const opt = document.createElement('option');
    opt.value = acc.id;
    opt.textContent = `${acc.name || acc.email} (${acc.email})`;
    el.advSearchAccount.appendChild(opt);
  });
  if (currentVal) el.advSearchAccount.value = currentVal;
  await updateAdvSearchFolders();
}

async function updateAdvSearchFolders() {
  if (!el.advSearchFolder) return;
  const accountId = el.advSearchAccount ? el.advSearchAccount.value : 'ALL';
  el.advSearchFolder.innerHTML = '<option value="ALL">All Folders</option>';
  if (accountId === 'ALL' || !accountId) return;

  let folders = state.accountFolders[accountId];
  if (!folders) {
    try {
      const res = await fetch(`/api/accounts/${accountId}/folders`);
      if (res.ok) {
        folders = await res.json();
        state.accountFolders[accountId] = folders;
      }
    } catch (err) {
      console.error('Failed to load folders for advanced search:', err);
    }
  }

  if (folders && folders.length > 0) {
    folders.forEach(f => {
      const opt = document.createElement('option');
      opt.value = f.id;
      opt.textContent = f.remote_name;
      el.advSearchFolder.appendChild(opt);
    });
  }
}

function handleDatePresetClick(btn) {
  const preset = btn.dataset.preset;
  document.querySelectorAll('.btn-date-preset').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const now = new Date();
  if (preset === 'all') {
    if (el.advSearchDateFrom) el.advSearchDateFrom.value = '';
    if (el.advSearchDateTo) el.advSearchDateTo.value = '';
  } else if (preset === '7d') {
    const past = new Date();
    past.setDate(now.getDate() - 7);
    if (el.advSearchDateFrom) el.advSearchDateFrom.value = past.toISOString().split('T')[0];
    if (el.advSearchDateTo) el.advSearchDateTo.value = now.toISOString().split('T')[0];
  } else if (preset === '30d') {
    const past = new Date();
    past.setDate(now.getDate() - 30);
    if (el.advSearchDateFrom) el.advSearchDateFrom.value = past.toISOString().split('T')[0];
    if (el.advSearchDateTo) el.advSearchDateTo.value = now.toISOString().split('T')[0];
  } else if (preset === '90d') {
    const past = new Date();
    past.setDate(now.getDate() - 90);
    if (el.advSearchDateFrom) el.advSearchDateFrom.value = past.toISOString().split('T')[0];
    if (el.advSearchDateTo) el.advSearchDateTo.value = now.toISOString().split('T')[0];
  } else if (preset === 'year') {
    const startOfYear = new Date(now.getFullYear(), 0, 1);
    if (el.advSearchDateFrom) el.advSearchDateFrom.value = startOfYear.toISOString().split('T')[0];
    if (el.advSearchDateTo) el.advSearchDateTo.value = now.toISOString().split('T')[0];
  }
}

function handleResetAdvancedSearch() {
  if (el.advancedSearchForm) el.advancedSearchForm.reset();
  document.querySelectorAll('.btn-date-preset').forEach(b => {
    b.classList.toggle('active', b.dataset.preset === 'all');
  });
  if (el.advSearchFolder) {
    el.advSearchFolder.innerHTML = '<option value="ALL">All Folders</option>';
  }
}

async function handleAdvancedSearchSubmit(e) {
  e.preventDefault();

  const from = el.advSearchFrom ? el.advSearchFrom.value.trim() : '';
  const to = el.advSearchTo ? el.advSearchTo.value.trim() : '';
  const cc = el.advSearchCc ? el.advSearchCc.value.trim() : '';
  const subject = el.advSearchSubject ? el.advSearchSubject.value.trim() : '';
  const q = el.advSearchKeywords ? el.advSearchKeywords.value.trim() : '';
  const exclude = el.advSearchExclude ? el.advSearchExclude.value.trim() : '';
  const dateFrom = el.advSearchDateFrom ? el.advSearchDateFrom.value : '';
  const dateTo = el.advSearchDateTo ? el.advSearchDateTo.value : '';
  const accountId = el.advSearchAccount ? el.advSearchAccount.value : 'ALL';
  const folderId = el.advSearchFolder ? el.advSearchFolder.value : 'ALL';
  const attName = el.advSearchAttName ? el.advSearchAttName.value.trim() : '';
  const attType = el.advSearchAttType ? el.advSearchAttType.value : 'all';
  const minSizeMb = el.advSearchMinSize ? (parseFloat(el.advSearchMinSize.value) || 0) : 0;
  const hasAtt = el.advSearchHasAtt ? el.advSearchHasAtt.checked : false;
  const includeDeleted = el.advSearchIncludeDeleted ? el.advSearchIncludeDeleted.checked : false;

  const params = new URLSearchParams();
  const filterDesc = [];

  if (q) { params.set('q', q); filterDesc.push(`Keywords: "${q}"`); }
  if (from) { params.set('from', from); filterDesc.push(`From: "${from}"`); }
  if (to) { params.set('to', to); filterDesc.push(`To: "${to}"`); }
  if (cc) { params.set('cc', cc); filterDesc.push(`CC: "${cc}"`); }
  if (subject) { params.set('subject', subject); filterDesc.push(`Subject: "${subject}"`); }
  if (exclude) { params.set('exclude', exclude); filterDesc.push(`Exclude: "${exclude}"`); }
  if (dateFrom) { params.set('date_from', dateFrom); filterDesc.push(`After: ${dateFrom}`); }
  if (dateTo) { params.set('date_to', dateTo); filterDesc.push(`Before: ${dateTo}`); }
  if (accountId && accountId !== 'ALL') { params.set('account_id', accountId); }
  if (folderId && folderId !== 'ALL') { params.set('folder_id', folderId); }
  if (hasAtt) { params.set('has_attachments', 'true'); filterDesc.push('Has Attachments'); }
  if (attName) { params.set('att_name', attName); filterDesc.push(`File: "${attName}"`); }
  if (attType && attType !== 'all') { params.set('att_type', attType); filterDesc.push(`Type: ${attType}`); }
  if (minSizeMb > 0) { params.set('min_size_mb', minSizeMb); filterDesc.push(`Size > ${minSizeMb}MB`); }
  if (includeDeleted) { params.set('include_deleted', 'true'); filterDesc.push('Include Deleted'); }

  if ([...params.keys()].length === 0) {
    showToast('Please specify at least one search filter.');
    return;
  }

  closeModal(el.advancedSearchModal);
  await executeAdvancedSearch(params, filterDesc.join(' • '));
}

async function executeAdvancedSearch(params, desc) {
  if (el.globalSearch) el.globalSearch.value = '';
  el.currentFolderTitle.innerHTML = desc
    ? `<span>Filtered: ${escapeHtml(desc)}</span> <button type="button" class="btn-clear-search" id="btn-clear-search" title="Clear search and return to mailbox">✕ Clear</button>`
    : '<span>Advanced Search Results</span>';
  
  const btnClearSearch = document.getElementById('btn-clear-search');
  if (btnClearSearch) {
    btnClearSearch.addEventListener('click', () => {
      if (state.selectedFolderId) {
        loadFolderMessages(state.selectedFolderId);
      } else if (state.accounts.length > 0) {
        loadFolders(state.accounts[0].id);
      }
    });
  }

  el.emailItemsContainer.innerHTML = `<div class="empty-state"><p>Searching across archives...</p></div>`;

  try {
    const res = await fetch(`/api/search?${params.toString()}`);
    if (!res.ok) {
      showToast('Search failed');
      return;
    }
    const results = await res.json();
    state.messages = results;
    el.folderMsgCount.textContent = `${results.length} matches`;

    el.emailItemsContainer.innerHTML = '';
    if (results.length === 0) {
      el.emailItemsContainer.innerHTML = `<div class="empty-state"><div class="empty-icon">🔍</div><h3>No matches found</h3><p>Try adjusting your search criteria or date ranges.</p></div>`;
      return;
    }

    const sortedResults = applySort(results);

    sortedResults.forEach(item => {
      const card = document.createElement('div');
      card.className = `email-card ${item.message_id === state.selectedMessageId ? 'active' : ''}`;
      const dateStr = formatMailDateTime(item.date);
      const fullDateTitle = item.date ? new Date(item.date).toLocaleString() : '';

      card.innerHTML = `
        <div class="card-top-row">
          <span class="card-sender" title="${escapeHtml(item.from_addr)}">${escapeHtml(item.from_addr || '(Unknown Sender)')}</span>
          <span class="card-date" title="${escapeHtml(fullDateTitle)}">${dateStr}</span>
        </div>
        <div class="card-subject">${escapeHtml(item.subject || '(No Subject)')}</div>
        <div class="card-snippet">${item.snippet || escapeHtml(item.folder_name ? `Folder: ${item.folder_name}` : '')}</div>
      `;
      card.addEventListener('click', () => selectMessage(item.message_id));
      el.emailItemsContainer.appendChild(card);
    });
  } catch (err) {
    console.error('Advanced search error:', err);
    showToast('Error performing advanced search');
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

  updateExportDefaultPath();
}

function updateExportDefaultPath() {
  const timestamp = new Date().toISOString().split('T')[0];
  const selectedAccId = el.exportAccountSelect ? el.exportAccountSelect.value : '';
  const acc = state.accounts.find(a => a.id === selectedAccId);
  const accSlug = acc ? acc.name.replace(/[^a-zA-Z0-9_-]/g, '_') : 'backup';
  const fileName = `${accSlug}_${timestamp}.mbox`;

  const input = document.getElementById('export-output-path');
  if (!input) return;

  if (state.defaultExportDir) {
    const sep = state.defaultExportDir.includes('\\') ? '\\' : '/';
    input.value = `${state.defaultExportDir}${sep}${fileName}`;
  } else {
    input.value = fileName;
  }
}

async function handleExportMbox(e) {
  e.preventDefault();
  const rawPath = document.getElementById('export-output-path').value.trim();
  if (!rawPath) {
    showToast('Please enter an output destination path');
    return;
  }

  const payload = {
    account_id: el.exportAccountSelect.value,
    folder_id: el.exportFolderSelect.value === 'ALL' ? null : el.exportFolderSelect.value,
    output_path: rawPath,
  };

  const btn = document.getElementById('btn-export-submit');
  const originalText = btn ? btn.textContent : 'Export Archive to Disk';
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Exporting...';
  }

  try {
    const res = await fetch('/api/export/mbox', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      const result = await res.json();
      showToast(`Exported ${result.exported_count} message(s) to ${result.output_path || 'archive'}! ✅`);
      closeModal(el.exportModal);
    } else {
      const err = await res.text();
      showToast(`Export failed: ${err}`);
    }
  } catch (err) {
    showToast(`Export error: ${err.message || err}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  }
}

function handleDownloadMboxBrowser() {
  const accountId = el.exportAccountSelect.value;
  if (!accountId) {
    showToast('Please select an account to export');
    return;
  }
  const folderId = el.exportFolderSelect.value;
  showToast('Preparing .mbox archive download in browser... 📦');
  window.location.href = `/api/export/mbox/download?account_id=${encodeURIComponent(accountId)}&folder_id=${encodeURIComponent(folderId)}`;
  closeModal(el.exportModal);
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
    if (el.settingsDbPathInput) {
      el.settingsDbPathInput.value = data.db_path;
    }
    if (el.settingsDbPath) {
      el.settingsDbPath.textContent = data.db_path;
    }
    if (el.settingsCloseToTray) {
      el.settingsCloseToTray.checked = data.close_to_tray !== false;
      updateTrayBadge(el.settingsCloseToTray.checked);
    }
    if (el.settingsAutostart) {
      el.settingsAutostart.checked = !!data.autostart;
      updateAutostartBadge(data.autostart);
    }
    if (el.settingsRunAsService) {
      el.settingsRunAsService.checked = !!data.run_as_service;
    }
    if (data.service_status) {
      updateServiceBadge(data.service_status, !!data.run_as_service);
    }
    if (data.default_export_dir) {
      state.defaultExportDir = data.default_export_dir;
    }
  } catch (err) {
    console.error('Failed to load settings:', err);
  }
}

function updateTrayBadge(enabled) {
  if (!el.traySettingStatus) return;
  if (enabled) {
    el.traySettingStatus.textContent = 'Enabled';
    el.traySettingStatus.style.background = 'rgba(34, 197, 94, 0.15)';
    el.traySettingStatus.style.color = '#4ade80';
  } else {
    el.traySettingStatus.textContent = 'Disabled';
    el.traySettingStatus.style.background = 'rgba(239, 68, 68, 0.15)';
    el.traySettingStatus.style.color = '#f87171';
  }
}

function updateAutostartBadge(enabled) {
  if (!el.autostartSettingStatus) return;
  if (enabled) {
    el.autostartSettingStatus.textContent = 'Enabled';
    el.autostartSettingStatus.style.background = 'rgba(34, 197, 94, 0.15)';
    el.autostartSettingStatus.style.color = '#4ade80';
  } else {
    el.autostartSettingStatus.textContent = 'Disabled';
    el.autostartSettingStatus.style.background = 'rgba(148, 163, 184, 0.15)';
    el.autostartSettingStatus.style.color = 'var(--text-secondary)';
  }
}

function updateServiceBadge(status, configured) {
  if (!el.serviceSettingStatus) return;

  if (el.serviceDetailsBox) {
    el.serviceDetailsBox.style.display = 'block';
  }
  if (el.serviceTypeLabel && status.service_type) {
    el.serviceTypeLabel.textContent = `${status.service_type}`;
  }
  if (el.serviceDetailsText && status.details) {
    el.serviceDetailsText.textContent = status.details;
  }
  if (el.serviceManualCmd && status.manual_install_cmd) {
    el.serviceManualCmd.textContent = status.installed
      ? (status.manual_uninstall_cmd || 'Service installed')
      : status.manual_install_cmd;
  }

  if (status.installed && status.running) {
    el.serviceSettingStatus.textContent = 'Active (Running)';
    el.serviceSettingStatus.style.background = 'rgba(34, 197, 94, 0.15)';
    el.serviceSettingStatus.style.color = '#4ade80';
  } else if (status.installed) {
    el.serviceSettingStatus.textContent = 'Installed (Idle)';
    el.serviceSettingStatus.style.background = 'rgba(234, 179, 8, 0.15)';
    el.serviceSettingStatus.style.color = '#facc15';
  } else if (status.service_type === 'Unsupported') {
    el.serviceSettingStatus.textContent = 'Unsupported';
    el.serviceSettingStatus.style.background = 'rgba(239, 68, 68, 0.15)';
    el.serviceSettingStatus.style.color = '#f87171';
  } else {
    el.serviceSettingStatus.textContent = 'Not Installed';
    el.serviceSettingStatus.style.background = 'rgba(148, 163, 184, 0.15)';
    el.serviceSettingStatus.style.color = 'var(--text-secondary)';
  }
}

async function handleToggleCloseToTray(e) {
  const isChecked = e.target.checked;
  updateTrayBadge(isChecked);

  try {
    const res = await fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        close_to_tray: isChecked,
      }),
    });

    if (res.ok) {
      showToast(
        isChecked
          ? 'Background mode enabled: closing window keeps app in system tray 📥'
          : 'Background mode disabled: closing window exits application 🚪'
      );
    } else {
      const errText = await res.text();
      showToast(`Failed to update setting: ${errText}`);
      e.target.checked = !isChecked;
      updateTrayBadge(!isChecked);
    }
  } catch (err) {
    showToast(`Error updating setting: ${err.message}`);
    e.target.checked = !isChecked;
    updateTrayBadge(!isChecked);
  }
}

async function handleToggleAutostart(e) {
  const isChecked = e.target.checked;
  updateAutostartBadge(isChecked);

  try {
    const res = await fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        autostart: isChecked,
      }),
    });

    if (res.ok) {
      showToast(
        isChecked
          ? 'Autostart Enabled: MailBackup will launch on system login 🚀'
          : 'Autostart Disabled 🛑'
      );
    } else {
      const errText = await res.text();
      showToast(`Failed to update autostart: ${errText}`);
      e.target.checked = !isChecked;
      updateAutostartBadge(!isChecked);
    }
  } catch (err) {
    showToast(`Error updating autostart: ${err.message}`);
    e.target.checked = !isChecked;
    updateAutostartBadge(!isChecked);
  }
}

async function handleToggleService(e) {
  const isChecked = e.target.checked;
  showToast(isChecked ? 'Registering OS system background service... (check for admin prompt)' : 'Removing system service...');

  try {
    const res = await fetch('/api/service/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enabled: isChecked,
      }),
    });

    const data = await res.json();
    if (res.ok && data.success) {
      showToast(
        isChecked
          ? 'System Service Activated: MailBackup will run at boot without user login! ⚙️'
          : 'System Service Removed 🛑'
      );
      if (data.service_status) {
        updateServiceBadge(data.service_status, isChecked);
      }
    } else {
      showToast(`Service setup failed: ${data.message || 'Permission denied'}`);
      e.target.checked = !isChecked;
      if (data.service_status) {
        updateServiceBadge(data.service_status, !isChecked);
      }
    }
  } catch (err) {
    showToast(`Error setting service: ${err.message}`);
    e.target.checked = !isChecked;
  }
}

function handleCopyServiceCmd() {
  if (!el.serviceManualCmd) return;
  const cmd = el.serviceManualCmd.textContent;
  if (!cmd) return;
  navigator.clipboard.writeText(cmd).then(() => {
    showToast('Terminal command copied to clipboard! 📋');
  }).catch(() => {
    showToast('Failed to copy command');
  });
}

async function handleSaveStorageSettings(e) {
  e.preventDefault();
  const newDir = el.settingsDataDir.value.trim();
  const newDb = el.settingsDbPathInput ? el.settingsDbPathInput.value.trim() : '';

  if (!newDir) {
    showToast('Please enter a valid directory path');
    return;
  }

  const moveExisting = el.settingsMoveExisting ? el.settingsMoveExisting.checked : true;
  const moveDbExisting = el.settingsMoveDbExisting ? el.settingsMoveDbExisting.checked : true;
  const closeToTray = el.settingsCloseToTray ? el.settingsCloseToTray.checked : true;
  const autostartVal = el.settingsAutostart ? el.settingsAutostart.checked : false;
  const runAsServiceVal = el.settingsRunAsService ? el.settingsRunAsService.checked : false;

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
        db_path: newDb || undefined,
        move_db_existing: moveDbExisting,
        close_to_tray: closeToTray,
        autostart: autostartVal,
        run_as_service: runAsServiceVal,
      }),
    });

    if (res.ok) {
      const data = await res.json();
      if (el.settingsDataDir) el.settingsDataDir.value = data.data_dir;
      if (el.settingsDbPathInput) el.settingsDbPathInput.value = data.db_path;
      if (el.settingsDbPath) el.settingsDbPath.textContent = data.db_path;
      if (el.settingsCloseToTray) {
        el.settingsCloseToTray.checked = data.close_to_tray !== false;
        updateTrayBadge(el.settingsCloseToTray.checked);
      }
      if (el.settingsAutostart) {
        el.settingsAutostart.checked = !!data.autostart;
        updateAutostartBadge(data.autostart);
      }
      if (el.settingsRunAsService) {
        el.settingsRunAsService.checked = !!data.run_as_service;
      }
      if (data.service_status) {
        updateServiceBadge(data.service_status, !!data.run_as_service);
      }
      showToast(data.message || 'Settings saved successfully! ✅');
      await loadStats();
      if (state.selectedAccountId) {
        await loadFolders(state.selectedAccountId);
      }
    } else {
      const errText = await res.text();
      showToast(`Failed to update settings: ${errText}`);
    }
  } catch (err) {
    showToast(`Error updating settings: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

// Live Sync Progress Polling
let isSyncActive = false;
let syncPollTimer = null;

function startSyncProgressPolling() {
  checkSyncProgress();
  if (syncPollTimer) clearTimeout(syncPollTimer);
  syncPollTimer = setTimeout(startSyncProgressPolling, isSyncActive ? 750 : 2500);
}

async function checkSyncProgress() {
  try {
    const res = await fetch('/api/sync/status');
    if (!res.ok) return;
    const list = await res.json();
    const activeSync = list.find(s => s.is_syncing);

    if (activeSync) {
      isSyncActive = true;
      if (el.syncProgressBanner) el.syncProgressBanner.style.display = 'flex';

      const total = activeSync.total_messages || 0;
      const processed = activeSync.processed_messages || 0;
      const pct = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;
      const mb = (activeSync.downloaded_bytes / (1024 * 1024)).toFixed(1);

      if (el.syncStatusTitle) {
        el.syncStatusTitle.textContent = `Syncing ${activeSync.account_name}: ${activeSync.current_folder || 'Connecting...'}`;
      }
      if (el.syncStatusSubtitle) {
        if (total > 0) {
          el.syncStatusSubtitle.textContent = `${processed} / ${total} msgs (${pct}%) • ${mb} MB`;
        } else {
          el.syncStatusSubtitle.textContent = activeSync.current_folder || 'Connecting to server...';
        }
      }
      if (el.syncProgressBarFill) {
        el.syncProgressBarFill.style.width = `${total > 0 ? pct : 30}%`;
        el.syncProgressBarFill.style.background = 'linear-gradient(90deg, var(--primary), var(--accent-cyan))';
      }
    } else {
      if (isSyncActive) {
        isSyncActive = false;
        if (el.syncStatusTitle) el.syncStatusTitle.textContent = 'Sync Finished! ✅';
        if (el.syncStatusSubtitle) el.syncStatusSubtitle.textContent = 'All messages up to date';
        if (el.syncProgressBarFill) {
          el.syncProgressBarFill.style.width = '100%';
          el.syncProgressBarFill.style.background = '#22c55e';
        }
        await loadStats();
        if (state.selectedAccountId) {
          await loadFolders(state.selectedAccountId);
        }
        setTimeout(() => {
          if (!isSyncActive && el.syncProgressBanner) {
            el.syncProgressBanner.style.display = 'none';
          }
        }, 3500);
      } else if (el.syncProgressBanner && el.syncProgressBanner.style.display !== 'none') {
        el.syncProgressBanner.style.display = 'none';
      }
    }
  } catch (err) {
    console.error('Error polling sync status:', err);
  }
}

// Event Logs Functions
let cachedLogs = [];

async function loadLogs() {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    const data = await res.json();
    cachedLogs = data.logs || [];

    if (el.logsFilePath) {
      el.logsFilePath.textContent = data.path || '';
    }

    renderLogs(cachedLogs);
  } catch (err) {
    console.error('Failed to load logs:', err);
  }
}

function renderLogs(logs) {
  if (!el.logsEntriesList) return;
  const filterVal = el.logsFilter ? el.logsFilter.value : 'ALL';

  let filtered = logs;
  if (filterVal === 'ACCOUNT') {
    filtered = logs.filter(l => l.event_type.startsWith('ACCOUNT'));
  } else if (filterVal === 'SYNC') {
    filtered = logs.filter(l => l.event_type.startsWith('SYNC'));
  } else if (filterVal === 'STORAGE') {
    filtered = logs.filter(l => l.event_type.includes('MOVED') || l.event_type.includes('SETTINGS'));
  } else if (filterVal === 'ERROR') {
    filtered = logs.filter(l => l.event_type.includes('ERROR') || l.event_type.includes('FAIL'));
  }

  if (el.logsEntryCount) {
    el.logsEntryCount.textContent = `${filtered.length} of ${logs.length} events`;
  }

  if (filtered.length === 0) {
    el.logsEntriesList.innerHTML = `<div style="color: #64748B; padding: 12px 0;">No matching event entries found.</div>`;
    return;
  }

  el.logsEntriesList.innerHTML = filtered.map(item => {
    let tagClass = 'tag-system';
    const type = item.event_type;
    if (type.startsWith('ACCOUNT')) tagClass = 'tag-account';
    else if (type.includes('SUCCESS')) tagClass = 'tag-success';
    else if (type.includes('ERROR') || type.includes('FAIL')) tagClass = 'tag-error';
    else if (type.startsWith('SYNC')) tagClass = 'tag-sync';

    const timeStr = new Date(item.timestamp).toLocaleTimeString();
    const dateStr = new Date(item.timestamp).toLocaleDateString();

    return `
      <div class="log-entry-row">
        <span class="log-ts">${dateStr} ${timeStr}</span>
        <span class="log-badge ${tagClass}">[${escapeHtml(type)}]</span>
        <span class="log-msg">${escapeHtml(item.details)}</span>
      </div>
    `;
  }).join('');
}

function handleDownloadLogs() {
  window.open('/api/logs/download', '_blank');
}

async function handleClearLogs() {
  if (!confirm('Are you sure you want to clear the event logs history?')) return;
  try {
    const res = await fetch('/api/logs/clear', { method: 'POST' });
    if (res.ok) {
      showToast('Event logs cleared! 🧹');
      await loadLogs();
    } else {
      showToast('Failed to clear logs');
    }
  } catch (err) {
    showToast(`Error: ${err.message}`);
  }
}
