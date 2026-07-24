const { invoke: rawInvoke, transformCallback } = window.__TAURI_INTERNALS__ || {};

async function invoke(cmd, args) {
  if (!rawInvoke) throw new Error('Tauri IPC not available');
  return rawInvoke(cmd, args);
}

async function listen(event, handler) {
  if (!rawInvoke) return () => {};
  const id = await rawInvoke('plugin:event|listen', { event, handler: transformCallback(handler) });
  return () => rawInvoke('plugin:event|unlisten', { eventId: id });
}

const App = {
  currentPage: 'dashboard',
  connected: false,
  protocolMode: 'Auto',
  theme: localStorage.getItem('theme') || 'dark',
  sensorInterval: null,
  sensorRefreshRate: 5000,
  solConnected: false,
  solBuffer: '',
  solListener: null,

  pages: [
    { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', shortcut: 'Ctrl+1', section: 'Management' },
    { id: 'power', label: 'Power Control', icon: 'power', shortcut: 'Ctrl+2', section: 'Management' },
    { id: 'sensors', label: 'Sensor Monitor', icon: 'sensors', shortcut: 'Ctrl+3', section: 'Monitoring' },
    { id: 'sol', label: 'Serial Console', icon: 'terminal', shortcut: 'Ctrl+4', section: 'Tools' },
    { id: 'media', label: 'Virtual Media', icon: 'media', shortcut: 'Ctrl+5', section: 'Tools' },
    { id: 'sel', label: 'Event Log', icon: 'log', shortcut: 'Ctrl+6', section: 'Monitoring' },
    { id: 'fru', label: 'BIOS / FRU', icon: 'info', shortcut: 'Ctrl+7', section: 'Info' },
    { id: 'settings', label: 'Settings', icon: 'settings', shortcut: '', section: 'Config' },
  ],

  icons: {
    dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
    power: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>',
    sensors: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v10m5.66 1.34L16 16m-8-4l1.66 2.66M2 12h10m10 0H12m4.34-5.66L16 8"/></svg>',
    terminal: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
    media: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="22"/><line x1="2" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="22" y2="12"/></svg>',
    log: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  },

  init() {
    console.log('[IDM] init() called, Tauri available:', !!window.__TAURI_INTERNALS__);
    this.applyTheme();
    this.renderSidebar();
    this.bindKeyboardShortcuts();
    this.navigate('dashboard');
    this.checkConnectionStatus().then(() => {
      if (!this.connected) this.autoConnect();
    });
  },

  applyTheme() {
    document.documentElement.setAttribute('data-theme', this.theme);
  },

  async checkConnectionStatus() {
    try {
      const connected = await invoke('get_connection_status');
      this.connected = connected;
      this.updateConnectionStatus(connected);
      if (connected && this.currentPage === 'dashboard') {
        this.loadDashboard();
      }
    } catch (e) {
      this.connected = false;
      this.updateConnectionStatus(false);
    }
  },

  toggleTheme() {
    this.theme = this.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('theme', this.theme);
    this.applyTheme();
  },

  renderSidebar() {
    const sections = {};
    this.pages.forEach(p => {
      if (!sections[p.section]) sections[p.section] = [];
      sections[p.section].push(p);
    });

    const nav = document.getElementById('sidebar-nav');
    nav.innerHTML = Object.entries(sections).map(([section, pages]) => `
      <div class="nav-section">
        <div class="nav-section-title">${section}</div>
        ${pages.map(p => `
          <div class="nav-item" data-page="${p.id}" onclick="App.navigate('${p.id}')">
            ${this.icons[p.icon]}
            <span>${p.label}</span>
            ${p.shortcut ? `<span class="shortcut">${p.shortcut.replace('Ctrl+', '')}</span>` : ''}
          </div>
        `).join('')}
      </div>
    `).join('');
  },

  navigate(pageId) {
    console.log('[IDM] navigate called:', pageId);
    this.currentPage = pageId;

    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.page === pageId);
    });

    const page = this.pages.find(p => p.id === pageId);
    document.getElementById('page-title').textContent = page?.label || '';

    this.renderPage(pageId);
    console.log('[IDM] navigate done:', pageId);
  },

  renderPage(pageId) {
    const body = document.getElementById('page-body');
    const headerActions = document.getElementById('page-actions');
    headerActions.innerHTML = '';

    switch (pageId) {
      case 'dashboard': this.renderDashboard(body, headerActions); break;
      case 'power': this.renderPower(body, headerActions); break;
      case 'sensors': this.renderSensors(body, headerActions); break;
      case 'sol': this.renderSOL(body, headerActions); break;
      case 'media': this.renderVirtualMedia(body, headerActions); break;
      case 'sel': this.renderSEL(body, headerActions); break;
      case 'fru': this.renderFRU(body, headerActions); break;
      case 'settings': this.renderSettings(body, headerActions); break;
    }
  },

  renderDashboard(body, actions) {
    actions.innerHTML = `
      <button class="btn btn-secondary btn-sm" onclick="App.loadDashboard()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        Refresh
      </button>
    `;

    body.innerHTML = `
      <div class="stat-grid" id="dashboard-stats">
        <div class="stat-card"><div class="stat-label">Power State</div><div class="stat-value small" id="d-power">--</div></div>
        <div class="stat-card"><div class="stat-label">Server</div><div class="stat-value small" id="d-server">--</div></div>
        <div class="stat-card"><div class="stat-label">BMC Firmware</div><div class="stat-value small" id="d-bmc">--</div></div>
        <div class="stat-card"><div class="stat-label">BIOS Version</div><div class="stat-value small" id="d-bios">--</div></div>
        <div class="stat-card"><div class="stat-label">CPU Temp</div><div class="stat-value" id="d-cpu-temp">--<span class="stat-unit">°C</span></div></div>
        <div class="stat-card"><div class="stat-label">Power Draw</div><div class="stat-value" id="d-power-draw">--<span class="stat-unit">W</span></div></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">Fan Status</div>
        </div>
        <div id="d-fans"><div class="empty-state"><div class="spinner"></div></div></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">Temperature Sensors</div>
        </div>
        <div id="d-temps"><div class="empty-state"><div class="spinner"></div></div></div>
      </div>
    `;
    this.loadDashboard();
  },

  async loadDashboard() {
    if (!this.connected) {
      ['d-power','d-server','d-bmc','d-bios','d-cpu-temp','d-power-draw'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '--';
      });
      this.showNotConnected('d-fans');
      this.showNotConnected('d-temps');
      return;
    }

    try {
      const data = await invoke('get_dashboard');

      if (data.system) {
        document.getElementById('d-server').textContent = data.system.model || 'Unknown';
        document.getElementById('d-power').textContent = data.system.power_state || 'Unknown';
      }
      if (data.firmware) {
        document.getElementById('d-bmc').textContent = data.firmware.bmc_version || 'N/A';
        document.getElementById('d-bios').textContent = data.firmware.bios_version || 'N/A';
      }
      if (data.power?.power_consumed_watts) {
        document.getElementById('d-power-draw').innerHTML = `${Math.round(data.power.power_consumed_watts)}<span class="stat-unit">W</span>`;
      }
      if (data.thermal) {
        const cpuTemp = data.thermal.temperatures.find(t => t.name.toLowerCase().includes('cpu'));
        if (cpuTemp?.reading_celsius) {
          document.getElementById('d-cpu-temp').innerHTML = `${Math.round(cpuTemp.reading_celsius)}<span class="stat-unit">°C</span>`;
        }

        document.getElementById('d-fans').innerHTML = data.thermal.fans.length ? `
          <div class="table-container">
            <table>
              <thead><tr><th>Fan</th><th>Speed</th><th>Status</th></tr></thead>
              <tbody>
                ${data.thermal.fans.map(f => `
                  <tr>
                    <td>${f.name}</td>
                    <td>${f.reading ?? '--'} ${f.reading_units || 'RPM'}</td>
                    <td><span class="badge badge-${this.healthBadge(f.status?.health)}">${f.status?.health || 'Unknown'}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        ` : '<div class="empty-state"><div class="empty-state-text">No fan data available</div></div>';

        document.getElementById('d-temps').innerHTML = data.thermal.temperatures.length ? `
          <div class="table-container">
            <table>
              <thead><tr><th>Sensor</th><th>Temperature</th><th>Status</th></tr></thead>
              <tbody>
                ${data.thermal.temperatures.map(t => `
                  <tr>
                    <td>${t.name}</td>
                    <td>${t.reading_celsius ?? '--'} °C</td>
                    <td><span class="badge badge-${this.healthBadge(t.status?.health)}">${t.status?.health || 'Unknown'}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        ` : '<div class="empty-state"><div class="empty-state-text">No temperature data available</div></div>';
      }
    } catch (e) {
      this.toast('Failed to load dashboard: ' + e, 'error');
    }
  },

  renderPower(body, actions) {
    const isRedfish = this.connected && (this.protocolMode === 'Auto' || this.protocolMode === 'Redfish Only');
    body.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Power State</div>
          <span class="badge badge-info" id="power-state-badge">${this.connected ? 'Checking...' : 'Unknown'}</span>
        </div>
        <div class="power-controls">
          <button class="power-btn" onclick="App.powerAction('power_on')" ${!this.connected ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
            <span class="power-btn-label">Power On</span>
          </button>
          <button class="power-btn warning" onclick="App.powerAction('graceful_shutdown')" ${!this.connected ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><line x1="7" y1="11" x2="7" y2="3"/></svg>
            <span class="power-btn-label">Graceful Shutdown</span>
          </button>
          <button class="power-btn danger" onclick="App.powerAction('power_off')" ${!this.connected ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"/></svg>
            <span class="power-btn-label">Force Off</span>
          </button>
          <button class="power-btn" onclick="App.powerAction('power_cycle')" ${!this.connected ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            <span class="power-btn-label">Power Cycle</span>
          </button>
          <button class="power-btn warning" onclick="App.powerAction('hard_reset')" ${!this.connected ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>
            <span class="power-btn-label">Hard Reset</span>
          </button>
        </div>
      </div>
      ${isRedfish ? `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Boot Override</div>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="btn btn-outline" onclick="App.setBoot('Cd', false)">Boot from Virtual CD</button>
          <button class="btn btn-outline" onclick="App.setBoot('Hdd', false)">Boot from HDD</button>
          <button class="btn btn-outline" onclick="App.setBoot('Pxe', false)">Boot from PXE</button>
          <button class="btn btn-outline" onclick="App.setBoot('Cd', true)">Boot from CD (Persistent)</button>
        </div>
      </div>
      ` : ''}
    `;

    if (this.connected) {
      this.loadPowerState();
    }
  },

  async loadPowerState() {
    try {
      const data = await invoke('get_dashboard');
      const badge = document.getElementById('power-state-badge');
      if (badge && data.power_state) {
        const ps = data.power_state.toLowerCase();
        badge.textContent = data.power_state;
        badge.className = `badge badge-${ps === 'on' ? 'success' : ps === 'off' ? 'danger' : 'warning'}`;
      }
    } catch (e) {
      const badge = document.getElementById('power-state-badge');
      if (badge) badge.textContent = 'Unknown';
    }
  },

  async powerAction(action) {
    if (!this.connected) {
      this.toast('Not connected to BMC', 'warning');
      return;
    }
    try {
      await invoke(action);
      this.toast(`Power command sent: ${action.replace(/_/g, ' ')}`, 'success');
    } catch (e) {
      this.toast(`Failed: ${e}`, 'error');
    }
  },

  async setBoot(target, persistent) {
    if (!this.connected) {
      this.toast('Not connected to BMC', 'warning');
      return;
    }
    try {
      await invoke('set_boot_device', { target, persistent });
      this.toast(`Boot device set to ${target}`, 'success');
    } catch (e) {
      this.toast(`Failed: ${e}`, 'error');
    }
  },

  renderSensors(body, actions) {
    actions.innerHTML = `
      <div class="refresh-bar">
        <div class="refresh-interval">
          <button class="interval-btn ${this.sensorRefreshRate===2000?'active':''}" onclick="App.setRefreshRate(2000)">2s</button>
          <button class="interval-btn ${this.sensorRefreshRate===5000?'active':''}" onclick="App.setRefreshRate(5000)">5s</button>
          <button class="interval-btn ${this.sensorRefreshRate===10000?'active':''}" onclick="App.setRefreshRate(10000)">10s</button>
          <button class="interval-btn ${this.sensorRefreshRate===30000?'active':''}" onclick="App.setRefreshRate(30000)">30s</button>
        </div>
        <label class="form-check">
          <div class="toggle ${this.sensorInterval ? 'active' : ''}" id="auto-refresh-toggle" onclick="App.toggleAutoRefresh()"></div>
          <span>Auto-refresh</span>
        </label>
        <button class="btn btn-secondary btn-sm" onclick="App.loadSensors()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Refresh
        </button>
      </div>
    `;

    body.innerHTML = '<div class="sensor-grid" id="sensor-grid"><div class="empty-state"><div class="spinner"></div></div></div>';
    this.loadSensors();
  },

  setRefreshRate(ms) {
    this.sensorRefreshRate = ms;
    document.querySelectorAll('.interval-btn').forEach(b => {
      b.classList.toggle('active', parseInt(b.textContent) * 1000 === ms || parseInt(b.textContent) === ms / 1000);
    });
    if (this.sensorInterval) {
      clearInterval(this.sensorInterval);
      this.sensorInterval = setInterval(() => this.loadSensors(), ms);
    }
  },

  toggleAutoRefresh() {
    const toggle = document.getElementById('auto-refresh-toggle');
    if (this.sensorInterval) {
      clearInterval(this.sensorInterval);
      this.sensorInterval = null;
      toggle?.classList.remove('active');
    } else {
      this.sensorInterval = setInterval(() => this.loadSensors(), this.sensorRefreshRate);
      toggle?.classList.add('active');
    }
  },

  async loadSensors() {
    if (!this.connected) {
      const grid = document.getElementById('sensor-grid');
      if (grid) {
        grid.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="2" x2="22" y2="22"/></svg><div class="empty-state-title">Not connected</div><div class="empty-state-text">Connect to a BMC to view sensor readings</div></div>';
      }
      return;
    }

    try {
      const sensors = await invoke('get_sensors');
      const grid = document.getElementById('sensor-grid');
      if (!grid) return;

      if (!sensors.length) {
        grid.innerHTML = '<div class="empty-state"><div class="empty-state-title">No sensor data</div><div class="empty-state-text">No sensors found on this system</div></div>';
        return;
      }

      grid.innerHTML = sensors.map(s => {
        const health = s.status?.toLowerCase() || 'ok';
        const color = health === 'critical' ? 'var(--danger)' : health === 'warning' ? 'var(--warning)' : 'var(--success)';
        const value = s.value !== null ? s.value.toFixed(1) : '--';
        return `
          <div class="sensor-card" style="border-left: 3px solid ${color}">
            <div class="sensor-card-header">
              <span class="sensor-name">${s.name}</span>
              <span class="badge badge-${health === 'critical' ? 'danger' : health === 'warning' ? 'warning' : 'success'}">${health}</span>
            </div>
            <div class="sensor-value" style="color: ${color}">${value}<span class="stat-unit">${s.unit}</span></div>
            ${s.upper_critical && s.value !== null ? `<div class="sensor-bar"><div class="sensor-bar-fill" style="width: ${Math.min(100, (s.value / s.upper_critical) * 100)}%; background: ${color}"></div></div>` : ''}
          </div>
        `;
      }).join('');
    } catch (e) {
      const grid = document.getElementById('sensor-grid');
      if (grid) {
        grid.innerHTML = `<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="2" x2="22" y2="22"/></svg><div class="empty-state-title">Sensor data unavailable</div><div class="empty-state-text">${e}</div></div>`;
      }
    }
  },

  renderSOL(body, actions) {
    actions.innerHTML = `
      <button class="btn ${this.solConnected ? 'btn-danger' : 'btn-success'} btn-sm" onclick="App.toggleSOL()">
        ${this.solConnected ? 'Disconnect' : 'Connect'}
      </button>
    `;

    body.innerHTML = `
      <div class="terminal-container">
        <div class="terminal-header">
          <div class="terminal-dots">
            <div class="terminal-dot red"></div>
            <div class="terminal-dot yellow"></div>
            <div class="terminal-dot green"></div>
          </div>
          <div class="terminal-title">Serial-over-LAN Console ${this.solConnected ? '(Connected)' : '(Disconnected)'}</div>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-outline btn-sm" onclick="App.clearTerminal()">Clear</button>
          </div>
        </div>
        <div class="terminal-output" id="sol-output">Serial-over-LAN Console\n${this.solConnected ? 'Connected to BMC serial port.' : 'Click Connect to start a SOL session.'}\n\n</div>
        <div class="terminal-input">
          <input type="text" id="sol-input" placeholder="${this.solConnected ? 'Type commands...' : 'Connect first...'}" ${this.solConnected ? '' : 'disabled'} onkeydown="if(event.key==='Enter')App.sendSOLInput()" />
          <button class="btn btn-primary btn-sm" onclick="App.sendSOLInput()" ${this.solConnected ? '' : 'disabled'}>Send</button>
        </div>
      </div>
    `;
  },

  async toggleSOL() {
    try {
      if (this.solConnected) {
        await invoke('sol_deactivate');
        await invoke('stop_sol_output_stream');
        if (this.solListener) {
          this.solListener();
          this.solListener = null;
        }
        this.solConnected = false;
        this.appendSOL('\n[Session closed]\n');
      } else {
        await invoke('sol_activate');
        this.solConnected = true;
        this.solListener = await listen('sol-output', (event) => {
          this.appendSOL(event.payload);
        });
        await invoke('start_sol_output_stream');
        this.appendSOL('\n[Session started]\n');
      }
      this.renderPage('sol');
    } catch (e) {
      this.toast('SOL error: ' + e, 'error');
    }
  },

  appendSOL(text) {
    const output = document.getElementById('sol-output');
    if (output) {
      output.textContent += text;
      output.scrollTop = output.scrollHeight;
    }
  },

  clearTerminal() {
    const output = document.getElementById('sol-output');
    if (output) output.textContent = '';
  },

  async sendSOLInput() {
    const input = document.getElementById('sol-input');
    if (!input || !input.value) return;
    try {
      await invoke('sol_send_input', { input: input.value });
      this.appendSOL(input.value + '\n');
      input.value = '';
    } catch (e) {
      this.toast('SOL input error: ' + e, 'error');
    }
  },

  renderVirtualMedia(body, actions) {
    const isRedfish = this.connected && (this.protocolMode === 'Auto' || this.protocolMode === 'Redfish Only');
    body.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Virtual Media Mount</div>
        </div>
        ${!isRedfish ? '<div class="empty-state" style="padding: 24px;"><div class="empty-state-title">Redfish required</div><div class="empty-state-text">Virtual Media requires a Redfish connection</div></div>' : `
        <div class="form-group">
          <label class="form-label">Slot</label>
          <select class="form-input" id="vm-slot">
            <option value="CD1">CD1</option>
            <option value="CD2">CD2</option>
            <option value="Floppy">Floppy</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Image URL or File Path</label>
          <input type="text" class="form-input" id="vm-url" placeholder="https://example.com/image.iso or C:\\path\\to\\image.iso" />
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-primary" onclick="App.mountMedia()">Mount</button>
          <button class="btn btn-danger" onclick="App.unmountMedia()">Unmount</button>
          <button class="btn btn-secondary" onclick="App.refreshMedia()">Refresh Status</button>
        </div>
        `}
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">Current Status</div>
        </div>
        <div id="vm-status"><div class="empty-state"><div class="empty-state-text">${isRedfish ? 'Click Refresh to check status' : 'Connect via Redfish to use Virtual Media'}</div></div></div>
      </div>
    `;
  },

  async mountMedia() {
    const slot = document.getElementById('vm-slot')?.value;
    const url = document.getElementById('vm-url')?.value;
    if (!url) { this.toast('Enter an image URL', 'warning'); return; }
    try {
      await invoke('mount_virtual_media', { slot, imageUrl: url, inserted: true });
      this.toast('Virtual media mounted', 'success');
      this.refreshMedia();
    } catch (e) {
      this.toast('Mount failed: ' + e, 'error');
    }
  },

  async unmountMedia() {
    const slot = document.getElementById('vm-slot')?.value;
    try {
      await invoke('unmount_virtual_media', { slot });
      this.toast('Virtual media unmounted', 'success');
      this.refreshMedia();
    } catch (e) {
      this.toast('Unmount failed: ' + e, 'error');
    }
  },

  async refreshMedia() {
    try {
      const status = await invoke('get_virtual_media_status');
      const el = document.getElementById('vm-status');
      if (!el) return;
      if (!status.length) {
        el.innerHTML = '<div class="empty-state"><div class="empty-state-text">No virtual media slots found</div></div>';
        return;
      }
      el.innerHTML = `
        <div class="table-container">
          <table>
            <thead><tr><th>Slot</th><th>Image</th><th>Inserted</th><th>Write Protected</th></tr></thead>
            <tbody>
              ${status.map((s, i) => `
                <tr>
                  <td>CD${i + 1}</td>
                  <td>${s.image || 'Empty'}</td>
                  <td><span class="badge badge-${s.inserted ? 'success' : 'info'}">${s.inserted ? 'Yes' : 'No'}</span></td>
                  <td>${s.write_protected ? 'Yes' : 'No'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch (e) {
      this.toast('Failed to get media status: ' + e, 'error');
    }
  },

  renderSEL(body, actions) {
    const isRedfish = this.connected && (this.protocolMode === 'Auto' || this.protocolMode === 'Redfish Only');
    actions.innerHTML = `
      <button class="btn btn-secondary btn-sm" onclick="App.loadSEL()" ${!this.connected ? 'disabled' : ''}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        Refresh
      </button>
      <button class="btn btn-secondary btn-sm" onclick="App.exportSEL()" ${!this.connected ? 'disabled' : ''}>Export CSV</button>
      ${isRedfish ? `<button class="btn btn-danger btn-sm" onclick="App.confirmClearSEL()">Clear Log</button>` : ''}
    `;

    body.innerHTML = `
      <div class="form-row" style="margin-bottom: 16px;">
        <div class="form-group">
          <label class="form-label">Filter by Severity</label>
          <select class="form-input" id="sel-filter" onchange="App.filterSEL()">
            <option value="all">All</option>
            <option value="Critical">Critical</option>
            <option value="Warning">Warning</option>
            <option value="OK">Info</option>
          </select>
        </div>
      </div>
      <div id="sel-entries"><div class="empty-state"><div class="spinner"></div></div></div>
    `;
    this.loadSEL();
  },

  selData: [],

  async loadSEL() {
    if (!this.connected) {
      this.showNotConnected('sel-entries');
      return;
    }

    try {
      this.selData = await invoke('get_sel_entries');
      this.filterSEL();
    } catch (e) {
      const el = document.getElementById('sel-entries');
      if (el) {
        el.innerHTML = `<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="2" x2="22" y2="22"/></svg><div class="empty-state-title">Event log unavailable</div><div class="empty-state-text">${e}</div></div>`;
      }
    }
  },

  filterSEL() {
    if (!this.connected || !this.selData) return;
    const filter = document.getElementById('sel-filter')?.value || 'all';
    const entries = filter === 'all' ? this.selData : this.selData.filter(e => e.severity === filter);
    const el = document.getElementById('sel-entries');
    if (!el) return;

    if (!entries.length) {
      el.innerHTML = '<div class="empty-state"><div class="empty-state-title">No events</div><div class="empty-state-text">System event log is empty or no events match the filter</div></div>';
      return;
    }

    el.innerHTML = `
      <div class="table-container" style="max-height: 500px; overflow-y: auto;">
        <table>
          <thead><tr><th>ID</th><th>Severity</th><th>Date</th><th>Message</th></tr></thead>
          <tbody>
            ${entries.map(e => `
              <tr>
                <td>${e.id}</td>
                <td><span class="badge badge-${e.severity === 'Critical' ? 'danger' : e.severity === 'Warning' ? 'warning' : 'success'}">${e.severity}</span></td>
                <td style="white-space:nowrap">${e.created || '--'}</td>
                <td>${e.message}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  exportSEL() {
    if (!this.selData.length) { this.toast('No data to export', 'warning'); return; }
    const csv = 'ID,Severity,Created,Message\n' + this.selData.map(e =>
      `"${e.id}","${e.severity}","${e.created}","${e.message}"`
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sel_export_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    this.toast('SEL exported to CSV', 'success');
  },

  confirmClearSEL() {
    this.showModal('Clear System Event Log', 'Are you sure you want to clear the BMC event log? This action cannot be undone.', async () => {
      try {
        await invoke('clear_sel');
        this.toast('SEL cleared', 'success');
        this.loadSEL();
      } catch (e) {
        this.toast('Failed to clear SEL: ' + e, 'error');
      }
    });
  },

  renderFRU(body, actions) {
    actions.innerHTML = `
      <button class="btn btn-secondary btn-sm" onclick="App.loadFRU()">Refresh</button>
    `;
    body.innerHTML = '<div id="fru-content"><div class="empty-state"><div class="spinner"></div></div></div>';
    this.loadFRU();
  },

  async loadFRU() {
    if (!this.connected) {
      const el = document.getElementById('fru-content');
      if (el) {
        el.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="2" x2="22" y2="22"/></svg><div class="empty-state-title">Not connected</div><div class="empty-state-text">Connect to a BMC to view hardware information</div></div>';
      }
      return;
    }

    try {
      const fru = await invoke('get_fru_info');
      const el = document.getElementById('fru-content');
      if (!el) return;

      if (!fru.board && !fru.product && !fru.chassis) {
        el.innerHTML = '<div class="empty-state"><div class="empty-state-title">No FRU data</div><div class="empty-state-text">No field-replaceable unit information found</div></div>';
        return;
      }

      el.innerHTML = `
        <div class="fru-grid">
          ${fru.board ? `
            <div class="fru-card">
              <div class="fru-card-title">Board Information</div>
              <div class="fru-row"><span class="fru-label">Name</span><span class="fru-value">${fru.board.name}</span></div>
              <div class="fru-row"><span class="fru-label">Manufacturer</span><span class="fru-value">${fru.board.manufacturer || '--'}</span></div>
              <div class="fru-row"><span class="fru-label">Serial Number</span><span class="fru-value">${fru.board.serial_number || '--'}</span></div>
              <div class="fru-row"><span class="fru-label">Part Number</span><span class="fru-value">${fru.board.part_number || '--'}</span></div>
            </div>
          ` : ''}
          ${fru.product ? `
            <div class="fru-card">
              <div class="fru-card-title">Product Information</div>
              <div class="fru-row"><span class="fru-label">Name</span><span class="fru-value">${fru.product.name}</span></div>
              <div class="fru-row"><span class="fru-label">Manufacturer</span><span class="fru-value">${fru.product.manufacturer || '--'}</span></div>
              <div class="fru-row"><span class="fru-label">Version</span><span class="fru-value">${fru.product.version || '--'}</span></div>
              <div class="fru-row"><span class="fru-label">Serial Number</span><span class="fru-value">${fru.product.serial_number || '--'}</span></div>
            </div>
          ` : ''}
          ${fru.chassis ? `
            <div class="fru-card">
              <div class="fru-card-title">Chassis Information</div>
              <div class="fru-row"><span class="fru-label">Name</span><span class="fru-value">${fru.chassis.name}</span></div>
              <div class="fru-row"><span class="fru-label">Serial Number</span><span class="fru-value">${fru.chassis.serial_number || '--'}</span></div>
              <div class="fru-row"><span class="fru-label">Part Number</span><span class="fru-value">${fru.chassis.part_number || '--'}</span></div>
            </div>
          ` : ''}
        </div>
      `;
    } catch (e) {
      const el = document.getElementById('fru-content');
      if (el) {
        el.innerHTML = `<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="2" x2="22" y2="22"/></svg><div class="empty-state-title">Hardware info unavailable</div><div class="empty-state-text">${e}</div></div>`;
      }
    }
  },

  renderSettings(body, actions) {
    console.log('[IDM] renderSettings called, body:', !!body);
    body.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Connection</div>
        </div>
        <div class="form-group">
          <label class="form-label">BMC IP Address or FQDN</label>
          <input type="text" class="form-input" id="set-host" placeholder="192.168.1.100" />
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Port</label>
            <input type="number" class="form-input" id="set-port" value="443" />
          </div>
          <div class="form-group">
            <label class="form-label">Protocol Mode</label>
            <select class="form-input" id="set-protocol">
              <option value="Auto">Auto</option>
              <option value="Redfish Only">Redfish Only</option>
              <option value="IPMI Only">IPMI Only</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Username</label>
          <input type="text" class="form-input" id="set-username" placeholder="ADMIN" />
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <input type="password" class="form-input" id="set-password" placeholder="Password" />
        </div>
        <div class="form-group">
          <label class="form-check">
            <input type="checkbox" id="set-skip-tls" />
            <span>Skip TLS certificate verification (for self-signed certs)</span>
          </label>
        </div>
        <div class="form-group">
          <label class="form-check">
            <input type="checkbox" id="set-save-creds" checked />
            <span>Save credentials to system keychain</span>
          </label>
        </div>
        <div class="form-group">
          <label class="form-check">
            <input type="checkbox" id="set-auto-connect" checked />
            <span>Auto-connect on launch</span>
          </label>
        </div>
        <div style="display: flex; gap: 8px; margin-top: 16px;">
          <button class="btn btn-primary" id="connect-btn" onclick="App.doConnect()">Connect</button>
          <button class="btn btn-danger" onclick="App.doDisconnect()" ${!this.connected ? 'disabled' : ''}>Disconnect</button>
          <button class="btn btn-outline" onclick="App.doDeleteSavedCredentials()">Clear Saved</button>
          ${this.connected ? '<button class="btn btn-secondary" onclick="App.runRedfishDiagnostics()">Test Redfish</button>' : ''}
        </div>
      </div>
      ${this.connected ? `
      <div class="card" id="redfish-diagnostics" style="display:none;">
        <div class="card-header">
          <div class="card-title">Redfish Diagnostics</div>
        </div>
        <div id="redfish-diag-results"><div class="spinner"></div></div>
      </div>
      ` : ''}
      <div class="card">
        <div class="card-header">
          <div class="card-title">Appearance</div>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="font-size: 13px; color: var(--text-secondary);">Theme</span>
          <button class="btn btn-outline btn-sm" onclick="App.toggleTheme()">
            ${this.theme === 'dark' ? 'Switch to Light' : 'Switch to Dark'}
          </button>
        </div>
      </div>
    `;
    this.loadSavedCredentials();
  },

  async loadSavedCredentials() {
    try {
      const result = await invoke('load_credentials');
      if (result) {
        const [creds, password] = result;
        const setHost = document.getElementById('set-host');
        const setPort = document.getElementById('set-port');
        const setUsername = document.getElementById('set-username');
        const setPassword = document.getElementById('set-password');
        const setProtocol = document.getElementById('set-protocol');
        const setSkipTls = document.getElementById('set-skip-tls');
        const setAutoConnect = document.getElementById('set-auto-connect');
        if (setHost) setHost.value = creds.host || '';
        if (setPort) setPort.value = creds.port || 443;
        if (setUsername) setUsername.value = creds.username || '';
        if (setProtocol) setProtocol.value = creds.protocol_mode || 'Auto';
        if (setSkipTls) setSkipTls.checked = creds.skip_tls_verify || false;
        if (setPassword && password) setPassword.value = password;
        if (setAutoConnect) {
          const ac = localStorage.getItem('auto_connect');
          setAutoConnect.checked = ac !== 'false';
        }
      }
    } catch (e) {
      console.warn('Failed to load saved credentials:', e);
    }
  },

  async doConnect() {
    const host = document.getElementById('set-host')?.value;
    const port = parseInt(document.getElementById('set-port')?.value || '443');
    const username = document.getElementById('set-username')?.value;
    const password = document.getElementById('set-password')?.value;
    const protocol_mode = document.getElementById('set-protocol')?.value || 'Auto';
    const skip_tls_verify = document.getElementById('set-skip-tls')?.checked ?? true;
    const save_credentials = document.getElementById('set-save-creds')?.checked || false;
    const auto_connect = document.getElementById('set-auto-connect')?.checked || false;

    localStorage.setItem('auto_connect', auto_connect ? 'true' : 'false');

    if (!host || !username) {
      this.toast('Host and username are required', 'warning');
      return;
    }

    try {
      const btn = document.getElementById('connect-btn');
      if (btn) { btn.textContent = 'Connecting...'; btn.disabled = true; }
      await invoke('connect', { params: { host, port, username, password: password || '', protocol_mode, skip_tls_verify, save_credentials } });
      this.connected = true;
      this.protocolMode = protocol_mode;
      this.updateConnectionStatus(true);
      this.toast('Connected to BMC', 'success');
      if (this.currentPage === 'dashboard') this.loadDashboard();
    } catch (e) {
      this.toast('Connection failed: ' + e, 'error');
    } finally {
      const btn = document.getElementById('connect-btn');
      if (btn) { btn.textContent = 'Connect'; btn.disabled = false; }
    }
  },

  async doDisconnect() {
    try {
      await invoke('disconnect');
      this.connected = false;
      this.protocolMode = 'Auto';
      this.updateConnectionStatus(false);
      this.toast('Disconnected', 'success');
      if (this.currentPage === 'dashboard') this.loadDashboard();
    } catch (e) {
      this.toast('Disconnect failed: ' + e, 'error');
    }
  },

  async doDeleteSavedCredentials() {
    try {
      await invoke('delete_saved_credentials');
      this.toast('Saved credentials cleared', 'success');
    } catch (e) {
      this.toast('Failed to clear saved credentials: ' + e, 'error');
    }
  },

  updateConnectionStatus(connected) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (dot) {
      dot.classList.toggle('connected', connected);
    }
    if (text) {
      if (connected) {
        text.textContent = `Connected (${this.protocolMode})`;
      } else {
        text.textContent = 'Disconnected';
      }
    }
  },

  toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = '0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  },

  showModal(title, body, onConfirm) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal">
        <div class="modal-title">${title}</div>
        <div class="modal-body">${body}</div>
        <div class="modal-actions">
          <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
          <button class="btn btn-danger" id="modal-confirm">Confirm</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-confirm').addEventListener('click', () => {
      overlay.remove();
      onConfirm();
    });
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.remove();
    });
  },

  showNotConnected(containerId) {
    const el = document.getElementById(containerId);
    if (el) {
      el.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="2" x2="22" y2="22"/></svg><div class="empty-state-title">Not connected</div><div class="empty-state-text">Connect to a BMC to view data</div></div>';
    }
  },

  showRedfishRequired(containerId) {
    const el = document.getElementById(containerId);
    if (el) {
      el.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><div class="empty-state-title">Redfish required</div><div class="empty-state-text">This feature requires a Redfish connection</div></div>';
    }
  },

  healthBadge(health) {
    if (!health) return 'info';
    const h = health.toLowerCase();
    if (h === 'critical') return 'danger';
    if (h === 'warning') return 'warning';
    return 'success';
  },

  async runRedfishDiagnostics() {
    const panel = document.getElementById('redfish-diagnostics');
    const results = document.getElementById('redfish-diag-results');
    if (panel) panel.style.display = 'block';
    if (results) results.innerHTML = '<div class="spinner"></div>';

    try {
      const data = await invoke('test_redfish');
      if (results) {
        results.innerHTML = `<div class="table-container"><table><thead><tr><th>Endpoint</th><th>Result</th></tr></thead><tbody>
          ${Object.entries(data).map(([k, v]) => `<tr><td><code>${k}</code></td><td><code>${v}</code></td></tr>`).join('')}
        </tbody></table></div>`;
      }
    } catch (e) {
      if (results) {
        results.innerHTML = `<div class="empty-state"><div class="empty-state-title">Diagnostics failed</div><div class="empty-state-text">${e}</div></div>`;
      }
    }
  },

  async autoConnect() {
    try {
      const result = await invoke('load_credentials');
      if (!result) return false;
      const [creds, password] = result;
      if (!creds || !creds.host || !password) return false;

      const autoConnectEnabled = localStorage.getItem('auto_connect');
      if (autoConnectEnabled === 'false') return false;

      console.log('[IDM] Auto-connecting to', creds.host);
      this.toast('Auto-connecting to ' + creds.host + '...', 'info');

      await invoke('connect', {
        params: {
          host: creds.host,
          port: creds.port || 443,
          username: creds.username,
          password: password,
          protocol_mode: creds.protocol_mode || 'Auto',
          skip_tls_verify: creds.skip_tls_verify ?? true,
          save_credentials: false,
        }
      });

      this.connected = true;
      this.protocolMode = creds.protocol_mode || 'Auto';
      this.updateConnectionStatus(true);
      this.toast('Auto-connected to ' + creds.host, 'success');
      if (this.currentPage === 'dashboard') this.loadDashboard();
      return true;
    } catch (e) {
      console.warn('[IDM] Auto-connect failed:', e);
      return false;
    }
  },

  bindKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key >= '1' && e.key <= '7') {
        e.preventDefault();
        const idx = parseInt(e.key) - 1;
        if (this.pages[idx]) this.navigate(this.pages[idx].id);
      }
      if (e.ctrlKey && e.key.toLowerCase() === 'r') {
        e.preventDefault();
        if (this.currentPage === 'sensors') this.loadSensors();
        if (this.currentPage === 'dashboard') this.loadDashboard();
      }
      if (e.ctrlKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        if (this.currentPage === 'sol') this.toggleSOL();
      }
    });
  },
};

document.addEventListener('DOMContentLoaded', () => App.init());
