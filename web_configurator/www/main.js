// Device Configurator frontend logic.
//
// This script handles tab switching, form submission and periodic
// fetching of statistics.  It is written using vanilla JavaScript so
// that it can run on an embedded system without any external
// dependencies.  All fetch calls are directed to the local API
// endpoints (e.g. `/api/get_all`, `/api/get_stat`) and send/receive
// JSON payloads.

(() => {
    // Global mutable state for configuration and statistics.  After
    // calling `/api/get_all` the response is stored here so the UI
    // can be repopulated when necessary.
    let state = {};

    // Dirty tracking for enabling/disabling Save buttons.
    // Each group keeps a baseline snapshot; when current form values differ,
    // the corresponding Save button is enabled.
    const baselines = {
        halow: '',
        lbt: '',
        net: '',
        tcp: ''
    };

    function jsonSnapshot(obj) {
        return JSON.stringify(obj, Object.keys(obj).sort());
    }

    function readHalowForm() {
        return {
            power_dbm: parseFloat(document.getElementById('halow_power_dbm').value),
            central_freq: parseFloat(document.getElementById('halow_central_freq').value),
            mcs_index: document.getElementById('halow_mcs_index').value,
            bandwidth: document.getElementById('halow_bandwidth').value,
            super_power: document.getElementById('halow_super_power').checked
        };
    }

    function readLbtForm() {
        return {
            uen: document.getElementById('lbt_uen').checked,
            umax: parseInt(document.getElementById('lbt_umax').value, 10)
        };
    }

    function readNetForm() {
        return {
            dhcp: document.getElementById('net_dhcp').checked,
            ip_address: document.getElementById('net_ip_address').value,
            gw_address: document.getElementById('net_gw_address').value,
            netmask: document.getElementById('net_netmask').value
        };
    }

    function readTcpForm() {
        return {
            enable: document.getElementById('tcp_enable').checked,
            port: parseInt(document.getElementById('tcp_port').value, 10),
            whitelist: document.getElementById('tcp_whitelist').value
        };
    }

    function updateSaveButton(group) {
        let current = '';
        let btn = null;
        if (group === 'halow') { current = jsonSnapshot(readHalowForm()); btn = document.getElementById('save_halow'); }
        if (group === 'lbt')   { current = jsonSnapshot(readLbtForm());   btn = document.getElementById('save_lbt'); }
        if (group === 'net')   { current = jsonSnapshot(readNetForm());   btn = document.getElementById('save_net'); }
        if (group === 'tcp')   { current = jsonSnapshot(readTcpForm());   btn = document.getElementById('save_tcp'); }
        if (!btn) return;
        btn.disabled = (current === baselines[group]);
    }

    function snapshotGroup(group) {
        if (group === 'halow') baselines.halow = jsonSnapshot(readHalowForm());
        if (group === 'lbt')   baselines.lbt   = jsonSnapshot(readLbtForm());
        if (group === 'net')   baselines.net   = jsonSnapshot(readNetForm());
        if (group === 'tcp')   baselines.tcp   = jsonSnapshot(readTcpForm());
        updateSaveButton(group);
    }

    function snapshotAll() {
        snapshotGroup('halow');
        snapshotGroup('lbt');
        snapshotGroup('net');
        snapshotGroup('tcp');
    }

    function setupDirtyTracking() {
        const map = [
            { group: 'halow', btn: 'save_halow', ids: ['halow_power_dbm','halow_central_freq','halow_mcs_index','halow_bandwidth','halow_super_power'] },
            { group: 'lbt',   btn: 'save_lbt',   ids: ['lbt_uen','lbt_umax'] },
            { group: 'net',   btn: 'save_net',   ids: ['net_dhcp','net_ip_address','net_gw_address','net_netmask'] },
            { group: 'tcp',   btn: 'save_tcp',   ids: ['tcp_enable','tcp_port','tcp_whitelist'] }
        ];

        map.forEach(m => {
            m.ids.forEach(id => {
                const el = document.getElementById(id);
                if (!el) return;
                const ev = (el.tagName === 'SELECT' || el.type === 'checkbox') ? 'change' : 'input';
                el.addEventListener(ev, () => updateSaveButton(m.group));
                if (ev !== 'change') {
                    el.addEventListener('change', () => updateSaveButton(m.group));
                }
            });
            const btn = document.getElementById(m.btn);
            if (btn) btn.disabled = true;
        });
    }

    // Load-all retry loop. Makes /api/get_all requests once per second until
    // a successful response is received.
    let loadAllLoopActive = false;

    async function loadAllUntilSuccess() {
		if (loadAllLoopActive) return;
		loadAllLoopActive = true;

		while (true) {
			const ok = await loadAll();
			if (ok) break;
			await new Promise(r => setTimeout(r, 1000));
		}

		loadAllLoopActive = false;
	}


    document.addEventListener('DOMContentLoaded', () => {
        setupTabs();
        setupHandlers();
        setupDirtyTracking();
        // Load all configuration on startup.
        loadAllUntilSuccess();
        // Kick off periodic statistic updates.
        updateStats();
        setInterval(updateStats, 1000);
    });

    /**
     * Attach click handlers to the tab buttons so that only one tab
     * content section is visible at a time.  Active tab buttons are
     * highlighted via the `active` class.
     */
    function setupTabs() {
        const buttons = document.querySelectorAll('.tabs button');
        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                // Skip if already active.
                if (btn.classList.contains('active')) return;
                // Remove active class from currently active button.
                const current = document.querySelector('.tabs button.active');
                if (current) current.classList.remove('active');
                btn.classList.add('active');
                // Hide all sections and show the selected one.
                const tabName = btn.dataset.tab;
                document.querySelectorAll('.tab-content').forEach(sec => {
                    sec.classList.remove('active');
                });
                const activeSec = document.getElementById(tabName);
                if (activeSec) activeSec.classList.add('active');
            });
        });
    }

    /**
     * Set up event handlers for interactive elements (buttons and form
     * controls).  These handlers gather values, send them to the
     * appropriate endpoint and refresh the configuration after the
     * request completes.
     */
    function setupHandlers() {
        // RF Settings
        document.getElementById('halow_mcs_index').addEventListener('change', updateBandwidthDisabled);
        document.getElementById('save_halow').addEventListener('click', saveHalow);
        // LBT
        document.getElementById('lbt_uen').addEventListener('change', updateLbtUtilDisabled);
        document.getElementById('save_lbt').addEventListener('click', saveLbt);
        // Network
        document.getElementById('net_dhcp').addEventListener('change', updateNetDisabled);
        document.getElementById('save_net').addEventListener('click', saveNet);
        // TCP Bridge
        document.getElementById('tcp_enable').addEventListener('change', updateTcpDisabled);
        document.getElementById('save_tcp').addEventListener('click', saveTcp);
		
		document.getElementById('stat_reset_btn').addEventListener('click', resetStats);
        // Firmware Update
		document.getElementById('fw_file').addEventListener('change', updateFwDisabled);
		document.getElementById('fw_flash').addEventListener('click', fwFlash);
		initFwConsole();
    }

    /**
     * Disable the bandwidth dropdown when the selected MCS index
     * requires it (MCS10) and enable it otherwise.
     */
    function updateBandwidthDisabled() {
        const mcs = document.getElementById('halow_mcs_index').value;
        const bw = document.getElementById('halow_bandwidth');
        bw.disabled = (mcs === 'MCS10');
    }

    /**
     * Enable or disable all LBT fields based on the primary enable
     * toggle.  When disabled the nested inputs are greyed out to
     * prevent user interaction.
     */
    function updateLbtDisabled() {
        // LBT parameters are not supported on current firmware.
        // Keep only utilisation limit controls.
    }

    /**
     * Enable or disable the channel utilisation fields depending on
     * whether utilisation is globally enabled and LBT is enabled.  If
     * either toggle is off then the utilisation limit fields are
     * disabled.
     */
    function updateLbtUtilDisabled() {
        const utilEnabled = document.getElementById('lbt_uen').checked;
        const el = document.getElementById('lbt_umax');
        if (el) {
            el.disabled = !utilEnabled;
        }
    }

    /**
     * When DHCP is enabled disable manual IP/gateway/mask fields.  If
     * DHCP is disabled the fields become editable.
     */
    function updateNetDisabled() {
        const dhcp = document.getElementById('net_dhcp').checked;
        const netFields = document.getElementById('net_fields');
        netFields.querySelectorAll('input').forEach(el => {
            el.disabled = dhcp;
        });
    }

    /**
     * Toggle the TCP bridge port/whitelist fields when the bridge
     * enable checkbox is toggled.  If disabled the inputs are
     * greyed out.
     */
    function updateTcpDisabled() {
        const enabled = document.getElementById('tcp_enable').checked;
        const tcpFields = document.getElementById('tcp_fields');
        tcpFields.querySelectorAll('input').forEach(el => {
            el.disabled = !enabled;
        });
    }

	async function resetStats() {
		try {
			await fetch('/api/reset_stat', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: '{}'
			});
		} catch (err) {
			console.error('resetStats error', err);
		}
	}

    /**
     * Request the full configuration from the backend.  After the
     * promise resolves the local state is overwritten and the UI
     * fields are refreshed.  If the request fails the state is not
     * modified.
     */
    async function loadAll() {
        try {
            const res = await fetch('/api/get_all');
            if (!res.ok) {
                console.error('get_all failed', res.status);
                return false;
            }
            state = await res.json();
            populateFromState();
            snapshotAll();
            return true;
        } catch (err) {
            console.error('get_all error', err);
            return false;
        }
    }

    /**
     * Request only the statistics from the backend.  The returned
     * statistics are displayed on the dashboard but do not modify
     * saved configuration.  If the device responds with
     * `api_radio_stat` and/or `api_dev_stat` the corresponding
     * elements are updated; missing fields are ignored.
     */
    async function updateStats() {
		try {
			const res = await fetch('/api/get_stat');
			if (!res.ok) return;

			const data = await res.json();

			const r = data.radio || data.api_radio_stat;
			if (r) {
				setText('stat_rx_bytes', r.rx_bytes);
				setText('stat_tx_bytes', r.tx_bytes);
				setText('stat_rx_packets', r.rx_packets);
				setText('stat_tx_packets', r.tx_packets);
				setText('stat_rx_speed', r.rx_speed);
				setText('stat_tx_speed', r.tx_speed);
				setText('stat_airtime', r.airtime);
				setText('stat_ch_util', r.ch_util);
				setText('stat_bg_pwr_now_dbm', r.bg_pwr_now_dbm);
				setText('stat_bg_pwr_dbm', r.bg_pwr_dbm);
			}

			const d = data.device || data.api_dev_stat;
			if (d) {
				setText('stat_uptime', d.uptime);
				setText('stat_hostname', d.hostname);
				setText('stat_ip', d.ip);
				setText('stat_mac', d.mac);
				setText('stat_fwver', d.ver);
			}
		} catch (err) {
			// ignore
		}
	}
    /**
     * Helper to set the text content of an element if the value is
     * defined; otherwise leave the element unchanged.  Undefined or
     * null values result in a placeholder `--`.
     */
    function setText(id, value) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = (value !== undefined && value !== null) ? value : '--';
    }

    /**
     * Populate the UI fields from the current configuration stored in
     * `state`.  For each configuration group we attempt to read
     * common field names; if a property is missing the corresponding
     * form control remains untouched.  After population dependent
     * fields are enabled/disabled based on their toggles.
     */
    function populateFromState() {
		const unwrap = (x) => (x && typeof x === 'object' && 'value' in x) ? x.value : x;
		const pick = (...xs) => {
			for (const x of xs) {
				const v = unwrap(x);
				if (v !== undefined && v !== null) { return v; }
			}
			return {};
		};

		// Halow / RF settings
		const halow = pick(state?.halow, state?.api_halow_cfg, state?.halow_cfg);
		setInput('halow_power_dbm', halow.power_dbm);
		setInput('halow_central_freq', halow.central_freq);
		setSelect('halow_mcs_index', halow.mcs_index);
		setSelect('halow_bandwidth', halow.bandwidth);
		setCheckbox('halow_super_power', halow.super_power);
		updateBandwidthDisabled();

		// LBT settings
		const lbt = pick(state?.lbt, state?.api_lbt_cfg, state?.lbt_cfg);
		setCheckbox('lbt_uen', lbt.uen);
		setInput('lbt_umax', lbt.umax);
		updateLbtUtilDisabled();

		// Network settings
		const net = pick(state?.net, state?.api_net_cfg, state?.net_cfg);
		setCheckbox('net_dhcp', net.dhcp);
		setInput('net_ip_address', net.ip_address);
		setInput('net_gw_address', net.gw_address);
		setInput('net_netmask', net.netmask);
		updateNetDisabled();

		// TCP bridge
		const tcp = pick(state?.tcp, state?.api_tcp_server_cfg, state?.tcp_server_cfg);
		setCheckbox('tcp_enable', tcp.enable);
		setInput('tcp_port', tcp.port);
		setInput('tcp_whitelist', tcp.whitelist);
		setText('tcp_client', tcp.connected);
		updateTcpDisabled();

		// Firmware update (versions list)
		const ota = pick(state?.ota, state?.api_online_ota, state?.online_ota);
		if (ota.versions && Array.isArray(ota.versions)) {
			const select = document.getElementById('fw_versions');
			if (select) {
				select.innerHTML = '';
				ota.versions.forEach(v => {
					const opt = document.createElement('option');
					opt.value = v;
					opt.textContent = v;
					select.appendChild(opt);
				});
				if (ota.selected_version) {
					select.value = ota.selected_version;
				}
			}
		}

		// Device firmware version
		const devStat =
			unwrap(state?.api_dev_stat) ||
			unwrap(state?.dev_stat) ||
			unwrap(state?.stat?.device) ||
			{};

		setText('fw_current', devStat.ver);
	}

    /**
     * Helper to set a text input value if provided.  Undefined values
     * leave the input unchanged.  Null values clear the input.
     */
    function setInput(id, value) {
        const el = document.getElementById(id);
        if (!el) return;
        if (value === undefined) return;
        el.value = value !== null ? value : '';
    }

    /**
     * Helper to set a select value if provided and option exists.
     */
    function setSelect(id, value) {
        const el = document.getElementById(id);
        if (!el || value === undefined) return;
        const exists = Array.from(el.options).some(opt => opt.value == value);
        if (exists) el.value = value;
    }

    /**
     * Helper to set a checkbox state.  Undefined values leave the
     * checkbox untouched.
     */
    function setCheckbox(id, value) {
        const el = document.getElementById(id);
        if (!el || value === undefined) return;
        el.checked = !!value;
    }

    /**
     * Gather the RF settings and send them to the backend.  On
     * completion the full configuration is reloaded.  Errors are
     * logged to the console.
     */
    async function saveHalow() {
        const payload = {
            power_dbm: parseFloat(document.getElementById('halow_power_dbm').value),
            central_freq: parseFloat(document.getElementById('halow_central_freq').value),
            mcs_index: document.getElementById('halow_mcs_index').value,
            bandwidth: document.getElementById('halow_bandwidth').value,
            super_power: document.getElementById('halow_super_power').checked
        };
        try {
            await fetch('/api/halow_cfg', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            console.error('saveHalow error', err);
        }
        // Refresh configuration after saving
        loadAllUntilSuccess();
    }

    /**
     * Gather the LBT settings and POST them.  After saving the
     * configuration is refreshed.
     */
    async function saveLbt() {
        const payload = {
            uen: document.getElementById('lbt_uen').checked,
            umax: parseInt(document.getElementById('lbt_umax').value, 10)
        };
        try {
            await fetch('/api/lbt_cfg', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            console.error('saveLbt error', err);
        }
        loadAllUntilSuccess();
    }

    /**
     * Gather the network settings and POST them.  After saving the
     * configuration is refreshed.
     */
    async function saveNet() {
        const payload = {
            dhcp: document.getElementById('net_dhcp').checked,
            ip_address: document.getElementById('net_ip_address').value,
            gw_address: document.getElementById('net_gw_address').value,
            netmask: document.getElementById('net_netmask').value
        };
        try {
            await fetch('/api/net_cfg', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            console.error('saveNet error', err);
        }
        loadAllUntilSuccess();
    }

    /**
     * Gather the TCP bridge settings and POST them.  After saving the
     * configuration is refreshed.
     */
    async function saveTcp() {
        const payload = {
            enable: document.getElementById('tcp_enable').checked,
            port: parseInt(document.getElementById('tcp_port').value, 10),
            whitelist: document.getElementById('tcp_whitelist').value
        };
        try {
            await fetch('/api/tcp_server_cfg', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            console.error('saveTcp error', err);
        }
        loadAllUntilSuccess();
    }



	function updateFwDisabled() {
		const f = document.getElementById('fw_file').files;
		document.getElementById('fw_flash').disabled = !(f && f.length === 1);
	}

	function bytesToB64( u8 ){
		let s = '';
		const chunk = 0x8000;
		for (let i = 0; i < u8.length; i += chunk){
			s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
		}
		return btoa(s);
	}

	// CRC32 (чтобы послать crc32 в begin/end). Если ты уже считаешь crc на девайсе — можно выкинуть.
	function crc32_make_table(){
		const t = new Uint32Array(256);
		for (let i = 0; i < 256; i++){
			let c = i;
			for (let k = 0; k < 8; k++){
				c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
			}
			t[i] = c >>> 0;
		}
		return t;
	}
	const CRC32_T = crc32_make_table();

	function crc32_update( crc, u8 ){
		let c = (crc ^ 0xFFFFFFFF) >>> 0;
		for (let i = 0; i < u8.length; i++){
			c = CRC32_T[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
		}
		return (c ^ 0xFFFFFFFF) >>> 0;
	}

	function sleepMs( ms ){
	return new Promise(r => setTimeout(r, ms));
}

async function fetchJsonRetry( url, opts, tries, baseDelayMs ){
	let lastErr;

	for (let i = 0; i < tries; i++){
		try {
			const r = await fetch(url, opts);

			if (!r.ok){
				lastErr = new Error('HTTP ' + r.status);
			} else {
				return r;
			}
		} catch (e){
			lastErr = e;
		}

		if (i + 1 < tries){
			const d = baseDelayMs * (1 << i);
			await sleepMs(d);
		}
	}

	throw lastErr;
}

function initFwConsole() {
	const consoleEl = document.getElementById('fw_console');
	if (!consoleEl) { return; }

	consoleEl.innerHTML = '';
	const line = document.createElement('div');
	line.textContent = 'Firmware update console ready.';
	consoleEl.appendChild(line);
}

async function fwFlash() {

	const fileEl    = document.getElementById('fw_file');
	const btn       = document.getElementById('fw_flash');
	const consoleEl = document.getElementById('fw_console');

	const file = (fileEl.files && fileEl.files.length === 1) ? fileEl.files[0] : null;
	if (!file) { return; }

	if (!confirm('Upload OTA file to device and flash it?')) { return; }

	function log( msg ){
		const line = document.createElement('div');
		line.textContent = msg;
		consoleEl.appendChild(line);
		consoleEl.scrollTop = consoleEl.scrollHeight;
		return line;
	}

	function stage( msg ){ log('[*] ' + msg); }
	function ok( msg ){ log('[OK] ' + msg); }
	function err( msg ){ log('[ERR] ' + msg); }

	function mkPost( url, obj ){
		return fetchJsonRetry(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(obj)
		}, tries, baseDelayMs);
	}

	btn.disabled = true;
	consoleEl.innerHTML = '';

	const chunkSize = 512;
	const tries = 6;
	const baseDelayMs = 80;

	try {

		stage('Reading file: ' + file.name);
		const fileBuf = await file.arrayBuffer();
		const fileU8  = new Uint8Array(fileBuf);
		ok('File loaded (' + fileU8.length + ' bytes)');

		stage('Calculating CRC32...');
		const fileCrc32 = (crc32_update(0 >>> 0, fileU8) >>> 0);
		ok('CRC32 = 0x' + fileCrc32.toString(16));

		stage('Starting OTA session...');
		await mkPost('/api/ota_begin', {
			size: fileU8.length,
			crc32: fileCrc32
		});
		ok('ota_begin accepted');

		// ===== Upload with single progress line =====
		stage('Uploading firmware...');
		const progressLine = log('    0%');

		let offset = 0;
		while (offset < fileU8.length) {
			const nextOffset = Math.min(offset + chunkSize, fileU8.length);
			const chunkBin   = fileU8.subarray(offset, nextOffset);
			const chunkB64   = bytesToB64(chunkBin);

			await mkPost('/api/ota_chunk', {
				off: offset,
				b64: chunkB64
			});

			offset = nextOffset;

			const percent = Math.floor((offset * 100) / fileU8.length);
			progressLine.textContent = '    ' + percent + '%';
		}

		progressLine.textContent = '[OK] Upload complete';

		stage('Verifying file on device...');
		await mkPost('/api/ota_end', { crc32: fileCrc32 });
		ok('Device CRC verification OK');

		stage('Writing firmware to flash...');
		await mkPost('/api/ota_write', {});
		ok('Flash write + verify OK');

		stage('OTA finished. Device may reboot.');

	} catch (e) {
		err(e && e.message ? e.message : 'unknown error');
		btn.disabled = false;
	}
}

})();