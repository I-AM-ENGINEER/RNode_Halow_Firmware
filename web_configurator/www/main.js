// Device Configurator frontend logic.
//
// This script handles tab switching, form submission and periodic
// fetching of statistics. It is written using vanilla JavaScript so
// that it can run on an embedded system without any external
// dependencies. All fetch calls are directed to the local API
// endpoints (e.g. `/api/get_all`, `/api/get_stat`) and send/receive
// JSON payloads.

(() => {
    let state = {};
    const baselines = {
        halow: '',
        lbt: '',
        net: '',
        slip: '',
        log: '',
        tcp: '',
        telemetry: ''
    };
    const DASHBOARD_REFRESH_MS = 1000;
    const dashboardState = {
        active: false,
        timer: null,
        loading: false
    };
    const nearbyState = {
        auto: true,
        periodMs: 5000,
        timer: null,
        loading: false,
        active: false,
        speedCache: new Map()
    };
    const reticulumState = {
        auto: true,
        periodMs: 5000,
        timer: null,
        loading: false,
        active: false,
        speedCache: new Map()
    };
    const fwUpdateState = {
        releases: [],
        selectedVersion: null,
        downloading: false,
        betaEnabled: false
    };

    document.addEventListener('DOMContentLoaded', () => {
        setupTabs();
        setupHandlers();
        setupDirtyTracking();
        loadAll();
        updateNearbyUi();
        updateReticulumUi();
        handleTabActivated('dashboard');
        startLiveAgeTicker();
    });

    function jsonSnapshot(obj) {
        return JSON.stringify(obj, Object.keys(obj).sort());
    }

    function readHalowForm() {
        return {
            power_dbm: parseFloat(document.getElementById('halow_power_dbm').value),
            central_freq: parseFloat(document.getElementById('halow_central_freq').value),
            mcs_index: document.getElementById('halow_mcs_index').value,
            bandwidth: document.getElementById('halow_bandwidth').value
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

    function readSlipForm() {
        const ip = document.getElementById('slip_ip_address').value;
        const gw = document.getElementById('slip_gw_address').value;

        return {
            enable: document.getElementById('slip_enable').checked,
            baud: parseInt(document.getElementById('slip_baud').value, 10),
            ip: ip,
            gw: gw,
            ip_address: ip,
            gw_address: gw
        };
    }

    function readLogForm() {
        return {
            udp_enable: document.getElementById('log_udp_enable').checked,
            host: document.getElementById('log_udp_host').value,
            port: parseInt(document.getElementById('log_udp_port').value, 10)
        };
    }

    function readTcpForm() {
        return {
            enable: document.getElementById('tcp_enable').checked,
            port: parseInt(document.getElementById('tcp_port').value, 10),
            whitelist: document.getElementById('tcp_whitelist').value
        };
    }

    function readTelemetryForm() {
        return {
            en: document.getElementById('telemetry_en').checked,
            ext: document.getElementById('telemetry_ext').checked,
            prd: parseInt(document.getElementById('telemetry_prd').value, 10),
            host: document.getElementById('telemetry_host').value.trim(),
            port: parseInt(document.getElementById('telemetry_port').value, 10),
            lat: document.getElementById('telemetry_lat').value.trim(),
            lon: document.getElementById('telemetry_lon').value.trim(),
            dir_en: document.getElementById('telemetry_dir_en').checked,
            dir: parseInt(document.getElementById('telemetry_dir').value, 10),
            usr: document.getElementById('telemetry_usr').value,
            pwd: document.getElementById('telemetry_pwd').value,
            top: document.getElementById('telemetry_top').value,
            name: document.getElementById('telemetry_name').value,
            lxmf: sanitizeLxmf(document.getElementById('telemetry_lxmf').value)
        };
    }

    function updateSaveButton(group) {
        let current = '';
        let btn = null;

        if (group === 'halow') { current = jsonSnapshot(readHalowForm()); btn = document.getElementById('save_halow'); }
        if (group === 'lbt') { current = jsonSnapshot(readLbtForm()); btn = document.getElementById('save_lbt'); }
        if (group === 'net') { current = jsonSnapshot(readNetForm()); btn = document.getElementById('save_net'); }
        if (group === 'slip') { current = jsonSnapshot(readSlipForm()); btn = document.getElementById('save_slip'); }
        if (group === 'log') { current = jsonSnapshot(readLogForm()); btn = document.getElementById('save_log'); }
        if (group === 'tcp') { current = jsonSnapshot(readTcpForm()); btn = document.getElementById('save_tcp'); }
        if (group === 'telemetry') {
            current = jsonSnapshot(readTelemetryForm());
            btn = document.getElementById('save_telemetry');
        }

        if (!btn) { return; }

        if (group === 'telemetry') {
            btn.disabled = (current === baselines[group]) || !validateTelemetryForm({ silent: true });
            return;
        }

        btn.disabled = (current === baselines[group]);
    }

    function snapshotGroup(group) {
        if (group === 'halow') { baselines.halow = jsonSnapshot(readHalowForm()); }
        if (group === 'lbt') { baselines.lbt = jsonSnapshot(readLbtForm()); }
        if (group === 'net') { baselines.net = jsonSnapshot(readNetForm()); }
        if (group === 'slip') { baselines.slip = jsonSnapshot(readSlipForm()); }
        if (group === 'log') { baselines.log = jsonSnapshot(readLogForm()); }
        if (group === 'tcp') { baselines.tcp = jsonSnapshot(readTcpForm()); }
        if (group === 'telemetry') { baselines.telemetry = jsonSnapshot(readTelemetryForm()); }
        updateSaveButton(group);
    }

    function snapshotAll() {
        snapshotGroup('halow');
        snapshotGroup('lbt');
        snapshotGroup('net');
        snapshotGroup('slip');
        snapshotGroup('log');
        snapshotGroup('tcp');
        snapshotGroup('telemetry');
    }

    function setupDirtyTracking() {
        const map = [
            { group: 'halow', btn: 'save_halow', ids: ['halow_power_dbm', 'halow_central_freq', 'halow_mcs_index', 'halow_bandwidth'] },
            { group: 'lbt', btn: 'save_lbt', ids: ['lbt_uen', 'lbt_umax'] },
            { group: 'net', btn: 'save_net', ids: ['net_dhcp', 'net_ip_address', 'net_gw_address', 'net_netmask'] },
            { group: 'slip', btn: 'save_slip', ids: ['slip_enable', 'slip_baud', 'slip_ip_address', 'slip_gw_address'] },
            { group: 'log', btn: 'save_log', ids: ['log_udp_enable', 'log_udp_host', 'log_udp_port'] },
            { group: 'tcp', btn: 'save_tcp', ids: ['tcp_enable', 'tcp_port', 'tcp_whitelist'] },
            {
                group: 'telemetry',
                btn: 'save_telemetry',
                ids: [
                    'telemetry_en', 'telemetry_ext', 'telemetry_prd', 'telemetry_host', 'telemetry_port',
                    'telemetry_lat', 'telemetry_lon', 'telemetry_dir_en', 'telemetry_dir',
                    'telemetry_usr', 'telemetry_pwd', 'telemetry_top', 'telemetry_name', 'telemetry_lxmf'
                ]
            }
        ];

        map.forEach(m => {
            m.ids.forEach(id => {
                const el = document.getElementById(id);
                if (!el) { return; }
                const ev = (el.tagName === 'SELECT' || el.type === 'checkbox') ? 'change' : 'input';
                el.addEventListener(ev, () => updateSaveButton(m.group));
                if (ev !== 'change') {
                    el.addEventListener('change', () => updateSaveButton(m.group));
                }
            });
            const btn = document.getElementById(m.btn);
            if (btn) { btn.disabled = true; }
        });
    }

    function setupTabs() {
        const buttons = document.querySelectorAll('.tabs button');
        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                if (btn.classList.contains('active')) { return; }

                const current = document.querySelector('.tabs button.active');
                if (current) { current.classList.remove('active'); }
                btn.classList.add('active');

                const tabName = btn.dataset.tab;
                document.querySelectorAll('.tab-content').forEach(sec => sec.classList.remove('active'));
                const activeSec = document.getElementById(tabName);
                if (activeSec) { activeSec.classList.add('active'); }
                handleTabActivated(tabName);
            });
        });
    }

    function setupHandlers() {
        document.getElementById('halow_mcs_index').addEventListener('change', updateBandwidthDisabled);
        document.getElementById('save_halow').addEventListener('click', saveHalow);

        document.getElementById('lbt_uen').addEventListener('change', updateLbtUtilDisabled);
        document.getElementById('save_lbt').addEventListener('click', saveLbt);

        document.getElementById('net_dhcp').addEventListener('change', updateNetDisabled);
        document.getElementById('save_net').addEventListener('click', saveNet);

        document.getElementById('slip_enable').addEventListener('change', updateSlipDisabled);
        document.getElementById('save_slip').addEventListener('click', saveSlip);

        document.getElementById('log_udp_enable').addEventListener('change', updateLogDisabled);
        document.getElementById('save_log').addEventListener('click', saveLog);

        document.getElementById('tcp_enable').addEventListener('change', updateTcpDisabled);
        document.getElementById('save_tcp').addEventListener('click', saveTcp);

        document.getElementById('telemetry_en').addEventListener('change', updateTelemetryDisabled);
        document.getElementById('telemetry_dir_en').addEventListener('change', updateTelemetryDirectionDisabled);
        document.getElementById('save_telemetry').addEventListener('click', saveTelemetry);
        document.getElementById('telemetry_send_btn').addEventListener('click', sendTelemetryNow);
        document.getElementById('telemetry_lxmf').addEventListener('input', handleTelemetryLxmfInput);
        document.getElementById('telemetry_lat').addEventListener('blur', () => normalizeCoordinateField('telemetry_lat', 'lat'));
        document.getElementById('telemetry_lon').addEventListener('blur', () => normalizeCoordinateField('telemetry_lon', 'lon'));
        document.getElementById('telemetry_lat').addEventListener('input', () => validateTelemetryForm({ silent: true }));
        document.getElementById('telemetry_lon').addEventListener('input', () => validateTelemetryForm({ silent: true }));
        document.getElementById('telemetry_lxmf').addEventListener('blur', () => validateTelemetryForm({ silent: true }));
        document.getElementById('telemetry_lat').addEventListener('change', () => validateTelemetryForm({ silent: true }));
        document.getElementById('telemetry_lon').addEventListener('change', () => validateTelemetryForm({ silent: true }));

        document.getElementById('stat_reset_btn').addEventListener('click', resetStats);

        document.getElementById('nearby_auto').addEventListener('change', handleNearbyAutoChange);
        document.getElementById('nearby_period').addEventListener('change', handleNearbyPeriodChange);
        document.getElementById('nearby_refresh').addEventListener('click', () => refreshNearby(true));

        document.getElementById('reticulum_auto').addEventListener('change', handleReticulumAutoChange);
        document.getElementById('reticulum_period').addEventListener('change', handleReticulumPeriodChange);
        document.getElementById('reticulum_refresh').addEventListener('click', () => refreshReticulum(true));

        document.getElementById('webota_file').addEventListener('change', updateWebOtaDisabled);
        document.getElementById('webota_flash').addEventListener('click', fwWebOtaFlash);
        document.getElementById('fw_reboot').addEventListener('click', rebootDevice);
        document.getElementById('fw_factory_reset').addEventListener('click', factoryResetDevice);

        document.getElementById('fw_beta_toggle').addEventListener('change', handleFwBetaToggle);
        document.getElementById('fw_check_updates').addEventListener('click', checkFwUpdates);
        document.getElementById('fw_version_select').addEventListener('change', handleFwVersionSelect);
        document.getElementById('fw_download_flash').addEventListener('click', fwDownloadAndFlash);

        initFwConsole();
    }

    function updateBandwidthDisabled() {
        const mcs = document.getElementById('halow_mcs_index').value;
        const bw = document.getElementById('halow_bandwidth');
        bw.disabled = (mcs === 'MCS10');
    }

    function updateLbtUtilDisabled() {
        const utilEnabled = document.getElementById('lbt_uen').checked;
        const el = document.getElementById('lbt_umax');
        if (el) {
            el.disabled = !utilEnabled;
        }
    }

    function updateNetDisabled() {
        const dhcp = document.getElementById('net_dhcp').checked;
        const netFields = document.getElementById('net_fields');
        netFields.querySelectorAll('input').forEach(el => {
            el.disabled = dhcp;
        });
    }

    function updateSlipDisabled() {
        const enabled = document.getElementById('slip_enable').checked;
        const slipFields = document.getElementById('slip_fields');
        slipFields.querySelectorAll('input').forEach(el => {
            el.disabled = !enabled;
        });
    }

    function updateLogDisabled() {
        const enabled = document.getElementById('log_udp_enable').checked;
        const logFields = document.getElementById('log_udp_fields');
        logFields.querySelectorAll('input').forEach(el => {
            el.disabled = !enabled;
        });
    }

    function updateTcpDisabled() {
        const enabled = document.getElementById('tcp_enable').checked;
        const tcpFields = document.getElementById('tcp_fields');
        tcpFields.querySelectorAll('input').forEach(el => {
            el.disabled = !enabled;
        });
    }

    function updateTelemetryDisabled() {
        const telemetryEnabled = document.getElementById('telemetry_en').checked;
        const telemetryFields = document.getElementById('telemetry_fields');
        if (telemetryFields) {
            telemetryFields.querySelectorAll('input, select, textarea, button').forEach(el => {
                if (el.id === 'telemetry_send_btn') { return; }
                el.disabled = !telemetryEnabled;
            });
        }
        updateTelemetryDirectionDisabled();
    }

    function updateTelemetryDirectionDisabled() {
        const telemetryEnabled = document.getElementById('telemetry_en').checked;
        const directional = document.getElementById('telemetry_dir_en').checked;
        const dir = document.getElementById('telemetry_dir');
        dir.disabled = !telemetryEnabled || !directional;
    }

    async function postJson(url, payload) {
        return fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload ?? {})
        });
    }

    async function resetStats() {
        try {
            await postJson('/api/reset_stat', {});
        } catch (err) {
            console.error('resetStats error', err);
        }
    }

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

    async function updateStats() {
        try {
            const res = await fetch('/api/get_stat');
            if (!res.ok) { return; }

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
                setText('stat_flashs', d.flashs);
				setText('stat_cpu', d.cpu);
				setText('stat_heap', d.heap);
            }
        } catch (err) {
            // ignore periodic fetch errors
        }
    }


    function stopDashboardTimer() {
        if (dashboardState.timer !== null) {
            clearTimeout(dashboardState.timer);
            dashboardState.timer = null;
        }
    }

    function scheduleDashboardRefresh() {
        stopDashboardTimer();
        if (!dashboardState.active) {
            return;
        }
        dashboardState.timer = setTimeout(() => {
            refreshDashboard(false);
        }, DASHBOARD_REFRESH_MS);
    }

    async function refreshDashboard(force) {
        if (!dashboardState.active && !force) {
            return;
        }

        if (dashboardState.loading) {
            return;
        }

        stopDashboardTimer();
        dashboardState.loading = true;

        try {
            await updateStats();
        } finally {
            dashboardState.loading = false;
            scheduleDashboardRefresh();
        }
    }

    function handleTabActivated(tabName) {
        dashboardState.active = (tabName === 'dashboard');
        nearbyState.active = (tabName === 'nearby');
        reticulumState.active = (tabName === 'reticulum');

        if (dashboardState.active) {
            refreshDashboard(true);
        } else {
            stopDashboardTimer();
        }

        if (nearbyState.active) {
            refreshNearby(true);
        } else {
            stopNearbyTimer();
        }

        if (reticulumState.active) {
            refreshReticulum(true);
        } else {
            stopReticulumTimer();
        }
    }

    function stopNearbyTimer() {
        if (nearbyState.timer !== null) {
            clearTimeout(nearbyState.timer);
            nearbyState.timer = null;
        }
    }

    function scheduleNearbyRefresh() {
        stopNearbyTimer();
        if (!nearbyState.active || !nearbyState.auto) {
            return;
        }
        nearbyState.timer = setTimeout(() => {
            refreshNearby(false);
        }, nearbyState.periodMs);
    }

    function updateNearbyUi() {
        const autoEl = document.getElementById('nearby_auto');
        const periodEl = document.getElementById('nearby_period');

        if (autoEl) {
            autoEl.checked = nearbyState.auto;
        }

        if (periodEl) {
            periodEl.value = String(Math.max(1, Math.round(nearbyState.periodMs / 1000)));
            periodEl.disabled = !nearbyState.auto;
        }
    }

    function normalizeNearbyPeriodMs(raw) {
        const sec = parseInt(raw, 10);
        if (!Number.isFinite(sec) || sec < 1) {
            return 5000;
        }
        return sec * 1000;
    }

    function handleNearbyAutoChange() {
        nearbyState.auto = document.getElementById('nearby_auto').checked;
        updateNearbyUi();
        if (nearbyState.auto) {
            scheduleNearbyRefresh();
        } else {
            stopNearbyTimer();
        }
    }

    function handleNearbyPeriodChange() {
        nearbyState.periodMs = normalizeNearbyPeriodMs(document.getElementById('nearby_period').value);
        updateNearbyUi();
        scheduleNearbyRefresh();
    }


    function normalizeNearbyMcs(value) {
        if (value === undefined || value === null || value === '') {
            return '--';
        }

        if (typeof value === 'string') {
            const match = value.match(/-?\d+/);
            if (match) {
                return match[0];
            }
        }

        return String(value);
    }


    function tickAgeCells() {
        document.querySelectorAll('[data-age-seconds]').forEach(el => {
            const age = parseInt(el.dataset.ageSeconds, 10);
            if (!Number.isFinite(age) || age < 0) {
                el.textContent = '--';
                return;
            }

            const nextAge = age + 1;
            el.dataset.ageSeconds = String(nextAge);
            el.textContent = formatDurationCompact(nextAge);
        });
    }

    function startLiveAgeTicker() {
        setInterval(tickAgeCells, 1000);
    }


    function formatMac(value) {
        if (typeof value !== 'string') {
            return value ?? '--';
        }

        const hex = value.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
        if (hex.length !== 12) {
            return value;
        }

        return hex.match(/.{1,2}/g).join(':');
    }

    function formatNearbyBitrate(bitsPerSecond) {
        if (!Number.isFinite(bitsPerSecond) || bitsPerSecond < 0) {
            return '--';
        }

        return String(Math.round(bitsPerSecond));
    }

    function formatNearbyLastSeen(seconds) {
        return formatDurationCompact(seconds);
    }

    function parseNearbyRow(row) {
        if (Array.isArray(row)) {
            return {
                mac: row[0],
                rssi: row[1],
                mcs: row[2],
                packets: row[3],
                bytes: row[4],
                lastSeen: row[5]
            };
        }

        return {
            mac: row?.m ?? row?.mac,
            rssi: row?.r ?? row?.rssi,
            mcs: row?.s ?? row?.mcs,
            packets: row?.p ?? row?.rx_packets,
            bytes: row?.b ?? row?.rx_bytes,
            lastSeen: row?.l ?? row?.last_seen
        };
    }

    function calcNearbyBitrate(mac, bytes) {
        const nowMs = Date.now();
        const rxBytes = Number(bytes);

        if (!mac || !Number.isFinite(rxBytes) || rxBytes < 0) {
            return '--';
        }

        const prev = nearbyState.speedCache.get(mac);
        nearbyState.speedCache.set(mac, { bytes: rxBytes, tsMs: nowMs });

        if (!prev) {
            return '--';
        }

        const deltaBytes = rxBytes - prev.bytes;
        const deltaMs = nowMs - prev.tsMs;

        if (deltaBytes < 0 || deltaMs <= 0) {
            return '--';
        }

        return formatNearbyBitrate((deltaBytes * 8000) / deltaMs);
    }

    function renderNearbyRows(rows) {
        const body = document.getElementById('nearby_table_body');
        if (!body) { return; }

        body.innerHTML = '';

        if (!rows.length) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 7;
            td.textContent = 'No devices';
            tr.appendChild(td);
            body.appendChild(tr);
            return;
        }

        rows.forEach(srcRow => {
            const row = parseNearbyRow(srcRow);
            const tr = document.createElement('tr');
            const values = [
                formatMac(row.mac),
                row.rssi,
                normalizeNearbyMcs(row.mcs),
                row.packets,
                row.bytes,
                calcNearbyBitrate(row.mac, row.bytes)
            ];

            values.forEach(value => {
                const td = document.createElement('td');
                td.textContent = (value !== undefined && value !== null && value !== '') ? value : '--';
                tr.appendChild(td);
            });

            const ageTd = document.createElement('td');
            const age = Number(row.lastSeen);
            if (Number.isFinite(age) && age >= 0) {
                ageTd.dataset.ageSeconds = String(Math.floor(age));
                ageTd.textContent = formatNearbyLastSeen(age);
            } else {
                ageTd.textContent = '--';
            }
            tr.appendChild(ageTd);

            body.appendChild(tr);
        });
    }

    async function refreshNearby(force) {
        if (!nearbyState.active && !force) {
            return;
        }

        if (nearbyState.loading) {
            return;
        }

        stopNearbyTimer();
        nearbyState.loading = true;
        updateNearbyUi();

        try {
            const res = await fetch('/api/get_nearby_modems', { cache: 'no-store' });
            if (!res.ok) {
                return;
            }

            const data = await res.json();
            const rows = Array.isArray(data?.d) ? data.d : (Array.isArray(data?.devices) ? data.devices : []);
            const total = Number(data?.c ?? data?.count ?? data?.total ?? rows.length ?? 0);

            setText('nearby_self_mac', formatMac(data?.m ?? data?.mac ?? data?.self_mac ?? document.getElementById('stat_mac')?.textContent));
            setText('nearby_count', total);
            renderNearbyRows(rows);
        } catch (err) {
            // ignore nearby fetch errors
        } finally {
            nearbyState.loading = false;
            updateNearbyUi();
            scheduleNearbyRefresh();
        }
    }

    function stopReticulumTimer() {
        if (reticulumState.timer !== null) {
            clearTimeout(reticulumState.timer);
            reticulumState.timer = null;
        }
    }

    function scheduleReticulumRefresh() {
        stopReticulumTimer();
        if (!reticulumState.active || !reticulumState.auto) {
            return;
        }
        reticulumState.timer = setTimeout(() => {
            refreshReticulum(false);
        }, reticulumState.periodMs);
    }

    function updateReticulumUi() {
        const autoEl = document.getElementById('reticulum_auto');
        const periodEl = document.getElementById('reticulum_period');

        if (autoEl) {
            autoEl.checked = reticulumState.auto;
        }

        if (periodEl) {
            periodEl.value = String(Math.max(1, Math.round(reticulumState.periodMs / 1000)));
            periodEl.disabled = !reticulumState.auto;
        }
    }

    function normalizeReticulumPeriodMs(raw) {
        const sec = parseInt(raw, 10);
        if (!Number.isFinite(sec) || sec < 1) {
            return 5000;
        }
        return sec * 1000;
    }

    function handleReticulumAutoChange() {
        reticulumState.auto = document.getElementById('reticulum_auto').checked;
        updateReticulumUi();
        if (reticulumState.auto) {
            scheduleReticulumRefresh();
        } else {
            stopReticulumTimer();
        }
    }

    function handleReticulumPeriodChange() {
        reticulumState.periodMs = normalizeReticulumPeriodMs(document.getElementById('reticulum_period').value);
        updateReticulumUi();
        scheduleReticulumRefresh();
    }


    function formatDurationCompact(seconds) {
        const total = Number(seconds);
        if (!Number.isFinite(total) || total < 0) {
            return '--';
        }

        let remain = Math.floor(total);
        const h = Math.floor(remain / 3600);
        remain -= h * 3600;
        const m = Math.floor(remain / 60);
        const s = remain - (m * 60);

        const parts = [];
        if (h > 0) {
            parts.push(h + 'h');
        }
        if (m > 0 || h > 0) {
            parts.push(m + 'm');
        }
        parts.push(s + 's');
        return parts.join(' ');
    }

    function parseReticulumRow(row) {
        if (Array.isArray(row)) {
            return {
                id: row[0],
                remoteMac: row[1],
                destination: row[2],
                state: row[3],
                rxBytes: row[4],
                txBytes: row[5],
                rxPackets: row[6],
                txPackets: row[7],
                lastRx: row[8],
                lastTx: row[9],
                mtu: row[10]
            };
        }

        return {
            id: row?.i ?? row?.id,
            remoteMac: row?.m ?? row?.remote_mac,
            destination: row?.d ?? row?.destination,
            state: row?.s ?? row?.state,
            rxBytes: row?.rb ?? row?.rx_bytes,
            txBytes: row?.tb ?? row?.tx_bytes,
            rxPackets: row?.rp ?? row?.rx_packets,
            txPackets: row?.tp ?? row?.tx_packets,
            lastRx: row?.lr ?? row?.last_rx,
            lastTx: row?.lt ?? row?.last_tx,
            mtu: row?.u ?? row?.mtu
        };
    }

    function calcReticulumBitrate(key, bytes) {
        const nowMs = Date.now();
        const numBytes = Number(bytes);

        if (!key || !Number.isFinite(numBytes) || numBytes < 0) {
            return '--';
        }

        const prev = reticulumState.speedCache.get(key);
        reticulumState.speedCache.set(key, { bytes: numBytes, tsMs: nowMs });

        if (!prev) {
            return '--';
        }

        const deltaBytes = numBytes - prev.bytes;
        const deltaMs = nowMs - prev.tsMs;

        if (deltaBytes < 0 || deltaMs <= 0) {
            return '--';
        }

        return String(Math.round((deltaBytes * 8000) / deltaMs));
    }

    function renderReticulumRows(rows) {
        const body = document.getElementById('reticulum_table_body');
        if (!body) { return; }

        body.innerHTML = '';

        if (!rows.length) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 13;
            td.textContent = 'No links';
            tr.appendChild(td);
            body.appendChild(tr);
            return;
        }

        rows.forEach(srcRow => {
            const row = parseReticulumRow(srcRow);
            const idKey = String(row.id ?? row.remoteMac ?? row.destination ?? '');
            const rxRate = calcReticulumBitrate('rx:' + idKey, row.rxBytes);
            const txRate = calcReticulumBitrate('tx:' + idKey, row.txBytes);
            const tr = document.createElement('tr');
            const values = [
                row.id,
                row.remoteMac,
                row.destination,
                row.state,
                row.rxBytes,
                row.txBytes,
                row.rxPackets,
                row.txPackets
            ];

            values.forEach(value => {
                const td = document.createElement('td');
                td.textContent = (value !== undefined && value !== null && value !== '') ? value : '--';
                tr.appendChild(td);
            });

            const lastRxTd = document.createElement('td');
            const lastRx = Number(row.lastRx);
            if (Number.isFinite(lastRx) && lastRx >= 0) {
                lastRxTd.dataset.ageSeconds = String(Math.floor(lastRx));
                lastRxTd.textContent = formatDurationCompact(lastRx);
            } else {
                lastRxTd.textContent = '--';
            }
            tr.appendChild(lastRxTd);

            const lastTxTd = document.createElement('td');
            const lastTx = Number(row.lastTx);
            if (Number.isFinite(lastTx) && lastTx >= 0) {
                lastTxTd.dataset.ageSeconds = String(Math.floor(lastTx));
                lastTxTd.textContent = formatDurationCompact(lastTx);
            } else {
                lastTxTd.textContent = '--';
            }
            tr.appendChild(lastTxTd);

            [rxRate, txRate, row.mtu].forEach(value => {
                const td = document.createElement('td');
                td.textContent = (value !== undefined && value !== null && value !== '') ? value : '--';
                tr.appendChild(td);
            });

            body.appendChild(tr);
        });
    }

    async function refreshReticulum(force) {
        if (!reticulumState.active && !force) {
            return;
        }

        if (reticulumState.loading) {
            return;
        }

        stopReticulumTimer();
        reticulumState.loading = true;
        updateReticulumUi();

        try {
            const res = await fetch('/api/get_reticulum_links', { cache: 'no-store' });
            if (!res.ok) {
                return;
            }

            const data = await res.json();
            const rows = Array.isArray(data?.d) ? data.d : (Array.isArray(data?.links) ? data.links : []);
            const total = Number(data?.c ?? data?.count ?? data?.total ?? rows.length ?? 0);

            setText('reticulum_count', total);
            renderReticulumRows(rows);
        } catch (err) {
            // ignore reticulum fetch errors
        } finally {
            reticulumState.loading = false;
            updateReticulumUi();
            scheduleReticulumRefresh();
        }
    }

    function setText(id, value) {
        const el = document.getElementById(id);
        if (!el) { return; }
        el.textContent = (value !== undefined && value !== null) ? value : '--';
    }

    function populateFromState() {
        const unwrap = (x) => (x && typeof x === 'object' && 'value' in x) ? x.value : x;
        const pick = (...xs) => {
            for (const x of xs) {
                const v = unwrap(x);
                if (v !== undefined && v !== null) {
                    return v;
                }
            }
            return {};
        };

        const halow = pick(state?.halow, state?.api_halow_cfg, state?.halow_cfg);
        setInput('halow_power_dbm', halow.power_dbm);
        setInput('halow_central_freq', halow.central_freq);
        setSelect('halow_mcs_index', halow.mcs_index);
        setSelect('halow_bandwidth', halow.bandwidth);
        updateBandwidthDisabled();

        const lbt = pick(state?.lbt, state?.api_lbt_cfg, state?.lbt_cfg);
        setCheckbox('lbt_uen', lbt.uen);
        setInput('lbt_umax', lbt.umax);
        updateLbtUtilDisabled();

        const net = pick(state?.net, state?.api_net_cfg, state?.net_cfg);
        setCheckbox('net_dhcp', net.dhcp);
        setInput('net_ip_address', net.ip_address);
        setInput('net_gw_address', net.gw_address);
        setInput('net_netmask', net.netmask);
        updateNetDisabled();

        const slip = pick(state?.slip, state?.api_slip_cfg, state?.slip_cfg);
        setCheckbox('slip_enable', slip.enable);
        setInput('slip_baud', slip.baud);
        setInput('slip_ip_address', slip.ip_address ?? slip.ip);
        setInput('slip_gw_address', slip.gw_address ?? slip.gw);
        updateSlipDisabled();

        const logCfg = pick(state?.log, state?.logs, state?.api_log_cfg, state?.log_cfg, state?.api_logs_cfg, state?.logs_cfg);
        setCheckbox('log_udp_enable', logCfg.udp_enable ?? logCfg.enable);
        setInput('log_udp_host', logCfg.host ?? logCfg.ip_address);
        setInput('log_udp_port', logCfg.port);
        updateLogDisabled();

        const tcp = pick(state?.tcp, state?.api_tcp_server_cfg, state?.tcp_server_cfg);
        setCheckbox('tcp_enable', tcp.enable);
        setInput('tcp_port', tcp.port);
        setInput('tcp_whitelist', tcp.whitelist);
        setText('tcp_client', tcp.connected);
        updateTcpDisabled();

        const telemetry = pick(state?.telemetry, state?.api_telemetry_cfg, state?.telemetry_cfg);
        setCheckbox('telemetry_en', telemetry.en);
        setCheckbox('telemetry_ext', telemetry.ext);
        setSelect('telemetry_prd', String(telemetry.prd));
        setInput('telemetry_host', telemetry.host);
        setInput('telemetry_port', telemetry.port);
        setInput('telemetry_lat', formatCoordinateNumber(telemetry.lat));
        setInput('telemetry_lon', formatCoordinateNumber(telemetry.lon));
        setCheckbox('telemetry_dir_en', telemetry.dir_en);
        setInput('telemetry_dir', telemetry.dir);
        setInput('telemetry_usr', telemetry.usr);
        setInput('telemetry_pwd', telemetry.pwd);
        setInput('telemetry_top', telemetry.top);
        setInput('telemetry_name', telemetry.name);
        setInput('telemetry_lxmf', sanitizeLxmf(telemetry.lxmf));
        clearTelemetryValidationState();
        clearStatus('telemetry_status');
        updateTelemetryDisabled();
        validateTelemetryForm({ silent: true });

        const devStat =
            unwrap(state?.api_dev_stat) ||
            unwrap(state?.dev_stat) ||
            unwrap(state?.stat?.device) ||
            {};

        setText('fw_current', devStat.ver);
    }

    function setInput(id, value) {
        const el = document.getElementById(id);
        if (!el) { return; }
        if (value === undefined) { return; }
        el.value = value !== null ? value : '';
    }

    function setSelect(id, value) {
        const el = document.getElementById(id);
        if (!el || value === undefined) { return; }
        const exists = Array.from(el.options).some(opt => opt.value == value);
        if (exists) {
            el.value = value;
        }
    }

    function setCheckbox(id, value) {
        const el = document.getElementById(id);
        if (!el || value === undefined) { return; }
        el.checked = !!value;
    }

    async function saveHalow() {
        const payload = readHalowForm();
        try {
            await postJson('/api/halow_cfg', payload);
        } catch (err) {
            console.error('saveHalow error', err);
        }
        loadAll();
    }

    async function saveLbt() {
        const payload = readLbtForm();
        try {
            await postJson('/api/lbt_cfg', payload);
        } catch (err) {
            console.error('saveLbt error', err);
        }
        loadAll();
    }

    async function saveNet() {
        const payload = readNetForm();
        try {
            await postJson('/api/net_cfg', payload);
        } catch (err) {
            console.error('saveNet error', err);
        }
        loadAll();
    }

    async function saveSlip() {
        const payload = readSlipForm();
        try {
            await postJson('/api/slip_cfg', payload);
        } catch (err) {
            console.error('saveSlip error', err);
        }
        loadAll();
    }

    async function saveLog() {
        const payload = readLogForm();
        try {
            await postJson('/api/log_cfg', payload);
        } catch (err) {
            console.error('saveLog error', err);
        }
        loadAll();
    }

    async function saveTcp() {
        const payload = readTcpForm();
        try {
            await postJson('/api/tcp_server_cfg', payload);
        } catch (err) {
            console.error('saveTcp error', err);
        }
        loadAll();
    }

    function sanitizeLxmf(value) {
        return String(value || '').toUpperCase().replace(/[^0-9A-F]/g, '').slice(0, 32);
    }

    function handleTelemetryLxmfInput() {
        const el = document.getElementById('telemetry_lxmf');
        const next = sanitizeLxmf(el.value);
        if (el.value !== next) {
            el.value = next;
        }
        validateTelemetryForm({ silent: true });
        updateSaveButton('telemetry');
    }

    function formatCoordinateNumber(value) {
        const n = Number(value);
        if (!Number.isFinite(n)) {
            return '';
        }
        return n.toFixed(6).replace(/\.0+$/, '').replace(/(\.\d*?)0+$/, '$1');
    }

    function parseCoordinate(raw, kind) {
        const text = String(raw || '').trim();
        const maxAbs = (kind === 'lat') ? 90 : 180;

        if (!text) {
            return { ok: false, message: 'Value is required' };
        }

        const decimalText = text.replace(/,/g, '.');
        if (/^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(decimalText)) {
            const value = Number(decimalText);
            if (!Number.isFinite(value) || Math.abs(value) > maxAbs) {
                return { ok: false, message: `Out of range for ${kind}` };
            }
            return { ok: true, value };
        }

        const upper = decimalText.toUpperCase();
        const hemiMatch = upper.match(/([NSEW])\s*$/);
        const hemi = hemiMatch ? hemiMatch[1] : '';
        const cleaned = upper
            .replace(/[NSEW]/g, ' ')
            .replace(/[°º]/g, ' ')
            .replace(/[′']/g, ' ')
            .replace(/[″"]/g, ' ')
            .trim();
        const parts = cleaned ? cleaned.split(/\s+/).filter(Boolean) : [];

        if (parts.length >= 1 && parts.length <= 3) {
            const nums = parts.map(Number);
            if (nums.every(Number.isFinite)) {
                const degRaw = nums[0];
                const min = nums[1] || 0;
                const sec = nums[2] || 0;

                if (min < 0 || min >= 60 || sec < 0 || sec >= 60) {
                    return { ok: false, message: 'Minutes and seconds must be in range 0..59' };
                }

                let sign = (degRaw < 0) ? -1 : 1;
                if (hemi === 'S' || hemi === 'W') { sign = -1; }
                if (hemi === 'N' || hemi === 'E') { sign = 1; }

                const value = sign * (Math.abs(degRaw) + (min / 60) + (sec / 3600));
                if (Math.abs(value) > maxAbs) {
                    return { ok: false, message: `Out of range for ${kind}` };
                }
                return { ok: true, value };
            }
        }

        return { ok: false, message: 'Unsupported coordinate format' };
    }

    function setFieldInvalid(id, invalid) {
        const el = document.getElementById(id);
        if (!el) { return; }
        el.classList.toggle('input-invalid', !!invalid);
    }

    function clearTelemetryValidationState() {
        setFieldInvalid('telemetry_lat', false);
        setFieldInvalid('telemetry_lon', false);
        setFieldInvalid('telemetry_lxmf', false);
    }

    function validateTelemetryForm(opts = {}) {
        const silent = !!opts.silent;
        let ok = true;
        let firstError = '';

        const telemetryEnabled = document.getElementById('telemetry_en').checked;
        const latRes = parseCoordinate(document.getElementById('telemetry_lat').value, 'lat');
        const lonRes = parseCoordinate(document.getElementById('telemetry_lon').value, 'lon');
        const lxmf = sanitizeLxmf(document.getElementById('telemetry_lxmf').value);

        if (!telemetryEnabled) {
            clearTelemetryValidationState();
            if (!silent) {
                clearStatus('telemetry_status');
            }
            return true;
        }

        setFieldInvalid('telemetry_lat', !latRes.ok);
        setFieldInvalid('telemetry_lon', !lonRes.ok);

        if (!latRes.ok) {
            ok = false;
            firstError = latRes.message;
        }

        if (!lonRes.ok && ok) {
            ok = false;
            firstError = lonRes.message;
        }

        const lxmfValid = (lxmf.length === 0 || lxmf.length === 32);
        setFieldInvalid('telemetry_lxmf', !lxmfValid);
        if (!lxmfValid && ok) {
            ok = false;
            firstError = 'LXMF address must contain exactly 32 hex characters';
        }

        if (!silent) {
            if (ok) {
                clearStatus('telemetry_status');
            } else {
                setStatus('telemetry_status', firstError, true);
            }
        }

        return ok;
    }

    function normalizeCoordinateField(id, kind) {
        const el = document.getElementById(id);
        const res = parseCoordinate(el.value, kind);
        setFieldInvalid(id, !res.ok);
        if (res.ok) {
            el.value = formatCoordinateNumber(res.value);
            clearStatus('telemetry_status');
        }
        updateSaveButton('telemetry');
    }

    function buildTelemetryPayload() {
        const enabled = document.getElementById('telemetry_en').checked;
        const lat = parseCoordinate(document.getElementById('telemetry_lat').value, 'lat');
        const lon = parseCoordinate(document.getElementById('telemetry_lon').value, 'lon');

        return {
            en: enabled,
            ext: document.getElementById('telemetry_ext').checked,
            prd: parseInt(document.getElementById('telemetry_prd').value, 10) || 300,
            host: document.getElementById('telemetry_host').value.trim(),
            port: parseInt(document.getElementById('telemetry_port').value, 10) || 1883,
            lat: (enabled && lat.ok) ? lat.value : 0,
            lon: (enabled && lon.ok) ? lon.value : 0,
            dir_en: document.getElementById('telemetry_dir_en').checked,
            dir: parseInt(document.getElementById('telemetry_dir').value, 10) || 0,
            usr: document.getElementById('telemetry_usr').value,
            pwd: document.getElementById('telemetry_pwd').value,
            top: document.getElementById('telemetry_top').value,
            name: document.getElementById('telemetry_name').value,
            lxmf: sanitizeLxmf(document.getElementById('telemetry_lxmf').value)
        };
    }

    async function saveTelemetry() {
        if (!validateTelemetryForm()) {
            updateSaveButton('telemetry');
            return;
        }

        const payload = buildTelemetryPayload();

        try {
            const res = await postJson('/api/telemetry_cfg', payload);
            if (!res.ok) {
                setStatus('telemetry_status', 'Failed to save telemetry settings', true);
                return;
            }
        } catch (err) {
            console.error('saveTelemetry error', err, payload);
            setStatus('telemetry_status', 'Failed to save telemetry settings', true);
            return;
        }

        document.getElementById('telemetry_lat').value = formatCoordinateNumber(payload.lat);
        document.getElementById('telemetry_lon').value = formatCoordinateNumber(payload.lon);
        document.getElementById('telemetry_lxmf').value = payload.lxmf;
        setStatus('telemetry_status', 'Telemetry settings saved', false);
        await loadAll();
    }

    async function sendTelemetryNow() {
        const btn = document.getElementById('telemetry_send_btn');
        btn.disabled = true;
        clearStatus('telemetry_status');

        try {
            const res = await postJson('/api/telemetry_send', {});
            if (!res.ok) {
                setStatus('telemetry_status', 'Telemetry send request failed', true);
                return;
            }

            setStatus('telemetry_status', 'Telemetry send request accepted', false);
        } catch (err) {
            console.error('sendTelemetryNow error', err);
            setStatus('telemetry_status', 'Telemetry send request failed', true);
        } finally {
            btn.disabled = false;
        }
    }

    function setStatus(id, text, isError) {
        const el = document.getElementById(id);
        if (!el) { return; }
        el.textContent = text || '';
        el.classList.toggle('ok', !isError && !!text);
        el.classList.toggle('error', !!isError && !!text);
    }

    function clearStatus(id) {
        setStatus(id, '', false);
    }

    function updateWebOtaDisabled() {
        const f = document.getElementById('webota_file').files;
        document.getElementById('webota_flash').disabled = !(f && f.length === 1);
    }

    function bytesToB64(u8) {
        let s = '';
        const chunk = 0x8000;
        for (let i = 0; i < u8.length; i += chunk) {
            s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
        }
        return btoa(s);
    }

    function crc32_make_table() {
        const t = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let k = 0; k < 8; k++) {
                c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            }
            t[i] = c >>> 0;
        }
        return t;
    }
    const CRC32_T = crc32_make_table();

    function crc32_update(crc, u8) {
        let c = (crc ^ 0xFFFFFFFF) >>> 0;
        for (let i = 0; i < u8.length; i++) {
            c = CRC32_T[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
        }
        return (c ^ 0xFFFFFFFF) >>> 0;
    }

    function sleepMs(ms) {
        return new Promise(r => setTimeout(r, ms));
    }

    async function fetchJsonRetry(url, opts, tries, baseDelayMs) {
        let lastErr;

        for (let i = 0; i < tries; i++) {
            try {
                const r = await fetch(url, opts);
                if (!r.ok) {
                    lastErr = new Error('HTTP ' + r.status);
                } else {
                    return r;
                }
            } catch (e) {
                lastErr = e;
            }

            if (i + 1 < tries) {
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

    function fwLog(msg) {
        const consoleEl = document.getElementById('fw_console');
        if (!consoleEl) { return; }
        const line = document.createElement('div');
        line.textContent = msg;
        consoleEl.appendChild(line);
        consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    function handleFwBetaToggle() {
        fwUpdateState.betaEnabled = document.getElementById('fw_beta_toggle').checked;
    }

    async function checkFwUpdates() {
        const btn = document.getElementById('fw_check_updates');
        const container = document.getElementById('fw_updates_container');
        const select = document.getElementById('fw_version_select');

        btn.disabled = true;
        container.style.display = 'none';

        try {
            const res = await fetch('https://api.github.com/repos/I-AM-ENGINEER/RNode_Halow_Firmware/releases', {
                cache: 'no-store'
            });

            if (!res.ok) {
                setStatus('fw_download_status', 'Failed to fetch releases', true);
                return;
            }

            const releases = await res.json();
            fwUpdateState.releases = releases.filter(r => {
                if (fwUpdateState.betaEnabled) return true;
                return !r.prerelease;
            });

            select.innerHTML = '';

            if (fwUpdateState.releases.length === 0) {
                const opt = document.createElement('option');
                opt.textContent = 'No versions available';
                opt.value = '';
                select.appendChild(opt);
                setStatus('fw_download_status', 'No releases found', true);
                return;
            }

            fwUpdateState.releases.forEach(release => {
                const opt = document.createElement('option');
                const label = release.prerelease ? `${release.tag_name} (beta)` : release.tag_name;
                opt.textContent = label;
                opt.value = release.id;
                select.appendChild(opt);
            });

            select.value = fwUpdateState.releases[0].id;
            handleFwVersionSelect();
            container.style.display = 'block';
            clearStatus('fw_download_status');
        } catch (err) {
            console.error('checkFwUpdates error', err);
            setStatus('fw_download_status', 'Error fetching updates: ' + (err?.message || 'network error'), true);
        } finally {
            btn.disabled = false;
        }
    }

    function handleFwVersionSelect() {
        const select = document.getElementById('fw_version_select');
        const infoEl = document.getElementById('fw_version_info');
        const flashBtn = document.getElementById('fw_download_flash');

        const releaseId = select.value;
        const release = fwUpdateState.releases.find(r => r.id == releaseId);

        if (!release) {
            infoEl.textContent = '--';
            flashBtn.disabled = true;
            return;
        }

        const tarAsset = release.assets.find(a => a.name.endsWith('.tar'));
        if (!tarAsset) {
            infoEl.textContent = 'No .tar file found in this release';
            flashBtn.disabled = true;
            return;
        }

        fwUpdateState.selectedVersion = {
            name: release.tag_name,
            downloadUrl: tarAsset.browser_download_url,
            size: tarAsset.size
        };

        const sizeMb = (tarAsset.size / (1024 * 1024)).toFixed(1);
        infoEl.textContent = `${sizeMb} MB • Released ${new Date(release.published_at).toLocaleDateString()}`;
        flashBtn.disabled = false;
    }

    async function fwDownloadAndFlash() {
        if (!fwUpdateState.selectedVersion) {
            setStatus('fw_download_status', 'No version selected', true);
            return;
        }

        const btn = document.getElementById('fw_download_flash');
        const consoleEl = document.getElementById('webota_console');

        function log(msg) {
            const line = document.createElement('div');
            line.textContent = msg;
            consoleEl.appendChild(line);
            consoleEl.scrollTop = consoleEl.scrollHeight;
            return line;
        }
        function stage(msg) { log('[*] ' + msg); }
        function ok(msg) { log('[OK] ' + msg); }
        function err(msg) { log('[ERR] ' + msg); }

        const select = document.getElementById('fw_version_select');
        const versionLabel = select.options[select.selectedIndex].text;
        if (!confirm('Download ' + versionLabel + ' and flash?')) { return; }

        btn.disabled = true;
        fwUpdateState.downloading = true;
        consoleEl.innerHTML = '';
        clearStatus('fw_download_status');

        try {
            stage('Downloading firmware...');

            const res = await fetch(fwUpdateState.selectedVersion.downloadUrl, {
                cache: 'no-store'
            });

            if (!res.ok) {
                throw new Error('HTTP ' + res.status);
            }

            const arrayBuf = await res.arrayBuffer();
            const tarU8 = new Uint8Array(arrayBuf);
            ok('Downloaded ' + tarU8.length + ' bytes');

            const chunkSize = 512;
            const tries = 6;
            const baseDelayMs = 80;

            function mkPost(url, obj) {
                return fetchJsonRetry(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(obj)
                }, tries, baseDelayMs);
            }

            stage('Parsing TAR...');
            const allEntries = tarParse(tarU8);
            const fwEntry = allEntries.find(e => e.name === 'fw.bin' || e.name === '/fw.bin');
            const fileEntries = allEntries.filter(e => e.name !== 'fw.bin' && e.name !== '/fw.bin');

            if (!fwEntry && fileEntries.length === 0) {
                throw new Error('No files in archive');
            }
            ok('Found ' + allEntries.length + ' file(s)');

            if (fileEntries.length > 0) {
                stage('Wiping filesystem...');
                await mkPost('/api/ota_wipe_lfs', {});
                ok('Filesystem cleared');

                for (let i = 0; i < fileEntries.length; i++) {
                    const entry = fileEntries[i];
                    const targetPath = '/www/' + entry.name.replace(/^www\//, '');
                    const fileU8 = entry.data;

                    stage('[' + (i + 1) + '/' + fileEntries.length + '] ' + targetPath + ' (' + fileU8.length + 'B)');

                    const fileCrc32 = (crc32_update(0 >>> 0, fileU8) >>> 0);

                    await mkPost('/api/ota_file_begin', {
                        path: targetPath,
                        size: fileU8.length,
                        crc32: fileCrc32
                    });

                    const progressLine = log('    CRC32=0x' + fileCrc32.toString(16));
                    let offset = 0;
                    while (offset < fileU8.length) {
                        const nextOffset = Math.min(offset + chunkSize, fileU8.length);
                        const chunkBin = fileU8.subarray(offset, nextOffset);
                        const chunkB64 = bytesToB64(chunkBin);
                        await mkPost('/api/ota_file_chunk', { b64: chunkB64 });
                        offset = nextOffset;
                        const percent = Math.floor((offset * 100) / fileU8.length);
                        progressLine.textContent = '    ' + percent + '% (' + offset + '/' + fileU8.length + 'B)';
                    }

                    await mkPost('/api/ota_file_end', {});
                    ok('Verified');
                }
            }

            if (fwEntry) {
                const fileU8 = fwEntry.data;
                const fileCrc32 = (crc32_update(0 >>> 0, fileU8) >>> 0);
                ok('Firmware: ' + fileU8.length + ' bytes, CRC32=0x' + fileCrc32.toString(16));

                stage('Starting firmware flash...');
                await mkPost('/api/ota_fw_begin', {
                    size: fileU8.length,
                    crc32: fileCrc32
                });
                ok('Ready');

                stage('Uploading firmware...');
                const progressLine = log('    0%');

                let offset = 0;
                while (offset < fileU8.length) {
                    const nextOffset = Math.min(offset + chunkSize, fileU8.length);
                    const chunkBin = fileU8.subarray(offset, nextOffset);
                    const chunkB64 = bytesToB64(chunkBin);
                    await mkPost('/api/ota_fw_chunk', { off: offset, b64: chunkB64 });
                    offset = nextOffset;
                    const percent = Math.floor((offset * 100) / fileU8.length);
                    progressLine.textContent = '    ' + percent + '% (' + offset + '/' + fileU8.length + 'B)';
                }

                progressLine.textContent = '[OK] Upload complete';

                stage('Verifying firmware...');
                await mkPost('/api/ota_fw_end', {});
                ok('Verified');

                stage('Rebooting...');
                fetch('/api/reboot', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                }).catch(() => {});
                ok('Rebooting...');

                stage('Waiting for device...');
                let newVersion = null;
                for (let poll = 0; poll < 120; poll++) {
                    await sleepMs(1000);
                    try {
                        const res = await fetch('/api/get_stat', { cache: 'no-store' });
                        if (res.ok) {
                            const data = await res.json();
                            const device = data.device || data.api_dev_stat;
                            if (device && device.ver) {
                                newVersion = device.ver;
                                break;
                            }
                        }
                    } catch (_) { }
                }

                if (newVersion) {
                    ok('Device ready. New firmware version: ' + newVersion);
                } else {
                    ok('Device ready');
                }

                setStatus('fw_download_status', 'OTA complete. Please reload page.', false);
                return;
            }

            setStatus('fw_download_status', 'Update complete. Please reload page.', false);
            stage('Done.');
        } catch (e) {
            err(e && e.message ? e.message : 'error');
            setStatus('fw_download_status', 'Download and flash failed', true);
            btn.disabled = false;
        } finally {
            fwUpdateState.downloading = false;
        }
    }

    async function rebootDevice() {
        clearStatus('fw_action_status');
        fwLog('[*] Reboot request sent');

        try {
            const res = await postJson('/api/reboot', {});

            if (!res.ok) {
                setStatus('fw_action_status', 'Reboot request failed', true);
                fwLog('[ERR] Reboot request failed');
                return;
            }

            setStatus('fw_action_status', 'Reboot request accepted', false);
            fwLog('[OK] Reboot request accepted');
        } catch (err) {
            console.error('rebootDevice error', err);
            setStatus('fw_action_status', 'Reboot request failed', true);
            fwLog('[ERR] Reboot request failed');
        }
    }

    async function factoryResetDevice() {
        if (!confirm('Reset all settings to factory defaults?')) {
            return;
        }

        clearStatus('fw_action_status');
        fwLog('[*] Factory reset request sent');

        try {
            const res = await postJson('/api/default_rst', {});

            if (!res.ok) {
                setStatus('fw_action_status', 'Factory reset request failed', true);
                fwLog('[ERR] Factory reset request failed');
                return;
            }

            setStatus('fw_action_status', 'Factory reset request accepted', false);
            fwLog('[OK] Factory reset request accepted');
            loadAll();
        } catch (err) {
            console.error('factoryResetDevice error', err);
            setStatus('fw_action_status', 'Factory reset request failed', true);
            fwLog('[ERR] Factory reset request failed');
        }
    }

    function tarParse(u8) {
        const files = [];
        const BLOCK = 512;
        let pos = 0;

        function readStr(start, len) {
            let end = start;
            while (end < start + len && u8[end] !== 0) { end++; }
            return new TextDecoder().decode(u8.subarray(start, end));
        }

        function readOct(start, len) {
            return parseInt(readStr(start, len).trim() || '0', 8);
        }

        function isZeroBlock(off) {
            for (let i = 0; i < BLOCK; i++) {
                if (u8[off + i] !== 0) { return false; }
            }
            return true;
        }

        while (pos + BLOCK <= u8.length) {
            if (isZeroBlock(pos)) { break; }

            const name = readStr(pos, 100);
            const typeflag = String.fromCharCode(u8[pos + 156]);
            const size = readOct(pos + 124, 12);

            pos += BLOCK;

            if (typeflag === '5' || size === 0) {
                pos += Math.ceil(size / BLOCK) * BLOCK;
                continue;
            }

            if (typeflag === '0' || typeflag === '\0') {
                const data = u8.slice(pos, pos + size);
                files.push({ name: name.replace(/^\./, ''), data });
            }

            pos += Math.ceil(size / BLOCK) * BLOCK;
        }

        return files;
    }

    async function fwWebOtaFlash() {
        const fileEl = document.getElementById('webota_file');
        const btn = document.getElementById('webota_flash');
        const consoleEl = document.getElementById('webota_console');

        const tarFile = (fileEl.files && fileEl.files.length === 1) ? fileEl.files[0] : null;
        if (!tarFile) { return; }

        if (!confirm('Unpack ' + tarFile.name + ' and flash?')) { return; }

        function log(msg) {
            const line = document.createElement('div');
            line.textContent = msg;
            consoleEl.appendChild(line);
            consoleEl.scrollTop = consoleEl.scrollHeight;
            return line;
        }
        function stage(msg) { log('[*] ' + msg); }
        function ok(msg) { log('[OK] ' + msg); }
        function err(msg) { log('[ERR] ' + msg); }

        const chunkSize = 512;
        const tries = 6;
        const baseDelayMs = 80;

        function mkPost(url, obj) {
            return fetchJsonRetry(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(obj)
            }, tries, baseDelayMs);
        }

        btn.disabled = true;
        consoleEl.innerHTML = '';
        clearStatus('webota_status');

        try {
            stage('Reading TAR...');
            const tarBuf = await tarFile.arrayBuffer();
            const tarU8 = new Uint8Array(tarBuf);

            const allEntries = tarParse(tarU8);
            const fwEntry = allEntries.find(e => e.name === 'fw.bin' || e.name === '/fw.bin');
            const fileEntries = allEntries.filter(e => e.name !== 'fw.bin' && e.name !== '/fw.bin');

            if (!fwEntry && fileEntries.length === 0) {
                throw new Error('No files in archive');
            }
            ok('Found ' + allEntries.length + ' file(s)');

            if (fileEntries.length > 0) {
                stage('Wiping filesystem...');
                await mkPost('/api/ota_wipe_lfs', {});
                ok('Filesystem cleared');

                for (let i = 0; i < fileEntries.length; i++) {
                    const entry = fileEntries[i];
                    const targetPath = '/www/' + entry.name.replace(/^www\//, '');
                    const fileU8 = entry.data;

                    stage('[' + (i + 1) + '/' + fileEntries.length + '] ' + targetPath + ' (' + fileU8.length + 'B)');

                    const fileCrc32 = (crc32_update(0 >>> 0, fileU8) >>> 0);

                    await mkPost('/api/ota_file_begin', {
                        path: targetPath,
                        size: fileU8.length,
                        crc32: fileCrc32
                    });

                    const progressLine = log('    CRC32=0x' + fileCrc32.toString(16));
                    let offset = 0;
                    while (offset < fileU8.length) {
                        const nextOffset = Math.min(offset + chunkSize, fileU8.length);
                        const chunkBin = fileU8.subarray(offset, nextOffset);
                        const chunkB64 = bytesToB64(chunkBin);
                        await mkPost('/api/ota_file_chunk', { b64: chunkB64 });
                        offset = nextOffset;
                        const percent = Math.floor((offset * 100) / fileU8.length);
                        progressLine.textContent = '    ' + percent + '% (' + offset + '/' + fileU8.length + 'B)';
                    }

                    await mkPost('/api/ota_file_end', {});
                    ok('Verified');
                }
            }

            if (fwEntry) {
                const fileU8 = fwEntry.data;
                const fileCrc32 = (crc32_update(0 >>> 0, fileU8) >>> 0);
                ok('Firmware: ' + fileU8.length + ' bytes, CRC32=0x' + fileCrc32.toString(16));

                stage('Starting firmware flash...');
                await mkPost('/api/ota_fw_begin', {
                    size: fileU8.length,
                    crc32: fileCrc32
                });
                ok('Ready');

                stage('Uploading firmware...');
                const progressLine = log('    0%');

                let offset = 0;
                while (offset < fileU8.length) {
                    const nextOffset = Math.min(offset + chunkSize, fileU8.length);
                    const chunkBin = fileU8.subarray(offset, nextOffset);
                    const chunkB64 = bytesToB64(chunkBin);
                    await mkPost('/api/ota_fw_chunk', { off: offset, b64: chunkB64 });
                    offset = nextOffset;
                    const percent = Math.floor((offset * 100) / fileU8.length);
                    progressLine.textContent = '    ' + percent + '% (' + offset + '/' + fileU8.length + 'B)';
                }

                progressLine.textContent = '[OK] Upload complete';

                stage('Verifying firmware...');
                await mkPost('/api/ota_fw_end', {});
                ok('Verified');

                stage('Rebooting...');
                fetch('/api/reboot', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                }).catch(() => {});
                ok('Rebooting...');

                stage('Waiting for device...');
                let newVersion = null;
                for (let poll = 0; poll < 120; poll++) {
                    await sleepMs(1000);
                    try {
                        const res = await fetch('/api/get_stat', { cache: 'no-store' });
                        if (res.ok) {
                            const data = await res.json();
                            const device = data.device || data.api_dev_stat;
                            if (device && device.ver) {
                                newVersion = device.ver;
                                break;
                            }
                        }
                    } catch (_) { }
                }

                if (newVersion) {
                    ok('Device ready. New firmware version: ' + newVersion);
                } else {
                    ok('Device ready');
                }

                setStatus('webota_status', 'OTA complete. Please reload page.', false);
                return;
            }

            setStatus('webota_status', 'Update complete. Please reload page.', false);
            stage('Done.');
        } catch (e) {
            err(e && e.message ? e.message : 'error');
            setStatus('webota_status', 'Web update failed', true);
            btn.disabled = false;
        }
    }

})();
