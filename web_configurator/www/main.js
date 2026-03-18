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
        tcp: '',
        telemetry: ''
    };

    document.addEventListener('DOMContentLoaded', () => {
        setupTabs();
        setupHandlers();
        setupDirtyTracking();
        loadAll();
        updateStats();
        setInterval(updateStats, 1000);
    });

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
        if (group === 'tcp') { baselines.tcp = jsonSnapshot(readTcpForm()); }
        if (group === 'telemetry') { baselines.telemetry = jsonSnapshot(readTelemetryForm()); }
        updateSaveButton(group);
    }

    function snapshotAll() {
        snapshotGroup('halow');
        snapshotGroup('lbt');
        snapshotGroup('net');
        snapshotGroup('tcp');
        snapshotGroup('telemetry');
    }

    function setupDirtyTracking() {
        const map = [
            { group: 'halow', btn: 'save_halow', ids: ['halow_power_dbm', 'halow_central_freq', 'halow_mcs_index', 'halow_bandwidth', 'halow_super_power'] },
            { group: 'lbt', btn: 'save_lbt', ids: ['lbt_uen', 'lbt_umax'] },
            { group: 'net', btn: 'save_net', ids: ['net_dhcp', 'net_ip_address', 'net_gw_address', 'net_netmask'] },
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

        document.getElementById('fw_file').addEventListener('change', updateFwDisabled);
        document.getElementById('fw_flash').addEventListener('click', fwFlash);
        document.getElementById('fw_reboot').addEventListener('click', rebootDevice);
        document.getElementById('fw_factory_reset').addEventListener('click', factoryResetDevice);

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
        setCheckbox('halow_super_power', halow.super_power);
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

    function updateFwDisabled() {
        const f = document.getElementById('fw_file').files;
        document.getElementById('fw_flash').disabled = !(f && f.length === 1);
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

    async function fwFlash() {
        const fileEl = document.getElementById('fw_file');
        const btn = document.getElementById('fw_flash');
        const consoleEl = document.getElementById('fw_console');

        const file = (fileEl.files && fileEl.files.length === 1) ? fileEl.files[0] : null;
        if (!file) { return; }

        if (!confirm('Upload OTA file to device and flash it?')) { return; }

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

        function mkPost(url, obj) {
            return fetchJsonRetry(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(obj)
            }, tries, baseDelayMs);
        }

        btn.disabled = true;
        consoleEl.innerHTML = '';
        clearStatus('fw_action_status');

        const chunkSize = 512;
        const tries = 6;
        const baseDelayMs = 80;

        try {
            stage('Reading file: ' + file.name);
            const fileBuf = await file.arrayBuffer();
            const fileU8 = new Uint8Array(fileBuf);
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

            stage('Uploading firmware...');
            const progressLine = log('    0%');

            let offset = 0;
            while (offset < fileU8.length) {
                const nextOffset = Math.min(offset + chunkSize, fileU8.length);
                const chunkBin = fileU8.subarray(offset, nextOffset);
                const chunkB64 = bytesToB64(chunkBin);

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
