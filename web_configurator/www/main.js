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
        telemetry: '',
        privacy: '',
        ack: ''
    };
    const DASHBOARD_REFRESH_MS = 1000;
    const dashboardState = {
        active: false,
        timer: null,
        loading: false
    };

    const nearbyState = {
        timer: null,
        loading: false,
        active: false,
        speedCache: new Map(),
        rows: [],
        sortKey: null,
        sortDesc: false
    };
    const reticulumState = {
        timer: null,
        loading: false,
        active: false,
        speedCache: new Map(),
        rows: [],
        sortKey: null,
        sortDesc: false
    };
    const fwUpdateState = {
        releases: [],
        selectedVersion: null,
        downloading: false,
        betaEnabled: false
    };

    setupTabs();

    document.addEventListener('DOMContentLoaded', () => {
        setupHandlers();
        setupDirtyTracking();
        fwUpdateState.betaEnabled = document.getElementById('fw_beta_toggle').checked;
        loadAll();
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
            en: document.getElementById('cca_en').checked ? 1 : 0,
            ftpct: parseFloat(document.getElementById('cca_ftpct').value) || 0,
            dlpct: parseFloat(document.getElementById('cca_dlpct').value) || 0,
            thdyn: parseInt(document.getElementById('cca_thdyn').value, 10),
            sens: parseInt(document.getElementById('cca_sens').value, 10)
        };
    }

    function readCcaForm() { return readLbtForm(); }

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

    function readPrivacyForm() {
        return {
            rotation: parseInt(document.getElementById('privacy_mac_rotation').value, 10) || 0,
            broadcast: document.getElementById('privacy_mac_broadcast').checked
        };
    }

    function updateSaveButton(group) {
        let current = '';
        let btn = null;
        let isValid = true;

        if (group === 'halow') {
            current = jsonSnapshot(readHalowForm());
            btn = document.getElementById('save_halow');
            isValid = isHalowFormValid();
        }
        if (group === 'lbt') {
            current = jsonSnapshot(readLbtForm());
            btn = document.getElementById('save_lbt');
            isValid = isLbtFormValid();
        }
        if (group === 'cca') {
            current = jsonSnapshot(readCcaForm());
            btn = document.getElementById('save_cca');
        }
        if (group === 'net') {
            current = jsonSnapshot(readNetForm());
            btn = document.getElementById('save_net');
            isValid = isNetFormValid();
        }
        if (group === 'slip') {
            current = jsonSnapshot(readSlipForm());
            btn = document.getElementById('save_slip');
            isValid = isSlipFormValid();
        }
        if (group === 'log') {
            current = jsonSnapshot(readLogForm());
            btn = document.getElementById('save_log');
            isValid = isLogFormValid();
        }
        if (group === 'tcp') {
            current = jsonSnapshot(readTcpForm());
            btn = document.getElementById('save_tcp');
            isValid = isTcpFormValid();
        }
        if (group === 'telemetry') {
            current = jsonSnapshot(readTelemetryForm());
            btn = document.getElementById('save_telemetry');
            isValid = validateTelemetryForm({ silent: true });
        }
        if (group === 'privacy') {
            current = jsonSnapshot(readPrivacyForm());
            btn = document.getElementById('save_privacy');
        }
        if (group === 'ack') {
            current = jsonSnapshot(readAckForm());
            btn = document.getElementById('save_ack');
        }

        if (!btn) { return; }

        btn.disabled = (current === baselines[group]) || !isValid;
    }

    function snapshotGroup(group) {
        if (group === 'halow') { baselines.halow = jsonSnapshot(readHalowForm()); }
        if (group === 'lbt') { baselines.lbt = jsonSnapshot(readLbtForm()); }
        if (group === 'cca') { baselines.cca = jsonSnapshot(readCcaForm()); }
        if (group === 'net') { baselines.net = jsonSnapshot(readNetForm()); }
        if (group === 'slip') { baselines.slip = jsonSnapshot(readSlipForm()); }
        if (group === 'log') { baselines.log = jsonSnapshot(readLogForm()); }
        if (group === 'tcp') { baselines.tcp = jsonSnapshot(readTcpForm()); }
        if (group === 'telemetry') { baselines.telemetry = jsonSnapshot(readTelemetryForm()); }
        if (group === 'privacy') { baselines.privacy = jsonSnapshot(readPrivacyForm()); }
        if (group === 'ack') { baselines.ack = jsonSnapshot(readAckForm()); }
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
        snapshotGroup('privacy');
    }

    function setupDirtyTracking() {
        const map = [
            { group: 'halow', btn: 'save_halow', ids: ['halow_power_dbm', 'halow_central_freq', 'halow_mcs_index', 'halow_bandwidth'] },
            { group: 'lbt', btn: 'save_lbt', ids: ['cca_en', 'cca_ftpct', 'cca_dlpct', 'cca_thdyn', 'cca_sens'] },
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
            },
            { group: 'privacy', btn: 'save_privacy', ids: ['privacy_mac_rotation', 'privacy_mac_broadcast'] },
            { group: 'ack', btn: 'save_ack', ids: ['ack_retries', 'ack_rate_adapt', 'ack_ra_loss_up', 'ack_ra_loss_down', 'ack_agg', 'ack_bc_repeat'] }
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

        const retriesFld = document.getElementById('ack_retries');
        const raBox = document.getElementById('ack_rate_adapt');
        const upFld = document.getElementById('ack_ra_loss_up');
        const dnFld = document.getElementById('ack_ra_loss_down');
        const raPanel = document.getElementById('ra_panel');
        const raWarn = document.getElementById('ra_warn');
        if (retriesFld && raBox) {
            const syncRateAdapt = () => {
                const ackOn = (parseInt(retriesFld.value, 10) || 0) > 0;
                if (!ackOn) raBox.checked = false;
                const raOn = !!raBox.checked && ackOn;
                if (upFld) upFld.disabled = !raOn;
                if (dnFld) dnFld.disabled = !raOn;
                if (raPanel) raPanel.classList.toggle('disabled', !ackOn);
                if (raWarn) raWarn.style.display = ackOn ? 'none' : 'block';
                updateSaveButton('ack');
            };
            retriesFld.addEventListener('input', syncRateAdapt);
            retriesFld.addEventListener('change', syncRateAdapt);
            raBox.addEventListener('change', syncRateAdapt);
        }
    }

    function switchTab(tabName) {
        const buttons = document.querySelectorAll('.tabs button');
        buttons.forEach(b => b.classList.toggle('active', b.dataset.tab === tabName));
        document.querySelectorAll('.tab-content').forEach(sec => sec.classList.remove('active'));
        const sec = document.getElementById(tabName);
        if (sec) { sec.classList.add('active'); }
        history.replaceState(null, '', '#' + tabName);
        handleTabActivated(tabName);
    }

    function setupTabs() {
        document.querySelectorAll('.tabs button').forEach(btn => {
            btn.addEventListener('click', () => {
                if (btn.classList.contains('active')) { return; }
                switchTab(btn.dataset.tab);
            });
        });

        const hash = location.hash.slice(1);
        switchTab((hash && document.getElementById(hash)) ? hash : 'dashboard');
    }

    function validateHalowFields() {
        const powerField = document.getElementById('halow_power_dbm');
        const freqField = document.getElementById('halow_central_freq');
        const power = parseFloat(powerField.value);
        const freq = parseFloat(freqField.value);

        const powerInvalid = isNaN(power) || power < 1 || power > 25;
        const freqInvalid = isNaN(freq) || freq < 730 || freq > 1080;

        powerField.classList.toggle('error', powerInvalid);
        freqField.classList.toggle('error', freqInvalid);
        updateSaveButton('halow');
    }

    function isHalowFormValid() {
        const power = parseFloat(document.getElementById('halow_power_dbm').value);
        const freq = parseFloat(document.getElementById('halow_central_freq').value);
        return !(isNaN(power) || power < 1 || power > 25 || isNaN(freq) || freq < 730 || freq > 1080);
    }

    function validateLbtFields() {
        const ftpctField = document.getElementById('cca_ftpct');
        const dlpctField = document.getElementById('cca_dlpct');
        const sensField  = document.getElementById('cca_sens');

        const ftpct = parseFloat(ftpctField.value);
        const dlpct = parseFloat(dlpctField.value);
        const sens  = parseInt(sensField.value, 10);

        ftpctField.classList.toggle('error', isNaN(ftpct) || ftpct < 0.1 || ftpct > 100);
        dlpctField.classList.toggle('error', isNaN(dlpct) || (dlpct !== 0 && dlpct < 1) || dlpct > 100);
        sensField.classList.toggle('error',  isNaN(sens)  || sens < 0 || sens > 10);

        updateSaveButton('lbt');
    }

    function isLbtFormValid() {
        const ftpct = parseFloat(document.getElementById('cca_ftpct').value);
        const dlpct = parseFloat(document.getElementById('cca_dlpct').value);
        const sens  = parseInt(document.getElementById('cca_sens').value, 10);

        if (isNaN(ftpct) || ftpct < 0.1 || ftpct > 100) return false;
        if (isNaN(dlpct) || (dlpct !== 0 && dlpct < 1) || dlpct > 100) return false;
        if (isNaN(sens) || sens < 0 || sens > 10) return false;
        return true;
    }

    function isValidIp(ip) {
        const parts = ip.trim().split('.');
        if (parts.length !== 4) return false;
        return parts.every(part => {
            const num = parseInt(part, 10);
            return Number.isFinite(num) && num >= 0 && num <= 255 && part === String(num);
        });
    }

    function isValidNetmask(mask) {
        const parts = mask.trim().split('.');
        if (parts.length !== 4) return false;
        const nums = parts.map(p => {
            const num = parseInt(p, 10);
            return Number.isFinite(num) && num >= 0 && num <= 255 && p === String(num) ? num : -1;
        });
        if (nums.some(n => n === -1)) return false;

        let combined = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3];
        combined = combined >>> 0;

        let ones = 0;
        let seenZero = false;
        for (let i = 31; i >= 0; i--) {
            const bit = (combined >>> i) & 1;
            if (bit === 0) {
                seenZero = true;
            } else if (seenZero) {
                return false;
            }
            if (bit === 1) ones++;
        }
        return ones > 0;
    }

    function validateNetFields() {
        const dhcp = document.getElementById('net_dhcp').checked;
        const ipField = document.getElementById('net_ip_address');
        const gwField = document.getElementById('net_gw_address');
        const nmField = document.getElementById('net_netmask');

        if (dhcp) {
            ipField.classList.remove('error');
            gwField.classList.remove('error');
            nmField.classList.remove('error');
        } else {
            const ip = ipField.value.trim();
            const gw = gwField.value.trim();
            const nm = nmField.value.trim();
            ipField.classList.toggle('error', !isValidIp(ip));
            gwField.classList.toggle('error', !isValidIp(gw));
            nmField.classList.toggle('error', !isValidNetmask(nm));
        }
        updateSaveButton('net');
    }

    function isNetFormValid() {
        const dhcp = document.getElementById('net_dhcp').checked;
        if (dhcp) return true;
        const ip = document.getElementById('net_ip_address').value.trim();
        const gw = document.getElementById('net_gw_address').value.trim();
        const nm = document.getElementById('net_netmask').value.trim();
        return isValidIp(ip) && isValidIp(gw) && isValidNetmask(nm);
    }

    function validateSlipFields() {
        const enabled = document.getElementById('slip_enable').checked;
        const baudField = document.getElementById('slip_baud');
        const ipField = document.getElementById('slip_ip_address');
        const gwField = document.getElementById('slip_gw_address');

        if (enabled) {
            const baud = parseInt(baudField.value, 10);
            const ip = ipField.value.trim();
            const gw = gwField.value.trim();
            baudField.classList.toggle('error', isNaN(baud) || baud < 1);
            ipField.classList.toggle('error', !isValidIp(ip));
            gwField.classList.toggle('error', !isValidIp(gw));
        } else {
            baudField.classList.remove('error');
            ipField.classList.remove('error');
            gwField.classList.remove('error');
        }
        updateSaveButton('slip');
    }

    function isSlipFormValid() {
        const enabled = document.getElementById('slip_enable').checked;
        if (!enabled) return true;
        const baud = parseInt(document.getElementById('slip_baud').value, 10);
        const ip = document.getElementById('slip_ip_address').value.trim();
        const gw = document.getElementById('slip_gw_address').value.trim();
        return !isNaN(baud) && baud >= 1 && isValidIp(ip) && isValidIp(gw);
    }

    function validateLogFields() {
        const enabled = document.getElementById('log_udp_enable').checked;
        const hostField = document.getElementById('log_udp_host');
        const portField = document.getElementById('log_udp_port');

        if (enabled) {
            const host = hostField.value.trim();
            const port = parseInt(portField.value, 10);
            hostField.classList.toggle('error', !isValidIp(host));
            portField.classList.toggle('error', isNaN(port) || port < 1 || port > 65535);
        } else {
            hostField.classList.remove('error');
            portField.classList.remove('error');
        }
        updateSaveButton('log');
    }

    function isLogFormValid() {
        const enabled = document.getElementById('log_udp_enable').checked;
        if (!enabled) return true;
        const host = document.getElementById('log_udp_host').value.trim();
        const port = parseInt(document.getElementById('log_udp_port').value, 10);
        return isValidIp(host) && !isNaN(port) && port >= 1 && port <= 65535;
    }

    function isValidCidr(cidr) {
        const trimmed = cidr.trim();
        if (!trimmed) return false;

        const parts = trimmed.split('/');
        if (parts.length !== 2) return false;

        const ip = parts[0];
        const prefix = parseInt(parts[1], 10);

        if (!isValidIp(ip)) return false;
        if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return false;

        return true;
    }

    function validateTcpFields() {
        const enabled = document.getElementById('tcp_enable').checked;
        const portField = document.getElementById('tcp_port');
        const whitelistField = document.getElementById('tcp_whitelist');

        if (enabled) {
            const port = parseInt(portField.value, 10);
            const whitelist = whitelistField.value.trim();
            portField.classList.toggle('error', isNaN(port) || port < 1024 || port > 65535);

            let whitelistValid = true;
            if (whitelist) {
                const entries = whitelist.split(/[,\s]+/).filter(s => s.trim());
                whitelistValid = entries.length > 0 && entries.every(entry => isValidCidr(entry));
            }
            whitelistField.classList.toggle('error', !whitelistValid);
        } else {
            portField.classList.remove('error');
            whitelistField.classList.remove('error');
        }
        updateSaveButton('tcp');
    }

    function isTcpFormValid() {
        const enabled = document.getElementById('tcp_enable').checked;
        if (!enabled) return true;
        const port = parseInt(document.getElementById('tcp_port').value, 10);
        const whitelist = document.getElementById('tcp_whitelist').value.trim();

        if (isNaN(port) || port < 1024 || port > 65535) return false;

        if (whitelist) {
            const entries = whitelist.split(/[,\s]+/).filter(s => s.trim());
            if (entries.length === 0) return false;
            return entries.every(entry => isValidCidr(entry));
        }
        return true;
    }

    function clampDecimal(e, decimals) {
        const sep = e.target.value.search(/[.,]/);
        if (sep >= 0 && e.target.value.length - sep - 1 > decimals)
            e.target.value = e.target.value.slice(0, sep + 1 + decimals);
    }

    function setupHandlers() {
        setupTableSort('.nearby-table', nearbyState, parseNearbyRow, renderNearby);
        setupTableSort('.reticulum-table', reticulumState, parseReticulumRow, renderReticulum);

        const powerField = document.getElementById('halow_power_dbm');
        const freqField = document.getElementById('halow_central_freq');

        powerField.addEventListener('input', validateHalowFields);
        freqField.addEventListener('input', validateHalowFields);

        document.getElementById('halow_mcs_index').addEventListener('change', updateBandwidthDisabled);
        document.getElementById('save_halow').addEventListener('click', saveHalow);

        document.getElementById('save_lbt').addEventListener('click', saveLbt);
        document.getElementById('cca_ftpct').addEventListener('input', function(e) { clampDecimal(e, 1); validateLbtFields(); });
        document.getElementById('cca_dlpct').addEventListener('input', function(e) { clampDecimal(e, 1); validateLbtFields(); });
        document.getElementById('cca_sens').addEventListener('input', validateLbtFields);
        document.getElementById('cca_thdyn').addEventListener('change', updateCcaThresholdFields);

        updateCcaThresholdFields();

        document.getElementById('net_dhcp').addEventListener('change', () => { updateNetDisabled(); validateNetFields(); });
        document.getElementById('net_ip_address').addEventListener('input', validateNetFields);
        document.getElementById('net_gw_address').addEventListener('input', validateNetFields);
        document.getElementById('net_netmask').addEventListener('input', validateNetFields);
        document.getElementById('save_net').addEventListener('click', saveNet);

        document.getElementById('slip_enable').addEventListener('change', () => { updateSlipDisabled(); validateSlipFields(); });
        document.getElementById('slip_baud').addEventListener('input', validateSlipFields);
        document.getElementById('slip_ip_address').addEventListener('input', validateSlipFields);
        document.getElementById('slip_gw_address').addEventListener('input', validateSlipFields);
        document.getElementById('save_slip').addEventListener('click', saveSlip);

        document.getElementById('log_udp_enable').addEventListener('change', () => { updateLogDisabled(); validateLogFields(); });
        document.getElementById('log_udp_host').addEventListener('input', validateLogFields);
        document.getElementById('log_udp_port').addEventListener('input', validateLogFields);
        document.getElementById('save_log').addEventListener('click', saveLog);

        document.getElementById('tcp_enable').addEventListener('change', () => { updateTcpDisabled(); validateTcpFields(); });
        document.getElementById('tcp_port').addEventListener('input', validateTcpFields);
        document.getElementById('tcp_whitelist').addEventListener('input', validateTcpFields);
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

        document.getElementById('save_privacy').addEventListener('click', savePrivacy);
        const saveAckBtn = document.getElementById('save_ack');
        if (saveAckBtn) saveAckBtn.addEventListener('click', saveAck);

        document.getElementById('privacy_mac_rotation').addEventListener('change', () => {
            if (document.getElementById('privacy_mac_rotation').value !== '0') {
                document.getElementById('privacy_mac_broadcast').checked = false;
            }
            updateSaveButton('privacy');
        });
        document.getElementById('privacy_mac_broadcast').addEventListener('change', () => {
            if (document.getElementById('privacy_mac_broadcast').checked) {
                document.getElementById('privacy_mac_rotation').value = '0';
            }
            updateSaveButton('privacy');
        });

        document.getElementById('webota_file').addEventListener('change', updateWebOtaDisabled);
        document.getElementById('webota_flash').addEventListener('click', fwWebOtaFlash);
        document.getElementById('fw_reboot').addEventListener('click', rebootDevice);
        document.getElementById('fw_factory_reset').addEventListener('click', factoryResetDevice);

        document.getElementById('fw_beta_toggle').addEventListener('change', handleFwBetaToggle);
        document.getElementById('fw_check_updates').addEventListener('click', checkFwUpdates);
        document.getElementById('fw_version_select').addEventListener('change', handleFwVersionSelect);
        document.getElementById('fw_download_only').addEventListener('click', fwDownloadOnly);

        initFwConsole();
    }

    function updateBandwidthDisabled() {
        const mcs = document.getElementById('halow_mcs_index').value;
        const bw = document.getElementById('halow_bandwidth');
        const note = document.getElementById('halow_mcs10_note');
        if (mcs === 'MCS10') {
            bw.value = '1 MHz';
            bw.disabled = true;
            note.style.display = '';
        } else {
            bw.disabled = false;
            note.style.display = 'none';
        }
    }

    function updateLbtUtilDisabled() {
        const utilEnabled = document.getElementById('lbt_uen').checked;
        const el = document.getElementById('lbt_umax');
        if (el) {
            el.disabled = !utilEnabled;
        }
    }

    function updateCcaThresholdFields() { }

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

    async function loadAckConfig() {
        try {
            const res = await fetch('/api/ack_cfg');
            if (!res.ok) return;
            const data = await res.json();
            setInput('ack_retries', data.retries != null ? data.retries : 3);
            setInput('ack_bc_repeat', data.bc_repeat != null ? data.bc_repeat : 2);
            setInput('ack_ra_loss_up',   data.ra_loss_up   != null ? data.ra_loss_up   : 5);
            setInput('ack_ra_loss_down', data.ra_loss_down != null ? data.ra_loss_down : 30);
            const aggBox = document.getElementById('ack_agg');
            if (aggBox) aggBox.checked = !!data.agg;
            const ra = document.getElementById('ack_rate_adapt');
            const upFld = document.getElementById('ack_ra_loss_up');
            const dnFld = document.getElementById('ack_ra_loss_down');
            const raPanel = document.getElementById('ra_panel');
            const raWarn = document.getElementById('ra_warn');
            const retries = Number(data.retries) || 0;
            const ackOn = retries > 0;
            const raOn = !!data.rate_adapt && ackOn;
            if (ra) ra.checked = raOn;
            if (upFld) upFld.disabled = !raOn;
            if (dnFld) dnFld.disabled = !raOn;
            if (raPanel) raPanel.classList.toggle('disabled', !ackOn);
            if (raWarn) raWarn.style.display = ackOn ? 'none' : 'block';
            snapshotGroup('ack');
        } catch (err) {
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
            loadAckConfig();
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
				setText('stat_chip_temp', d.chip_temp);
				setText('stat_vcc', d.vcc);
				setText('stat_vdd13b', d.vdd13b);
				setText('stat_vdd13c', d.vdd13c);
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
        if (!nearbyState.active) {
            return;
        }
        nearbyState.timer = setTimeout(() => {
            refreshNearby(false);
        }, 1000);
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
        if (!Number.isFinite(bitsPerSecond) || bitsPerSecond <= 0) {
            return '0 kbit/s';
        }

        if (bitsPerSecond >= 1e6) return (bitsPerSecond / 1e6).toFixed(1) + ' Mbit/s';
        if (bitsPerSecond >= 1e3) return (bitsPerSecond / 1e3).toFixed(1) + ' kbit/s';
        return Math.round(bitsPerSecond) + ' bit/s';
    }

    function formatBytes(n) {
        if (!Number.isFinite(n) || n < 0) return '--';
        if (n >= 1048576) return (n / 1048576).toFixed(3) + ' MiB';
        if (n >= 1024) return (n / 1024).toFixed(3) + ' KiB';
        return n + ' B';
    }

    function formatNearbyLastSeen(seconds) {
        return formatDurationCompact(seconds);
    }

    function parseNearbyRow(row) {
        /* Firmware (web_api_nearby_modems_get) emits self-describing objects
         * keyed with rx_/tx_ prefixes (mirrors rns_link_db_link_t). has_rx /
         * has_tx flag which direction carries real data so the UI can render
         * '--' for the absent half (a heard-only neighbour has no TX stats;
         * a TX-only peer has no RX stats). Output keys match the <th
         * data-key=...> in the nearby table so sortRows can index by them. */
        const o = (row && typeof row === 'object') ? row : {};
        return {
            mac:            o.mac,
            hasRx:          !(o.has_rx === false || o.has_rx === 0),
            hasTx:          (o.has_tx === true || o.has_tx === 1),
            rxRssi:         o.rx_rssi,
            rxSnr:          o.rx_snr,
            rxMcs:          o.rx_mcs,
            rxBytes:        o.rx_bytes,
            rxPackets:      o.rx_packets,
            rxLast:         o.rx_last_age,
            txMcs:          o.tx_mcs,
            txEvm:          o.tx_evm,
            txPackets:      o.tx_frames,      /* wire MPDUs == "TX packets" */
            txBytes:        o.tx_bytes,
            txAcked:        o.tx_acked,
            txDropped:      o.tx_dropped,
            txRetransmitted:o.tx_retransmitted,
            txLast:         o.tx_last_age,
            txLoss:         o.tx_loss_pct     /* TX loss AFTER retries (windowed IIR), 0..100 */
        };
    }

    /* Per-direction bitrate delta for the nearby table. Separated from the
     * reticulum speedCache and keyed by 'rx:'/<mac> / 'tx:'/<mac> so RX and TX
     * deltas don't collide for the same peer. Returns '--' until two samples
     * exist (i.e. after the second poll). */
    function nearbyBitrate(cacheKey, bytes) {
        const nowMs = Date.now();
        const numBytes = Number(bytes);

        if (!cacheKey || !Number.isFinite(numBytes) || numBytes < 0) {
            return '--';
        }

        const prev = nearbyState.speedCache.get(cacheKey);
        nearbyState.speedCache.set(cacheKey, { bytes: numBytes, tsMs: nowMs });

        if (!prev) {
            return '--';
        }

        const deltaBytes = numBytes - prev.bytes;
        const deltaMs = nowMs - prev.tsMs;

        if (deltaBytes < 0 || deltaMs <= 0) {
            return '--';
        }

        return formatNearbyBitrate((deltaBytes * 8000) / deltaMs);
    }

    function peekBitrate(cache, key, bytes) {
        const prev = cache.get(key);
        if (!prev) return -1;
        const numBytes = Number(bytes);
        if (!Number.isFinite(numBytes) || numBytes < 0) return -1;
        const deltaBytes = numBytes - prev.bytes;
        const deltaMs = Date.now() - prev.tsMs;
        if (deltaBytes < 0 || deltaMs <= 0) return -1;
        return Math.round((deltaBytes * 8000) / deltaMs);
    }

    function sortRows(rows, parseFn, key, desc, rateCache) {
        if (!key) return rows;
        const sorted = rows.slice();
        /* Numeric sort keys used by BOTH the nearby and reticulum tables. Keys
         * match the parsed-row field names (parseNearbyRow / parseReticulumRow)
         * and the <th data-key=...> headers in index.html. */
        const numericKeys = new Set([
            'rxRssi', 'rxSnr', 'rxMcs', 'txMcs', 'txLoss', 'txEvm',
            'rxPackets', 'txPackets', 'rxBytes', 'txBytes',
            'rxLast', 'txLast', 'mtu'
        ]);
        sorted.sort((a, b) => {
            const pa = parseFn(a);
            const pb = parseFn(b);
            let va, vb;

            if (key === 'rxRate' || key === 'txRate') {
                /* Rate is derived from per-poll byte deltas in the table's own
                 * speedCache (reticulum or nearby), keyed 'rx:'/<id-or-mac> or
                 * 'tx:'/<id-or-mac>. Identify the row by whichever identity the
                 * table carries (reticulum = id/remoteMac, nearby = mac). */
                const ka = String(pa.mac ?? pa.id ?? pa.remoteMac ?? '');
                const kb = String(pb.mac ?? pb.id ?? pb.remoteMac ?? '');
                const isRx = (key === 'rxRate');
                va = peekBitrate(rateCache, (isRx ? 'rx:' : 'tx:') + ka, isRx ? pa.rxBytes : pa.txBytes);
                vb = peekBitrate(rateCache, (isRx ? 'rx:' : 'tx:') + kb, isRx ? pb.rxBytes : pb.txBytes);
            } else if (numericKeys.has(key)) {
                va = Number(pa[key]) || 0;
                vb = Number(pb[key]) || 0;
            } else {
                va = String(pa[key] ?? '');
                vb = String(pb[key] ?? '');
                return desc ? vb.localeCompare(va) : va.localeCompare(vb);
            }

            return desc ? vb - va : va - vb;
        });
        return sorted;
    }

    function applyHeaderSort(tableSel, sortKey, sortDesc) {
        const ths = document.querySelectorAll(tableSel + ' thead th');
        ths.forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.dataset.key === sortKey) {
                th.classList.add(sortDesc ? 'sort-desc' : 'sort-asc');
            }
        });
    }

    function setupTableSort(tableSel, stateObj, parseFn, renderFn) {
        const ths = document.querySelectorAll(tableSel + ' thead th');
        ths.forEach(th => {
            th.addEventListener('click', () => {
                const key = th.dataset.key;
                if (!key) return;
                if (stateObj.sortKey === key) {
                    stateObj.sortDesc = !stateObj.sortDesc;
                } else {
                    stateObj.sortKey = key;
                    stateObj.sortDesc = false;
                }
                renderFn();
            });
        });
    }

    function renderNearby() {
        applyHeaderSort('.nearby-table', nearbyState.sortKey, nearbyState.sortDesc);
        const sorted = sortRows(nearbyState.rows, parseNearbyRow, nearbyState.sortKey, nearbyState.sortDesc, nearbyState.speedCache);
        renderNearbyRows(sorted);
    }

    function renderReticulum() {
        applyHeaderSort('.reticulum-table', reticulumState.sortKey, reticulumState.sortDesc);
        const sorted = sortRows(reticulumState.rows, parseReticulumRow, reticulumState.sortKey, reticulumState.sortDesc, reticulumState.speedCache);
        renderReticulumRows(sorted);
    }

    function renderNearbyRows(rows) {
        const body = document.getElementById('nearby_table_body');
        if (!body) { return; }

        body.innerHTML = '';

        if (!rows.length) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 15;   /* keep in sync with the <thead> column count */
            td.textContent = 'No devices';
            tr.appendChild(td);
            body.appendChild(tr);
            return;
        }

        /* Helpers: each cell is either a real value or '--' when the peer has
         * no data for that direction (has_rx/has_tx). A unit suffix is appended
         * for signal-quality cells. */
        const dash = '--';
        const cell = (v) => (v !== undefined && v !== null && v !== '') ? String(v) : dash;
        const cellUnit = (v, unit) => (v !== undefined && v !== null && v !== '') ? (v + unit) : dash;
        const ageCell = (ageRaw) => {
            const age = Number(ageRaw);
            return (Number.isFinite(age) && age >= 0) ? formatNearbyLastSeen(age) : dash;
        };

        rows.forEach(srcRow => {
            const row = parseNearbyRow(srcRow);
            const tr = document.createElement('tr');
            const mac = String(row.mac ?? '');
            const hasRx = row.hasRx !== false;
            const hasTx = row.hasTx === true;

            const rxRate = hasRx ? nearbyBitrate('rx:' + mac, row.rxBytes) : dash;
            const txRate = hasTx ? nearbyBitrate('tx:' + mac, row.txBytes) : dash;

            /* Order MUST match the <thead data-key=...> in index.html:
             *   mac, rxRssi, rxSnr, rxMcs, txMcs, txLoss, txEvm,
             *   rxPackets, txPackets, rxBytes, txBytes, rxRate, txRate,
             *   rxLast, txLast */
            const values = [
                formatMac(row.mac),
                hasRx ? cellUnit(row.rxRssi, ' dBm') : dash,
                hasRx ? cellUnit(row.rxSnr, ' dB') : dash,
                hasRx ? cell(row.rxMcs) : dash,
                hasTx ? cell(row.txMcs) : dash,
                hasTx ? cellUnit(row.txLoss, '%') : dash,
                hasTx ? cellUnit(row.txEvm, ' dB') : dash,
                hasRx ? Number(row.rxPackets).toLocaleString('ru-RU') : dash,
                hasTx ? Number(row.txPackets).toLocaleString('ru-RU') : dash,
                hasRx ? formatBytes(row.rxBytes) : dash,
                hasTx ? formatBytes(row.txBytes) : dash,
                rxRate,
                txRate,
                hasRx ? ageCell(row.rxLast) : dash,
                hasTx ? ageCell(row.txLast) : dash
            ];

            values.forEach(value => {
                const td = document.createElement('td');
                td.textContent = value;
                tr.appendChild(td);
            });

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

        try {
            const res = await fetch('/api/get_nearby_modems', { cache: 'no-store' });
            if (!res.ok) {
                return;
            }

            const data = await res.json();
            const rows = Array.isArray(data?.d) ? data.d : (Array.isArray(data?.devices) ? data.devices : []);
            const total = Number(data?.c ?? data?.count ?? data?.total ?? rows.length ?? 0);

            setText('nearby_self_mac', formatMac(data?.m ?? '--'));
            setText('nearby_count', total);
            nearbyState.rows = rows;
            renderNearby();
        } catch (err) {
            // ignore nearby fetch errors
        } finally {
            nearbyState.loading = false;
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
        if (!reticulumState.active) return;
        reticulumState.timer = setTimeout(() => {
            refreshReticulum(false);
        }, 1000);
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

    /* RNS link state enum — MUST match rns_link_db_state_t in inc/rns/defines.h.
     * The firmware ships this as a raw number, so we map it to a human-readable
     * label here for the Reticulum table. */
    function formatRnsState(state) {
        switch (Number(state)) {
            case 0: return 'Closed';
            case 1: return 'Pending';      // REQUEST_SENT  — LinkRequest sent, awaiting reply
            case 2: return 'Handshake';    // PROOF_RECEIVED — proof phase, almost open
            case 3: return 'Open';         // OPEN          — fully established, data flows
            default: return (state !== undefined && state !== null && state !== '')
                       ? String(state) : '--';
        }
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
            const idKey = String(row.id ?? row.remoteMac ?? '');
            const rxRate = calcReticulumBitrate('rx:' + idKey, row.rxBytes);
            const txRate = calcReticulumBitrate('tx:' + idKey, row.txBytes);
            const tr = document.createElement('tr');
            const fmt = v => (v !== undefined && v !== null && v !== '') ? v : '--';
            const lastRx = Number(row.lastRx);
            const lastTx = Number(row.lastTx);
            const values = [
                fmt(row.id),
                fmt(row.remoteMac),
                fmt(row.destination),
                formatRnsState(row.state),
                formatBytes(row.rxBytes),
                formatBytes(row.txBytes),
                fmt(row.rxPackets),
                fmt(row.txPackets),
                (Number.isFinite(lastRx) && lastRx >= 0) ? formatDurationCompact(lastRx) : '--',
                (Number.isFinite(lastTx) && lastTx >= 0) ? formatDurationCompact(lastTx) : '--',
                rxRate !== '--' ? formatNearbyBitrate(Number(rxRate)) : '0 kbit/s',
                txRate !== '--' ? formatNearbyBitrate(Number(txRate)) : '0 kbit/s',
                fmt(row.mtu)
            ];

            values.forEach(value => {
                const td = document.createElement('td');
                td.textContent = value;
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

        try {
            const res = await fetch('/api/get_reticulum_links', { cache: 'no-store' });
            if (!res.ok) {
                return;
            }

            const data = await res.json();
            const rows = Array.isArray(data?.d) ? data.d : (Array.isArray(data?.links) ? data.links : []);
            const total = Number(data?.c ?? data?.count ?? data?.total ?? rows.length ?? 0);

            setText('reticulum_count', total);
            reticulumState.rows = rows;
            renderReticulum();
        } catch (err) {
            // ignore reticulum fetch errors
        } finally {
            reticulumState.loading = false;
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

        const cca = pick(state?.cca, state?.api_cca_cfg, state?.cca_cfg);
        setCheckbox('cca_en', cca.en ?? 1);
        setInput('cca_ftpct', cca.ftpct ?? 0.1);
        setInput('cca_dlpct', cca.dlpct ?? 100);
        setSelect('cca_thdyn', String(cca.thdyn ?? 0));
        setInput('cca_sens', cca.sens ?? 5);
        validateLbtFields();

        const net = pick(state?.net, state?.api_net_cfg, state?.net_cfg);
        setCheckbox('net_dhcp', net.dhcp);
        setInput('net_ip_address', net.ip_address);
        setInput('net_gw_address', net.gw_address);
        setInput('net_netmask', net.netmask);
        updateNetDisabled();
        validateNetFields();

        const slip = pick(state?.slip, state?.api_slip_cfg, state?.slip_cfg);
        setCheckbox('slip_enable', slip.enable);
        setInput('slip_baud', slip.baud);
        setInput('slip_ip_address', slip.ip_address ?? slip.ip);
        setInput('slip_gw_address', slip.gw_address ?? slip.gw);
        updateSlipDisabled();
        validateSlipFields();

        const logCfg = pick(state?.log, state?.logs, state?.api_log_cfg, state?.log_cfg, state?.api_logs_cfg, state?.logs_cfg);
        setCheckbox('log_udp_enable', logCfg.udp_enable ?? logCfg.enable);
        setInput('log_udp_host', logCfg.host ?? logCfg.ip_address);
        setInput('log_udp_port', logCfg.port);
        updateLogDisabled();
        validateLogFields();

        const tcp = pick(state?.tcp, state?.api_tcp_server_cfg, state?.tcp_server_cfg);
        setCheckbox('tcp_enable', tcp.enable);
        setInput('tcp_port', tcp.port);
        setInput('tcp_whitelist', tcp.whitelist);
        setText('tcp_client', tcp.connected);
        updateTcpDisabled();
        validateTcpFields();

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

        const privacy = pick(state?.privacy, state?.api_privacy_cfg, state?.privacy_cfg);
        setSelect('privacy_mac_rotation', String(privacy.rotation ?? 0));
        setCheckbox('privacy_mac_broadcast', privacy.broadcast);
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
        const powerField = document.getElementById('halow_power_dbm');
        const freqField = document.getElementById('halow_central_freq');

        if (powerField.classList.contains('error') || freqField.classList.contains('error')) {
            return;
        }

        const payload = readHalowForm();
        try {
            await postJson('/api/halow_cfg', payload);
        } catch (err) {
            console.error('saveHalow error', err);
        }
        loadAll();
    }

    async function saveLbt() {
        if (!isLbtFormValid()) return;
        try {
            await postJson('/api/cca_cfg', readLbtForm());
        } catch (err) {
            console.error('saveLbt error', err);
        }
        loadAll();
    }

    async function saveCca() {
        const payload = readCcaForm();
        try {
            await postJson('/api/cca_cfg', payload);
        } catch (err) {
            console.error('saveCca error', err);
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

    async function savePrivacy() {
        const payload = readPrivacyForm();
        try {
            await postJson('/api/privacy_cfg', payload);
        } catch (err) {
            console.error('savePrivacy error', err);
        }
        loadAll();
    }

    function readAckForm() {
        const ra = document.getElementById('ack_rate_adapt');
        const up = parseInt(document.getElementById('ack_ra_loss_up').value, 10);
        const dn = parseInt(document.getElementById('ack_ra_loss_down').value, 10);
        const bcr = parseInt(document.getElementById('ack_bc_repeat').value, 10);
        return {
            retries: parseInt(document.getElementById('ack_retries').value, 10) || 0,
            rate_adapt: (ra && ra.checked && !ra.disabled) ? 1 : 0,
            ra_loss_up:   isNaN(up) ? 5   : Math.max(0, Math.min(99, up)),
            ra_loss_down: isNaN(dn) ? 30  : Math.max(1, Math.min(100, dn)),
            bc_repeat:    isNaN(bcr) ? 2  : Math.max(1, Math.min(3, bcr)),
            agg:    (document.getElementById('ack_agg') && document.getElementById('ack_agg').checked) ? 1 : 0
        };
    }

    async function saveAck() {
        const payload = readAckForm();
        try {
            await postJson('/api/ack_cfg', payload);
        } catch (err) {
            console.error('saveAck error', err);
        }
        loadAckConfig();
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
        updateFwVersionList();
    }

    async function checkFwUpdates() {
        const btn = document.getElementById('fw_check_updates');
        const container = document.getElementById('fw_updates_container');

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

            fwUpdateState.releases = await res.json();

            if (fwUpdateState.releases.length === 0) {
                setStatus('fw_download_status', 'No releases found', true);
                return;
            }

            updateFwVersionList();
            container.style.display = 'block';
            clearStatus('fw_download_status');
        } catch (err) {
            console.error('checkFwUpdates error', err);
            setStatus('fw_download_status', 'Error fetching updates: ' + (err?.message || 'network error'), true);
        } finally {
            btn.disabled = false;
        }
    }

    function updateFwVersionList() {
        const select = document.getElementById('fw_version_select');
        select.innerHTML = '';

        const visibleReleases = fwUpdateState.releases.filter(r => {
            if (fwUpdateState.betaEnabled) return true;
            return !r.prerelease;
        });

        if (visibleReleases.length === 0) {
            const opt = document.createElement('option');
            opt.textContent = 'No versions available';
            opt.value = '';
            select.appendChild(opt);
            return;
        }

        visibleReleases.forEach(release => {
            const opt = document.createElement('option');
            const label = release.prerelease ? `${release.tag_name} (beta)` : release.tag_name;
            opt.textContent = label;
            opt.value = release.id;
            select.appendChild(opt);
        });

        select.value = visibleReleases[0].id;
        handleFwVersionSelect();
    }

    function handleFwVersionSelect() {
        const select = document.getElementById('fw_version_select');
        const infoEl = document.getElementById('fw_version_info');
        const downloadBtn = document.getElementById('fw_download_only');

        const releaseId = select.value;
        const release = fwUpdateState.releases.find(r => r.id == releaseId);

        if (!release) {
            infoEl.textContent = '--';
            downloadBtn.disabled = true;
            return;
        }

        const tarAsset = release.assets.find(a => a.name.endsWith('.tar'));
        if (!tarAsset) {
            infoEl.textContent = 'No .tar file found in this release';
            downloadBtn.disabled = true;
            return;
        }

        fwUpdateState.selectedVersion = {
            name: release.tag_name,
            downloadUrl: tarAsset.browser_download_url
        };

        const dateStr = new Date(release.published_at).toLocaleDateString('ru-RU');
        infoEl.textContent = `Released ${dateStr}`;
        downloadBtn.disabled = false;
    }

    function fwDownloadOnly() {
        if (!fwUpdateState.selectedVersion) {
            return;
        }

        const a = document.createElement('a');
        a.href = fwUpdateState.selectedVersion.downloadUrl;
        a.download = fwUpdateState.selectedVersion.name + '.tar';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
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
