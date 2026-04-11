#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_TELEMETRY

#include "telemetry.h"
#include "lwip/netif.h"
#include "lwip/apps/mqtt.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/sys.h"

#include "configdb.h"
#include "halow.h"
#include "statistics.h"
#include "utils.h"
#include "cJSON.h"
#include "lib/logc/log.h"

#define TELEMETRY_CONFIG_PREFIX                 CONFIGDB_ADD_MODULE("tlm")
#define TELEMETRY_CONFIG_ADD_CONFIG(name)       TELEMETRY_CONFIG_PREFIX "." name

#define TELEMETRY_CONFIG_EN_NAME              TELEMETRY_CONFIG_ADD_CONFIG("en")
#define TELEMETRY_CONFIG_EXT_EN_NAME          TELEMETRY_CONFIG_ADD_CONFIG("exten")
#define TELEMETRY_CONFIG_NODE_NAME_NAME       TELEMETRY_CONFIG_ADD_CONFIG("name")
#define TELEMETRY_CONFIG_IP_ADDR_NAME         TELEMETRY_CONFIG_ADD_CONFIG("ip")
#define TELEMETRY_CONFIG_USER_NAME            TELEMETRY_CONFIG_ADD_CONFIG("usr")
#define TELEMETRY_CONFIG_PASS_NAME            TELEMETRY_CONFIG_ADD_CONFIG("pwd")
#define TELEMETRY_CONFIG_TOPIC_NAME           TELEMETRY_CONFIG_ADD_CONFIG("top")
#define TELEMETRY_CONFIG_SEND_PERIOD_NAME     TELEMETRY_CONFIG_ADD_CONFIG("period")
#define TELEMETRY_CONFIG_LATITUDE_NAME        TELEMETRY_CONFIG_ADD_CONFIG("lat")
#define TELEMETRY_CONFIG_LONGITUDE_NAME       TELEMETRY_CONFIG_ADD_CONFIG("lon")
#define TELEMETRY_CONFIG_DIRECTIONAL_NAME     TELEMETRY_CONFIG_ADD_CONFIG("diren")
#define TELEMETRY_CONFIG_DIRECTION_NAME       TELEMETRY_CONFIG_ADD_CONFIG("dir")
#define TELEMETRY_CONFIG_LXMF_NAME            TELEMETRY_CONFIG_ADD_CONFIG("lxmf")

extern struct netif *netif_default;
static struct os_work telemetry_work;

static struct {
    sys_sem_t sem;
    ip_addr_t ip;
    volatile bool done;
    volatile err_t err;
    volatile mqtt_connection_status_t st;
} g_telemetry_ctx;

static void telemetry_config_log_trace( const char *tag, const telemetry_config_t *cfg ){
    if(cfg == NULL){
        return;
    }

    log_trace("%s en=%d ext=%d period=%lu domain='%s' topic='%s' port=%u",
              tag ? tag : "CFG",
              cfg->enabled ? 1 : 0,
              cfg->extended_enabled ? 1 : 0,
              (unsigned long)cfg->send_period_s,
              cfg->domain,
              cfg->topic,
              (unsigned)cfg->port);
}

static void telemetry_config_log_debug( const char *tag, const telemetry_config_t *cfg ){
    if(cfg == NULL){
        return;
    }

    log_debug("%s en=%d ext=%d period=%lu domain='%s' topic='%s' port=%u",
              tag ? tag : "CFG",
              cfg->enabled ? 1 : 0,
              cfg->extended_enabled ? 1 : 0,
              (unsigned long)cfg->send_period_s,
              cfg->domain,
              cfg->topic,
              (unsigned)cfg->port);
}

static uint32_t telemetry_get_id( void ){
    static uint32_t id;

    if(id == 0){
        uint32_t hash = 0x811C9DC5;
        uint8_t mac[6];
        get_mac(mac);
        for (uint8_t i = 0; i < 6; i++) {
            hash ^= mac[i];
            hash *= 0x01000193;
        }
        id = hash;
    }
    
    return id;
}

static void telemetry_config_set_default( telemetry_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }
    
    memset(cfg, 0, sizeof(telemetry_config_t));

    cfg->send_period_s = 3600;
    cfg->port = 1883;

    if ((netif_default != NULL) && (netif_default->hostname != NULL)) {
        strncpy(cfg->nodename, netif_default->hostname, sizeof(cfg->nodename) - 1);
    }
    strncpy(cfg->topic, TELEMETRY_MQTT_DEFAULT_TOPIC, sizeof(cfg->topic)-1);
    strncpy(cfg->username, TELEMETRY_MQTT_DEFAULT_USERNAME, sizeof(cfg->username)-1);
    strncpy(cfg->password, TELEMETRY_MQTT_DEFAULT_PASSWORD, sizeof(cfg->password)-1);
    strncpy(cfg->domain, TELEMETRY_MQTT_DEFAULT_DOMAIN, sizeof(cfg->domain)-1);
}

static void telemetry_config_sanitize( telemetry_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }

    cfg->enabled = cfg->enabled ? true : false;
    cfg->extended_enabled = cfg->extended_enabled ? true : false;
    cfg->directional = cfg->directional ? true : false;

    if (cfg->send_period_s < 1) {
        cfg->send_period_s = 1;
    }
    if (cfg->send_period_s > 86400u * 7u) {
        cfg->send_period_s = 86400u * 7u;
    }

    if ((cfg->latitude < -90.0f) || (cfg->latitude > 90.0f)) {
        cfg->latitude = 0.0f;
    }

    if ((cfg->longitude < -180.0f) || (cfg->longitude > 180.0f)) {
        cfg->longitude = 0.0f;
    }

    if (cfg->direction < 0) {
        cfg->direction = 0;
        cfg->directional = false;
    }
    if (cfg->direction > 359) {
        cfg->direction = 359;
        cfg->directional = false;
    }

    if(cfg->port < 1024){
        cfg->port = 1883;
    }

    cfg->nodename[TELEMETRY_NODENAME_LEN - 1] = '\0';
    cfg->domain[TELEMETRY_DOMAIN_LEN - 1] = '\0';
    cfg->username[TELEMETRY_MQTT_USERNAME_LEN - 1] = '\0';
    cfg->password[TELEMETRY_MQTT_PASSWORD_LEN - 1] = '\0';
    cfg->topic[TELEMETRY_MQTT_TOPIC_LEN - 1] = '\0';
}

void telemetry_config_load( telemetry_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }

    telemetry_config_set_default(cfg);

    configdb_get_i8 (TELEMETRY_CONFIG_EN_NAME,            (int8_t *)&cfg->enabled);
    configdb_get_i8 (TELEMETRY_CONFIG_EXT_EN_NAME,        (int8_t *)&cfg->extended_enabled);
    configdb_get_i32(TELEMETRY_CONFIG_SEND_PERIOD_NAME,   (int32_t *)&cfg->send_period_s);
    configdb_get_i8 (TELEMETRY_CONFIG_DIRECTIONAL_NAME,   (int8_t *)&cfg->directional);
    configdb_get_i16(TELEMETRY_CONFIG_DIRECTION_NAME,     (int16_t *)&cfg->direction);

    configdb_get_blob(TELEMETRY_CONFIG_LATITUDE_NAME,     &cfg->latitude,  sizeof(cfg->latitude));
    configdb_get_blob(TELEMETRY_CONFIG_LONGITUDE_NAME,    &cfg->longitude, sizeof(cfg->longitude));

    configdb_get_blob(TELEMETRY_CONFIG_NODE_NAME_NAME,    cfg->nodename, sizeof(cfg->nodename));
    configdb_get_blob(TELEMETRY_CONFIG_IP_ADDR_NAME,      cfg->domain,   sizeof(cfg->domain));
    configdb_get_blob(TELEMETRY_CONFIG_USER_NAME,         cfg->username, sizeof(cfg->username));
    configdb_get_blob(TELEMETRY_CONFIG_PASS_NAME,         cfg->password, sizeof(cfg->password));
    configdb_get_blob(TELEMETRY_CONFIG_TOPIC_NAME,        cfg->topic,    sizeof(cfg->topic));
    configdb_get_blob(TELEMETRY_CONFIG_LXMF_NAME,         cfg->lxmf,     sizeof(cfg->lxmf));

    cfg->nodename[sizeof(cfg->nodename) - 1] = '\0';
    cfg->domain[sizeof(cfg->domain) - 1] = '\0';
    cfg->username[sizeof(cfg->username) - 1] = '\0';
    cfg->password[sizeof(cfg->password) - 1] = '\0';
    cfg->topic[sizeof(cfg->topic) - 1] = '\0';
    
    telemetry_config_sanitize(cfg);
    telemetry_config_log_trace("LOAD", cfg);
}

void telemetry_config_save( telemetry_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }
    telemetry_config_sanitize(cfg);

    configdb_set_i8 (TELEMETRY_CONFIG_EN_NAME,          (const int8_t *)&cfg->enabled);
    configdb_set_i8 (TELEMETRY_CONFIG_EXT_EN_NAME,      (const int8_t *)&cfg->extended_enabled);
    configdb_set_i32(TELEMETRY_CONFIG_SEND_PERIOD_NAME, (const int32_t *)&cfg->send_period_s);
    configdb_set_i8 (TELEMETRY_CONFIG_DIRECTIONAL_NAME, (const int8_t *)&cfg->directional);
    configdb_set_i16(TELEMETRY_CONFIG_DIRECTION_NAME,   (const int16_t *)&cfg->direction);

    configdb_set_blob(TELEMETRY_CONFIG_LATITUDE_NAME,   &cfg->latitude,  sizeof(cfg->latitude));
    configdb_set_blob(TELEMETRY_CONFIG_LONGITUDE_NAME,  &cfg->longitude, sizeof(cfg->longitude));

    configdb_set_blob(TELEMETRY_CONFIG_NODE_NAME_NAME,  cfg->nodename, sizeof(cfg->nodename));
    configdb_set_blob(TELEMETRY_CONFIG_IP_ADDR_NAME,    cfg->domain,   sizeof(cfg->domain));
    configdb_set_blob(TELEMETRY_CONFIG_USER_NAME,       cfg->username, sizeof(cfg->username));
    configdb_set_blob(TELEMETRY_CONFIG_PASS_NAME,       cfg->password, sizeof(cfg->password));
    configdb_set_blob(TELEMETRY_CONFIG_TOPIC_NAME,      cfg->topic,    sizeof(cfg->topic));
    configdb_set_blob(TELEMETRY_CONFIG_LXMF_NAME,       cfg->lxmf,     sizeof(cfg->lxmf));

    telemetry_config_log_debug("SAVE", cfg);
}

static struct telemetry_pkg_ext telemetry_build_pkg_ext(){
    struct telemetry_pkg_ext pkg;
    statistics_radio_t radio_stats = statistics_radio_get();
    pkg.rx_bytes = radio_stats.rx_bytes;
    pkg.tx_bytes = radio_stats.tx_bytes;
    pkg.rx_packets = radio_stats.rx_packets;
    pkg.tx_packets = radio_stats.tx_packets;
    return pkg;
}

static struct telemetry_pkg telemetry_build_pkg(){
    struct telemetry_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));

    pkg.id = telemetry_get_id();
    pkg.uptime_s = (uint32_t)(get_time_ms() / 1000LL);
    strncpy(pkg.firmware_ver, FW_VERSION, sizeof(pkg.firmware_ver)-1);

    {
        halow_config_t halow_cfg;
        halow_config_load(&halow_cfg);
        pkg.bandwidth = halow_cfg.bandwidth;
        pkg.frequency_x100khz = halow_cfg.central_freq;
        pkg.mcs = halow_cfg.mcs;
    }

    {
        telemetry_config_t telemetry_cfg;
        telemetry_config_load(&telemetry_cfg);
        strncpy(pkg.name, telemetry_cfg.nodename, sizeof(pkg.name)-1);
        memcpy(pkg.lxmf, telemetry_cfg.lxmf, sizeof(pkg.lxmf));
        pkg.latitude = telemetry_cfg.latitude;
        pkg.longitude = telemetry_cfg.longitude;
        pkg.direction = telemetry_cfg.direction;
        pkg.directional = telemetry_cfg.directional;
        memcpy(pkg.lxmf, telemetry_cfg.lxmf, sizeof(pkg.lxmf));
    }

    return pkg;
}

static void telemetry_pkg_json_add( cJSON *j, const struct telemetry_pkg *pkg ){
    if ((j == NULL) || (pkg == NULL)) {
        return;
    }

    cJSON_AddNumberToObject(j, "id", pkg->id);
    cJSON_AddStringToObject(j, "name", pkg->name);
    cJSON_AddStringToObject(j, "fw", pkg->firmware_ver);

    char buf[48];

    snprintf(buf, sizeof(buf), "%.6f,%.6f", pkg->latitude, pkg->longitude);
    cJSON_AddStringToObject(j, "loc", buf);

    snprintf(buf, sizeof(buf), "%.1f MHz", pkg->frequency_x100khz / 10.0f);
    cJSON_AddStringToObject(j, "freq", buf);

    snprintf(buf, sizeof(buf), "%u MHz", pkg->bandwidth);
    cJSON_AddStringToObject(j, "bw", buf);

    if (pkg->directional) {
        cJSON_AddNumberToObject(j, "direction", pkg->direction);
    }

    cJSON_AddNumberToObject(j, "uptime", pkg->uptime_s);
    cJSON_AddNumberToObject(j, "mcs", pkg->mcs);

    bin16_to_hex32(pkg->lxmf, buf);
    cJSON_AddStringToObject(j, "lxmf", buf);
}

static void telemetry_pkg_ext_json_add( cJSON *j, const struct telemetry_pkg_ext *pkg ){
    if ((j == NULL) || (pkg == NULL)) {
        return;
    }

    cJSON_AddNumberToObject(j, "tx_b", (double)pkg->tx_bytes);
    cJSON_AddNumberToObject(j, "rx_b", (double)pkg->rx_bytes);
    cJSON_AddNumberToObject(j, "tx_p", (double)pkg->tx_packets);
    cJSON_AddNumberToObject(j, "rx_p", (double)pkg->rx_packets);
}

static void telemetry_dns_cb ( const char *name, const ip_addr_t *ipaddr, void *arg ){
    (void)arg;

    if (ipaddr != NULL) {
        log_debug("dns cb: name=%s resolved", (name != NULL) ? name : "(null)");
        ip_addr_copy(g_telemetry_ctx.ip, *ipaddr);
        g_telemetry_ctx.err = ERR_OK;
    } else {
        log_warn("dns cb: name=%s resolve failed", (name != NULL) ? name : "(null)");
        g_telemetry_ctx.err = ERR_VAL;
    }

    g_telemetry_ctx.done = true;
    sys_sem_signal(&g_telemetry_ctx.sem);
}

static void telemetry_conn_cb ( mqtt_client_t *client, void *arg, mqtt_connection_status_t status ){
    (void)client;
    (void)arg;

    log_debug("mqtt conn cb: status=%d", (int)status);

    g_telemetry_ctx.st = status;
    g_telemetry_ctx.done = true;
    sys_sem_signal(&g_telemetry_ctx.sem);
}

static void telemetry_pub_cb ( void *arg, err_t err ){
    (void)arg;

    log_debug("mqtt pub cb: err=%d", (int)err);

    g_telemetry_ctx.err = err;
    g_telemetry_ctx.done = true;
    sys_sem_signal(&g_telemetry_ctx.sem);
}

static bool telemetry_wait( uint32_t timeout_ms ){
    uint32_t start = sys_now();

    log_trace("wait start: timeout=%lu ms", (unsigned long)timeout_ms);

    while (!g_telemetry_ctx.done) {
        uint32_t dt = sys_now() - start;

        if (dt >= timeout_ms) {
            log_warn("wait timeout: dt=%lu ms", (unsigned long)dt);
            return false;
        }

        sys_arch_sem_wait(&g_telemetry_ctx.sem, timeout_ms - dt);
    }

    log_trace("wait done: err=%d st=%d", (int)g_telemetry_ctx.err, (int)g_telemetry_ctx.st);
    return true;
}

void telemetry_send ( void ){
    telemetry_config_t cfg;
    cJSON *j;
    char *json;
    mqtt_client_t *client = NULL;
    struct mqtt_connect_client_info_t ci;
    ip_addr_t ip;
    err_t err;
    int i;
    char cid[24];

    log_debug("send begin");

    telemetry_config_load(&cfg);
    telemetry_config_log_trace("SEND_CFG", &cfg);

    if (!cfg.enabled || !cfg.domain[0] || !cfg.topic[0]) {
        log_debug("send skip: invalid config");
        return;
    }

    j = cJSON_CreateObject();
    if (j == NULL) {
        log_error("json create failed");
        return;
    }

    {
        struct telemetry_pkg pkg = telemetry_build_pkg();
        log_trace("pkg built: id=%lu name='%s' fw='%s'",
                  (unsigned long)pkg.id,
                  pkg.name,
                  pkg.firmware_ver);
        telemetry_pkg_json_add(j, &pkg);
    }

    if (cfg.extended_enabled) {
        struct telemetry_pkg_ext ext = telemetry_build_pkg_ext();
        log_trace("extended pkg built");
        telemetry_pkg_ext_json_add(j, &ext);
    }

    json = cJSON_PrintUnformatted(j);
    if (json == NULL) {
        log_error("json print failed");
        cJSON_Delete(j);
        return;
    }

    log_trace("json ready: len=%lu", (unsigned long)strlen(json));

    if (sys_sem_new(&g_telemetry_ctx.sem, 0) != ERR_OK) {
        log_error("sem create failed");
        cJSON_free(json);
        cJSON_Delete(j);
        return;
    }

    for (i = 0; i < MQTT_RETRIES; i++) {
        memset(&ci, 0, sizeof(ci));

        log_debug("attempt %d/%d", i + 1, MQTT_RETRIES);

        g_telemetry_ctx.done = false;
        g_telemetry_ctx.err = ERR_OK;
        g_telemetry_ctx.st = MQTT_CONNECT_DISCONNECTED;

        if(ipaddr_aton(cfg.domain, &ip)){
            log_debug("host is IP: %s", cfg.domain);
            err = ERR_OK;
        } else {
            log_debug("dns query: host='%s'", cfg.domain);
            err = dns_gethostbyname(cfg.domain, &ip, telemetry_dns_cb, NULL);
        }

        if (err == ERR_INPROGRESS) {
            log_trace("dns pending");
            if (!telemetry_wait(MQTT_DNS_TO_MS)) {
                log_warn("dns wait timeout");
                goto fail;
            }

            if (g_telemetry_ctx.err != ERR_OK) {
                log_warn("dns failed after callback: err=%d", (int)g_telemetry_ctx.err);
                goto fail;
            }

            ip_addr_copy(ip, g_telemetry_ctx.ip);
            log_debug("dns resolved asynchronously");
        } else if (err != ERR_OK) {
            log_warn("dns_gethostbyname failed immediately: err=%d", (int)err);
            goto fail;
        } else {
            log_debug("dns resolved immediately or IP used");
        }

        client = mqtt_client_new();
        if (client == NULL) {
            log_error("mqtt_client_new failed");
            goto fail;
        }

        snprintf(cid, sizeof(cid), "tel-%08lx", (unsigned long)telemetry_get_id());
        ci.client_id = cid;
        ci.client_user = cfg.username[0] ? cfg.username : NULL;
        ci.client_pass = cfg.password[0] ? cfg.password : NULL;
        ci.keep_alive = 30;

        log_debug("mqtt connect: cid='%s' port=%u user=%s",
                  cid,
                  (unsigned)(cfg.port ? cfg.port : MQTT_PORT),
                  ci.client_user != NULL ? ci.client_user : "(null)");

        g_telemetry_ctx.done = false;
        err = mqtt_client_connect(client,
                                  &ip,
                                  cfg.port ? cfg.port : MQTT_PORT,
                                  telemetry_conn_cb,
                                  NULL,
                                  &ci);
        if (err != ERR_OK) {
            log_warn("mqtt_client_connect failed: err=%d", (int)err);
            goto fail;
        }

        if (!telemetry_wait(MQTT_CONN_TO_MS)) {
            log_warn("mqtt connect wait timeout");
            goto fail;
        }

        if (g_telemetry_ctx.st != MQTT_CONNECT_ACCEPTED) {
            log_warn("mqtt connect rejected: status=%d", (int)g_telemetry_ctx.st);
            goto fail;
        }

        log_debug("mqtt connected");

        g_telemetry_ctx.done = false;
        err = mqtt_publish(client,
                           cfg.topic,
                           json,
                           (u16_t)strlen(json),
                           1,
                           0,
                           telemetry_pub_cb,
                           NULL);
        if (err != ERR_OK) {
            log_warn("mqtt_publish failed immediately: err=%d", (int)err);
            goto fail;
        }

        log_debug("mqtt publish started: topic='%s'", cfg.topic);

        if (!telemetry_wait(MQTT_PUB_TO_MS)) {
            log_warn("mqtt publish wait timeout");
            goto fail;
        }

        if (g_telemetry_ctx.err != ERR_OK) {
            log_warn("mqtt publish failed in callback: err=%d", (int)g_telemetry_ctx.err);
            goto fail;
        }

        log_info("mqtt publish success");

        mqtt_disconnect(client);
        mqtt_client_free(client);
        sys_sem_free(&g_telemetry_ctx.sem);
        cJSON_free(json);
        cJSON_Delete(j);

        log_debug("send done");
        return;

fail:
        log_warn("attempt %d failed", i + 1);

        if (client != NULL) {
            mqtt_disconnect(client);
            mqtt_client_free(client);
            client = NULL;
        }

        if ((i + 1) < MQTT_RETRIES) {
            sys_msleep(MQTT_RETRY_MS);
        }
    }

    log_error("send failed after all retries");

    sys_sem_free(&g_telemetry_ctx.sem);
    cJSON_free(json);
    cJSON_Delete(j);
}

static int32 telemetry_work_handler( struct os_work *work ){
    telemetry_config_t cfg;

    (void)work;

    log_trace("work handler begin");
    telemetry_send();

    telemetry_config_load(&cfg);
    if (cfg.enabled) {
        log_debug("work re-schedule: %lu s", (unsigned long)cfg.send_period_s);
        os_run_work_delay(&telemetry_work, cfg.send_period_s * 1000LU);
    } else {
        log_debug("work not re-scheduled: telemetry disabled");
    }

    return 0;
}

void telemetry_init( void ){
    telemetry_config_t cfg;

    log_debug("init begin");

    OS_WORK_INIT(&telemetry_work, telemetry_work_handler, TELEMETRY_WORK_PRIO);

    telemetry_config_set_default(&cfg);
    telemetry_config_load(&cfg);
    telemetry_config_save(&cfg);

    telemetry_config_log_debug("INIT", &cfg);

    if (cfg.enabled) {
        log_debug("init schedule first send after 5 s");
        os_run_work_delay(&telemetry_work, 5000LU);
    } else {
        log_debug("init: telemetry disabled");
    }
}

void telemetry_send_now( void ){
    log_debug("send_now");
    os_work_cancle(&telemetry_work, 1);
    os_run_work(&telemetry_work);
}
