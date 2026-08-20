#ifndef __HALOW_H_
#define __HALOW_H_

#include "lib/lmac/ieee802_11_defs.h"
#include <stdint.h>
#include <stdbool.h>

struct hgic_rx_info;

typedef void (*halow_rx_cb)(
    struct hgic_rx_info *info,
    struct ieee80211_hdr *hdr,
    uint8_t *data,
    int32_t len);

typedef struct {
    uint16_t central_freq;
    uint8_t bandwidth;
    uint8_t mcs;
    uint8_t rf_power;
    uint8_t rf_super_power;
} halow_config_t;

bool halow_init(uint32_t rxbuf, uint32_t rxbuf_size,
                uint32_t tdma_buf, uint32_t tdma_buf_size);

void halow_set_rx_cb(halow_rx_cb cb);
int32_t halow_tx(const uint8_t *data, uint32_t len, const uint8_t destination_mac[6], uint8_t mcs);
/* Same, with an 802.1d tid (0..7) so the frame lands in a priority AC queue
 * (tid 6/7 -> AC3): ACK frames must not queue behind a saturated data AC or
 * retransmit timers outrun the ACKs (dup-ACK storms, bench build 44). */
int32_t halow_tx_p(const uint8_t *data, uint32_t len, const uint8_t destination_mac[6], uint8_t mcs, uint8_t tid);
/* Refresh the TX-path MCS/BW config cache from configdb. Runs the KV reads
 * (flash mutexes -- can stall seconds behind a config-save GC): call ONLY
 * from a low-stakes context such as the statistics task, never from the TX
 * path or with the ack mutex held. */
void halow_cfg_mcs_bw_refresh(void);
uint8_t halow_cfg_mcs_get_cached(void);   /* statistics-warmed config cache */

void halow_gain_pilot_tick(void);
void halow_gain_pilot_set(bool enable);
bool halow_gain_pilot_enabled(void);
uint8_t halow_gain_pilot_state(void);   /* 0 manual, 1 g5, 2 trial4, 3 stable4, 4 probe5 */
void halow_gain_pilot_dbg(int32_t *debris_x, int32_t *prod_x, int32_t *base_x);

uint32_t halow_get_tx_vacancy(void);   /* free bytes in the bounded LMAC TX buffer (non-blocking) */
void halow_tx_vacancy_watchdog(void);  /* self-heal the TX budget after lost TX-complete events */
/* Run one skb through the TX-complete accounting: give its bytes back to the
 * TX budget, wake a blocked sender, free it. Used by the normal TX-complete
 * callback AND by the hard-wedge purge (frames that will never complete). */
struct sk_buff;
void halow_tx_skb_complete(struct sk_buff *skb);

/* TX-path diagnostics: live counters + a snapshot of the LMAC TX machine
 * captured at the moment a hard wedge was detected (before the purge destroys
 * the evidence). Exposed over HTTP as /api/tx_dbg -- the way to root-cause
 * why TX-completes stop under saturation without a debugger attached. */
typedef struct {
    /* live counters */
    uint32_t tx_end_count;      /* lmac_irq_tx_end invocations */
    uint32_t tx_end_sub[8];     /* sub_state histogram at tx_end entry */
    uint32_t tx_end_err;        /* TX_STAT error-path takes */
    uint32_t tx_tmo_count;      /* lmac_irq_tx_tmo invocations (TX timer expiry) */
    uint32_t bo_tmo_recov;      /* tier-0 fast armed-TX timeouts (FSM abort + retry) */
    uint32_t complete_seq;      /* TX-complete budget operations */
    uint32_t wedge_count;       /* hard-wedge purges so far */
    /* loss counters (invariant: no frame vanishes without a number moving) */
    uint32_t tx_drop_budget;    /* halow_send_frame -6: LMAC TX budget full */
    uint32_t tx_drop_alloc;     /* halow_send_frame -5: alloc_tx_skb failed */
    uint32_t tx_drop_lmac;      /* LMAC enqueue rejected (lmac_tx/fast_tx err) */
    uint32_t rx_frag_drop;      /* MCS10 RX fragment rejected (bounds/dup/total) */
    uint32_t rf_tcp_dropped;    /* RF->TCP ring full / host write failed */
    uint32_t tx_mcs_bump;       /* frames re-rated up: len > max MSDU at requested MCS */
    uint32_t tx_drop_oversize;  /* frames even MCS7's max MSDU cannot carry (rejected) */
    /* wedge snapshot */
    uint32_t snap_jiffies;
    uint32_t snap_complete_seq;
    uint32_t snap_tx_end_count;
    uint32_t snap_budget;       /* g_tx_vacated_bytes */
    uint32_t snap_tx_stat;      /* LMAC_HW->TX_STAT */
    uint32_t snap_ac;           /* lmac_current_ac() */
    uint8_t  snap_sub;          /* ah_lmac.bo_tx_substate */
    uint8_t  snap_bo_ftype;     /* ah_lmac.bo_frame_type */
    uint8_t  snap_ctrl_flags;   /* ah_lmac.tx_irq_ctrl_flags */
    uint8_t  snap_pad;
    uint32_t snap_q_ac[4];      /* pTx_ac_queues[] depths */
    uint32_t snap_sel[4];       /* per-AC selected_count */
    uint32_t snap_fsm;          /* LMAC_HW->FSM_STAT at wedge */
    uint32_t snap_comn;         /* LMAC_HW->COMN_CTRL at wedge (RF gates) */
    uint32_t snap_irqpd;        /* LMAC_HW->IRQ_PD at wedge */
    uint32_t snap_bocnt;        /* LMAC_HW->BO_CNT0 at wedge (CCA/backoff) */
    /* live machine state (not only at wedge time) -- the detailed view for
     * soak monitoring: tells a live CCA/LBT loop from a keyed-radio hang */
    uint32_t ac_pd;             /* live lmac_ac_pd_count (ac_pd IRQ fires) */
    uint32_t budget_live;       /* live g_tx_vacated_bytes */
    uint32_t q_live[4];         /* live pTx_ac_queues[] depths */
    uint32_t sel_live[4];       /* live per-AC selected_count */
    uint8_t  bo_ftype_live;     /* live ah_lmac.bo_frame_type */
    uint8_t  bo_sub_live;       /* live ah_lmac.bo_tx_substate */
    uint8_t  airtime_pct_x10;   /* live halow_lbt airtime, %*10 */
    uint8_t  ch_util_pct_x10;   /* live channel utilization, %*10 */
    uint32_t tcps_beat;         /* tcp_server client-loop heartbeat */
    int32_t  tcps_last_err;     /* last netconn error seen by the client loop */
    uint32_t tcps_recv_ok;      /* netconn_recv completions */
    uint32_t tcps_fed;          /* frames handed to the RF path */
    uint8_t  tcps_held;         /* netbuf currently held (throttle path) */
    uint8_t  tcps_pad[3];
} halow_tx_dbg_t;
void halow_tx_dbg_get( halow_tx_dbg_t *out );
void halow_config_set_bandwidth(uint8_t bw);
void halow_config_load(halow_config_t *cfg);
void halow_config_save(const halow_config_t *cfg);
void halow_config_apply(const halow_config_t *cfg);
void halow_config_set_mcs(uint8_t mcs);
uint32_t halow_get_mtu(uint8_t mcs);

#define HALOW_MCS_DEFAULT 0xFF  /* use globally configured MCS */

#endif //__HALOW_H_
