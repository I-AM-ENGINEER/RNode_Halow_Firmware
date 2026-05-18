# TX Pipeline C Rewrite — Status & Plan

## Background

The firmware uses a precompiled binary `mars_lmac_tx_origfuncs.o` for the LMAC TX path.
Functions in that binary are renamed to `fn_orig` via the WRAP mechanism in `mars_lmac_tx_orig.c`.
Our C implementations replace them by defining the plain `fn` symbol and keeping the WRAP commented out.

Key files:
- `sdk/lib/lmac/mars_lmac_tx.c` — TX task, frame queuing, pv0 frame dispatch
- `sdk/lib/lmac/mars_lmac_phy.c` — HW TX path: IRQ handlers, DMA, TX vector
- `sdk/lib/lmac/mars_lmac_tx_orig.c` — WRAP stubs; comment out a line to activate our C impl
- `sdk/include/lib/lmac/mars_lmac_tx.h` — shared types and AH_* offset constants

## IRQ call chain (data TX path, per packet)

```
lmac_irq_ac_pd        ← AC-period-done: selects AC, builds aggregate, arms backoff
  └─ lmac_irq_bo_fns  ← backoff-done: dispatches by tx_state
       └─ lmac_tx_frm               ← loads frame into HW
            ├─ lmac_send_data_to_phy  ← DMA descriptor setup + kick
            └─ lmac_cfg_txvec_part2   ← TXVEC2/3/4 registers + antenna
lmac_irq_tx_end       ← TX complete: update stats, handle retry/BA
```

## Function status

### Done — C implementation

| Function | File | Notes |
|---|---|---|
| `lmac_ah_tx` | mars_lmac_tx.c | top-level entry from UMAC |
| `lmac_kick_tx_task` | mars_lmac_tx.c | |
| `lmac_tx_init` | mars_lmac_tx.c | |
| `lmac_tx_queue_init` | mars_lmac_tx.c | |
| `lmac_tx_data_reload` | mars_lmac_tx.c | moves skbs from status→AC queues |
| `lmac_tx_pv0_data` | mars_lmac_tx.c | clears retry/PS bits |
| `lmac_tx_pv0_mgmt/ctrl/ext` | mars_lmac_tx.c | stubs (not used in STA data path) |
| `lmac_tx_pv1_*` | mars_lmac_tx.c | stubs |
| `lmac_check_aggregation` | mars_lmac_tx.c | stub returns -1 (no agg) |
| `seq_num_space_update` | mars_lmac_tx.c | stub returns 0 |
| `lmac_irq_bo_fns` | mars_lmac_phy.c | state=1 (direct TX) full; other states fall back to _orig |
| `lmac_tx_frm` | mars_lmac_phy.c | |
| `lmac_send_data_to_phy` | mars_lmac_phy.c | DMA inlined (no binary helpers) |
| `lmac_cfg_txvec_part2` | mars_lmac_phy.c | |
| `lmac_hdr_dur_calc` | mars_lmac_phy.c | |
| `lmac_irq_tx_end` | mars_lmac_phy.c | sub_state=1 (data ACK) and RTS path; error path with gain restore |
| `lmac_update_tx_state_ack` | mars_lmac_phy.c | modem mode: mark first frame done regardless of ACK outcome |
| `lmac_update_tx_state_ba` | mars_lmac_phy.c | modem mode: mark all aggregate frames done |
| `lmac_partial_aid_update` | mars_lmac_phy.c | no-op in modem mode (no STA table) |
| `lmac_update_tx_rate` | mars_lmac_phy.c | explicit MCS/BW passthrough; fixes MCS10 corruption and MCS0 min-floor from binary |

### TODO — still binary, rewrite in priority order

| # | Function | Why important |
|---|---|---|
| 1 | **`lmac_gen_txvec`** | TX vector (MCS, BW, power) — keep binary; too complex, wrong TXVEC = broken TX |

### Cannot rewrite — static local symbols in binary

| Function | Blocker |
|---|---|
| `lmac_irq_ac_pd` | `lmac_attempt_tx`, `lmac_gen_tx_agglist`, `lmac_check_tx_queue_empty`, `lmac_attempt_tx_obss` are `t` (local) symbols in `mars_lmac_tx_origfuncs.o` — not linkable from C |

## Named fields added to lmac_ctx (data-state session)

| Field | Offset | Type | Semantics |
|---|---|---|---|
| `tx_last_mcs_bw` | 0x70F | uint8_t | packed MCS/BW from TXVEC1 for last data frame |
| `tx_attempt_count` | 0x740 | uint32_t | TX event counter (+1 per backoff→TX: data and beacon) |
| `tx_mpdu_count` | 0x744 | uint32_t | total MPDUs transmitted (+=selected_count per aggregate) |
| `tx_byte_count_total` | 0x748 | uint32_t | total TX bytes (+=total_len_bytes per aggregate) |
| `tx_sym_time_acc` | 0x750 | uint32_t | accumulated TXCTX symbol time (+=TXCTX[0x560]+[0x562]) |
| `tx_latency_acc_lo/hi` | 0x808/0x80C | uint32_t×2 | U64 TX latency accumulator (acc = acc - enqueue_ts + now) |
| `tx_airtime_acc_lo/hi` | 0x810/0x814 | uint32_t×2 | U64 TX airtime accumulator (scaled half-symbol units) |
| `tx_airtime_scale_offset` | 0x83D | int8_t | airtime scale: effective = (100 - this)%; 0 = no adjustment |
| `pSta_list_head` | 0x9F8 | void * | circular STA linked list head (sentinel = &ah_lmac.pSta_list_head) |
| `tx_irq_ctrl_flags` | 0xA4F | uint8_t | bit0=cleared by tx_status_task; bit3=PS-skip set by bo_fns, checked by tx_end LO recal |
| `pTx_current_sta` | 0xA50 | void * | pointer to last TX STA; written by bo_fns data state, cleared to NULL by tx_end on error |

## DMA inlining (item #1)

`lhw_cfg_dma_list_cnt(cnt)` and `lhw_cfg_tx_sub_frm(idx, addr, len)` reduce to:

```c
LMAC_HW->TXDMACTL = (LMAC_HW->TXDMACTL & ~0x7fu) | (cnt & 0x7fu);
LMAC_HW->TX_SUB_FRM[idx * 2]     = addr;
LMAC_HW->TX_SUB_FRM[idx * 2 + 1] = len;
```

## Rules for IRQ-path functions

`lmac_irq_bo_fns` and everything it calls runs from interrupt context.
**No `log_trace`/`log_debug` on the normal (non-error) path** — blocking UART output in IRQ
breaks TX timers. `log_warn` on error paths is acceptable (system already broken at that point).
