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
| `lmac_irq_ac_pd` | mars_lmac_phy.c | wrapper: clears lmac[0x865] floor=0 then calls orig; see floor-fix note below |
| `lmac_irq_bo_fns` | mars_lmac_phy.c | state=1 (direct TX) full; other states fall back to _orig |
| `lmac_tx_frm` | mars_lmac_phy.c | |
| `lmac_send_data_to_phy` | mars_lmac_phy.c | DMA inlined (no binary helpers) |
| `lmac_cfg_txvec_part2` | mars_lmac_phy.c | |
| `lmac_hdr_dur_calc` | mars_lmac_phy.c | |
| `lmac_irq_tx_end` | mars_lmac_phy.c | sub_state=1 (data ACK) and RTS path; error path with gain restore |
| `lmac_update_tx_state_ack` | mars_lmac_phy.c | modem mode: mark first frame done regardless of ACK outcome |
| `lmac_update_tx_state_ba` | mars_lmac_phy.c | modem mode: mark all aggregate frames done |
| `lmac_partial_aid_update` | mars_lmac_phy.c | no-op in modem mode (no STA table) |

### TODO — still binary, rewrite in priority order

| # | Function | Why important |
|---|---|---|
| 1 | **`lmac_gen_txvec`** | TX vector (MCS, BW, power) — keep binary; too complex, wrong TXVEC = broken TX |

### Cannot rewrite — static local symbols in binary

| Function | Blocker |
|---|---|
| `lmac_irq_ac_pd` (full rewrite) | `lmac_attempt_tx`, `lmac_gen_tx_agglist`, `lmac_check_tx_queue_empty`, `lmac_attempt_tx_obss` are `t` (local) symbols — not linkable. **We do wrap it** to clear the MCS floor before calling orig; see floor-fix note. |
| `lmac_update_tx_rate` | Called as `lmac_update_tx_rate_orig` directly by `lmac_irq_ac_pd_orig` (hardcoded `_orig` — WRAP cannot intercept). Floor bypass: clear lmac[0x865]=0 in our `lmac_irq_ac_pd` wrapper before each call. |
| `lmac_cfg_txvec_part1` | All callers are `_orig` binary functions. Not needed to rewrite — binary generates correct txvec once floor=0. |

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

## MCS0/MCS10 bugs — two separate root causes

### Bug 1: MCS floor (lmac[0x865]) — affects first-attempt MCS0 and MCS10

`lmac_cfg_set_bss_bw(bss_bw=1)` always sets `lmac[0x865] = 1` for 1 MHz channels.
`lmac_update_tx_rate_orig` (hardcoded `_orig`, un-interceptable) reads this floor via a
compound conditional with a C comma-operator side-effect:

```c
mcs = mcs_tmp;   // = requested MCS
if (((floor != 0) && (mcs = floor, mcs_tmp != 10)) && (floor <= mcs_tmp))
    mcs = mcs_tmp;
// floor=1: MCS0 → mcs=1; MCS10 → mcs=1 (side-effect fires, 10!=10 false, stays floor)
// floor=0: (0!=0) false → short-circuit → mcs stays mcs_tmp = correct
```

Fix: `lmac_irq_ac_pd` wrapper clears `lmac[0x865] = 0` immediately before calling orig.

### Bug 2: MCS10 retry rate table out-of-bounds — affects all retried MCS10 frames

When `txi[0x28]` (retry count) != 0, `lmac_update_tx_rate_orig` skips the floor path and
consults the retry rate table:

```c
index = mcs * 4 + (bw_hint + 1) & 3;   // MCS10, bw_hint=3: index=40
mcs = retry_table[index] & 0xf;         // rc_tb1_orig[40] = 0x01 → mcs=1
```

The table covers MCS0-7 only (32 entries). Index 40 is OOB; `rc_tb1_orig[40] = 0x01`.

`lmac_gen_txvec_orig` (called with mcs=1 from the retry table) corrupts **five** fields:
- `buf[1]` bits[7:4] → TXVEC1 bits[15:12] (primary MCS field) — written as 1
- `buf[8..9]` bits[10:7] → TXVEC3 bits[10:7] (MCS, non-RTS path) — written as 1
- `buf[4..7]` = TXVEC2 — `agg_symbol_len` computed for MCS=1 (NDBPS=24)
- `buf[8..11]` bits[20:12] → TXVEC3 bits[20:12] — same symbol count
- `stride[0x1bc]` — source symbol count (used by `lmac_send_data_to_phy` for Duration)

**NDBPS table** (1 MHz, bw\_idx=0): MCS0→12, MCS1→24, MCS10→**6**.
`calc_symbol_len(bytes, bw=3, mcs) = ceil((bytes×8 + 14) / NDBPS)`.
MCS=10 needs **4×** more OFDM symbols than MCS=1 for the same payload.
If only the MCS field is patched but not the symbol count, the hardware TX timer fires after
1/4 of the needed airtime → frame is physically truncated → undecodable at receiver.

Fix: after `lmac_irq_ac_pd_orig` returns, if `lmac[0x866]=10` but `buf[1]`[7:4] ≠ 10:
1. Patch MCS in `buf[1]` bits[7:4] and `buf[8..9]` bits[10:7]
2. Derive AC from `buf` pointer: `ac = (buf − &ah_lmac_tx_orig − 0x1c8) / 0x120`
3. Read `total_bytes` from `stride[0x1b8]`; compute `n_syms = ceil((total_bytes+4)×8 + 14) / 6)`
4. Patch TXVEC2, TXVEC3 bits[20:12], and `stride[0x1bc]` with `n_syms`
5. Re-write `LMAC_HW->TXVEC1` from patched buffer; sync `lmac[0x6e8]=10`

Key register map:
- `lmac[0x864]` — max-MCS ceiling (255 = no limit)
- `lmac[0x865]` — min-MCS floor (set to 1 for 1MHz by bss_bw; we keep at 0)
- `lmac[0x866]` — globally configured MCS (written by halow_config_set_mcs)
- `lmac[0x867]` — bw_hint for TDMA/modem mode (3 = 1MHz, set by bss_bw)
- `lmac[0x6e8]` — actual MCS last selected by lmac_update_tx_rate_orig
- `lmac[0x6ec]` — actual bw_hint last selected
- `lmac[0x34a]` bit0 — 1MHz channel flag (set by bss_bw for 1MHz)

## TXVEC hardware parameters

The PHY accepts four 32-bit vectors (`LMAC_HW->TXVEC1`–`TXVEC4`).  The MCS number is NOT
an abstraction that disappears before the hardware — it is literally written into the registers
and the on-chip PHY encoder uses it to select modulation and coding.  But MCS alone is not
enough: several independent fields must all be consistent.

### Per-AC descriptor (stride base = `&ah_lmac_tx_orig + ac * AH_AC_STRIDE`)

| Offset constant | Byte offset | Width | Content |
|---|---|---|---|
| `AH_AGGBYTES_OFS` | `0x1B8` | uint32 | Total PSDU bytes (sum of skb lengths for the aggregate) |
| `AH_AGGSYM_OFS`  | `0x1BC` | uint32 | `agg_symbol_len` = `calc_symbol_len(bytes+4, bw_hint, mcs)` |
| `AH_AGGNUM_OFS`  | `0x1C4` | uint8  | Number of selected frames (`selected_count`) |
| `AH_AGGCNT_OFS`  | `0x1C5` | uint8  | Aggregate count (total queued) |
| `AH_AGGHDR_OFS`  | `0x1C6` | uint16 | Frame descriptor: bits[1:0]=bw\_hint&3, bits[5:2]=MCS, bits[9:6]=frame\_type |
| (flags)          | `0x1C7` | uint8  | bit2 = txvec-ready flag (set by `lmac_gen_txvec_orig` at end) |
| `AH_CUR_TXVEC_OFS` | see txvec buffer below | ptr | `pPv0_txvec` → `stride + 0x1C8` |

**txvec buffer** (`stride + 0x1C8`, 16 bytes = TXVEC1–4):

| Buf bytes | Register | Key fields |
|---|---|---|
| `buf[0]`  | TXVEC1[7:0]   | bits[4:0] = TX power index; bits[7:6] = `bw_hint%3` (0=1MHz) |
| `buf[1]`  | TXVEC1[15:8]  | bits[3:2] = preamble-mode bits; bits[7:4] = **MCS** |
| `buf[2]`  | TXVEC1[23:16] | power cap / coding flags |
| `buf[3]`  | TXVEC1[31:24] | antenna format bits[1:0] |
| `buf[4..7]`  | TXVEC2[31:0]  | **`agg_symbol_len`** (full 32-bit symbol count) |
| `buf[8..11]` | TXVEC3[31:0]  | bits[10:7]=**MCS**; bit[11]=1; bits[20:12]=`agg_symbol_len`[8:0]; other flags |
| `buf[12..15]`| TXVEC4[31:0]  | response indicator; GI flag; misc |

### NDBPS table (1 MHz, `bw_idx = (bw_hint+1)&3 = 0`)

| MCS | Modulation | Code rate | NDBPS | Symbols for N bytes |
|---|---|---|---|---|
| 0  | BPSK   | 1/2 | 12 | `ceil((N×8+14)/12)` |
| 1  | QPSK   | 1/2 | 24 | `ceil((N×8+14)/24)` — 2× fewer than MCS0 |
| 10 | S1G\_DUP\_1M | — | **6** | `ceil((N×8+14)/6)` — **2× more than MCS0, 4× more than MCS1** |

`agg_symbol_len = calc_symbol_len(total_bytes + 4, bw_hint, mcs)`
= `ceil((total_bytes+4)×8 + 14) / NDBPS)`

TXVEC2 (full symbol count) drives the HW TX timer — it determines when transmission
physically ends.  If this is wrong, the frame is truncated mid-air.

`lmac_cfg_txvec_part1_orig` writes TXVEC1 from `buf[0..3]` (reads only the txvec buffer,
not `AH_AGGHDR_OFS`).  `lmac_cfg_txvec_part2` (our C impl) writes TXVEC2–4 from
`buf[4..15]`.

### Preamble mode (for `bw_hint=3`, 1 MHz modem mode)

`lmac_gen_txvec_orig` sets `preamble_mode=0` for **all** MCS at `bw_hint=3` — no special
S1G\_DUP\_1M preamble is generated; the format field in `AH_AGGHDR_OFS` bits[9:6] is
always `0b1110` (`0x380`).  The on-chip PHY interprets MCS=10 + format=0b1110 as the
modem-mode duplicate-TX operation.  NDBPS=6 accounts for the PHY counting double symbol
periods internally.

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
