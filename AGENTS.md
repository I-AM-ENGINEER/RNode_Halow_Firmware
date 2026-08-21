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

## PHY size-rate constraint (max MSDU per MCS, 1 MHz) — found 2026-08-18

The binary LMAC rejects any PPDU whose symbol count exceeds **511** at non-MCS10
(`lmac error!!!len=... too long for non-mcs10, max 511`) and then **retries the
frame forever** — one oversized frame jams its AC queue until the tier-2 purge
(5-15 s) or watchdog reboot (30 s). This was the root cause of the "periodic
pause" stalls and 100%-loss windows. Max payload per MCS (1 MHz):
`halow_max_msdu[0][mcs] = {700,1450,2200,3000,4500,6050,6800,7600}`, MCS10≈500.
`halow_tx_p` bumps the per-frame MCS to the lowest rate whose max MSDU fits the
frame (+32 B margin, 802.11 hdr) — counters `tx_mcs_bump`/`tx_drop_oversize` in
`/api/tx_dbg`. ACK-layer agg sizing (`eff_agg_bytes` in halow_ack.c) uses the same
table. Any new TX entry point MUST NOT bypass this check. RX decodes each frame
at its own rate, so a per-frame upshift is transparent to the peer.

Other night-fixed traps (see NIGHT_STATUS.md): binary `lmac rx` task stack is
only 1024 B — never add stack frames to the RX callback chain; `trap_c` now
reboots (was `while(1)` while acktk fed the watchdog = permanent dark loop);
purge/reconfig must reset `queued_count` in the SAME irq-off window that NULLs
`skb_list[]` (reorder derefs it in ac_pd IRQ).

## Overnight-2026-08-17 traps (see NIGHT_STATUS.md for details)

Throughput work (218->1650 kbit/s unidir) + bug hunt landed in b187. Permanent
traps to remember:
- Test tools MUST tag seq 32-bit (16-bit wraps at exactly 65536 frames and
  fakes a "collapse"); rns_link_test.Node._loop resolves parse_seq in ITS OWN
  module globals -- monkeypatch `rns_link_test.parse_seq` when reusing Node
  with a different payload tag.
- ACK-layer knobs are runtime/configdb: hack.window (16), hack.fids (32) --
  POST /api/ack_cfg. (gapms/agghold removed 2026-08-20: assembly no longer
  waits, the TCP recv window paces TX.)
- TX watchdog ac_pd "moved" must be latched only at TX-complete/purge, never
  sampled per 10 ms tick (false purge -> false reboot of a live node).
- Gain pilot: never switch RX gain while a session is active; STABLE4 needs
  the prod-collapse exit; healthy prod base must be captured in clean air.
- Never park a frame in g_pend_buf without len <= ACK_WIRE_MAX 2048 (BSS
  smash); the binary lmac-rx task stack (1024 B) has ~zero headroom under
  halow_ack_on_rx -> SHA256 -- no logs/locals there.

## Module layout (post-2026-08-20 refactor)

ACK/reliability layer lives in `src/halow_ack.c` (frame buffers, peers, RA,
envelope v1, acktk task; public API in `inc/halow_ack.h`). `src/halow_pkg_handler.c`
is only the RNS<->TCP bridge (rf_to_tcp / tcp_to_rf / MTU clamp); the RNS stream
framing (SLIP-like 0x7E/0x7D) is `src/rns/stream_parser.c` and holds ONE
THROTTLE-rejected frame for retry.

## ACK module design (2026-08-20 heap rewrite)

One heap node per tracked frame, exact-size (os_malloc, flexible-array `data[]`),
16 pointer slots (STAGING/INFLIGHT/SENDING — no PARKED, no static pool). Static
RAM: 3.2 KB of the 50 KB cap (size_test.c). Heap use is rate-shaped: staging
alloc = 6 + eff_agg + 16 (~730 B for an MCS0 peer, ~4 KB for MCS7), so far nodes
never pay for near-node frames; malloc failure returns THROTTLE (TCP window
closes) and is counted in `heap_fail`/`heap_bytes` stats.

Max ACK-tracked frame: payload sum 4000 B per bundle (`HALOW_ACK_AGG_PAYLOAD_MAX`,
2x2000 or 8x500 MTU packets), wire cap ACK_WIRE_MAX = 4000+6+16 = 4022. Bigger
frames go out untracked/broadcast. Single max-size sub unwraps to plain on flush.

Reticulum link MTU is FIXED at 500 B (RNS_LINK_MTU_FIXED in halow_pkg_handler.c,
no configdb key, /api/rns_mtu_cfg removed): 500-B packets look like ordinary
LoRa traffic on air and still glue into large blocks in the ACK layer.

Aggregation never waits (no gap/hold timers — removed with cfg ver 4): frames
glue while lwIP has bytes, the bundle leaves the moment it is full, and
`halow_ack_flush()` (called from tcp_server.c when netconn_recv returns
WOULDBLOCK) sends the incomplete frame when the TCP side runs dry. The tick only
retries gated flushes and drops staging stuck >= 1 s (drop_throttle). Backpressure
contract: THROTTLE → stream decoder holds the frame + reports *consumed → tcps
skips netconn_recv → lwIP recv window closes; no frame is ever fire-and-forgotten.

## Test running (tests/ack)

Host: `make` (gcc; use ucrt64 `mingw32-make`, plain msys make mangles TMP).
Target ISA: `make qemu` — cross-builds the same suite for ck803 and runs it in
the T-Head simulator (CDKRepo/Simulator cskysim = QEMU 9 fork, board
soccfg/cskyv2/smartl_803_cfg.xml: ck803efr3, unaligned_access=off, UART
0x40015000 console, write to 0x10002000 exits). qemu/support.c carries the
bare-metal runtime (mini-printf, memcpy, first-fit free-list malloc for the
heap-frame path); startup.s + qemu/test.ld place everything in D-SRAM 0x20000000.
The suite links the REAL pkg_handler/rns/sha256 chain: full-path tests feed TCP
bytes (SLIP, escapes, split chunks) through stream_parser → link_db → bundle
builder → captured halow_tx, and back via rf_to_tcp → captured tcp_server_send.
A virtual lossy RF channel (vchan: per-frame drop%, data AND ACK frames cross
it, retransmits + dedup close the loop) covers 20-30% loss round-trips and 70%
exhaustion. 207,822 checks green on host and emulated ck803; gcov line coverage
95.6% over the six pipeline files (ack 97.7%, pkg 99.0%, stream 95.0%,
parser 90.5%, utils 95.9%, link_db 85.6%; the rest is log-off/sweeper-task/
malloc-fail glue). `make qemu-bench` runs the staged pipeline bench with
per-stage wall timing (bench_time.py timestamps each UART line).

No-wait proof: t_vlink_zero_wait_invariant asserts feed → bundle → air →
receive → decode → TCP completes at the SAME virtual jiffy with zero os_sleep
calls. `make qemu-bench` runs under `-icount shift=0` with the APB timer
(0x40011000) as an instruction counter (calibrated: 1 tick = 1 executed
instruction; qemu/timer_probe.c) and links the PRODUCTION toolchain
memcpy/memset objects (libc.a memcpy_fast: word path only when (src|dst)%4==0,
else byte loop) — stage `tks:` lines are exact, run-to-run identical
instruction counts. 128 ticks = 1 µs at the SoC core clock (DEFAULT_SYS_CLK
128 MHz), assuming 1 CPI (no SRAM stall model). Per 500-B packet:
full TX chain 26,745 cycles (209 µs, 19.1 Mbit/s), full RX chain 21,041
(164 µs, 24.3 Mbit/s), SLIP decode 11,163, SLIP encode+malloc 10,600,
fnv1a 3,008, 500-B aligned memcpy 436, RNS parse 325, empty tick 469
(0.0037% CPU at 100 Hz). RF ceiling at 1 MHz MCS7 is 7.8 Mbit/s, so CPU has
~2.5× headroom; at 2 MHz channels (15.6 Mbit/s) the TX byte-FSMs become the
limiter. Hotspots if more CPU is ever needed: the SLIP decode/encode
per-byte state machines (~22 instr/byte, 42-50% of each direction) and fnv1a
(~3× per frame end-to-end: TX fid, RX dedup, ack path) — NOT the memcpys.

Copy-layer audit (measured with -Wl,--wrap=memcpy in bench.elf): TX moves a
500-B packet through 6 memcpy calls / 1,616 B (SLIP-decode byte-loop into the
decoder frame buffer + staging append halow_ack.c:985 [the intended one
copy] + skb copy halow.c:886 + 2×16-B RNS header copies + 32-B fids init);
RX through 4 calls / 571 B (SLIP-encode byte-loop + tcp_server.c:556 heap
copy + netconn NETCONN_COPY inside lwIP + 2×16-B header copies). The RF→TCP
bundle walk itself is zero-copy (pointers into the wire frame).

Env-peer ACK starvation (found by the lossy model, fixed 2026-08-21): after
the 8-ack probe flips a peer to envelope compat, plain frames (seq 0xFFFF)
can never match the env bitmap ACK — env peers now ALWAYS ride seq'd bundles
(ack_tx_uc forces the bundle path; staging is sized to fit one oversize sub).
Regression: t_env_peer_agg_off_still_acked. halow_ack_init also pre-ages
g_last_data_tx_jiff past the busy window (fresh boot used to read as
link-busy for the first 10 s).
