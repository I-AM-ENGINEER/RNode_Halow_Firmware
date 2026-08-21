/* Scenario registry -- run order is load-bearing (shared link_db budget,
 * dedup ring and ACK-layer state carry across scenarios by design).
 * Suite implementations live in suite/*.c, one file per module under test. */
#include "test_fw.h"
#include "tests.h"

#include <stdio.h>

int main( void ){
#ifndef __csky__
    setvbuf(stdout, NULL, _IONBF, 0);
#endif
    struct { const char *name; void (*fn)(void); } tests[] = {
        {"init_defaults",               t_init_defaults},
        {"config_clamp",                t_config_clamp},
        {"broadcast_noack_bc_repeat",   t_broadcast_noack},
        {"bundle_flush_fid_ack",        t_bundle_flush_fid_ack},
        {"retry_exhaust",               t_retry_exhaust},
        {"slot_lifetime_deadline",      t_slot_lifetime_deadline},
        {"rx_dedup",                    t_rx_dedup},
        {"cumulative_ack_coalesce",     t_cumulative_ack_coalesce},
        {"env_compat_upgrade",          t_env_compat_upgrade},
        {"env_blockack_roundtrip",      t_env_blockack_roundtrip},
        {"env_probe_8th_ack",           t_env_probe_8th_ack},
        {"env_unknown_malformed",       t_env_unknown_malformed},
        {"l0_downgrade_magic_recovery", t_l0_downgrade_magic_recovery},
        {"throttle_staging_drain",      t_throttle_staging_drain},
        {"window_gate",                 t_window_gate},
        {"tx_ready_gating",             t_tx_ready_gating},
        {"ra_upshift",                  t_ra_upshift},
        {"is_internal_frame",           t_is_internal_frame},
        {"agg_size_per_mcs",            t_agg_size_per_mcs},
        {"ack_evm_zero_encoding",       t_ack_evm_zero_encoding},
        {"sixteen_peers_evict_lru",     t_sixteen_peers_evict_lru},
        {"peer_evict_protected_by_buf", t_peer_evict_protected_by_buf},
        {"pool_exhaustion",            t_pool_exhaustion},
        {"window_runtime_change",       t_window_runtime_change},
        {"dedup_ring_wrap",             t_dedup_ring_wrap},
        {"blockack_partial_bitmap",     t_blockack_partial_bitmap},
        {"config_migration_reseed",     t_config_migration_reseed},
        {"soak_fid_roundtrip",          t_soak_fid_roundtrip},
        {"soak_bundle_delayed_ack",     t_soak_bundle_delayed_ack},
        {"soak_lossy_exhaust",          t_soak_lossy_exhaust},
        {"soak_bidir_two_peers",        t_soak_bidir_two_peers},
        {"soak_multipeer_pressure",     t_soak_multipeer_pressure},
        {"soak_window_one_serial",      t_soak_window_one_serial},
        {"edge_frame_size_boundaries",  t_edge_frame_size_boundaries},
        {"edge_bundle_exact_fit",       t_edge_bundle_exact_fit},
        {"edge_seq_rollover",           t_edge_seq_rollover},
        {"edge_backoff_exact_timing",   t_edge_backoff_exact_timing},
        {"edge_ack_len_parity",         t_edge_ack_len_parity},
        {"edge_fid_zero_and_ack_storm", t_edge_fid_zero_and_ack_storm},
        {"edge_blockack_bitmap_extremes", t_edge_blockack_bitmap_extremes},
        {"edge_staging_timeout",        t_edge_staging_timeout},
        {"edge_ack_hold_extremes",      t_edge_ack_hold_extremes},
        {"edge_env_bundle_nsub_zero",   t_edge_env_bundle_nsub_zero},
        {"edge_stale_reheard_compat_reset", t_edge_stale_reheard_compat_reset},
        {"edge_vacancy_flap",           t_edge_vacancy_flap},
        {"edge_rapid_reconfig",         t_edge_rapid_reconfig},
        {"fp_single_broadcast_learn",   t_fp_single_broadcast_learn},
        {"fp_stream_framing_edges",     t_fp_stream_framing_edges},
        {"fp_mtu_clamp",                t_fp_mtu_clamp},
        {"fp_bundle_glue",              t_fp_bundle_glue},
        {"fp_partial_bundle_on_idle",   t_fp_partial_bundle_on_idle},
        {"fp_two_x_2000_bundle",        t_fp_two_x_2000_bundle},
        {"fp_throttle_blast_resume",    t_fp_throttle_blast_resume},
        {"fp_heap_fail_throttle",       t_fp_heap_fail_throttle},
        {"fp_roundtrip_soak",           t_fp_roundtrip_soak},
        {"fp_rx_edge_bundles",          t_fp_rx_edge_bundles},
        {"fp_tcp_ring_full",            t_fp_tcp_ring_full},
        {"vlink_zero_wait_invariant",    t_vlink_zero_wait_invariant},
        {"vlink_lossy_roundtrip",        t_vlink_lossy_roundtrip},
        {"vlink_lossy_deadline",         t_vlink_lossy_deadline},
        {"vlink_latency_profile",        t_vlink_latency_profile},
        {"cov_ack_misc",                 t_cov_ack_misc},
        {"cov_ra_walk_and_stale",        t_cov_ra_walk_and_stale},
        {"cov_slot_exhaust_untracked",   t_cov_slot_exhaust_untracked},
        {"cov_ack_tx_fail",              t_cov_ack_tx_fail},
        {"cov_env_seq_jump",             t_cov_env_seq_jump},
        {"cov_type2_and_parse_fail",     t_cov_type2_and_parse_fail},
        {"cov_utils_guards",             t_cov_utils_guards},
        {"cov_stream_guards",            t_cov_stream_guards},
        {"zero_copy_rx_encode",          t_zero_copy_rx_encode},
        {"legacy_detector_rns_space",     t_legacy_detector_rns_space},
        {"legacy_detector_internal",      t_legacy_detector_internal},
        {"legacy_bundle_compat",          t_legacy_bundle_compat},
        {"cov_gap_fill",                 t_cov_gap_fill},
        {"cov_linkdb_fill_close_hijack", t_cov_linkdb_fill_close_hijack},
        {"cov_legacy_bundle_deliver",    t_cov_legacy_bundle_deliver},
        {"env_peer_agg_off_still_acked", t_env_peer_agg_off_still_acked},
        };

    printf("halow_ack host tests: %d scenarios\n", (int)(sizeof(tests) / sizeof(tests[0])));
    for( unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++ ){
        int pass_before = test_pass_count();
        int fail_before = test_fail_count();
        printf("  %-30s", tests[i].name);
        tests[i].fn();
        if( test_pass_count() == pass_before && test_fail_count() == fail_before ) printf(" [no checks]\n");
        else if( test_fail_count() == fail_before )                                 printf(" ok\n");
        else                                                                        printf(" FAIL\n");
    }
    printf("\n%d checks passed, %d failed\n", test_pass_count(), test_fail_count());
    return test_fail_count() ? 1 : 0;
}
