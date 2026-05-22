// Reconstructed from mars_lmac_cipher.o disassembly
#include "typesdef.h"
#include "osal/string.h"
#include "osal/irq.h"
#include "osal/mutex.h"
#include "osal/semaphore.h"
#include "lib/lmac/lmac_ctx.h"
//#include "lib/lmac/lmac_globals.h"

extern void hgprintf(const char *fmt, ...);

/* ah_cipher is defined here, as in the original object. */
void *ah_cipher = 0;

/* ---- IRQ handler ---------------------------------------------------- */

void ah_ce_irq_handler(void)
{
    lmac_ah_cipher_ctx_t *ctx = (lmac_ah_cipher_ctx_t *)ah_cipher;
    volatile uint32_t *base = ctx->base_addr;
    if (base[0x68 / 4] & 1) {
        base[0x68 / 4] |= 1;
        os_sema_up(&ctx->sema);
    }
}

/* ---- Init ------------------------------------------------------------ */
/*
 * Assembly puts cipher_ctx in r1 (second argument), r0 is unused.
 * The caller passes a parent struct pointer in r0 and the cipher ctx in r1.
 */
void ah_ce_init(void *unused, lmac_ah_cipher_ctx_t *ctx)
{
    ah_cipher = ctx;
    os_mutex_init(&ctx->mutex);
    os_sema_init(&ctx->sema, 0);
    request_irq(ctx->irq_num, (irq_handle)ah_ce_irq_handler, ctx);

    /* enable IRQ in NVIC ISPR */
    uint32_t irq   = ctx->irq_num;
    uint32_t group = (irq >> 5) & 3;
    uint32_t bit   = irq & 31;
    volatile uint32_t *nvic_ispr = (volatile uint32_t *)0xe000e100;
    nvic_ispr[group] = 1u << bit;

    /* enable CE in hardware */
    volatile uint32_t *base = ctx->base_addr;
    base[0x60 / 4] |= 2;
}

/* ---- Start CE operation --------------------------------------------- */

int ah_ce_start(lmac_ah_cipher_ctx_t *ctx, const ah_ce_cfg_t *cfg)
{
    volatile uint32_t *base;
    uint8_t tmp[30];

    if (os_mutex_lock(&ctx->mutex, -1) != 0) {
        hgprintf("\2cipher engine ce_lock timeout!\r\n");
        hgprintf("\2LMAC_AH_CE_FAIL\r\n");
        os_mutex_unlock(&ctx->mutex);
        return -1;
    }

    uint8_t mode = cfg->mode;

    if (mode == 0) {
        base = ctx->base_addr;
        const uint8_t *key = cfg->key;

        /* clear cipher mode bits 12 and 13 */
        uint32_t ce_cfg = base[0x64 / 4];
        ce_cfg &= ~(1u << 12);
        ce_cfg &= ~(1u << 13);
        base[0x64 / 4] = ce_cfg;

        /* load 4 x 32-bit key words (little-endian byte assembly) */
        for (uint32_t i = 0; i < 4; i++) {
            uint32_t w = (uint32_t)key[0]
                       | ((uint32_t)key[1] << 8)
                       | ((uint32_t)key[2] << 16)
                       | ((uint32_t)key[3] << 24);
            base[i] = w;
            key += 4;
        }
        /* fall through to common iv_setup */

    } else if (mode == 2) {
        base = ctx->base_addr;
        const uint8_t *key = cfg->key;

        /* clear bits 12,13 then set bit 13 */
        uint32_t ce_cfg = base[0x64 / 4];
        ce_cfg &= ~(1u << 12);
        ce_cfg &= ~(1u << 13);
        base[0x64 / 4] = ce_cfg;
        ce_cfg = base[0x64 / 4];
        ce_cfg |= 0x2000u;
        base[0x64 / 4] = ce_cfg;

        /* load 8 x 32-bit key words */
        for (uint32_t i = 0; i < 8; i++) {
            uint32_t w = (uint32_t)key[0]
                       | ((uint32_t)key[1] << 8)
                       | ((uint32_t)key[2] << 16)
                       | ((uint32_t)key[3] << 24);
            base[i] = w;
            key += 4;
        }
        /* jump to common iv_setup */
        goto iv_setup;

    } else {
        hgprintf("\2LMAC_AH_CE_FAIL\r\n");
        os_mutex_unlock(&ctx->mutex);
        return -1;
    }

iv_setup:
    /* mode control register (base + 0x20, index 8):
     * bits[3:0] from cfg->ctrl5, bit4 from cfg->ctrl6[0], bit5 from cfg->ctrl7[0]
     */
    {
        uint32_t mode_bits = ((uint32_t)(cfg->ctrl5) & 0x0fu)
                           | (((uint32_t)(cfg->ctrl6) << 4) & 0x10u)
                           | (((uint32_t)(cfg->ctrl7) << 5) & 0x20u);
        base[0x20 / 4] = (base[0x20 / 4] & 0xffffff00u) | mode_bits;
    }

    /* IV bytes into CE_MODE[8] (bits 31:8) and CE_IV1[9] */
    {
        const uint8_t *iv = cfg->iv;
        /* upper 3 bytes of base[0x20/4]: iv[2]<<24 | iv[1]<<16 | iv[0]<<8 */
        uint32_t iv_hi = ((uint32_t)iv[2] << 24)
                       | ((uint32_t)iv[1] << 16)
                       | ((uint32_t)iv[0] << 8);
        base[0x20 / 4] |= iv_hi;
        /* base[0x24/4]: iv[3] | iv[4]<<8 | iv[5]<<16 */
        base[0x24 / 4] = (uint32_t)iv[3]
                       | ((uint32_t)iv[4] << 8)
                       | ((uint32_t)iv[5] << 16);
    }

    /* AAD bytes */
    {
        const uint8_t *aad = cfg->aad;
        /* base[0x28/4]: aad[2]<<24 | aad[3]<<16 | aad[4]<<8 | aad[5] */
        base[0x28 / 4] = ((uint32_t)aad[2] << 24)
                       | ((uint32_t)aad[3] << 16)
                       | ((uint32_t)aad[4] << 8)
                       |  (uint32_t)aad[5];
        /* base[0x2c/4]: aad[0]<<8 | aad[1] */
        base[0x2c / 4] = ((uint32_t)aad[0] << 8) | (uint32_t)aad[1];
    }

    /* secondary key header: base[0x30/4] = key2[1]<<24 | key2[0]<<16 | key2_len<<8 */
    memset(tmp, 0, sizeof(tmp));

    uint8_t key2_len = cfg->key2_len;
    if (key2_len >= 31) {
        hgprintf("\2LMAC_AH_CE_FAIL\r\n");
        os_mutex_unlock(&ctx->mutex);
        return -1;
    }

    {
        const uint8_t *key2 = cfg->key2;
        base[0x30 / 4] = ((uint32_t)key2[1] << 24)
                        | ((uint32_t)key2[0] << 16)
                        | ((uint32_t)key2_len << 8);

        /* copy key2[2..key2_len-1] into tmp[2..] */
        for (uint32_t i = 2; (uint8_t)i < key2_len; i++)
            tmp[i] = key2[i];
    }

    /* load GHASH key (7 words) from tmp[2..29] into CE registers 13..19 */
    {
        const uint8_t *p = &tmp[2];
        for (uint32_t j = 0; j < 7; j++) {
            uint32_t w = (uint32_t)p[0]
                       | ((uint32_t)p[1] << 8)
                       | ((uint32_t)p[2] << 16)
                       | ((uint32_t)p[3] << 24);
            base[13 + j] = w;   /* base + (13+j)*4 = base + 0x34..0x4c */
            p += 4;
        }
    }

    /* data length: base[0x50/4] = base[20] */
    {
        uint16_t data_len = cfg->data_len;
        if (data_len >= 16385) {
            hgprintf("\2LMAC_AH_CE_FAIL\r\n");
            os_mutex_unlock(&ctx->mutex);
            return -1;
        }
        base[0x50 / 4] = data_len;
        base[0x54 / 4] = cfg->src_addr;
        base[0x58 / 4] = cfg->dst_addr;
    }

    /* direction */
    uint8_t dir = cfg->direction;
    if (dir == 0) {
        /* encrypt: clear bit0 of CE_CFG, set bit0 of CE_CTRL */
        base[0x64 / 4] &= ~1u;
        base[0x60 / 4] |= 1u;
    } else if (dir == 1) {
        /* decrypt: set bit0 of CE_CFG, then start CE */
        base[0x64 / 4] |= 1u;
        base[0x60 / 4] |= 1u;
    } else {
        hgprintf("\2LMAC_AH_CE_FAIL\r\n");
        os_mutex_unlock(&ctx->mutex);
        return -1;
    }

    if (os_sema_down(&ctx->sema, 100) == 0) {
        hgprintf("\2cipher engine ce_done timeout!\r\n");
        hgprintf("\2LMAC_AH_CE_FAIL\r\n");
        os_mutex_unlock(&ctx->mutex);
        return -1;
    }

    if (dir != 1) {
        os_mutex_unlock(&ctx->mutex);
        return 0;
    }

    /* decrypt: check CE status register for errors */
    base = ctx->base_addr;
    uint32_t status = base[0x68 / 4];
    if (status & 2) {
        uint32_t e1 = base[0x70 / 4];
        uint32_t e2 = base[0x74 / 4];
        uint32_t e3 = base[0x78 / 4];
        uint32_t e4 = base[0x7c / 4];
        hgprintf("\2hw_MIC: %x %x %x %x\r\n", e1, e2, e3, e4);
    }
    status = base[0x68 / 4];
    if (status & 2) {
        hgprintf("\2MIC_ERROR! key_size= %d\r\n", (unsigned)cfg->mode);
        dump_hex("key: ", (uint8 *)cfg->key, cfg->mode, 1);
        os_mutex_unlock(&ctx->mutex);
        return -1;
    }

    os_mutex_unlock(&ctx->mutex);
    return 0;
}
