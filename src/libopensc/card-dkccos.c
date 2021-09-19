/*
 * card-dkccos.c: Support for Datakey DKCCOS (Datakey Cryptographic Card
 * Operating System) based cards and tokens (for example
 * Rainbow Technologies iKey 2032)
 *
 * Copyright (c) 2021  Shiz <hi@shiz.me>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"


enum dkccos_instructions {
    DKCCOS_INS_CHANGE_PIN = 0x1A,
    DKCCOS_INS_RECYCLE = 0x44,
    DKCCOS_INS_END_SESSION = 0x48,
    DKCCOS_INS_GET_CHALLENGE = 0x4C,
};

enum dkccos_file_type {
    DKCCOS_FILE_NORMAL = 0x1,
    DKCCOS_FILE_INTERNAL = 0x9,
    DKCCOS_FILE_DIR = 0x38,
    DKCCOS_FILE_PUBKEY = 0xF009,
    DKCCOS_FILE_PRIVKEY = 0xF109,
};

#define DKCCOS_PIN_MAX_LENGTH   20
#define DKCCOS_PIN_ID_SO        1
#define DKCCOS_PIN_ID_USER      2


static const struct sc_atr_table dkccos_atrs[] = {
    /* DKCCOS 6.0 */
    { "3b:ff:11:00:00:81:31:fe:4d:80:25:a0:00:00:00:56:57:44:4b:33:33:30:06:00:d0",
      "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:ff:00",
      "Datakey Model 330", SC_CARD_TYPE_DKCCOS_V6_0, 0, NULL },
    { NULL, NULL, NULL, 0, 0, NULL },
};

/* private data for dkccos driver */
struct dkccos_private_data {
    unsigned int curr_file;
    unsigned int curr_size;
};

static const struct sc_card_operations *iso_ops = NULL;



static int dkccos_match_card(sc_card_t *card)
{
    if (_sc_match_atr(card, dkccos_atrs, &card->type) < 0)
        return 0;
    return 1;
}

static int dkccos_init(sc_card_t *card)
{
    LOG_FUNC_CALLED(card->ctx);

    struct dkccos_private_data *priv = NULL;

    priv = calloc(1, sizeof(struct dkccos_private_data));
    if (!priv)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
    card->drv_data = priv;

    card->cla = 0x00;
    card->caps |= SC_CARD_CAP_RNG;

    LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int dkccos_finish(sc_card_t *card)
{
    LOG_FUNC_CALLED(card->ctx);

    if (!card)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

    /* free priv data */
    if (card->drv_data) {
        free(card->drv_data);
        card->drv_data = NULL;
    }

    LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/* yoinked from iso7816.c */
static int dkccos_select_file(struct sc_card *card, const struct sc_path *in_path, struct sc_file **file_out)
{
    struct sc_apdu apdu;
    unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
    unsigned char pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
    int r = 0;
    struct sc_file *file = NULL;
    size_t path_len;
    struct dkccos_private_data *priv = NULL;

    if (card == NULL || in_path == NULL || in_path->aid.len) {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    memcpy(path, in_path->value, in_path->len);
    path_len = in_path->len;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);

    switch (in_path->type) {
    case SC_PATH_TYPE_FILE_ID:
        apdu.p1 = 0;
        if (path_len != 2)
            return SC_ERROR_INVALID_ARGUMENTS;
        break;
    case SC_PATH_TYPE_DF_NAME:
        apdu.p1 = 4;
        break;
    case SC_PATH_TYPE_PATH:
        apdu.p1 = 8;
        if (path_len >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
            path += 2;
            path_len -= 2;
            if (!path_len) // only 3F00 supplied
                apdu.cse = SC_APDU_CASE_2_SHORT;
        }
        break;
    case SC_PATH_TYPE_FROM_CURRENT:
        apdu.p1 = 9;
        break;
    case SC_PATH_TYPE_PARENT:
        apdu.p1 = 3;
        path_len = 0;
        apdu.cse = SC_APDU_CASE_2_SHORT;
        break;
    default:
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
    }

    apdu.lc = path_len;
    apdu.data = path;
    apdu.datalen = path_len;
    apdu.le = MIN(sc_get_max_recv_size(card), 256);
    apdu.resp = buf;
    apdu.resplen = sizeof(buf);

    r = sc_transmit_apdu(card, &apdu);
    if (r)
        LOG_FUNC_RETURN(card->ctx, r);
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r)
        LOG_FUNC_RETURN(card->ctx, r);

    if (apdu.resplen < 2 || apdu.resp[0])
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

    file = sc_file_new();
    if (file == NULL)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
    r = card->ops->process_fci(card, file, apdu.resp, apdu.resplen);
    LOG_TEST_RET(card->ctx, r, "processing FCI failed");

    priv = card->drv_data;
    priv->curr_file = file->id;
    priv->curr_size = file->size;

    if (file_out)
        *file_out = file;
    else
        free(file);

    return SC_SUCCESS;
}

/* yoinked from iso7816.c */
static int dkccos_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{
    int r;
    struct sc_apdu apdu;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_2, DKCCOS_INS_GET_CHALLENGE, 0x00, 0x00);
    apdu.le = len;
    apdu.resp = rnd;
    apdu.resplen = len;

    r = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(card->ctx, r, "GET CHALLENGE failed");

    if (len < apdu.resplen) {
        return (int) len;
    }
   
    return (int) apdu.resplen;
}


static void dkccos_pin_init_pin(sc_card_t *card, struct sc_pin_cmd_pin *pin, unsigned n)
{
    pin->offset = DKCCOS_PIN_MAX_LENGTH * (n - 1);
    pin->pad_char = ' ';
    pin->encoding = SC_PIN_ENCODING_ASCII; /* not really, but good enough */
    pin->max_length = pin->pad_length = DKCCOS_PIN_MAX_LENGTH;
}

static void dkccos_pin_init(sc_card_t *card, struct sc_pin_cmd_data *data)
{
    data->flags |= SC_PIN_CMD_NEED_PADDING;
    dkccos_pin_init_pin(card, &data->pin1, 1);
    dkccos_pin_init_pin(card, &data->pin2, 2);
}

static int dkccos_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
    int r = 0;
    struct sc_apdu apdu;
    u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

    if (data->pin_type != SC_AC_CHV)
        LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "unsupported PIN type");

    dkccos_pin_init(card, data);
    r = iso7816_build_pin_apdu(card, &apdu, data, sbuf, sizeof(sbuf));
    LOG_TEST_RET(card->ctx, r, "building pin APDU failed");
    data->apdu = &apdu;

    switch (data->cmd) {
    case SC_PIN_CMD_CHANGE:
        apdu.ins = DKCCOS_INS_CHANGE_PIN;
        break;
    case SC_PIN_CMD_VERIFY:
        apdu.p1 = apdu.p2;
        apdu.p2 = 0;
        break;
    }

    r = iso_ops->pin_cmd(card, data, tries_left);
    LOG_TEST_RET(card->ctx, r, "pin command failed");

    return r;
}

static int dkccos_logout(sc_card_t *card)
{
    int r = 0;
    struct sc_apdu apdu;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_1, DKCCOS_INS_END_SESSION, 0x00, 0x00);
    r = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(card->ctx, r, "LOGOUT failed");

    return r;
}


static int dkccos_construct_acl(struct sc_card *card, const sc_file_t *file, const sc_acl_entry_t *entry)
{
    unsigned char c = 0;
    for (; entry; entry = entry->next) {
        if (entry->key_ref == SC_AC_KEY_REF_NONE)
            c |= 0x7F;
        else
            c |= (1 << entry->key_ref);
    }
    return c;
}

static int dkccos_construct_fci(struct sc_card *card, const sc_file_t *file, u8 *out, size_t *outlen)
{
    const sc_acl_entry_t *entry;
    unsigned int type;

    switch (file->type) {
    case SC_FILE_TYPE_INTERNAL_EF:
        type = DKCCOS_FILE_INTERNAL;
        break;
    case SC_FILE_TYPE_WORKING_EF:
        type = DKCCOS_FILE_NORMAL;
        break;
    case SC_FILE_TYPE_DF:
        type = DKCCOS_FILE_DIR;
        break;
    default:
        LOG_TEST_RET(card->ctx, SC_ERROR_INCORRECT_PARAMETERS, "invalid file type");
    }

    u8 *p = out;
    *p++ = file->size >> 8;
    *p++ = file->size & 0xff;
    *p++ = file->id >> 8;
    *p++ = file->id & 0xff;
    *p++ = type >> 8;
    *p++ = type & 0xff;

    entry = sc_file_get_acl_entry(file, SC_AC_OP_READ);
    if (entry)
        *p++ = dkccos_construct_acl(card, file, entry);
    else
        *p++ = 119;
    entry = sc_file_get_acl_entry(file, SC_AC_OP_WRITE);
    if (entry)
        *p++ = dkccos_construct_acl(card, file, entry);
    else
        *p++ = 119;
    entry = sc_file_get_acl_entry(file, SC_AC_OP_DELETE);
    if (entry)
        *p++ = dkccos_construct_acl(card, file, entry);
    else
        *p++ = 127;

    *outlen = p - out;
    return 0;
}

static int dkccos_process_acl(struct sc_card *card, sc_file_t *file, unsigned int operation, int value)
{
    int r = 0;
    if (value == 0xff) {
        r = sc_file_add_acl_entry(file, operation, SC_AC_CHV, SC_AC_KEY_REF_NONE);
    } else {
        for (int i = 0; i < 8 && !r; i++) {
            if (value & (1 << i)) {
                r = sc_file_add_acl_entry(file, operation, SC_AC_CHV, i);
            }
        }
    }
    return r;
}

static int dkccos_process_fci(sc_card_t *card, sc_file_t *file, const u8 *data, size_t len)
{
    int r = 0;
    unsigned type;
    
    file->size = data[9] << 8 | data[10];
    file->id = data[2] << 8 | data[3];

    type = data[5] << 8 | data[4];
    switch (type) {
    case DKCCOS_FILE_INTERNAL:
        file->type = SC_FILE_TYPE_INTERNAL_EF;
        file->ef_structure = SC_FILE_EF_TRANSPARENT;
        break;
    case DKCCOS_FILE_NORMAL:
        file->type = SC_FILE_TYPE_WORKING_EF;
        file->ef_structure = SC_FILE_EF_TRANSPARENT;
        break;
    case DKCCOS_FILE_DIR:
        file->type = SC_FILE_TYPE_DF;
        break;
    default:
        LOG_TEST_RET(card->ctx, SC_ERROR_INCORRECT_PARAMETERS, "invalid file type");
    }

    r = dkccos_process_acl(card, file, SC_AC_OP_READ, data[6]);
    LOG_TEST_RET(card->ctx, r, "card read ACL conversion failed");
    r = dkccos_process_acl(card, file, SC_AC_OP_WRITE, data[7]);
    LOG_TEST_RET(card->ctx, r, "card write ACL conversion failed");
    r = dkccos_process_acl(card, file, SC_AC_OP_DELETE, data[8]);
    LOG_TEST_RET(card->ctx, r, "card delete ACL conversion failed");

    return 0;
}


static int dkccos_erase_card(sc_card_t *card)
{
    int r = 0;
    sc_apdu_t apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, DKCCOS_INS_RECYCLE, 0x6B, 0x2C);
    apdu.resp = rbuf;
    apdu.resplen = sizeof(rbuf);
    apdu.le = 264;

    r = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx, r, "card format command failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(card->ctx, r, "ERASE failed");

    return r;
}


static int dkccos_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
    int r = 0;
    unsigned int idx = 0;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    struct dkccos_private_data *priv = NULL;

    priv = card->drv_data;
    while (idx < priv->curr_size && buflen) {
        r = card->ops->read_binary(card, idx, rbuf, sizeof(rbuf), 0);
        LOG_TEST_RET(card->ctx, r, "failed to read directory entry");

        *buf++ = rbuf[2];
        *buf++ = rbuf[3];
        buflen -= 2;
        idx++;
    }

    if (idx < priv->curr_size)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
    return idx * 2;
}

static int dkccos_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
    switch (cmd) {
    case SC_CARDCTL_ERASE_CARD:
        return dkccos_erase_card(card);
    }
    return SC_ERROR_NOT_SUPPORTED;
}


static struct sc_card_operations dkccos_ops;

static struct sc_card_driver dkccos_drv = {
    "Datakey DKCCOS",
    "dkccos",
    &dkccos_ops,
    NULL, 0, NULL
};

static struct sc_card_driver *sc_get_driver(void)
{
    if (iso_ops == NULL)
        iso_ops = sc_get_iso7816_driver()->ops;
    dkccos_ops = *iso_ops;

    /* OpenSC functions */
    dkccos_ops.match_card = dkccos_match_card;
    dkccos_ops.init = dkccos_init;
    dkccos_ops.finish = dkccos_finish;

    /* ISO 7816-4 functions */
    dkccos_ops.append_record = NULL; /* conflicting */
    dkccos_ops.select_file = dkccos_select_file;
    dkccos_ops.get_challenge = dkccos_get_challenge;

    /* ISO 7816-8 functions */
    dkccos_ops.logout = dkccos_logout;

    /* ISO 7816-9 functions */
    dkccos_ops.list_files = dkccos_list_files;
    dkccos_ops.card_ctl = dkccos_card_ctl;
    dkccos_ops.construct_fci = dkccos_construct_fci;
    dkccos_ops.process_fci = dkccos_process_fci;

    /* misc functions */
    dkccos_ops.pin_cmd = dkccos_pin_cmd;

    return &dkccos_drv;
}

struct sc_card_driver *sc_get_dkccos_driver(void)
{
    return sc_get_driver();
}
