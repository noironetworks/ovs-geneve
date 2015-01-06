/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "cmap.h"
#include "compiler.h"
#include "match.h"
#include "ovs-thread.h"
#include "packets.h"
#include "nx-match.h"
#include "tun-metadata.h"
#include "openvswitch/vlog.h"
#include <errno.h>

VLOG_DEFINE_THIS_MODULE(tun_metadata);
static bool initialized;

/* table used to map tunnel metadata to a particular offset within
 * flow_tnl.metadata */
struct tun_meta_table {
    struct cmap cmap;         /* cmap */
    struct ovs_mutex mutex;   /* protect simultaneous writers */
    uint16_t next_ofs;        /* next offset in flow_tnl.metadata */
};

struct tun_meta_entry {
    struct cmap_node node;    /* node in hashmap */
    uint32_t key;             /* unique key */
    uint16_t len;             /* len of this metadata */
    uint16_t ofs;             /* offset in flow_tnl.metadata */
};

static struct tun_meta_table tun_meta_table;

static inline uint32_t tun_meta_hash(uint32_t key)
{
    return hash_int(key, 0);
}

static struct tun_meta_entry *
tun_meta_find(const struct cmap *cmap, uint32_t key)
{
    struct tun_meta_entry *entry;
    CMAP_FOR_EACH_WITH_HASH (entry, node, tun_meta_hash(key), cmap) {
        if (entry->key == key) {
            return entry;
        }
    }
    return NULL;
}

static void OVS_UNUSED
tun_meta_print(const char *name, const struct cmap *cmap)
{
    struct cmap_cursor cursor;
    struct tun_meta_entry *entry;
    printf("%s:", name);
    CMAP_CURSOR_FOR_EACH(entry, node, &cursor, cmap) {
        printf(" (%x %d %d)", entry->key, entry->len, entry->ofs);
    }
}

static struct tun_meta_entry *
tun_meta_add(struct cmap *cmap, uint32_t key, uint16_t len, uint16_t ofs)
{
    struct tun_meta_entry *entry = xmalloc(sizeof *entry);
    entry->key = key;
    entry->len = len;
    entry->ofs = ofs;
    cmap_insert(cmap, &entry->node, tun_meta_hash(key));
    return entry;
}

/* callers responsibility to verify entry->len is same as len */
static struct tun_meta_entry *
tun_meta_add_unique(struct tun_meta_table *table, uint32_t key, uint16_t len)
{
    struct tun_meta_entry *entry = tun_meta_find(&table->cmap, key);
    if (entry == NULL) {
        ovs_mutex_lock(&table->mutex);
        entry = tun_meta_add(&table->cmap, key, len, table->next_ofs);
        table->next_ofs += len;
        ovs_mutex_unlock(&table->mutex);
    }
    return entry;
}

static void OVS_UNUSED
tun_meta_remove(struct tun_meta_table *table, uint32_t key)
{
    struct cmap *cmap = &table->cmap;
    struct tun_meta_entry *entry = tun_meta_find(cmap, key);
    if (entry) {
        ovs_mutex_lock(&table->mutex);
        cmap_remove(cmap, &entry->node, tun_meta_hash(key));
        /* FIXME make offset available */
        ovs_mutex_unlock(&table->mutex);
        ovsrcu_postpone(free, entry);
    }
}

void
tun_meta_init(void)
{
    struct tun_meta_table *table = &tun_meta_table;
    cmap_init(&table->cmap);
    ovs_mutex_init(&table->mutex);
    table->next_ofs = 0;
    initialized = true;
}

void
tun_meta_destroy(void)
{
    struct tun_meta_table *table = &tun_meta_table;
    struct cmap *cmap = &table->cmap;
    struct tun_meta_entry *entry;
    ovs_mutex_lock(&table->mutex);
    CMAP_FOR_EACH(entry, node, cmap) {
        cmap_remove(cmap, &entry->node, tun_meta_hash(entry->key));
        ovsrcu_postpone(free, entry);
    }
    cmap_destroy(cmap);
    ovs_mutex_unlock(&table->mutex);
    ovs_mutex_destroy(&table->mutex);
}

#define TUN_META_KEY(metadata) \
    ((metadata)[0] << 16 | (metadata)[1] << 8 | (metadata)[2])

/* assumes metadata[0] contains length when invoking via mf_set
 * metadata here is mf_value or mf_mask adjusted to contain length */
static struct tun_meta_entry *
find_or_add_tun_meta_entry(const uint8_t metadata[TUN_METADATA_LEN], int len)
{
    uint32_t key = TUN_META_KEY(metadata);
    struct tun_meta_entry *e;

    if (!initialized) {
        tun_meta_init();
    }

    e = tun_meta_add_unique(&tun_meta_table, key, len);
    if (e->len != len) {
        VLOG_ERR("duplicate metadata (key %x, len %d), new len %d",
                 key, e->len, len);
        return NULL;
    } else {
        return e;
    }
}

static struct tun_meta_entry *
find_tun_meta_entry(const uint8_t metadata[TUN_METADATA_LEN])
{
    uint32_t key = TUN_META_KEY(metadata);

    if (!initialized) {
        tun_meta_init();
        return NULL;
    } else {
      return tun_meta_find(&tun_meta_table.cmap, key);
    }
}

bool
tun_metadata_get_lenofs(const uint8_t metadata[TUN_METADATA_LEN],
                        uint16_t *len, uint16_t *ofs)
{
    const struct tun_meta_entry *e = find_tun_meta_entry(metadata);
    if (e) {
        *len = e->len;
        *ofs = e->ofs;
        return true;
    } else {
        return false;
    }
}

/* copies a single tun_meta entry at the correct offset in
 * metadata and updates the map if needed. */
void match_set_tun_metadata(struct match *match,
                            const uint8_t metadata[TUN_METADATA_LEN],
                            int len)
{
    struct tun_meta_entry *entry = find_or_add_tun_meta_entry(metadata, len);
    if (entry) {
        uint16_t ofs = entry->ofs;
        uint16_t len = entry->len;
        memcpy(match->flow.tunnel.metadata + ofs, metadata, len);
        memset(match->wc.masks.tunnel.metadata + ofs, 0xff, len);
    }
}

/* copies a single tun_meta entry at the correct offset in
 * metadata and updates the map if needed. */
void match_set_tun_metadata_masked(struct match *match,
                                   const uint8_t metadata[TUN_METADATA_LEN],
                                   const uint8_t mask[TUN_METADATA_LEN],
                                   int len)
{
    struct tun_meta_entry *entry = find_or_add_tun_meta_entry(metadata, len);
    if (entry) {
        uint16_t ofs = entry->ofs;
        uint16_t len = entry->len;
        size_t i;
        for (i = 0; i < len; i++) {
            match->flow.tunnel.metadata[i + ofs] = metadata[i] & mask[i];
            match->wc.masks.tunnel.metadata[i + ofs] = mask[i];
        }
    }
}

int
geneve_nlattr_to_tun_metadata(const struct nlattr *attr,
                              uint8_t metadata[TUN_METADATA_LEN])
{
    int opts_len = nl_attr_get_size(attr);
    const struct geneve_opt *opt = nl_attr_get(attr);

    while (opts_len > 0) {
        int len;
        struct tun_meta_entry *entry;

        if (opts_len < sizeof(*opt)) {
            return -EINVAL;
        }

        len = sizeof(*opt) + opt->length * 4;
        if (len > opts_len) {
            return -EINVAL;
        }

        entry = find_tun_meta_entry((uint8_t *)opt);
        if (entry && entry->len == opt->length * 4) {
            memcpy(metadata + entry->ofs, opt, 3);
            memcpy(metadata + entry->ofs + 3, opt->opt_data, entry->len);
        } else if (opt->type & GENEVE_CRIT_OPT_TYPE) {
            return -EINVAL;
        }

        opt = opt + len / sizeof(*opt);
        opts_len -= len;
    };

    return 0;
}
