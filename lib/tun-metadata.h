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

#ifndef TUN_METADATA_H
#define TUN_METADATA_H

#include "netlink.h"
#include "match.h"

void tun_meta_init(void);
void tun_meta_destroy(void);
void match_set_tun_metadata(struct match *match,
                            const uint8_t metadata[TUN_METADATA_LEN],
                            int len);
void match_set_tun_metadata_masked(struct match *match,
                                   const uint8_t metadata[TUN_METADATA_LEN],
                                   const uint8_t mask[TUN_METADATA_LEN],
                                   int len);
bool tun_metadata_get_lenofs(const uint8_t metadata[TUN_METADATA_LEN],
                             uint16_t *len, uint16_t *ofs);
int geneve_nlattr_to_tun_metadata(const struct nlattr *attr,
                                  uint8_t metadata[TUN_METADATA_LEN]);
#endif /* tun-metadata.h */
