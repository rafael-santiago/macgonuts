/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_OUI_LOOKUP_H
#define MACGONUTS_OUI_LOOKUP_H 1

#include <macgonuts_types.h>

int macgonuts_oui_lookup(char *vendor_ident,
                         const size_t max_vendor_ident_size,
                         uint8_t *hw_addr,
                         const size_t hw_addr_size,
                         const char *oui_dbpath);

#endif // MACGONUTS_OUI_LOOKUP_H
