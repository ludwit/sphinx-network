/*
 * Copyright (C) 2023 ludwit
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       implements networking capabilities for sphinx
 *
 * @author      ludwit <ludwit@protonmail.com>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>

#include "shell.h"
#include "net/ipv6/addr.h"
#include "tweetnacl.h"

#include "shpinx.h"

int main(void)
{
    puts("Generated RIOT application: 'sphinx-networking'");

    /* verbose */
    puts("\nsphinx network nodes:");
    for (unsigned int i=0; i<SPHINX_NET_SIZE; i++) {
        ipv6_addr_print(&network_pki[i].addr);
        puts("");
    }
    puts("");

    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
