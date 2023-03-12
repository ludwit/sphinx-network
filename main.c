#include "shpinx.h"

int main(void)
{
    puts("Generated RIOT application: 'sphinx-networking'");

    /* verbose */
    puts("\nsphinx network nodes:");
    for (uint8_t i=0; i<SPHINX_NET_SIZE; i++) {
        ipv6_addr_print(&network_pki[i].addr);
        puts("");
    }
    puts("");

    /* start sphinx immediately */
    sphinx_start();

    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
