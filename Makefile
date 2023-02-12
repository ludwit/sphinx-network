# name of the application
APPLICATION = sphinx-networking

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules
USEMODULE += gnrc_ipv6
USEMODULE += gnrc_sock_udp
USEMODULE += gnrc_udp
USEMODULE += gnrc_icmpv6_error
USEMODULE += gnrc_icmpv6_echo
# Shell modules
USEMODULE +=  shell
USEMODULE +=  shell_cmds_default
USEMODULE +=  shell_cmd_gnrc_udp
USEMODULE +=  ps
# Crypto packages
USEPKG += tweetnacl


# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
