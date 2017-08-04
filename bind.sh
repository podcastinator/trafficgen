#!/bin/bash

SCRIPTS_DIR=$( dirname "${BASH_SOURCE[0]}" )
BASE_DIR="${SCRIPTS_DIR}/.."
TOOL_DIR="${BASE_DIR}/downloads/bess/bin"

while getopts ":ubsl" opt; do
    case $opt in
        s)  sudo ${TOOL_DIR}/dpdk-devbind.py -s
            ;;
        u)  sudo ${TOOL_DIR}/dpdk-devbind.py --bind=ixgbe 02:00.0
            sudo ifconfig ixgbes0 up
            ;;
        b)  sudo ifconfig ixgbes0 down
            sudo ${TOOL_DIR}/dpdk-devbind.py --bind=uio_pci_generic ixgbes0
            ;;
        l)  sudo modprobe uio_pci_generic
            ;;
        \?) ;;
    esac
done

