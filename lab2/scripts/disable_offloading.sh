#!/bin/bash

# The virtual NIC does not support "lro ufo rxhash" options.
TOE_OPTIONS="rx tx sg tso gso gro rxvlan txvlan"

for IFACE in `/sbin/ifconfig | grep '^.*-eth[0-9]' | awk '{print $1}' | awk -F: '{print $1}'`; do
	echo "Disabling $IFACE ..."
	for TOE_OPTION in $TOE_OPTIONS; do
		/sbin/ethtool --offload "$IFACE" "$TOE_OPTION" off
	done
done
