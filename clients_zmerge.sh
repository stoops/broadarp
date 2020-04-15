#!/bin/sh

d=$(cat /tmp/dhcp.leases | grep -i ':' | awk '{ print $1,$2,$3 }')
o=$(cat /tmp/wifi.leases /tmp/peer.leases /tmp/stat.leases | grep -i ':' | awk '{ print $1,$2,$3 }')
c=$( ( echo "$d" ; echo "$o" ) | sort | uniq | sort -n )
w=$(echo "$o" | awk '{ print $2 }' | sort | uniq)

echo -n "" > /tmp/apc.leases
test ! -z "$w" && echo "$w" | while read m
do
	t=$(echo "$c" | grep -i "$m" | awk '{ print $1 }' | head -n 1)
	a=$(echo "$c" | grep -i "$m" | awk '{ print $3 }' | grep -i '^[0-9][^ ]*\.[0-9][0-9][0-9]$' | sort | uniq)
	test -z "$a" && a=x
	for b in $a ; do echo "$t $m $b" ; done
done > /tmp/apc.leases
