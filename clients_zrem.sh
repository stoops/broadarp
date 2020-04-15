#!/bin/sh

afil="$1"
arpf=$(cat "$1")
shift

arpt=$(cat /tmp/wifi.aps)
devl=$(echo "$@" | tr ' ' '\n' | sort | uniq)
devs=$(echo "$devl" | tr '\n' '|' | sed -e 's/|*$//')

echo "$arpt" | grep -Ei " dev ($devs) " | while read line
do
	adr=$(echo "$line" | awk '{ print $1 }')
	del=$(echo "$line" | awk '{ print $1,$2,$3 }')
	perm=$(echo "$line" | grep -i " perm")
	erro=$(echo "$line" | grep -i " lladdr ")
	iadr=$(echo "$adr" | grep -i '^[0-9][^ ]*\.[0-9][0-9][0-9]$')
	iarp=$(echo "$arpf" | grep -i " $adr$")
	iper="x" ; if [ "$iadr" != "" -a "$iarp" == "" ] ; then iper="" ; fi
	if [ "$erro" == "" -o "$iper" == "" ] ; then
		ip -4 neigh del $del >/dev/null 2>&1
	elif [ "$perm" == "" -a "$iarp" != "" ] ; then
		touch "$afil"
	fi
done
