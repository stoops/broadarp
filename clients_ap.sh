#!/bin/sh

for d in "$@"
do
	( iw dev "$d" station dump ; cat "/tmp/${d}.leases" ) | grep -Ei '(station|inactive)' | \
	tr '~\t\r\n' ' ' | sed -e 's/[Ss]tation/~station:/g' | \
	tr '~' '\n' | tr -s ' ' | grep -i 'station' | \
	awk "{ print \$(NF-1),\$2,\"$d\" }" | while read l ; do \
		s=$(echo "$l" | awk '{ print $1 }' | tr -d '\t\r\n' | wc -c)
		let p="10-$s"
		if [ $p -lt 0 ] ; then
			p=$(echo "$p" | sed -e 's/^[^0-9]*//')
			l=$(echo "$l" | sed -E "s/^.{${p}}//")
		else
			for z in `seq 1 $p` ; do l="0$l" ; done
		fi
		echo "$l"
	done
done | sort > /tmp/wifi.leases
