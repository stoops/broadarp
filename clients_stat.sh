#!/bin/sh

limi=90
asec=0000000000
esec=9999999999
emac="00:00:00:00:00:00"
adrr="[0-9][^ ]*\.[0-9][0-9][0-9]"

wifi=$(cat /tmp/wifi.leases)
dhcp=$(cat /tmp/dhcp.leases | awk '{ print $1,$2,$3 }')
pout=$(cat /tmp/wifi.tmp | awk '{ print $1,$2,$3 }' | sort | uniq)
stat=$(cat /tmp/stat.leases | sort | uniq)

arpt=$(ip -4 neigh)
arpf=$(cat "$1")
shift

devl=$(echo "$@" | tr ' ' '\n' | sort | uniq)
devs=$(echo "$devl" | tr '\n' '|' | sed -e 's/|*$//')
peer=$(echo "$pout" | grep -i " $emac " | grep -i " $adrr$")
let dsec="$esec-1"



ipat=$(echo "$arpt" | grep -i "^$adrr dev .* lladdr ")

# perform a global AP IP-lookup to detect any unknown live hosts (static addresses):
#   - check the arp table for any mac that appears live and not one of our peers
#   - check that it is not in our dhcp table
#   - check that it is not in our arp file

temp=$(echo "$ipat" | grep -Ei " dev ($devs) ")
x=1 ; leng=0 ; test ! -z "$temp" && leng=$(echo "$temp" | wc -l)
while [ $x -le $leng -a $x -lt $limi ]
do
	line=$(echo "$temp" | head -n $x | tail -n 1)
	adr=$(echo "$line" | awk '{ print $1 }')
	mac=$(echo "$line" | awk '{ print $5 }')
	app=$(echo "$arpf" | grep -i " $adr$")
	if [ "$app" == "" ] ; then
		peer=$(echo "$peer" | grep -iv " $adr$" | grep -i ':' ; echo "$esec $emac $adr")
	fi
	let x="$x+1"
done



# perform a local-net host-ip arp-lookup on unknown peers (ping-check)

x=1 ; leng=0 ; test ! -z "$peer" && leng=$(echo "$peer" | wc -l)
while [ $x -le $leng -a $x -lt $limi ]
do
	line=$(echo "$peer" | head -n $x | tail -n 1)
	adr=$(echo "$line" | awk '{ print $3 }')
	app=$(echo "$arpf" | grep -i " $adr$")
	if [ "$app" == "" ] ; then
		for devn in $devl ; do
			ping -4 -I "$devn" -c 1 -W 1 "$adr" >/dev/null 2>&1 &
		done
	fi
	let x="$x+1"
done


sleep 1
arpt=$(ip -4 neigh)


# determine if any of the unknown clients resolved if:
#   - the ip address is listed in our arp table with a mac address associated and return if:
#     - the mac is already listed in our dhcp table
#     - the mac responded and it's not one of our peers addresses
#   - otherwise remove the client if it's in the arp file or it didn't respond at all

x=1 ; leng=0 ; test ! -z "$peer" && leng=$(echo "$peer" | wc -l)
while [ $x -le $leng -a $x -lt $limi ]
do
	line=$(echo "$peer" | head -n $x | tail -n 1)
	adr=$(echo "$line" | awk '{ print $3 }')
	app=$(echo "$arpf" | grep -i " $adr$")
	apd=$(echo "$dhcp" | grep -i " $adr$")
	apt=$(echo "$arpt" | grep -i "^$adr .* lladdr " | grep -iv 'perm')
	if [ "$app" != "" ] ; then
		peer=$(echo "$peer" | grep -iv " $adr$" | grep -i ':')
	elif [ "$apd" != "" ] ; then
		mac=$(echo "$apd" | awk '{ print $2 }')
		stat=$(echo "$stat" | grep -iv " $adr$" | grep -i ':' ; echo "$esec $mac $adr")
	elif [ "$apt" != "" ] ; then
		mac=$(echo "$apt" | awk '{ print $5 }')
		appr=$(echo "$arpt" | grep -i " $mac " | grep -iv "^$adrr ")
		if [ "$appr" == "" ] ; then
			stat=$(echo "$stat" | grep -iv " $adr$" | grep -i ':' ; echo "$dsec $mac $adr")
		else
			stat=$(echo "$stat" | grep -iv " $adr$" | grep -i ':')
		fi
	else
		peer=$(echo "$peer" | grep -iv " $adr$" | grep -i ':')
	fi
	let x="$x+1"
done


# remove any of our static entries if:
#   - a different mac-ip combo appears in our peers listing
#   - the mac is listed more than once in our arp table
#   - the mac is connected directly to us and in our dhcp table
x=1 ; leng=0 ; test ! -z "$stat" && leng=$(echo "$stat" | wc -l)
while [ $x -le $leng -a $x -lt $limi ]
do
	line=$(echo "$stat" | head -n $x | tail -n 1)
	sec=$(echo "$line" | awk '{ print $1 }')
	mac=$(echo "$line" | awk '{ print $2 }')
	adr=$(echo "$line" | awk '{ print $3 }')
	secs=$(echo "$pout" | grep -i " $mac [0-9]" | grep -iv " $adr$" | head -n 1 | awk '{ print $1 }')
	secr="" ; test ! -z "$secs" && test $secs -le $sec && secr="x"
	arpc=$(echo "$arpt" | grep -i " lladdr $mac " | wc -l)
	arpw=$(echo "$wifi" | grep -i " $mac ")
	arpd=$(echo "$dhcp" | grep -i " $mac ")
	arpr="" ; if [ $arpc -gt 1 -o "$arpw" != "" -a "$arpd" != "" ] ; then arpr="x" ; fi
	if [ "$secr" != "" -o "$arpr" != "" ] ; then
		stat=$(echo "$stat" | grep -iv " $adr$" | grep -i ':')
	fi
	let x="$x+1"
done



echo "$peer" > /tmp/peer.leases
echo "$stat" > /tmp/stat.leases
echo "$arpt" > /tmp/wifi.aps
