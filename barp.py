import os,sys,random,socket,time
import IN

APNS = 4
PSIZ = 9

def secs():
	return int(time.time())

def tt(ll):
	return (ll & 0xffffffff)

def delb(intf):
	os.system("ip -4 neigh del 255.255.255.255 dev %s" % (intf))

def mask(bits):
	invr = ((1 << (32 - bits)) - 1)
	return [0xffffffff ^ invr, invr]

def ipnl(addr):
	d = 0
	try:
		s = socket.inet_aton(addr)
	except:
		return d
	for c in s:
		d = (d << 8) ; d += ord(c)
	return d

def fill(last, host, part):
	init = []
	for x in range(0, 4):
		init.append(last & 0xff) ; last = (last >> 8)
	init.append(part)
	for x in range(0, 4):
		init.append(0)
	init.append(0)
	for p in socket.inet_aton(host):
		init.append(ord(p))
	init.append(0)
	for x in range(0, APNS):
		init.append(0)
	while (len(init) < 128):
		init.append(int(random.random()*256))
	return init

def swap(s, a, b):
	t = s[a] ; s[a] = s[b] ; s[b] = t
	return s

def keys(init, spwd, leng):
	j = 0
	m = min(15+APNS+leng, 128)
	skey = []
	for i in range(0, 256):
		skey.append(i)
	for i in range(0, 256):
		j = ((j + skey[i] + init[i % m] + ord(spwd[i % leng])) % 256)
		swap(skey, i, j)
	return (m, skey)

# Modified ARC4-KEY[IV]-DROP[4096]-MODE[CBC]
def ciph(inpt, leng, skey, mode):
	i = 0 ; j = 0
	l = (leng % 256)
	outp = ""
	for z in range(0, 4096):
		i = ((i + 1) % 256)
		j = ((j + skey[i]) % 256)
		swap(skey, i, j)
	for z in range(0, leng):
		i = ((i + 1) % 256)
		j = ((j + skey[i]) % 256)
		swap(skey, i, j)
		k = ((skey[i] + skey[j] + skey[l]) % 256)
		outp += chr(ord(inpt[z]) ^ skey[k])
		if (mode == 'e'):
			l = (l ^ ord(outp[z]))
		else:
			l = (l ^ ord(inpt[z]))
	return outp

# Modified SDBM-HASH[INIT]-ROUNDS[4]-SIZE[256]
def hmix(inpt, leng):
	mixs = [1, 6, 16, 13, 33, 27, 67, 55, 123]
	hshs = [0, 0, 0, 0, 0, 0, 0, 0, 0]
	more = 0
	mlen = len(hshs) ; rnds = (4 * mlen)
	for x in range(0, mlen+leng):
		hshs[0] = tt(mixs[x%mlen] + ord(inpt[x%leng]) + (hshs[0] << 6) + (hshs[0] << 16) - hshs[0])
		more = (more ^ (hshs[0] >> 16))
		i = ((x % (mlen - 1)) + 1)
		less = ((hshs[i] & 0xffff0000) ^ ((hshs[i] & 0xffff) << 16))
		hshs[i] = (less ^ more)
	for z in range(0, rnds):
		hshs[0] = tt(z + more + (hshs[0] << 6) + (hshs[0] << 16) - hshs[0])
		more = (more ^ (hshs[mlen-1] >> 16))
		for y in range(mlen-1, 0, -1):
			hshs[y] = tt((hshs[y] << 16) | (hshs[y-1] >> 16))
			hshs[y-1] = (hshs[y-1] & 0xffff)
	o = ""
	for h in hshs[1:]:
		for x in range(3, -1, -1):
			o += chr((h >> (x * 8)) & 0xff)
	return o

def hmac(mesg, mlen, skey, klen):
	inner_pad = 0x36 ; outer_pad = 0x5C
	block_size = 64 ; ikey = "" ; okey = ""
	tkey = skey ; tlen = klen
	if (klen > block_size):
		tkey = hmix(skey, klen)
		tlen = len(tkey)
	for x in range(0, block_size):
		c = 0
		if (x < tlen):
			c = ord(tkey[x])
		ikey += chr(inner_pad ^ c)
		okey += chr(outer_pad ^ c)
	ihsh = hmix(ikey+mesg, block_size+mlen)
	ilen = len(ihsh)
	ohsh = hmix(okey+ihsh, block_size+ilen)
	return ohsh

def ssnd(intf, data):
	socksend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socksend.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	try:
		socket.SO_BINDTODEVICE = 25
		socksend.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, intf)
		#socksend.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, intf)
	except:
		pass
	socksend.sendto(data, ("255.255.255.255", 1337))
	try:
		socksend.close()
	except:
		pass

if (len(sys.argv) < 5):
	print("Usage: barp.py [out-file] [key] [ap1-dev ap2-dev my-ip/mask] [peer1|dev1] [peer2|dev2] ...\n")
	sys.exit(1)

newb = -1 ; newp = -1 ; last = secs() ; proc = secs()
bsec = int(os.environ.get("BCAST", "5"))
psec = int(os.environ.get("PROCS", "10"))
isec = int(os.environ.get("EXPIRED", "15"))
forw = os.environ.get("RELAY", "")

sockrecv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockrecv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sockrecv.bind(("", 1337))
sockrecv.settimeout(0.33)

spwd = sys.argv[2] ; klen = len(spwd)
myinfo = sys.argv[3].split(" ")
(apdev, addrm) = (myinfo[:-1], myinfo[-1])
(myadr, mymsk) = addrm.split("/")
ints = [sa.split("|") for sa in sys.argv[4:]]
devs = " ".join([i[-1] for i in ints])

ipid = int(myadr.split(".")[-1])
ando = mask(int(mymsk)) ; adrn = ipnl(myadr)
begi = (adrn & ando[0]) ; endi = (begi + ando[1])
apls = []

while True:
	sys.stdout.write(".") ; sys.stdout.flush()
	nsec = secs()


	if ((nsec - last) >= bsec):
		if ((newb < 0) and (newp < 0)):
			last = nsec ; newb = os.fork()

	if (newb == 0):
		sys.stdout.write("b") ; sys.stdout.flush()

		os.system("clients_ap.sh %s" % (" ".join(apdev)))
		os.system("clients_stat.sh %s %s %s" % (sys.argv[1], " ".join(apdev), devs))
		os.system("clients_zmerge.sh")

		fobj = open("/tmp/apc.leases", "r")
		data = fobj.readlines()
		fobj.close()
		dlen = len(data) ; z = 0

		for part in range(0, PSIZ):
			mesg = "" ; mlen = 0
			while (z < dlen):
				llen = len(data[z])
				if ((mlen+llen) < (1024-256)):
					mesg += data[z] ; mlen += llen ; z += 1
				else:
					break

			if ((part == 0) and (mlen < 24)):
				mesg = "        " ; mlen = len(mesg)

			if ((part == 0) or (mlen > 24)):
				init = fill(last, myadr, part)
				(cmpr, arck) = keys(init, spwd, klen)
				encr = ciph(mesg, mlen, arck, 'e')

				inis = "".join([chr(init[x]) for x in range(0, cmpr)])
				encs = (inis + encr)
				sign = hmac(encs, len(encs), spwd, klen)

				init[15] = ipid
				inis = "".join([chr(init[x]) for x in range(0, cmpr)])
				encs = (inis + encr)

				for i in ints:
					delb(i[-1])
				for i in ints:
					ssnd(i[-1], encs + sign)

		sys.exit(0)


	if ((nsec - proc) >= psec):
		if ((newb < 0) and (newp < 0)):
			proc = nsec ; newp = os.fork()

	if (newp == 0):
		sys.stdout.write("p") ; sys.stdout.flush()

		fobj = open("/tmp/wifi.tmp", "w")
		for apid in apls:
			if ((nsec - apid["last"]) > isec):
				continue
			maxt = 0
			for part in range(0, PSIZ):
				maxt = max(apid["data"][part]["last"], maxt)
			for part in range(0, PSIZ):
				if ((maxt == 0) or (apid["data"][part]["last"] != maxt)):
					continue
				for line in apid["data"][part]["mesg"].split("\n"):
					if (not ":" in line):
						continue
					fobj.write(line.strip()+" "+apid["host"]+"\n")
		fobj.close()

		os.system("( cat /tmp/wifi.tmp ; cat /tmp/apc.leases | sed -e 's/$/ %s/' ) | grep -iv '00:00:00:00:00:00' | sort > /tmp/sarp.tmp" % (myadr))

		fobj = open("/tmp/sarp.tmp", "r")
		arps = fobj.readlines()
		fobj.close()
		fobj = open("/tmp/wifi.aps", "r")
		aprs = fobj.readlines()
		fobj.close()
		fobj = open("/tmp/wifi.leases", "r")
		wlan = fobj.readlines()
		fobj.close()
		seen = {}

		for line in arps:
			info = line.strip().split(" ")
			if (len(info) < 4):
				continue
			d = None ; m = info[1] ; a = info[2] ; r = info[3] ; s = r ; b = m
			if (not m in seen.keys()):
				if (r == myadr):
					for wcli in wlan:
						winf = wcli.strip().split(" ")
						if (winf[1] == m):
							d = winf[2] ; break
				if (not d):
					for peer in aprs:
						pinf = peer.strip().split(" ")
						if ((pinf[0] == s) and (" dev " in peer) and (" lladdr " in peer)):
							d = pinf[2] ; b = pinf[4] ; break
				if d:
					seen[m] = {"low":r, "adr":[], "dev":d, "mac":b}
			if ((m in seen.keys()) and (not a in seen[m]["adr"])):
				i = ipnl(a)
				if ((begi < i) and (i < endi)):
					seen[m]["adr"].append(a)

		tfil = sys.argv[1]+".tmp"
		fobj = open(tfil, "w")
		for m in seen.keys():
			for a in seen[m]["adr"]:
				fobj.write("%s %s %s\n" % (seen[m]["dev"], seen[m]["mac"], a))
		fobj.close()

		os.system("o=$(cat %s | sort) ; a=$(echo \"$o\" | md5sum) ; b=$(cat %s | md5sum) ; test \"$a\" != \"$b\" && echo \"$o\" > %s && mv %s %s" % (tfil, sys.argv[1], tfil, tfil, sys.argv[1]))
		os.system("clients_zrem.sh %s %s %s" % (sys.argv[1], " ".join(apdev), devs))

		sys.exit(0)


	try:
		data = sockrecv.recv(1024) ; dlen = len(data)
		ilen = min(15+APNS+klen, 128) ; slen = 32

		if (dlen > (ilen + slen)):
			encr = [] ; z = 0
			for x in range(0, ilen):
				encr.append(ord(data[x])) ; z = (x + 1)
			sign = data[dlen-slen:]
			data = data[z:dlen-slen]
			indx = -1 ; zero = -1 ; sndr = -1 ; cmps = "*"

			iips = encr[15:15+APNS]
			for x in range(0, APNS):
				if ((indx < 0) and (iips[x] == ipid)):
					indx = x
				if ((zero < 0) and (iips[x] == 0)):
					zero = x
				if ((sndr < 0) and (iips[x] == encr[13])):
					sndr = x
				encr[15+x] = 0

			if ((indx < 0) and (zero > -1) and (sndr > -1) and (ipid != encr[13])):
				inis = "".join([chr(encr[x]) for x in range(0, ilen)])
				encs = (inis + data)
				cmps = hmac(encs, len(encs), spwd, klen)

			if ((len(cmps) == slen) and (cmps == sign)):
				(null, arck) = keys(encr, spwd, klen)
				mesg = ciph(data, len(data), arck, 'd')
				cmpt = 0 ; part = encr[4] ; item = None

				for x in range(0, 4):
					cmpt = (cmpt << 8) ; cmpt += encr[3-x]
				hipa = ".".join([str(e) for e in encr[10:14]])
				print("\nr> [%d][%d][%s] [%d][%s]... " % (cmpt, part, hipa, len(mesg), mesg[:32]))

				for apid in apls:
					if (apid["host"] == hipa):
						item = apid

				if ((len(apls) < APNS) and (not item)):
					apls.append({"last":0, "host":hipa, "data":[]}) ; item = apls[-1]
					for x in range(0, PSIZ):
						item["data"].append({"last":0, "mesg":""})

				if (item and (part < PSIZ) and (cmpt > item["data"][part]["last"])):
					item["data"][part]["mesg"] = mesg
					item["data"][part]["last"] = cmpt
					item["last"] = secs()

					if (forw != ""):
						sys.stdout.write("f") ; sys.stdout.flush()
						iips[zero] = ipid
						for x in range(0, APNS):
							encr[15+x] = iips[x]
						inis = "".join([chr(encr[x]) for x in range(0, ilen)])
						encs = (inis + data)
						for i in ints:
							delb(i[-1])
						for i in ints:
							ssnd(i[-1], encs + sign)

	except socket.timeout:
		pass

	try:
		stat = os.wait3(os.WNOHANG)
	except:
		newb = -1 ; newp = -1
