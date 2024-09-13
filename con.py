#!/usr/bin/python

import os, sys, time, socket

def gets():
	return int(time.time())

def getl(objc):
	return list(objc.keys())

def stdo(line):
	sys.stdout.write("[%s] %s\n" % (gets(), line, ))
	sys.stdout.flush()

def send(sock, data, addr):
	try:
		sock.sendto(data, addr)
	except:
		pass

def recv(sock, size):
	try:
		return sock.recvfrom(size)
	except KeyboardInterrupt:
		sys.exit(0)
	except:
		return (None, None)

def loop():
	sepr = b" "
	maps = {}

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(("127.0.0.1", 31337))

	maxt = ((2 ** 9) + (2 ** 7))
	mode = { "get":b"get", "set":b"set" }
	while True:
		(data, addr) = recv(sock, 128)
		if ((not data) or (not addr)):
			continue
		(secs, keys) = (gets(), getl(maps))
		(leng, resp) = (len(keys), b"")
		info = data.split(sepr)
		while (len(info) < 3):
			info.append(b"")
		(actn, keyq, valu) = (info[0], info[1], info[2])
		if (actn == mode["get"]):
			resp = b" "
			if (keyq in keys):
				resp = maps[keyq][0]
				maps[keyq][1] = secs
		elif (actn == mode["set"]):
			maps[keyq] = [valu, secs]
			leng += 1
			for keyn in keys:
				last = maps[keyn][1]
				if ((secs - last) >= maxt):
					stdo("info dels [%s] -> %s (%s)" % (keyn, maps[keyn], leng, ))
					del maps[keyn]
		stdo("info serv %s -> [%s] (%s)" % (info, resp, leng, ))
		if (resp):
			send(sock, resp, addr)

def main():
	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork [%s]" % (pidn, ))
		sys.exit(0)
	loop()

if (__name__ == "__main__"):
	main()
