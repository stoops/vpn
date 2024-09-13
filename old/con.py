#!/usr/bin/python

import os, sys, time, socket, threading

maxt = 45
maps = {}

def gets():
	return int(time.time())

def getl(objc):
	return list(objc.keys())

def stdo(line):
	sys.stdout.write("[%s] %s\n" % (gets(), line, ))
	sys.stdout.flush()

def send(sock, data, addr):
	try:
		#sock.sendto(data, addr)
		sock.sendall(data)
	except:
		pass

def recv(sock, size):
	try:
		#return sock.recvfrom(size)
		return sock.recv(size)
	except KeyboardInterrupt:
		sys.exit(0)
	except:
		#return (None, None)
		return b""

def fins(sock):
	try:
		sock.shutdown(socket.SHUT_RDWR)
	except:
		pass
	try:
		sock.close()
	except:
		pass

def proc(args):
	global maxt
	global maps

	sock = args["conn"]

	sepr = b" "
	mode = { "get":b"get", "set":b"set" }

	addr = None
	data = recv(sock, 128)
	if (data):
		(secs, keys) = (gets(), getl(maps))
		(leng, resp) = (len(keys), b"")
		info = data.strip().split(sepr)
		while (len(info) < 3):
			info.append(b"")
		(actn, keyq, valu) = (info[0], info[1], info[2])

		if (actn == mode["get"]):
			resp = b" "
			try:
				resp = maps[keyq][0]
				maps[keyq][1] = secs
			except:
				pass
				#stdo("erro proc keys [%s]" % (keyq, ))

		elif (actn == mode["set"]):
			maps[keyq] = [valu, secs]
			leng += 1

		stdo("info serv %s -> [%s] (%s)" % (info, resp, leng, ))

		if (resp):
			send(sock, resp, addr)

	fins(sock)
	args["stat"] = False

def mgmt(objc):
	global maxt
	global maps

	while True:
		secs = gets()

		leng = (len(objc) - 1)
		while (leng > -1):
			thro = objc[leng]
			if (thro["thro"] and (not thro["stat"])):
				stdo("info mgmt join [%d]" % (leng, ))
				thro["thro"].join()
				objc.pop(leng)
			leng -= 1

		keys = getl(maps)
		leng = len(keys)
		for keyn in keys:
			last = maps[keyn][1]
			if ((secs - last) >= maxt):
				stdo("info dels %s [%s] -> %s (%s)" % (secs - last, keyn, maps[keyn], leng, ))
				try:
					del maps[keyn]
				except:
					stdo("erro mgmt dels [%s]" % (keyn, ))

		time.sleep(3)

def loop():
	global maxt
	global maps

	leng = len(sys.argv)
	for x in range(0, leng):
		if ((sys.argv[x] == "-t") and ((x + 1) < leng)):
			maxt = int(sys.argv[x + 1])

	thrs = []

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(("127.0.0.1", 31337))
	sock.listen(960)

	thrm = threading.Thread(target=mgmt, args=(thrs, ))
	thrm.start()
	while True:
		#(data, addr) = recv(sock, 128)
		(conn, addr) = sock.accept()

		if ((not conn) or (not addr)):
			continue

		info = { "thro":None, "conn":conn, "addr":addr, "stat":True }
		thro = threading.Thread(target=proc, args=(info, ))
		thro.start()
		info["thro"] = thro
		thrs.append(info)

def main():
	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork [%s]" % (pidn, ))
		sys.exit(0)
	loop()

if (__name__ == "__main__"):
	main()
