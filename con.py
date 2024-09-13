#!/usr/bin/python

import os, sys, time, socket, threading

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
	global maps

	sock = args["conn"]

	sepr = b" "
	maxt = ((2 ** 9) + (2 ** 7))
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

	fins(sock)
	args["stat"] = False

def mgmt(objc):
	while True:
		l = (len(objc) - 1)
		while (l > -1):
			thro = objc[l]
			if (thro["thro"] and (not thro["stat"])):
				print("info mgmt thro [%d]" % (l, ))
				thro["thro"].join()
				objc.pop(l)
			l -= 1
		time.sleep(3)

def loop():
	global maps

	thrs = []

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(("127.0.0.1", 31337))
	sock.listen(96)

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
