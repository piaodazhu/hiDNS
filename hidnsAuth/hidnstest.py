import hidnsmsgformat
import socket
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from base64 import b64encode
# import datetime
import time
import math

HIDNS_SERVER_ADDR = ('127.0.0.1', 5553)
name = "/icn/bit/txt/xxx"

query = hidnsmsgformat.hiDNSQuery(name, 2, 3, hidnsmsgformat.RR_TYPE_TXT)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query.make_query(), HIDNS_SERVER_ADDR)
buf = sock.recv(2048)
answer = hidnsmsgformat.hiDNSAnswer()
answer.parse_answer(buf)

pfx = answer.prefixbuf
# print(pfx)
components = pfx.split(b'/')
components.reverse()
# print(components)
dn = b''
for c in components:
	if len(c) != 0:
		dn += c
		dn += b'.'

# print("domain name is ", dn)
msg = answer.sort_and_dump_tbs()
with open('./icn_bit/private.key', 'rb') as f:
	key = load_pem_private_key(f.read(), password=None)
sigbuf = key.sign(msg)
with open('signature', 'wb') as f:
	f.write(b64encode(sigbuf))

with open('sig_log1', 'wb') as f:
	f.write(sigbuf)

with open('msg_log1', 'wb') as f:
	f.write(msg)


now = math.floor(time.time())
signer = b'/icn/bit/'
afteronemonth = now + 3600 * 24 * 30 * 1
hsig = hidnsmsgformat.hiDNSHsig(expirtime=afteronemonth, inceptime=now, signer=signer, signature=sigbuf)
with open('hsig.txt', 'wb') as f:
	f.write(b64encode(hsig.make_hsig()))

# output a RRSIG record
# stu  604800  IN   RRSIG   TXT 5 2 86400 (
#                                 20230719224348 20220619214514 5083 /icn/bit/.
#                                 DsYFf6qZ3C3fzAI249B3Gml4YqUA12AxNCWvY0dnqk2I
#                                 s1+5qINYRO+dpXfd9tEBy4ZjZ2rA2Szc68Sr9b6pNQ== )

# rttl = str(604800).encode()
# rclass = b'IN'
# qtype = b'TXT'
# algo = str(15).encode()
# labels = str(answer.exacn).encode()
# ttl = str(86400).encode()
# now = datetime.datetime.now()
# signer = '/icn/bit/'.encode() + b'.'
# afteronemonth = now + datetime.timedelta(days=30)
# keytag = str(7778).encode()
# rr = dn + b' ' + rttl + b' ' + rclass + b' ' + b'RRSIG' + b' ' + qtype + b' ' + algo + b' ' + labels + b' ' + ttl + b' '
# val = b'( ' + afteronemonth.strftime('%Y%m%d%H%M%S').encode() + b' ' + now.strftime('%Y%m%d%H%M%S').encode() + b' ' + keytag + b' ' + signer + b' ' + sig + b' )'
# rr += val
# with open('rrsig.txt', 'wb') as f:
# 	f.write(rr)

