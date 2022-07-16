from signal import SIGBUS
import sys
from random import randint
import bitstring
import ipaddress

RR_TYPE_A = 1
RR_TYPE_NS = 2
RR_TYPE_CNAME = 5
RR_TYPE_SOA = 6
RR_TYPE_TXT = 16
RR_TYPE_CERT = 37
RR_TYPE_RRSIG = 46

aentryfmt = 'uint:32, uint:8, uint:8, uint:16, bytes'
queryfmt = 'uint:32, 8*uint:1, 4*uint:4, 2*uint:8, bytes'
answerfmt = 'uint:32, 8*uint:1, 4*uint:4, 3*uint:8, bytes'

class hiDNSAnswerEntry():
	fixHeadersize = 8
	def __init__(self, ttl=60, type=0, value:bytes=b''):
		self.ttl = ttl
		self.type = type
		self.reserved = 0
		self.length = len(value)
		self.value = value

	def make_aentry(self) -> bytes:
		entry = bitstring.pack(aentryfmt, self.ttl, self.type, self.reserved, self.length, self.value)
		return entry.bytes

	def parse_aentry(self, buf) -> int:
		entry = bitstring.BitStream(buf)
		self.ttl, self.type, self.reserved, self.length, remain = entry.unpack(aentryfmt)
		self.value = remain[:self.length]
		return self.fixHeadersize + self.length

		


class hiDNSQuery():
	fixHeadersize = 9
	def __init__(self, namebuf:str="", mincn=0, maxcn=0, qtype=0, id=-1, hoplimit=3, rd=1, cd=0, od=0):
		self.id = id
		# nocheck
		self.z = 0
		self.od = od
		self.ad = 0
		self.cd = cd
		self.ra = 0
		self.rd = rd
		self.tc = 0
		self.aa = 0
		self.hoplimit = hoplimit
		self.reserved = 0
		self.maxcn = maxcn
		self.mincn = mincn
		self.qtype = qtype #?
		self.qnlen = len(namebuf)
		self.namebuf = namebuf.encode()

	def make_query_hod(self, destaddr) -> bytes:
		query = self.make_query()
		query += ipaddress.ip_address(destaddr[0]).packed
		return query

	def make_query(self) -> bytes:
		if self.id < 0 or self.id > 2147483647:
			self.id = randint(0, 2147483647)
		
		if sys.byteorder.capitalize() == "Little_unset":
			qbuf = bitstring.pack(queryfmt, self.id, self.aa, self.tc, self.rd, self.ra, self.cd, self.ad, self.od, self.z, self.reserved, self.hoplimit,self.mincn, self.maxcn, self.qtype, self.qnlen, self.namebuf).bytes
		else:
			qbuf = bitstring.pack(queryfmt, self.id, self.z, self.od, self.ad, self.cd, self.ra, self.rd, self.tc, self.aa, self.hoplimit, self.reserved,self.maxcn, self.mincn, self.qtype, self.qnlen,
			self.namebuf).bytes
		return qbuf
	
	def parse_query(self, qbuf) -> int:
		query = bitstring.BitStream(qbuf)
		if sys.byteorder.capitalize() == "Little_unset":
			self.id, self.aa, self.tc, self.rd, self.ra, self.cd, self.ad, self.od, self.z, self.reserved, self.hoplimit,self.mincn, self.maxcn, self.qtype, self.qnlen, self.namebuf = query.unpack(queryfmt)
		else:
			self.id, self.z, self.od, self.ad, self.cd, self.ra, self.rd, self.tc, self.aa, self.hoplimit, self.reserved,self.maxcn, self.mincn, self.qtype, self.qnlen,
			self.namebuf = query.unpack(queryfmt)
		return self.fixHeadersize + self.qnlen
	
	
class hiDNSAnswer():
	fixHeadersize = 10
	def __init__(self, rcode=0, prefix:str="", qtype=0, hoplimit=3, id=-1, aa=0, tc=0, ra=0, ad=0):
		self.id = id
		self.z = 0
		self.od = 0
		self.ad = ad
		self.cd = 0
		self.ra = ra
		self.rd = 0
		self.tc = tc
		self.aa = aa
		self.hoplimit = hoplimit
		self.reserved = 0
		self.exacn = prefix.count('/') - 1
		self.rcode = rcode
		self.exaplen = len(prefix)
		self.qtype = qtype
		self.ancount = 0
		self.prefixbuf = prefix.encode()
		self.answerlist = []
		self._ansbuflist = []	

	def make_answer(self) -> bytes:
		if self.ancount != len(self.answerlist):
			self.ancount = len(self.answerlist)
			print("warning: wrong ancount.")
		if self.id < 0 or self.id > 2147483647:
			self.id = randint(0, 2147483647)
		
		bodybuf = self.prefixbuf
		for entry in self.answerlist:
			bodybuf += entry.make_aentry()

		if sys.byteorder.capitalize() == "Little_unset":
			abuf = bitstring.pack(answerfmt, self.id,  self.aa, self.tc, self.rd, self.ra, self.cd, self.ad, self.od, self.z, self.reserved, self.hoplimit, self.rcode,self.exacn, self.exaplen, self.qtype, self.ancount, bodybuf)
		else:
			abuf = bitstring.pack(answerfmt, self.id, self.z, self.od, self.ad, self.cd, self.ra, self.rd, self.tc, self.aa, self.hoplimit, self.reserved, self.exacn, self.rcode, self.exaplen, self.qtype, self.ancount, bodybuf)
		return abuf

	def parse_answer(self, abuf):
		answer = bitstring.BitStream(abuf)
		if sys.byteorder.capitalize() == "Little_unset":
			self.id,  self.aa, self.tc, self.rd, self.ra, self.cd, self.ad, self.od, self.z, self.reserved, self.hoplimit, self.rcode,self.exacn, self.exaplen, self.qtype, self.ancount, bodybuf = answer.unpack(answerfmt)
		else:
			self.id, self.z, self.od, self.ad, self.cd, self.ra, self.rd, self.tc, self.aa, self.hoplimit, self.reserved, self.exacn, self.rcode, self.exaplen, self.qtype, self.ancount, bodybuf = answer.unpack(answerfmt)
		
		self.prefixbuf = bodybuf[:self.exaplen]
		self.answerlist.clear()

		alistbuf = bodybuf[self.exaplen:]
		pos = 0
		bound = len(alistbuf)
		# print(alistbuf)
		for i in range(self.ancount):
			# print("pos=%d"%pos)
			if pos >= bound:
				break
			aentry = hiDNSAnswerEntry()
			length = aentry.parse_aentry(alistbuf[pos:])
			self.answerlist.append(aentry)
			if aentry.type == self.qtype:
				# print("type=%d, length=%d, value=%s" % (aentry.type, aentry.length, aentry.value))
				self._ansbuflist.append(alistbuf[pos:pos+length])
			pos += length

		return self.fixHeadersize + pos
	
	def sort_and_dump_tbs(self) -> bytes:
		buf = b''
		self._ansbuflist.sort()
		for item in self._ansbuflist:
			buf += item
		buf += self.prefixbuf
		return buf

# ====== for cert =======
certvalfmt = '2*uint:16, uint:8, bytes'
algomap = {5:'SHA1RSA', 8: 'SHA256RSA', 15: 'ED25519'}
class hiDNSCert():
	fixHeadersize = 5
	def __init__(self, value:bytes=b''):
		self.type = 0
		self.keytag = 0
		self.algo = 0
		self.value = value

	def make_cert(self) -> bytes:
		cert = bitstring.pack(certvalfmt, self.type, self.keytag, self.algo, self.value)
		return cert.bytes

	def parse_cert(self, buf) -> int:
		cert = bitstring.BitStream(buf)
		self.type, self.keytag, self.algo, self.value = cert.unpack(certvalfmt)
		return len(buf)
	
	def get_algo(self) -> str:
		return algomap.get(self.algo)

# ====== for signature =======
hsigvalfmt = 'uint:16, uint:8, 2*uint:32, uint:8, uint:16, bytes'
class hiDNSHsig():
	fixHeadersize = 14
	def __init__(self, sigkeytag:int=1, algorithm:int=15, expirtime:int=0, inceptime:int=0, signer:bytes=b'', signature:bytes=b''):
		self.sigkeytag = sigkeytag
		self.algorithm = algorithm
		self.expirtime = expirtime
		self.inceptime = inceptime
		self.signerlen = len(signer)
		self.sigbuflen = len(signature)
		self.signerbuf = signer
		self.signature = signature

	def make_hsig(self) -> bytes:
		hsig = bitstring.pack(hsigvalfmt, self.sigkeytag, self.algorithm, self.expirtime, self.inceptime, self.signerlen, self.sigbuflen, self.signerbuf + self.signature)
		return hsig.bytes

	def parse_hsig(self, buf) -> int:
		hsig = bitstring.BitStream(buf)
		self.sigkeytag, self.algorithm, self.expirtime, self.inceptime, self.signerlen, self.sigbuflen, remains = hsig.unpack(hsigvalfmt)
		if len(remains) != self.signerlen + self.sigbuflen:
			print("parse hsig error")
			return 0
		self.signerbuf = remains[:self.signerlen]
		self.signature = remains[self.signerlen:]
		return len(buf)
