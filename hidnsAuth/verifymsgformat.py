import bitstring
from random import randint

# ======= start verify request message format defination ========
# request header: [request id, version, protocol, options, request body: [arg0, arg1...]]
reqheadfmt = 'uint:16, uint:4, uint:4, uint:8, bytes'
# request arg in body: [type, length, value]
reqargfmt = 'uint:8, uint:16, bytes'
# version -- only 0 for experiment
REQ_VERSION_V0 = 0
# protocol -- message verify protocol / certificate verify protocol / command verify protocol
REQ_PROTOCOL_MSG = 0
REQ_PROTOCOL_CERT = 1
REQ_PROTOCOL_CMD = 2
# options -- configure the secure strategy of the validator. only NONE for experiment
REQ_OPTIONS_NONE = 0
# type -- to-be-signed message / certificate / signer / signature
REQ_ARGTYPE_UNDEF = -1
REQ_ARGTYPE_TBS = 0
REQ_ARGTYPE_CERT_PEM = 1
REQ_ARGTYPE_CERT_DER = 2
REQ_ARGTYPE_CERT_DERB64 = 3
REQ_ARGTYPE_SIGNER_PREFIX = 11
REQ_ARGTYPE_SIGNER_CERTURL = 12
REQ_ARGTYPE_SIG_ED25519 = 21
REQ_ARGTYPE_SIG_SHA1RSA = 22
REQ_ARGTYPE_SIG_SHA224RSA = 23
REQ_ARGTYPE_SIG_SHA256RSA = 24
REQ_ARGTYPE_SIG_SHA384RSA = 25

# message verify protocol: verify a signed message. The body should include to-be-signed message, signer and signature.
# certificate verify protocol: verify a certificate. The body should include certificate.
# command verify protocol: verify a signed command. The body should include to-be-signed message, certificate and signature.

# ======= end verify request message format defination ========

# ======= start verify reply message format defination ========
# reply header: [reply id, version, protocol, reply code, body: [arg0, arg1...]]
replyheadfmt = 'uint:16, uint:4, uint:4, uint:8, bytes'
# reply args in body: [type, length, value]
replybodyfmt = reqargfmt
# version -- the same as which in request
REPLY_VERSION_V0 = REQ_VERSION_V0
# protocol -- the same as which in request
REPLY_PROTOCOL_MSG = REQ_PROTOCOL_MSG
REPLY_PROTOCOL_CERT = REQ_PROTOCOL_CERT
REPLY_PROTOCOL_CMD = REQ_PROTOCOL_CMD
# reply code -- ok or the error reason
REPLY_RCODE_OK = 0
REPLY_RCODE_MSG_MALFORMED = 1
REPLY_RCODE_MSG_INVALIDSIG = 2
REPLY_RCODE_MSG_INVALIDCERT = 3
REPLY_RCODE_CERT_NOTFOUND = 4
REPLY_RCODE_CERT_INVALID = 5
# type -- only chain breakpoint for experiment
REPLY_ARGTYPE_CHAINBREAKPOINT = 0

# chain breakpoint: the point that can't be verified in the trust chain.
# example: (type=chain breakpoint, value='/dummy/ca1/') means the issuer /dummy/ca1/ can't be verified.

# ======= end verify reply message format defination ========


class VerifyTLV():
	fixHeadersize = 3
	def __init__(self, type=REQ_ARGTYPE_UNDEF, length=0, value: bytes=b''):
		self.type = type
		self.length = length
		self.value = value
	
	def make_tlv(self) -> bytes:
		tlv = bitstring.pack(reqargfmt, self.type, self.length, self.value)
		return tlv.bytes

	def parse_tlv(self, buf) -> int:
		tlv = bitstring.BitStream(buf)
		self.type, self.length, remain = tlv.unpack(reqargfmt)
		self.value = remain[:self.length]
		return self.fixHeadersize + self.length


class VerifyRequest():
	fixHeadersize = 5
	def __init__(self, id=-1, version=REQ_VERSION_V0, protocol=REQ_PROTOCOL_MSG, options=REQ_OPTIONS_NONE):
		self.id = id
		self.version = version
		self.protocol = protocol
		self.options = options
		self.body = []

		self._tbs = b''
		self._signer = b''
		self._sig = b''
		self._hashalgo = None
		self._cert = b''
		self._certformat = REQ_ARGTYPE_UNDEF
	
	def add_arg(self, type, value: bytes) -> None:
		self.body.append(VerifyTLV(type, len(value), value))

	def add_data_tbs(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_TBS, value)
	
	def add_pem_certificate(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_CERT_PEM, value)
	
	def add_der_certificate(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_CERT_DER, value)
	
	def add_derb64_certificate(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_CERT_DERB64, value)
	
	def add_signer_prefix(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_SIGNER_PREFIX, value)
	
	def add_signer_certurl(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_SIGNER_CERTURL, value)
	
	def add_signature_ed25519(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_SIG_ED25519, value)
	
	def add_signature_SHA1RSA(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_SIG_SHA1RSA, value)
	
	def add_signature_SHA224RSA(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_SIG_SHA224RSA, value)
	
	def add_signature_SHA256RSA(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_SIG_SHA256RSA, value)

	def add_signature_SHA384RSA(self, value: bytes) -> None:
		self.add_arg(REQ_ARGTYPE_SIG_SHA384RSA, value)
	
	def make_request(self) -> bytes:
		if self.id < 0 or self.id > 65535:
			self.id = randint(0, 65535)
		
		body = b''
		for arg in self.body:
			body += arg.make_tlv()
		req = bitstring.pack(reqheadfmt, self.id, self.version, self.protocol, self.options, body).bytes	
		return req

	def parse_request(self, buf) -> int:
		req = bitstring.BitStream(buf)
		self.id, self.version, self.protocol, self.options, body= req.unpack(reqheadfmt)
		self.body.clear()
		pos = 0
		bound = len(body)
		while pos < bound:
			arg = VerifyTLV()
			pos += arg.parse_tlv(body[pos:])
			# print("type=%d, length=%d, value=%s" % (arg.type, arg.length, arg.value))
			self.body.append(arg)
		return self.fixHeadersize + pos


class VerifyReply():
	fixHeadersize = 4
	def __init__(self, req: VerifyRequest=None, rcode=REPLY_RCODE_OK, chainbreakpoint=''):
		if req == None:
			self.id = -1
			self.version = REPLY_VERSION_V0
			self.protocol = REPLY_PROTOCOL_MSG
		else:
			self.id = req.id
			self.version = req.version
			self.protocol = req.protocol
		self.rcode = rcode
		self.body = []
		if len(chainbreakpoint) > 0:
			if isinstance(chainbreakpoint, str):
				self.body.append(VerifyTLV(REPLY_ARGTYPE_CHAINBREAKPOINT, len(chainbreakpoint), chainbreakpoint.encode()))
			elif isinstance(chainbreakpoint, bytes):
				self.body.append(VerifyTLV(REPLY_ARGTYPE_CHAINBREAKPOINT, len(chainbreakpoint), chainbreakpoint))
	
	def make_reply(self):
		if self.id < 0 or self.id > 65535:
			self.id = randint(0, 65535)
		body = b''
		for arg in self.body:
			body += arg.make_tlv()
		reply = bitstring.pack(replyheadfmt, self.id, self.version, self.protocol, self.rcode, body).bytes	
		return reply
	
	def parse_reply(self, buf):
		reply = bitstring.BitStream(buf)
		self.id, self.version, self.protocol, self.rcode, body= reply.unpack(replyheadfmt)
		self.body.clear()
		pos = 0
		bound = len(body)
		while pos < bound:
			arg = VerifyTLV()
			pos += arg.parse_tlv(body[pos:])
			self.body.append(arg)
		return self.fixHeadersize + bound
