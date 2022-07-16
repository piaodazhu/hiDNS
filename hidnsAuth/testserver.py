import verifymsgformat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
import socket

LOCAL_SERVICE_ADDR = ('127.0.0.1', 5551)
sock = socket.socket(type = socket.SOCK_DGRAM)

# cert verify protocol
# request = verifymsgformat.VerifyRequest(protocol=verifymsgformat.REQ_PROTOCOL_CERT)
# with open('icn_bit/cert.pem', 'rb') as f:
# 	rawcert = f.read()
# request.add_pem_certificate(rawcert)
# sock.sendto(request.make_request(), LOCAL_SERVICE_ADDR)

# reply = verifymsgformat.VerifyReply()
# reply.parse_reply(sock.recv(2048))
# print(reply.rcode)

# msg verify protocol 
request = verifymsgformat.VerifyRequest(protocol=verifymsgformat.REQ_PROTOCOL_MSG)
with open('testmsg/msg', 'rb') as f:
	request.add_data_tbs(f.read())
with open('testmsg/signature', 'rb') as f:
	request.add_signature_ed25519(f.read())
request.add_signer_prefix(b'/icn/bit/')

sock.sendto(request.make_request(), LOCAL_SERVICE_ADDR)

reply = verifymsgformat.VerifyReply()
reply.parse_reply(sock.recv(2048))
print(reply.rcode)


# with open('cert.pem', 'rb') as f:
# 	rawcert = f.read()
# 	cert = load_pem_x509_certificate(rawcert)

# with open('private.key', 'rb') as f:
# 	key = load_pem_private_key(f.read(), b'hello')

# msg = b'1' * 64 + rawcert
# sig = key.sign(
# 	msg,
# 	padding.PSS(
# 		mgf=padding.MGF1(hashes.SHA256()),
# 		salt_length=padding.PSS.MAX_LENGTH
# 	),
# 	hashes.SHA256()
# )
# # print(len(sig))
# # cert.public_key().verify(
# # 	sig,
# # 	msg,
# # 	padding.PSS(
# # 		mgf=padding.MGF1(hashes.SHA256()),
# # 		salt_length=padding.PSS.MAX_LENGTH
# # 	),
# # 	hashes.SHA256()
# # )
# buf = msg + sig
# sock = socket.socket(type = socket.SOCK_DGRAM)
# sock.sendto(buf, ('127.0.0.1', 5551))

# buf, cli = sock.recvfrom(2048)
# reply = verifymsgformat.VerifyReply()
# len = reply.parse_reply(buf)
# print(len)
# print(reply.rcode)
# print(reply.plen)
# print(reply.prefix)