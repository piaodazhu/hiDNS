from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from base64 import b64decode, b64encode

def _load_pem_key_to_der(source:str) -> bytes:
	try:
		with open(source, 'rb') as f:
			buf = f.read()
	except:
		print("source %s not found." % source)
		return b''
	
	try:
		key = load_pem_private_key(buf, password=None)
		buf = key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
	except:
		try:
			key = load_pem_public_key(buf)
			buf = key.public_bytes(encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
		except:
			print("invalid source: %s." % source)
			b''
	return buf

def _load_pem_cert_to_der(source:str) -> bytes:
	try:
		with open(source, 'rb') as f:
			buf = f.read()
	except:
		print("source %s not found." % source)
		return b''
	
	try:
		cert = load_pem_x509_certificate(buf)
		buf = cert.public_bytes(encoding=serialization.Encoding.DER)
	except:
		print("invalid source: %s." % source)
		return b''
	return buf

def key_pem_to_der(source='./key.pem', target='./key.der'):
	buf = _load_pem_key_to_der(source)
	if len(buf) != 0:
		try:
			with open(target, 'wb') as f:
				f.write(buf)
		except:
			print("invalid target.")
			return

def key_pem_to_derb64(source='./key.pem', target='./key.derb64'):
	buf = _load_pem_key_to_der(source)
	if len(buf) != 0:
		try:
			with open(target, 'wb') as f:
				f.write(b64encode(buf))
		except:
			print("invalid target.")
			return

def cert_pem_to_der(source='./cert.pem', target='./cert.der'):
	buf = _load_pem_cert_to_der(source)
	if len(buf) != 0:
		try:
			with open(target, 'wb') as f:
				f.write(buf)
		except:
			print("invalid target.")
			return

def cert_pem_to_derb64(source='./cert.pem', target='./cert.derb64'):
	buf = _load_pem_cert_to_der(source)
	if len(buf) != 0:
		try:
			with open(target, 'wb') as f:
				f.write(b64encode(buf))
		except:
			print("invalid target.")
			return

if __name__ == '__main__':
	key_pem_to_der('./icn/private.key', './icn/private.der')