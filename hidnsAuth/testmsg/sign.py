from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

with open('msg', 'rb') as f:
	tbs = f.read()

with open('../icn_bit/private.key', 'rb') as f:
	key = load_pem_private_key(f.read(), password=None)

with open('signature', 'wb') as f:
	sig = key.sign(tbs)
	f.write(sig)

with open('../icn_bit/public.key', 'rb') as f:
	pub = load_pem_public_key(f.read())

pub.verify(sig, tbs)