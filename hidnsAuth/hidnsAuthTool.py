# encoding=utf-8
import argparse
from certsign import certsign
from csrgen import csrgen
from keygen import keygen
from fmttrans import key_pem_to_der, key_pem_to_derb64, cert_pem_to_der, cert_pem_to_derb64
args = {}

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-g","--generate-keypair", help="generate a key pair.", action="store_true")
	parser.add_argument("-r", "--create-csr", help="create a csr",  action="store_true")
	parser.add_argument("-i", "--issue-cert", help="issue a csr", action="store_true")
	parser.add_argument("-pem2der","--pem-to-der", help="key or cert format transform.", action="store_true")
	parser.add_argument("-pem2derb64","--pem-to-der-b64", help="key or cert format transform.", action="store_true")
	parser.add_argument("-csr", "--csr", help="location of pem csr", type=str, default="")
	parser.add_argument("-key", "--key", help="location of pem key", type=str, default="")
	parser.add_argument("-cert", "--certificate", help="location of pem certificate", type=str, default="")
	parser.add_argument("-outputdir", "--output-directory", help="output directory", type=str, default="./")
	parser.add_argument("-outputfile", "--output-file", help="output file", type=str)
	parser.add_argument("-keyalgo", "--keypair-algorithm", help="Only for keygen. Either secp384r1, ed25519 or rsa is accepted.", type=str, default="secp384r1")
	parser.add_argument("-digestalgo", "--digest-algorithm", help="Only for rsa keypair. Either sha1, sha224, sha256 or sha384 is accepted.", type=str, default=None)
	return parser.parse_args().__dict__

if __name__ == "__main__":
	args = parse_args()
	if args['generate_keypair'] == True:
		keygen(args['output_directory'], args['keypair_algorithm'])
	elif args['create_csr'] == True:
		csrgen(args['key'], args['output_directory'], args['digest_algorithm'])
	elif args['issue_cert'] == True:
		certsign(args['key'], args['csr'], args['output_directory'], args['digest_algorithm'])
	elif args['pem_to_der'] == True:
		if len(args['key']) != 0 and len(args['certificate']) == 0:
			key_pem_to_der(args['key'], args['output_file'])
		elif len(args['key']) == 0 and len(args['certificate']) != 0:
			cert_pem_to_der(args['certificate'], args['output_file'])
	elif args['pem_to_der_b64'] == True:
		if len(args['key']) != 0 and len(args['certificate']) == 0:
			key_pem_to_derb64(args['key'], args['output_file'])
		elif len(args['key']) == 0 and len(args['certificate']) != 0:
			cert_pem_to_derb64(args['certificate'], args['output_file'])
	else:
		print("-h to get some help")
