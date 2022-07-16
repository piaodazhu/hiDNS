```bash
# generate key-pair
$ python3 hidnsAuthTool.py -g -o lab101_dir/
$ ls lab101_dir/
private.key  public.key

# create certificate signing request
$python3 hidnsAuthTool.py -r -k lab101_dir/private.key -o ./
please input private key access password:
please input private key access password again:
your prefix [IMPORTANT]: /icn/bit/lab101/
2 character country code: CN
state or province name: beijing
locality name: beijing
organization name: BIT
email address: 
is above all right? y or n: y
CSR create succeed:
<Name(C=CN,ST=beijing,L=beijing,O=BIT,1.2.840.113549.1.9.1=,CN=/icn/bit/lab101/)>

# sign a certificate
$ python3 hidnsAuthTool.py -i -k bit_dir/private.key -c csr.pem -o ./
please input private key access password:
please input private key access password again:
The certificate signing request subject information is below:
<Name(C=CN,ST=beijing,L=beijing,O=BIT,1.2.840.113549.1.9.1=,CN=/icn/bit/lab101/)>
Are you sure to issue a certificate? y or n: y
issuer prefix [IMPORTANT]: /bit/icn/
organization name: BIT
email address: 
is above all right? y or n: y
certificate signing succeed:
<Name(O=BIT,1.2.840.113549.1.9.1=,CN=/bit/icn/)>
<Name(C=CN,ST=beijing,L=beijing,O=BIT,1.2.840.113549.1.9.1=,CN=/icn/bit/lab101/)>

# verifier
$ python3 hidnsVerify.py 
[+] Extracting certificate from message...
[+] Verifying signature of the message...
[+] Verifying certificate of /icn/bit/lab101/, signed by /icn/bit/
[+] Fetching certificate of /icn/bit/
[+] Receiving certificate of /icn/bit/, signed by /
[+] Verifying certificate of /icn/bit/ with trusted root key...
[+] Verifier return OK.

# test request
$ python3 testserver.py 
[+] Sending message to be verified...
[+] Receiving response...
[+] Response message:
[+] length =  2
[+] rcode =  0
[+] unauth plen =  0
[+] unauth prefix =  
```