import selectors
import socket
import time
from base64 import b64decode, b64encode
import hidnsmsgformat
import verifymsgformat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ed25519,ec

# a signature validator with Trust Chain walking
# Input: a verify request
# Output: a verify reply

VT_STATE_INIT = 0
VT_STATE_PROC = 0
VT_STATE_DONE = 0

HIDNS_SERVER_ADDR = ('127.0.0.1', 5553)
LOCAL_SERVICE_ADDR = ('127.0.0.1', 5551)
HOD_PROXY_ADDR = ('127.0.0.1', 5556)


Hidns_Over_DTLS = False
def send_hidns_query(sock:socket.socket, query:hidnsmsgformat.hiDNSQuery):
    if Hidns_Over_DTLS == True:
        query.od = 1
        # print("send (%s)", query.make_query_hod(HIDNS_SERVER_ADDR))
        sock.sendto(query.make_query_hod(HIDNS_SERVER_ADDR), HOD_PROXY_ADDR)
    else:
        sock.sendto(query.make_query(), HIDNS_SERVER_ADDR)


class ValidatorTaskCTX():
    def __init__(self, request:verifymsgformat.VerifyRequest, clientfd, cliaddr, sockfd, lifetime=1) -> None:
        self.request = request
        self.clientfd = clientfd
        self.socketfd = sockfd
        self.cliaddr = cliaddr
        self.taskstate = VT_STATE_INIT
        self.expiretime = time.time() + lifetime
        # self.currentcert = b''
        self.nextissuer = b''
        self.certchain = []
    
    def savecerts(self):
        for cert in self.certchain:
            certstorage[cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value] = cert

class CertStorage(dict):
    def __init__(self):
        self.dirty = False
        super().__init__()
    
    def __setitem__(self, __k: str, __v: x509.Certificate) -> None:
        self.dirty = True
        return super().__setitem__(__k, __v)
    
    def pop(self, __k: str):
        if __k not in super().keys():
            return None
        self.dirty = True
        return super().pop(__k)
    
    def dump(self, dumpfilename: str):
        buf = b''
        for prefix, cert in super().items():
            buf += prefix.encode()
            buf += b'\n'
            buf += cert.public_bytes(Encoding.PEM).replace(b'\r\n', b'').replace(b'\n', b'')
            buf += b'\n'
        with open(dumpfilename, 'wb') as f:
            f.write(buf)
            self.dirty = False

    def load(self, loadfilename: str):
        # super().clear()
        try:
            with open(loadfilename, 'rb') as f:
                buf = f.read().splitlines()

            i = 0
            while i < len(buf):
                k = buf[i].decode()
                v = load_pem_x509_certificate(buf[i + 1])
                self.__setitem__(k, v)
                i += 2
        except:
            print("%s not load." % loadfilename)

        self.dirty = False

rootkey = None
ctxmap = {}
sel = selectors.DefaultSelector()
certstorage = CertStorage()

def verifycert(public_key, cert_to_check):
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes
            )
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                    cert_to_check.signature,
                    cert_to_check.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert_to_check.signature_hash_algorithm
                )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
                ec.ECDSA(cert_to_check.signature_hash_algorithm)
            )
        else:
            return False
        return True
    except:
        return False

def verifymsg(public_key, sig_to_check, msg_to_check, hash_algo=None):
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(
                sig_to_check,
                msg_to_check
            )
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                    sig_to_check,
                    msg_to_check,
                    padding.PSS(
                        mgf=padding.MGF1(hash_algo),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_algo
                )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                sig_to_check,
                msg_to_check,
                hash_algo
            )
        else:
            return False
        return True
    except:
        return False

def msgverifytask(request:verifymsgformat.VerifyRequest, sock: socket.socket, clientaddr) -> bool:
    # fetch cert, then it verify the message, then verify the certchain
    for arg in request.body:
        if arg.type == verifymsgformat.REQ_ARGTYPE_TBS:
            request._tbs = arg.value
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIGNER_PREFIX: # TBD: URL
            request._signer = arg.value
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_ED25519:
            request._sig = arg.value
            request._hashalgo = None
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA1RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA1()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA224RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA224()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA256RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA256()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA384RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA384()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA256SECP256R1:
            request._sig = arg.value
            request._hashalgo = ec.ECDSA(hashes.SHA256()) 
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA384SECP384R1:
            request._sig = arg.value
            request._hashalgo = ec.ECDSA(hashes.SHA384())
    
    if len(request._tbs) == 0 or len(request._signer) == 0 or len(request._sig) == 0:
        return False
    
    # check done, fetch the signer's certificate
    # before that, check if the signer is root
    # print("[TAG] M-1")
    # print(request._tbs)
    signerprefix = request._signer.decode()
    keyfound = False
    if signerprefix == '/':
        keyfound = True
        signerkey = rootkey
    elif signerprefix in certstorage:
        print("hit ", signerprefix)
        keyfound = True
        signerkey = certstorage[signerprefix].public_key()
    
    if keyfound == True:
        # error point
        if verifymsg(signerkey, request._sig, request._tbs, request._hashalgo):
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_MSG_INVALIDSIG
        reply = verifymsgformat.VerifyReply(request, rcode)
        sock.sendto(reply.make_reply(), clientaddr)
        return True
    # print("[TAG] M-2")
    # need fetch issuer's cert
    newsockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    newsockfd.setblocking(False)
    
    newctx = ValidatorTaskCTX(request, sock, clientaddr, newsockfd)
    newctx.taskstate = VT_STATE_PROC
    # newctx.currentcert = cert
    newctx.nextissuer = signerprefix
 
    ctxmap[newsockfd] = newctx
    sel.register(newsockfd, selectors.EVENT_READ, readcertfromhidns)
    
    query = hidnsmsgformat.hiDNSQuery(signerprefix, 
        signerprefix.count('/') - 1,
        signerprefix.count('/') - 1, 
        hidnsmsgformat.RR_TYPE_CERT)
    # newsockfd.sendto(query.make_query(), HIDNS_SERVER_ADDR)
    send_hidns_query(newsockfd, query)
    return True

def certverifytask(request:verifymsgformat.VerifyRequest, sock: socket.socket, clientaddr) -> bool:
    # verify the cert chain
    for arg in request.body:
        if arg.type == verifymsgformat.REQ_ARGTYPE_CERT_DERB64:
            request._cert = arg.value
            request._certformat = verifymsgformat.REQ_ARGTYPE_CERT_DERB64
        elif arg.type == verifymsgformat.REQ_ARGTYPE_CERT_PEM:
            request._cert = arg.value
            request._certformat = verifymsgformat.REQ_ARGTYPE_CERT_PEM
        elif arg.type == verifymsgformat.REQ_ARGTYPE_CERT_DER:
            request._cert = arg.value
            request._certformat = verifymsgformat.REQ_ARGTYPE_CERT_DER
    
    if len(request._cert) == 0:
        return False
    
    # check done, load the signer's certificate
    # print("[TAG] C-1")
    try:
        if request._certformat == verifymsgformat.REQ_ARGTYPE_CERT_PEM:
            cert = load_pem_x509_certificate(request._cert)
        elif request._certformat == verifymsgformat.REQ_ARGTYPE_CERT_DERB64:
            cert = load_der_x509_certificate(b64decode(request._cert.decode()))
        else:
            cert = load_der_x509_certificate(request._cert)
    except:
        # print("[TAG] C-2")
        reply = verifymsgformat.VerifyReply(request, verifymsgformat.REPLY_RCODE_CERT_INVALID)
        sock.sendto(reply.make_reply(), clientaddr)
        return True
    # check sbj. some checks are omitted
    # suppose only one subject
    subjectprefix = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    # suppose only one issuer
    issuerprefix = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value 
    
    # need fetch next cert?
    if subjectprefix in certstorage:
        print("hit ", subjectprefix)
        # print(certstorage[issuerprefix].public_bytes(encoding=serialization.Encoding.PEM))
        # print(cert.public_bytes(encoding=serialization.Encoding.PEM))
        if certstorage[subjectprefix].public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo) == cert.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo):
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(request, rcode)
        sock.sendto(reply.make_reply(), clientaddr)
        return True
    
    # print("[TAG] C-3")
    # root? self-signed? avoid loop
    if subjectprefix.startswith(issuerprefix) == False:
        # failed
        reply = verifymsgformat.VerifyReply(request, verifymsgformat.REPLY_RCODE_CERT_INVALID)
        sock.sendto(reply.make_reply(), clientaddr)
        return True

    if issuerprefix == '/':
        if verifycert(rootkey, cert):
            certstorage[subjectprefix] = cert
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(request, rcode)
        sock.sendto(reply.make_reply(), clientaddr)
        return True

    if len(subjectprefix) == len(issuerprefix):
        # failed
        reply = verifymsgformat.VerifyReply(request, verifymsgformat.REPLY_RCODE_CERT_INVALID)
        sock.sendto(reply.make_reply(), clientaddr)
        return True
    
    # need fetch next cert?
    if issuerprefix in certstorage:
        print("hit ", issuerprefix)
        if verifycert(certstorage[issuerprefix].public_key(), cert):
            certstorage[subjectprefix] = cert
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(request, rcode)
        sock.sendto(reply.make_reply(), clientaddr)
        return True
    # print("[TAG] C-4")
    # print(rootkey)
    # newctx.currentcert = cert
    # need fetch issuer's cert
    newsockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    newsockfd.setblocking(False)
    
    newctx = ValidatorTaskCTX(request, sock, clientaddr, newsockfd)
    newctx.taskstate = VT_STATE_PROC
    newctx.nextissuer = issuerprefix
    newctx.certchain.append(cert)
 
    ctxmap[newsockfd] = newctx
    sel.register(newsockfd, selectors.EVENT_READ, readresponse)
    
    query = hidnsmsgformat.hiDNSQuery(issuerprefix, 
        issuerprefix.count('/') - 1,
        issuerprefix.count('/') - 1, 
        hidnsmsgformat.RR_TYPE_CERT)
    # newsockfd.sendto(query.make_query(), HIDNS_SERVER_ADDR)
    send_hidns_query(newsockfd, query)
    return True

def cmdverifytask(request:verifymsgformat.VerifyRequest, sock: socket.socket, clientaddr) -> bool:
    # verify the command signature, then verify the cert chain
    for arg in request.body:
        if arg.type == verifymsgformat.REQ_ARGTYPE_TBS:
            request._tbs = arg.value
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIGNER_PREFIX: # TBD: URL
            request._signer = arg.value
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_ED25519:
            request._sig = arg.value
            request._hashalgo = None
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA1RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA1()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA224RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA224()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA256RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA256()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA384RSA:
            request._sig = arg.value
            request._hashalgo = hashes.SHA384()
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA256SECP256R1:
            request._sig = arg.value
            request._hashalgo = ec.ECDSA(hashes.SHA256()) 
        elif arg.type == verifymsgformat.REQ_ARGTYPE_SIG_SHA384SECP384R1:
            request._sig = arg.value
            request._hashalgo = ec.ECDSA(hashes.SHA384())
        elif arg.type == verifymsgformat.REQ_ARGTYPE_CERT_DERB64:
            request._cert = arg.value
            request._certformat = verifymsgformat.REQ_ARGTYPE_CERT_DERB64
        elif arg.type == verifymsgformat.REQ_ARGTYPE_CERT_PEM:
            request._cert = arg.value
            request._certformat = verifymsgformat.REQ_ARGTYPE_CERT_PEM
    
    if len(request._tbs) == 0 or len(request._signer) == 0 or len(request._sig) == 0 or len(request._cert) == 0:
        return False
    
    # check done, load the signer's certificate
    try:
        if request._certformat == verifymsgformat.REQ_ARGTYPE_CERT_PEM:
            cert = load_pem_x509_certificate(request._cert)
        elif request._certformat == verifymsgformat.REQ_ARGTYPE_CERT_DER:
            cert = load_der_x509_certificate(request._cert)
        else:
            cert = load_der_x509_certificate(b64decode(request._cert.decode()))
    except:
        reply = verifymsgformat.VerifyReply(request, verifymsgformat.REPLY_RCODE_CERT_INVALID, request._signer)
        sock.sendto(reply.make_reply(), clientaddr)
        return True

    if verifymsg(cert.public_key(), request._sig, request._tbs, request._hashalgo) == False:
        reply = verifymsgformat.VerifyReply(request, verifymsgformat.REPLY_RCODE_MSG_INVALIDSIG, request._signer)
        sock.sendto(reply.make_reply(), clientaddr)
        return True
    
    # check sbj. some checks are omitted
    # suppose only one subject
    subjectprefix = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    # suppose only one issuer
    issuerprefix = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value 
    if request._signer != subjectprefix:
        return False
    
    # root? self-signed? avoid loop
    if subjectprefix.startswith(issuerprefix) == False:
        # failed
        reply = verifymsgformat.VerifyReply(request, verifymsgformat.REPLY_RCODE_CERT_INVALID)
        sock.sendto(reply.make_reply(), clientaddr)
        return True

    if issuerprefix == '/':
        if verifycert(rootkey, cert):
            certstorage[subjectprefix] = cert
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(request, rcode)
        sock.sendto(reply.make_reply(), clientaddr)
        return True

    if len(subjectprefix) == len(issuerprefix):
        # failed
        reply = verifymsgformat.VerifyReply(request, verifymsgformat.REPLY_RCODE_CERT_INVALID)
        sock.sendto(reply.make_reply(), clientaddr)
        return True
    
    # need fetch next cert?
    if issuerprefix in certstorage:
        print("hit ", issuerprefix)
        if verifycert(certstorage[issuerprefix].public_key(), cert):
            certstorage[subjectprefix] = cert
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(request, rcode)
        sock.sendto(reply.make_reply(), clientaddr)
        return True

    # newctx.currentcert = cert
    # need fetch issuer's cert
    newsockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    newsockfd.setblocking(False)
    
    newctx = ValidatorTaskCTX(request, sock, clientaddr, newsockfd)
    newctx.taskstate = VT_STATE_PROC
    # newctx.currentcert = cert
    newctx.nextissuer = issuerprefix
    newctx.certchain.append(cert)
 
    ctxmap[newsockfd] = newctx
    sel.register(newsockfd, selectors.EVENT_READ, readresponse)
    
    query = hidnsmsgformat.hiDNSQuery(issuerprefix, 
        issuerprefix.count('/') - 1,
        issuerprefix.count('/') - 1, 
        hidnsmsgformat.RR_TYPE_CERT)
    # newsockfd.sendto(query.make_query(), HIDNS_SERVER_ADDR)
    send_hidns_query(newsockfd, query)
    return True

def accepttask(sock: socket.socket, mask):
    data, addr = sock.recvfrom(2048)
    # some check and paring here
    # suppose the whole packet is made of [ones(64) + cert(??) + and sig(32)]
    req = verifymsgformat.VerifyRequest()
    req.parse_request(data)
    extract_ok = False
    if req.protocol == verifymsgformat.REQ_PROTOCOL_MSG:
        # print("[INFO] receive a message verify task")
        extract_ok = msgverifytask(req, sock, addr)
    elif req.protocol == verifymsgformat.REQ_PROTOCOL_CERT:
        # print("[INFO] receive a certificate verify task")
        extract_ok = certverifytask(req, sock, addr)
    elif req.protocol == verifymsgformat.REQ_PROTOCOL_CMD:
        # print("[INFO] receive a command verify task")
        extract_ok = cmdverifytask(req, sock, addr)
    
    if extract_ok == False:
        print("[ERROR] task parsing failed!")
        reply = verifymsgformat.VerifyReply(req, verifymsgformat.REPLY_RCODE_MSG_MALFORMED)
        sock.sendto(reply.make_reply(), addr)
    
    return

def readcertfromhidns(sock: socket.socket, mask):
    ctx:ValidatorTaskCTX = ctxmap.get(sock)
    if ctx is None:
        print("ctx is lost")
        sel.unregister(sock)
        sock.close()
        return
    msg_to_be_verified = ctx.request._tbs
    sig_to_be_verified = ctx.request._sig
    # print("[TAG] M-3")
    data = sock.recv(2048)
    answer = hidnsmsgformat.hiDNSAnswer()
    answer.parse_answer(data)
    # get cert from the answer
    certobj = hidnsmsgformat.hiDNSCert()
    for ans in answer.answerlist:
        if ans.type == hidnsmsgformat.RR_TYPE_CERT:
            certobj.parse_cert(ans.value)
    if len(certobj.value) == 0:
        # No record or other problem
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_NOTFOUND, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
    # print("[TAG] M-4")
    # load cert from certobj
    try:
        cert = load_der_x509_certificate(certobj.value)
    except:
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return

    if verifymsg(cert.public_key(), sig_to_be_verified, msg_to_be_verified, ctx.request._hashalgo) == False:
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_MSG_INVALIDSIG, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return

    # check sbj. some checks are omitted
    # suppose only one subject
    subjectprefix = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    # suppose only one issuer
    issuerprefix = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value 
    # print("[TAG] M-5")
    # root? self-signed? avoid loop
    if subjectprefix.startswith(issuerprefix) == False:
        # failed
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        return

    if issuerprefix == '/':
        if verifycert(rootkey, cert):
            certstorage[subjectprefix] = cert
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(ctx.request, rcode)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        return

    if len(subjectprefix) == len(issuerprefix):
        # failed
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        return
    
    # need fetch next cert?
    if issuerprefix in certstorage:
        print("hit ", issuerprefix)
        if verifycert(certstorage[issuerprefix].public_key(), cert):
            certstorage[subjectprefix] = cert
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(ctx.request, rcode)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        return
    # print("[TAG] M-6")
    # newctx.currentcert = cert
    ctx.nextissuer = issuerprefix
    ctx.certchain.append(cert)
    
    sel.unregister(sock)
    sel.register(sock, selectors.EVENT_READ, readresponse)
    
    query = hidnsmsgformat.hiDNSQuery(issuerprefix, 
        issuerprefix.count('/') - 1,
        issuerprefix.count('/') - 1, 
        hidnsmsgformat.RR_TYPE_CERT)
    # sock.sendto(query.make_query(), HIDNS_SERVER_ADDR)
    send_hidns_query(sock, query)

def readresponse(sock: socket.socket, mask):
    ctx:ValidatorTaskCTX = ctxmap.get(sock)
    if ctx is None:
        print("ctx is lost")
        sel.unregister(sock)
        sock.close()
        return
    cert_to_be_verified = ctx.certchain[-1]

    data = sock.recv(2048)

    answer = hidnsmsgformat.hiDNSAnswer()
    answer.parse_answer(data)
    # get cert from the answer
    certobj = hidnsmsgformat.hiDNSCert()
    for ans in answer.answerlist:
        if ans.type == hidnsmsgformat.RR_TYPE_CERT:
            certobj.parse_cert(ans.value)
    if len(certobj.value) == 0:
        # No record or other problem
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_NOTFOUND, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
    # load cert from certobj
    # print("[TAG] R-1")
    try:
        cert = load_der_x509_certificate(certobj.value)
    except:
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
    
    public_key = cert.public_key()

    # suppose only one subject
    subjectprefix = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    # suppose only one issuer
    issuerprefix = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    if subjectprefix != ctx.nextissuer:
        # not compatible
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
    # print("[TAG] R-2")
    # root? self-signed? avoid loop
    if subjectprefix.startswith(issuerprefix) == False:
        # failed
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
    
    if verifycert(public_key, cert_to_be_verified) == False:
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return

    if issuerprefix == '/':
        if verifycert(rootkey, cert):
            ctx.certchain.append(cert)
            ctx.savecerts()
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(ctx.request, rcode)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
    
    if len(subjectprefix) == len(issuerprefix):
        # failed
        reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_INVALID, ctx.nextissuer)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
 
    if issuerprefix in certstorage:
        print("hit ", issuerprefix)
        if verifycert(certstorage[issuerprefix].public_key(), cert):
            rcode = verifymsgformat.REPLY_RCODE_OK
        else:
            rcode = verifymsgformat.REPLY_RCODE_CERT_INVALID
        reply = verifymsgformat.VerifyReply(ctx.request, rcode)
        ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
        ctxmap.pop(sock)
        sel.unregister(sock)
        sock.close()
        return
    # print("[TAG] R-4")
    # towards upper level
    ctx.nextissuer = issuerprefix
    ctx.certchain.append(cert)
    # next query
    query = hidnsmsgformat.hiDNSQuery(issuerprefix, 
        issuerprefix.count('/') - 1,
        issuerprefix.count('/') - 1, 
        hidnsmsgformat.RR_TYPE_CERT)
    # sock.sendto(query.make_query(), HIDNS_SERVER_ADDR)
    send_hidns_query(sock, query)

def cleanctxmap():
    curtime = time.time()
    for fd, ctx in list(ctxmap.items()):
        if curtime > ctx.expiretime:
            print('fd timeout')
            reply = verifymsgformat.VerifyReply(ctx.request, verifymsgformat.REPLY_RCODE_CERT_NOTFOUND, ctx.nextissuer)
            ctx.clientfd.sendto(reply.make_reply(), ctx.cliaddr)
            ctxmap.pop(fd)
            sel.unregister(sock)
            fd.close()


if __name__ == "__main__":

    try:
        with open('./trustanchor/public.key', 'rb') as f:
            rootkey = load_pem_public_key(f.read())
    except:
        print("rootkey not found!")
        exit()

    try:
        with open('./dns/cert.pem', 'rb') as f:
            dnscacert = load_pem_x509_certificate(f.read())
    except:
        print("dnscacert not found!")
        exit()
    
    certstorage[dnscacert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value] = dnscacert

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(LOCAL_SERVICE_ADDR)
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ, accepttask)
   
    certstorage.load('./certstorage.txt')

    while True:
        events = sel.select(10)
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)
        
        if len(ctxmap) > 1000 or len(events) == 0:
            cleanctxmap()

        if certstorage.dirty:
            certstorage.dump('./certstorage.txt')