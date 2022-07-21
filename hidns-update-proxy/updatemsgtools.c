#include "updatemsgtools.h"

userkeypair *keypairhead;
int 
load_userkeypair(const char* keyfilename, const char* certfilename,
	unsigned short keytag, unsigned char algorithm, 
	userkeypair** userkeylist)
{
    int ret;
    X509_NAME *prefix;
    char prefixbuf[256];
    int prefixlen;
    EC_KEY *p_dsa = NULL;
    FILE *privatekeyfile = fopen(keyfilename, "r");
    if(!privatekeyfile)
    {
        printf("Cannot find ec privatekeyfile.\n");
        ret = -1;
        return ret;
    }
    if((p_dsa = PEM_read_ECPrivateKey(privatekeyfile, NULL, NULL, NULL)) == NULL) {
        printf("Cannot read ec privatekey.\n");
	    ret = -2;
        fclose(privatekeyfile);
        return ret;
    }
    fclose(privatekeyfile);

    X509 *cert;
    EVP_PKEY *prikey;
    FILE *certfile = fopen(certfilename, "r");
    if (!certfile)
    {
        printf("Cannot find public key certificatefile.\n");
        EC_KEY_free(p_dsa);
        ret = -1;
        return ret;
    }
    if ((cert = PEM_read_X509(certfile, NULL, NULL, NULL)) == NULL) {       
        EC_KEY_free(p_dsa);
        fclose(certfile);
        ret = -2;
        return ret;
    }
    fclose(certfile);

    prikey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(prikey, p_dsa);
    if (X509_check_private_key(cert, prikey) == 0) {
        ret = -3;
        EC_KEY_free(p_dsa);
        EVP_PKEY_free(prikey);
        X509_free(cert);
        return ret;
    }

    prefix = X509_get_subject_name(cert);
    prefixlen = X509_NAME_get_text_by_NID(prefix, NID_commonName, prefixbuf, sizeof(prefixbuf));
    
    // create new node.
    userkeypair *insert = (userkeypair*)malloc(sizeof(userkeypair));
    insert->next = NULL;

    userkeypair *ptr = *userkeylist;
    if (ptr == NULL) {
        *userkeylist = insert;
    } else {
        while (ptr->keytag != keytag && ptr->next != NULL) ptr = ptr->next;
        if (ptr->keytag == keytag) {
            printf("keytag %d already used.\n", keytag);
            free(insert);
            EC_KEY_free(p_dsa);
            EVP_PKEY_free(prikey);
            X509_free(cert);
            return -4;
        }
        ptr->next = insert;
    }

    insert->keytag = keytag;
    insert->algorithm = algorithm;
    insert->subjectlen = prefixlen;
    insert->subjectpfx = malloc(prefixlen);
    memcpy(insert->subjectpfx, prefixbuf, prefixlen);
    insert->privatekey = p_dsa;
    insert->certlen = i2d_X509(cert, &insert->certbuf);
    insert->next = NULL;
    // frees
    EVP_PKEY_free(prikey);
    X509_free(cert);
    return 0;
}

userkeypair*
get_userkeypair(userkeypair* userkeylist, unsigned short keytag)
{
    userkeypair *ans = userkeylist;
    if (ans == NULL) return NULL;
    while (ans != NULL && ans->keytag == keytag) {
        ans = ans->next;
    }
    return ans;
}

hidns_update_signature* 
sign_rawcommand(hidns_update_command *cmd, 
	unsigned short keytag, userkeypair* userkeylist)
{
    // check cmd and getkey
    if (cmd == NULL) return NULL;
    userkeypair *keypair;
    if ((keypair = get_userkeypair(userkeylist, keytag)) == NULL) {
        return NULL;
    }
    
    // encode cmd to tbs
    unsigned char tbsbuf[UPDATE_MSG_MAXBUFSIZE];
    unsigned short tbslen;
    unsigned char* tbsptr;

    tbsptr = tbsbuf;
    hidns_update_command cmd_n = *cmd;
    cmd_n.id = htonl(cmd->id);
	cmd_n.ts = htonl(cmd->ts);
	cmd_n.rrttl = htonl(cmd->rrttl);
	cmd_n.rrvaluelen = htons(cmd->rrvaluelen);
    memcpy(tbsptr, &cmd_n, COMMAND_FIXLEN);
    tbsptr += COMMAND_FIXLEN;
    memcpy(tbsptr, cmd->rrprefixbuf, cmd->rrprefixlen);
    tbsptr += cmd->rrprefixlen;
    memcpy(tbsptr, cmd->rrvaluebuf, cmd->rrvaluelen);
    tbsptr += cmd->rrvaluelen;
    tbslen = tbsptr - tbsbuf;
    
    // get digest and sign
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned char sigbuf[256];
    unsigned int sigbuflen;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);
    if (!EVP_DigestInit(md_ctx, EVP_sha256())) {
        printf("EVP_digest fail \n");
        goto error_out;
    }
    if (!EVP_DigestUpdate(md_ctx, (const void *)tbsbuf, tbslen)) {
        printf("TAG3\n");
	    printf("EVP_DigestUpdate fail \n");
        goto error_out;
    }
    if (!EVP_DigestFinal(md_ctx, digest, &digest_len)) {
        printf("EVP_DigestFinal fail \n");
        goto error_out;
    }

    printf("digest = %d\n", digest_len);
    
    if (ECDSA_sign(0, digest, digest_len, sigbuf, &sigbuflen, keypair->privatekey) != 1) {
        printf("ECDSA_sign fail \n");
	    goto error_out;
    }
    printf("signlen = %d\n", sigbuflen);
    EVP_MD_CTX_free(md_ctx);
    // make signature
    time_t now;
    time(&now);
    // hidns_update_signature *sig = (hidns_update_signature*) malloc(sizeof(hidns_update_signature));
    hidns_update_signature *sig = updatemsg_new_signature();
    sig->sigkeytag = keytag;
    sig->algorithm = keypair->algorithm;
    sig->expirtime = now + 300; // command signature will expire in 300s
    sig->inceptime = now;
    sig->signerlen = keypair->subjectlen;
    sig->sigbuflen = sigbuflen;
    sig->signerpfx = malloc(keypair->subjectlen);
    sig->signature = malloc(sigbuflen);
    memcpy(sig->signerpfx, keypair->subjectpfx, keypair->subjectlen);
    memcpy(sig->signature, sigbuf, sigbuflen);
    printf("signature done!\n");
    return sig;
    
error_out:
    EVP_MD_CTX_free(md_ctx);
    return NULL;
}

int
check_updatemsg_request(hidns_update_msg *msg)
{
    unsigned char musk;
    int ret;
    // A. check the construction of msg
    musk = MSG_MEMBER_MAP_CMD | MSG_MEMBER_MAP_SIG;
    if ((msg->_membermap & musk) != musk)
        return CHECK_MSG_INCOMPLETE;
    if (msg->cmd.rrvaluelen == 0 && (msg->_membermap & MSG_MEMBER_MAP_ADD) == 0) {
        return CHECK_MSG_INCOMPLETE;
    }
    // printf("TAG1\n");
    // B. check time stamp
    time_t now = time(NULL);
    if (now - msg->cmd.ts > 10) {
        return CHECK_MSG_OUTOFDATE;
    }
    if (now > msg->sig.expirtime) {
        return CHECK_MSG_INVALIDSIG;
    }
    // printf("TAG2\n");
    // C. check prefix relationship
    if (msg->cmd.rrprefixlen < msg->sig.signerlen) {
        return CHECK_MSG_INVALIDPFX;
    }
    // printf("%.*s\n", msg->cmd.rrprefixlen, msg->cmd.rrprefixbuf);
    // printf("%d\n", msg->sig.signerlen);
    // printf("%.*s\n", msg->sig.signerlen, msg->sig.signerpfx);
    if (msg->cmd.rrprefixbuf[0] != '/' || msg->cmd.rrprefixbuf[msg->cmd.rrprefixlen - 1] != '/' 
        || msg->sig.signerpfx[0] != '/' || msg->sig.signerpfx[msg->sig.signerlen - 1] != '/') {
            return CHECK_MSG_INVALIDPFX;
    }
    // printf("TAG2.5\n");
    if (memcmp(msg->cmd.rrprefixbuf, msg->sig.signerpfx, msg->sig.signerlen) != 0) {
        return CHECK_MSG_INVALIDPFX;
    }
    // D. check cert ( return 1 means cert absent)
    if ((msg->_membermap & MSG_MEMBER_MAP_CERT) == 0) {
        return CHECK_MSG_CERTABSENT;
    }   
    if (msg->cert.type != CERTIFICATE_TYPE_X509_DER) {
        return CHECK_MSG_UNSUPTCERT;
    }
    // printf("TAG3\n");
    X509 *cert = X509_new();
    if (d2i_X509(&cert, (const unsigned char **)&msg->cert.valbuf, msg->cert.length) == NULL) {
        X509_free(cert);
        return CHECK_MSG_INVALIDCERT;
    }
    // printf("TAG4\n");
    // E. verify the command
    EVP_PKEY *pub = X509_get_pubkey(cert);
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pub);
    X509_free(cert);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);
    if (!EVP_DigestInit(md_ctx, EVP_sha256())) {
        ret = CHECK_MSG_SERVERFAIL;
        goto finish_out;
    }
    if (!EVP_DigestUpdate(md_ctx, (const void *)msg->_tbsptr, msg->_tbslen)) {
        ret = CHECK_MSG_SERVERFAIL;
        goto finish_out;
    }
    if (!EVP_DigestFinal(md_ctx, digest, &digest_len)) {
        ret = CHECK_MSG_SERVERFAIL;
        goto finish_out;
    }
    // printf("TAG5\n");
    if (ECDSA_verify(0, digest, digest_len, msg->sig.signature, msg->sig.sigbuflen, eckey) != 1) {
        ret = CHECK_MSG_INVALIDSIG;
    }
    else {
        ret = CHECK_MSG_OK;
    }
finish_out:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub);
    EC_KEY_free(eckey);
    return ret;
}

int
check_updatemsg_reply(hidns_update_msg *msg)
{
    unsigned char musk;
    int ret;
    // A. check the construction of msg
    musk = MSG_MEMBER_MAP_CMD | MSG_MEMBER_MAP_RCODE | MSG_MEMBER_MAP_SIG;
    if ((msg->_membermap & musk) != musk)
        return CHECK_MSG_INCOMPLETE;
    if (msg->cmd.rrvaluelen == 0)
        return CHECK_MSG_INCOMPLETE;
    
    // B. check timestamp
    time_t now = time(NULL);
    if (now > msg->sig.expirtime) {
        return CHECK_MSG_INVALIDSIG;
    }
    // C. check prefix
    if (msg->sig.signerpfx[0] != '/' || msg->sig.signerpfx[msg->sig.signerlen - 1] != '/') {
            return CHECK_MSG_INVALIDPFX;
    }
    // D. check cert ( return 1 means cert absent)
    if ((msg->_membermap & MSG_MEMBER_MAP_CERT) == 0) {
        return CHECK_MSG_CERTABSENT;
    }   
    if (msg->cert.type != CERTIFICATE_TYPE_X509_DER) {
        return CHECK_MSG_UNSUPTCERT;
    }
    X509 *cert = X509_new();
    if (d2i_X509(&cert, (const unsigned char **)&msg->cert.valbuf, msg->cert.length) == NULL) {
        X509_free(cert);
        return CHECK_MSG_INVALIDCERT;
    }
    // E. verify the command
    EVP_PKEY *pub = X509_get_pubkey(cert);
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pub);
    X509_free(cert);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);
    if (!EVP_DigestInit(md_ctx, EVP_sha256())) {
        ret = CHECK_MSG_SERVERFAIL;
        goto finish_out;
    }
    if (!EVP_DigestUpdate(md_ctx, (const void *)msg->_tbsptr, msg->_tbslen)) {
        ret = CHECK_MSG_SERVERFAIL;
        goto finish_out;
    }
    if (!EVP_DigestFinal(md_ctx, digest, &digest_len)) {
        ret = CHECK_MSG_SERVERFAIL;
        goto finish_out;
    }
    if (ECDSA_verify(0, digest, digest_len, msg->sig.signature, msg->sig.sigbuflen, eckey) != 1) {
        ret = CHECK_MSG_INVALIDSIG;
    }
    else {
        ret = CHECK_MSG_OK;
    }
finish_out:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub);
    EC_KEY_free(eckey);
    return ret;
}

int
check_updatemsg_ismatch(hidns_update_msg *request, hidns_update_msg *reply)
{
    if (request->cmd.rrprefixlen != reply->cmd.rrprefixlen) {
        return 0;
    }
    if (memcmp(&request->cmd, &reply->cmd, COMMAND_FIXLEN + request->cmd.rrprefixlen) != 0) {
        return 0;
    }
    return 1;
}

//私钥签名
// base64 编码
char *base64_encode(const char *buffer, int length) {
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;
    char *buff = NULL;
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);

    return buff;
}

int test_sign(const char *input, int input_len, const char *pri_key_fn)
{
    EC_KEY *p_dsa = NULL;
    FILE *file = NULL;
    int signlen = 0;
    int i = 0;
    int ret = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned char sig[2048];
    unsigned int siglen;

    file = fopen(pri_key_fn, "r");
    if(!file)
    {
        ret = -1;
        return ret;
    }

    if((p_dsa = PEM_read_ECPrivateKey(file, NULL, NULL, NULL)) == NULL) { // 获取私钥的ec key
        printf("TAG2\n");
	ret = -2;
        fclose(file);
        return ret;
    }

    fclose(file);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new(); // free?
    EVP_MD_CTX_init(md_ctx);
    if (!EVP_DigestInit(md_ctx, EVP_sha256())) {
        printf("EVP_digest fail \n");
        ret = -1;
        goto error_out;
    }
    if (!EVP_DigestUpdate(md_ctx, (const void *)input, input_len)) {
        printf("TAG3\n");
	printf("EVP_DigestUpdate fail \n");
        ret = -1;
        goto error_out;
    }
    if (!EVP_DigestFinal(md_ctx, digest, &digest_len)) { // 待签名消息用sha256生成256比特的签名摘要
        printf("EVP_DigestFinal fail \n");
        ret = -1;
        goto error_out;
    }

    printf("signlen = %ld, digest: %s\n", strlen(digest), digest);
    
    if (ECDSA_sign(0, digest, digest_len, sig, &siglen, p_dsa) != 1) {
        printf("ECDSA_sign fail \n");
        ret = -1;
	goto error_out;
    }
    printf("ok. siglen = %d\n", siglen);
    unsigned char* sigbuf = base64_encode(sig, siglen);
    FILE *log = fopen("./siglog", "wb");
    fwrite(sigbuf, 1, strlen(sigbuf), log);
    fclose(log);
    // s = ECDSA_do_sign(digest, digest_len, p_dsa); // 对签名摘要进行签名得到签名数据s
    // if(s == NULL) {
    //     ret = -3;
    //     EC_KEY_free(p_dsa);
    //     return ret;
    // }

error_out:
    EC_KEY_free(p_dsa);
    EVP_MD_CTX_free(md_ctx);

    return 0;
}

int main()
{
	// test_sign("helloworld", strlen("helloworld"), "./curveprivate.key");
    load_userkeypair("dns.key", "dns.crt", 0, 14, &keypairhead);
    load_userkeypair("dns.key", "dns.crt", 2, 14, &keypairhead);
    load_userkeypair("dns.key", "dns.crt", 0, 14, &keypairhead);
    userkeypair *ptr = keypairhead;
    while (ptr != NULL) {
        printf("keytag=%d, subjectlen=%d, cerlen=%d\n", ptr->keytag, ptr->subjectlen, ptr->certlen);
        ptr = ptr->next;
    }

    hidns_update_command* cmd = updatemsg_new_command();
    cmd->opcode = COMMAND_OPCODE_ADDRR;
    cmd->rrtype = COMMAND_RRTYPE_TXT;
    cmd->rrprefixlen = strlen("/nssec/dns01/user1/");
    cmd->rrprefixbuf = "/nssec/dns01/user1/";
    cmd->rrvaluelen = strlen("helloworld");
    cmd->rrvaluebuf = "helloworld";
    cmd->rrttl = 86400;
    hidns_update_signature* sig = sign_rawcommand(cmd, 0, keypairhead);
    hidns_update_certificate* cert = updatemsg_new_certificate();
    cert->type = CERTIFICATE_TYPE_X509_DER;
    cert->length = get_userkeypair(keypairhead, 0)->certlen;
    cert->valbuf = get_userkeypair(keypairhead, 0)->certbuf;
    hidns_update_msg* msg = updatemsg_new_message();
    updatemsg_append_command(msg, cmd);
    updatemsg_append_signature(msg, sig);
    updatemsg_append_certificate(msg, cert);
    // printf("TAG4\n");
    FILE *f = fopen("dump.bin", "wb");
    fwrite(msg->rawbuf, 1, msg->rawbuflen, f);
    fclose(f);
    hidns_update_msg *rcvmsg = updatemsg_new_message();
    memcpy(rcvmsg->rawbuf, msg->rawbuf, msg->rawbuflen);
    updatemsg_parse(rcvmsg);
    // printf("%.*s\n", msg->sig.signerlen, msg->sig.signerpfx);
    printf("%u %u %u %u\n", rcvmsg->cmd.rrvaluelen, rcvmsg->cmd.rrttl, rcvmsg->sig.inceptime, rcvmsg->cert.type);
    printf("ret = %d\n", check_updatemsg_request(rcvmsg));
	return 0;
}
