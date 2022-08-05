#include "updatemsgfmt.h"

void updatemsg_init(hidns_update_msg* msg)
{
	if (msg == NULL) return;
	msg->_membermap = 0;
	msg->_tbslen = 0;
	msg->len_n = 0;
	msg->rawbuflen = sizeof(msg->len_n);
}

// parse msg
int
updatemsg_parse(hidns_update_msg* msg)
{
	msg->rawbuflen = ntohs(msg->len_n) + sizeof(msg->len_n);
	unsigned char *bound = msg->rawbuf + msg->rawbuflen;
	unsigned char *ptr = msg->buf;
	unsigned char type;
	unsigned short len, len_n;
	int ret;
	msg->_membermap = 0;
	while (ptr < bound) {
		type = *ptr++;
		len_n = *(unsigned short*)ptr;
		ptr += 2;
		len = ntohs(len_n);
		if (ptr + len > bound) return -1;
		switch (type)
		{
		case COMMAND_TYPEID:
			msg->_tbsptr = ptr;
			msg->_tbslen = len;
			ret = command_parse(&msg->cmd, ptr, len);
			msg->_membermap |= MSG_MEMBER_MAP_CMD;
			break;
		case COMMONTLV_TYPEID:
			ret = commontlv_parse(&msg->args, ptr, len);
			msg->_membermap |= MSG_MEMBER_MAP_ARGS;
			break;
		case CERTIFICATE_TYPEID:
			ret = commontlv_parse(&msg->cert, ptr, len);
			msg->_membermap |= MSG_MEMBER_MAP_CERT;
			break;
		case ADDITION_TYPEID:
			ret = commontlv_parse(&msg->addval, ptr, len);
			msg->_membermap |= MSG_MEMBER_MAP_ADD;
			break;
		case SIGNATURE_TYPEID:
			ret = signature_parse(&msg->sig, ptr, len);
			msg->_membermap |= MSG_MEMBER_MAP_SIG;
			break;
		case RCODE_TYPEID:
			msg->rcode = *ptr;
			msg->_membermap |= MSG_MEMBER_MAP_RCODE;
			break;
		default:
			ret = -3;
		}
		if (ret != 0) return ret;
		ptr += len;
	}
	return 0;
}

int
command_parse(hidns_update_command* cmd, unsigned char *ptr, int len)
{
	memcpy(cmd, ptr, COMMAND_FIXLEN);
	cmd->id = ntohl(cmd->id);
	cmd->ts = ntohl(cmd->ts);
	cmd->rrttl = ntohl(cmd->rrttl);
	cmd->rrvaluelen = ntohs(cmd->rrvaluelen);
	if (COMMAND_FIXLEN + cmd->rrprefixlen + cmd->rrvaluelen != len)
		return -2;
	cmd->rrprefixbuf = ptr + COMMAND_FIXLEN;
	cmd->rrvaluebuf = ptr + COMMAND_FIXLEN + cmd->rrprefixlen;
	return 0;
}

int
commontlv_parse(hidns_update_tlv* tlv, unsigned char *ptr, int len)
{
	memcpy(tlv, ptr, TLV_FIXLEN);
	tlv->length = ntohs(tlv->length);
	if (TLV_FIXLEN + tlv->length != len)
		return -2;
	tlv->valbuf = ptr + TLV_FIXLEN;
	return 0;
}

int
signature_parse(hidns_update_signature* sig, unsigned char *ptr, int len)
{
	FILE *f = fopen("sig.bin", "wb");
	fwrite(ptr, 1, len, f);
	fclose(f);
	memcpy(sig, ptr, SIGNATURE_FIXLEN);
	sig->sigkeytag = ntohs(sig->sigkeytag);
	sig->expirtime = ntohl(sig->expirtime);
	sig->inceptime = ntohl(sig->inceptime);
	sig->sigbuflen = ntohs(sig->sigbuflen);
	printf("%d - %d - %d\n", sig->signerlen, sig->sigbuflen, len);
	if (SIGNATURE_FIXLEN + sig->signerlen + sig->sigbuflen != len)
		return -2;
	sig->signerpfx = ptr + SIGNATURE_FIXLEN;
	sig->signature = ptr + SIGNATURE_FIXLEN + sig->signerlen;
	return 0;
}

// extract command
hidns_update_command*
updatemsg_extract_command(hidns_update_msg* msg)
{
	if ((msg->_membermap & MSG_MEMBER_MAP_CMD) == 0) {
		return NULL;
	}
	hidns_update_command *cmd = (hidns_update_command*) malloc(sizeof(hidns_update_command));
	*cmd = msg->cmd;
	cmd->rrprefixbuf = malloc(msg->cmd.rrprefixlen);
	memcpy(cmd->rrprefixbuf, msg->cmd.rrprefixbuf, cmd->rrprefixlen);
	if (cmd->rrtype == COMMAND_RRTYPE_A_TBF) {
		if (((msg->_membermap & MSG_MEMBER_MAP_ADD) != 0) && msg->addval.type == ADDITION_TYPE_A) {
			cmd->opcode = COMMAND_RRTYPE_A;
			cmd->rrvaluelen = msg->addval.length;
			cmd->rrvaluebuf = malloc(msg->addval.length);
			memcpy(cmd->rrvaluebuf, msg->addval.valbuf, cmd->rrvaluelen);
		}
		else {
			return NULL;
		}			
	}
	else {
		cmd->rrvaluebuf = malloc(msg->cmd.rrvaluelen);
		memcpy(cmd->rrvaluebuf, msg->cmd.rrvaluebuf, cmd->rrvaluelen);
	}
	return cmd;
}

// append value
int
_updatemsg_append_tlv(hidns_update_msg* msg, hidns_update_tlv* dstptr, hidns_update_tlv* tlv, unsigned char typeid)
{
	unsigned short tlvlen = tlv->length + TLV_FIXLEN;
	printf("tlv len=%d, ", tlvlen);
	unsigned short len_n;
	if (msg->rawbuflen + tlvlen + TLV_FIXLEN > UPDATE_MSG_MAXBUFSIZE)
		return -2;	
	printf("offset=%d\n", msg->rawbuflen);
	unsigned char* ptr = msg->rawbuf + msg->rawbuflen;
	*dstptr = *tlv;

	msg->rawbuflen += (tlvlen + TLV_FIXLEN);
	msg->len_n = htons(msg->rawbuflen - sizeof(unsigned short));

	*ptr++ = typeid;
	len_n = htons(tlvlen);
	memcpy(ptr, &len_n, 2);
	ptr += 2;

	*ptr++ = tlv->type;
	len_n = htons(tlv->length);
	memcpy(ptr, &len_n, 2);
	ptr += 2;
	dstptr->valbuf = ptr;
	memcpy(ptr, tlv->valbuf, tlv->length);

	return 0;
}

int
updatemsg_append_command(hidns_update_msg* msg, hidns_update_command* cmd)
{
	if ((msg->_membermap & MSG_MEMBER_MAP_CMD) != 0) {
		return -1;
	}	
	unsigned short cmdlen = COMMAND_FIXLEN + cmd->rrprefixlen + cmd->rrvaluelen;
	printf("cmd len=%d, ", cmdlen);
	unsigned short len_n;
	if (msg->rawbuflen + cmdlen + TLV_FIXLEN > UPDATE_MSG_MAXBUFSIZE)
		return -2;
	msg->_membermap |= MSG_MEMBER_MAP_CMD;
	printf("offset=%d\n", msg->rawbuflen);
	unsigned char* ptr = msg->rawbuf + msg->rawbuflen;

	msg->rawbuflen += (cmdlen + TLV_FIXLEN);
	msg->len_n = htons(msg->rawbuflen - sizeof(unsigned short));
	
	*ptr++ = COMMAND_TYPEID;
	len_n = htons(cmdlen);
	memcpy(ptr, &len_n, 2);
	ptr += 2;
	
	// FILE *f1 = fopen("dump1.bin", "wb");
	// fwrite(cmd, 1, COMMAND_FIXLEN, f1);
	// fclose(f1);
	hidns_update_command cmd_n = *cmd;
	cmd_n.id = htonl(cmd->id);
	cmd_n.ts = htonl(cmd->ts);
	cmd_n.rrttl = htonl(cmd->rrttl);
// printf("yyy %u <- %u\n", cmd_n.rrttl, cmd->rrttl);
	cmd_n.rrvaluelen = htons(cmd->rrvaluelen);
// printf("xxx %u <- %u\n", cmd_n.rrvaluelen, cmd->rrvaluelen);
	// FILE *f2 = fopen("dump2.bin", "wb");
	// fwrite(&cmd_n, 1, COMMAND_FIXLEN, f2);
	// fclose(f2);
	msg->cmd = *cmd;
	memcpy(ptr, &cmd_n, COMMAND_FIXLEN);
	ptr += COMMAND_FIXLEN;
	memcpy(ptr, cmd->rrprefixbuf, cmd->rrprefixlen);
	msg->cmd.rrprefixbuf = ptr;
	ptr += cmd->rrprefixlen;
	memcpy(ptr, cmd->rrvaluebuf, cmd->rrvaluelen);
	msg->cmd.rrvaluebuf = ptr;
	
	return 0;
}

int
updatemsg_append_signature(hidns_update_msg* msg, hidns_update_signature* sig)
{
	if ((msg->_membermap & MSG_MEMBER_MAP_SIG) != 0)
		return -1;
	unsigned short siglen = SIGNATURE_FIXLEN + sig->signerlen + sig->sigbuflen;
	printf("sig len=%d=%d+%d+%d, ", siglen, SIGNATURE_FIXLEN, sig->signerlen, sig->sigbuflen);
	unsigned short len_n;
	if (msg->rawbuflen + siglen + TLV_FIXLEN > UPDATE_MSG_MAXBUFSIZE)
		return -2;
	msg->_membermap |= MSG_MEMBER_MAP_SIG;
	printf("offset=%d, ", msg->rawbuflen);
	unsigned char* ptr = msg->rawbuf + msg->rawbuflen;

	msg->rawbuflen += (siglen + TLV_FIXLEN);
	msg->len_n = htons(msg->rawbuflen - sizeof(unsigned short));

	*ptr++ = SIGNATURE_TYPEID;
	len_n = htons(siglen);
	memcpy(ptr, &len_n, 2);
	ptr += 2;
	
	hidns_update_signature sig_n = *sig;
	sig_n.sigkeytag = htons(sig->sigkeytag);
	sig_n.expirtime = htonl(sig->expirtime);
	sig_n.inceptime = htonl(sig->inceptime);
	sig_n.sigbuflen = htons(sig->sigbuflen);

	msg->sig = *sig;
	memcpy(ptr, &sig_n, SIGNATURE_FIXLEN);
	ptr += SIGNATURE_FIXLEN;
	memcpy(ptr, sig->signerpfx, sig->signerlen);
	msg->sig.signerpfx = ptr;
	ptr += sig->signerlen;
	memcpy(ptr, sig->signature, sig->sigbuflen);
	msg->sig.signature = ptr;
	printf("siglen=%d\n", sig->sigbuflen);
	return 0;
}

int
updatemsg_append_addition(hidns_update_msg* msg, hidns_update_addition* addv)
{
	if ((msg->_membermap & MSG_MEMBER_MAP_ADD) != 0)
		return -1;
	int ret;
	if ((ret = _updatemsg_append_tlv(msg, &msg->addval,(hidns_update_tlv*)addv, ADDITION_TYPEID)) == 0)
		msg->_membermap |= MSG_MEMBER_MAP_ADD;
	return ret;
}

int
updatemsg_append_certificate(hidns_update_msg* msg, hidns_update_certificate* cert)
{
	if ((msg->_membermap & MSG_MEMBER_MAP_CERT) != 0)
		return -1;
	int ret;
	if ((ret = _updatemsg_append_tlv(msg, &msg->cert,(hidns_update_tlv*)cert, CERTIFICATE_TYPEID)) == 0)
		msg->_membermap |= MSG_MEMBER_MAP_CERT;
	return ret;
}

int
updatemsg_set_rcode(hidns_update_msg* msg, hidns_update_rcode rcode)
{
	if ((msg->_membermap & MSG_MEMBER_MAP_RCODE) != 0)
		msg->rcode = rcode;
		return 0;
	if (msg->rawbuflen + RCODE_FIXLEN + TLV_FIXLEN > UPDATE_MSG_MAXBUFSIZE)
		return -2;
	
	msg->_membermap |= MSG_MEMBER_MAP_RCODE;
	printf("offset=%d\n", msg->rawbuflen);
	unsigned char* ptr = msg->rawbuf + msg->rawbuflen;

	msg->rawbuflen += (RCODE_FIXLEN + TLV_FIXLEN);
	msg->len_n = htons(msg->rawbuflen - sizeof(unsigned short));

	*ptr++ = RCODE_TYPEID;
	unsigned len_n = htons(sizeof(hidns_update_rcode));
	memcpy(ptr, &len_n, 2);
	ptr += 2;
	*ptr = rcode;

	return 0;
}

// new value
hidns_update_msg* 
updatemsg_new_message()
{
	hidns_update_msg* p = (hidns_update_msg*) malloc(sizeof(hidns_update_msg));
	p->rawbuflen = sizeof(p->len_n);
	p->len_n = 0;
	p->_membermap = 0;
	return p;
}

hidns_update_tlv*
_updatemsg_new_tlv()
{
	hidns_update_tlv* p = (hidns_update_tlv*) malloc(sizeof(hidns_update_tlv));
	p->type = 0;
	p->length = 0;
	p->valbuf = NULL;
	return p;
}

hidns_update_command*
updatemsg_new_command()
{
	hidns_update_command* p = (hidns_update_command*) malloc(sizeof(hidns_update_command));
	p->id = rand();
	p->ts = time(NULL);
	p->opcode = 0;
	p->rrtype = 0;
	p->rrttl = 86400;
	p->rrprefixlen = 0;
	p->rrvaluelen = 0;
	p->rrprefixbuf = NULL;
	p->rrvaluebuf = NULL;
	return p;
}

hidns_update_signature*
updatemsg_new_signature()
{
	hidns_update_signature* p = (hidns_update_signature*) malloc(sizeof(hidns_update_signature));
	p->sigkeytag = 0;
	p->algorithm = 0;
	p->expirtime = 0;
	p->inceptime = 0;
	p->signerlen = 0;
	p->sigbuflen = 0;
	p->signerpfx = NULL;
	p->signature = NULL;
	return p;
}

hidns_update_addition*
updatemsg_new_addition()
{
	return _updatemsg_new_tlv();
}

hidns_update_certificate*
updatemsg_new_certificate()
{
	return _updatemsg_new_tlv();
}

// free value
void
updatemsg_free_message(hidns_update_msg* msg)
{
	free(msg);
}


void
_updatemsg_free_tlv(hidns_update_tlv* tlv)
{
	if (tlv) {
		if (tlv->valbuf)
			free(tlv->valbuf);
		free(tlv);
	}
}

void
updatemsg_free_command(hidns_update_command* cmd)
{
	if (cmd) {
		if (cmd->rrprefixbuf)
			free(cmd->rrprefixbuf);
		if (cmd->rrvaluebuf)
			free(cmd->rrvaluebuf);
		free(cmd);
	}
}

void
updatemsg_free_signature(hidns_update_signature* sig)
{
	if (sig) {
		if (sig->signerpfx)
			free(sig->signerpfx);
		if (sig->signature)
			free(sig->signature);
		free(sig);
	}
}

void
updatemsg_free_addition(hidns_update_addition* add)
{
	_updatemsg_free_tlv(add);
}

void
updatemsg_free_certificate(hidns_update_certificate* cert)
{
	_updatemsg_free_tlv(cert);
}

