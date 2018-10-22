
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvm_cert.h"

#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/oid.h"

#include "mbedtls/sm2.h"
#include "mbedtls/asn1write.h"

#include "MSCUKeyAPI.h"

static int _cvm_write_binary_file(char *filename, unsigned char *buf, int len)
{
	FILE *fp;

	if (!filename)
		return -1;
	if (!strlen(filename))
		return -1;

	fp = fopen(filename, "wb");
	if (fp)
	{
		fwrite(buf, 1, len, fp);
		fclose(fp);
	}
	else
		return -1;

	return 0;
}

int cvm_pk_write_pubkey_file(char *filename, unsigned char *pubkey, int plen)
{
	int ret;
	mbedtls_pk_context pk_ctx;
	mbedtls_ecp_keypair	*pk;
	unsigned char buf[200];
	int len;

	mbedtls_pk_init(&pk_ctx);

	mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	pk = mbedtls_pk_ec(pk_ctx);
	mbedtls_ecp_group_load(&pk->grp, MBEDTLS_ECP_DP_SM2);
	ret = mbedtls_ecp_point_read_binary(&pk->grp, &pk->Q, pubkey, plen);
	len = mbedtls_pk_write_pubkey_der(&pk_ctx, buf, sizeof(buf));
	if (len < 0)
	{
		ret = len;
		goto clean;
	}

	_cvm_write_binary_file(filename, buf + sizeof(buf) - len, len);

clean:
	mbedtls_pk_free(&pk_ctx);
	return ret;
}


int cvm_ecp_gen_key(CVM_ECP_GEN_OPT *opt, unsigned char *prikey, int *prilen, unsigned char *pubkey, int *publen)
{
	int ret;
	mbedtls_pk_context key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "cvm ecp gen";

	unsigned char buf[1024];
	int len;
	FILE *fp;

	mbedtls_pk_init(&key);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	//set pk type
	if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
		goto clean;

	//Set rand function
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers, strlen(pers))) != 0)
		goto clean;

	if (ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SM2, mbedtls_pk_ec(key),
		mbedtls_ctr_drbg_random, &ctr_drbg))
		goto clean;

	len = mbedtls_pk_write_key_der(&key, buf, sizeof(buf));
	if (len < 0)
	{
		ret = len;
		goto clean;
	}

	_cvm_write_binary_file(opt->pri_file, buf + sizeof(buf) - len, len);
	if (prikey)
	{
		memcpy(prikey, buf + sizeof(buf) - len, len);
		*prilen = len;
	}

	len = mbedtls_pk_write_pubkey_der(&key, buf, sizeof(buf));
	if (len < 0)
	{
		ret = len;
		goto clean;
	}

	_cvm_write_binary_file(opt->pub_file, buf + sizeof(buf) - len, len);
	if (pubkey)
	{
		memcpy(pubkey, buf + sizeof(buf) - len, len);
		*publen = len;
	}



clean:
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}


int cvm_csr_verify(unsigned char *creq, int len)
{
	int ret;
	mbedtls_x509_csr csr;
	unsigned char hash[32];
	unsigned char sign[64];


	mbedtls_x509_csr_init(&csr);

	if (ret = mbedtls_x509_csr_parse(&csr, creq, len))
		goto clean;

	if (ret = mbedtls_sm2_compute_e(MBEDTLS_MD_SM3, NULL, 0, csr.cri.p, csr.cri.len, 
		mbedtls_pk_ec(csr.pk), hash))
		goto clean;

	if (ret = mbedtls_pk_verify(&csr.pk, MBEDTLS_MD_SM3, hash, 0, csr.sig.p, csr.sig.len))
		goto clean;

clean:
	mbedtls_x509_csr_free(&csr);
	return ret;
}

static _cvm_sm2_write_signature(unsigned char *in, size_t ilen,
	unsigned char *sig, size_t *slen)
{
	int ret;
	unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
	unsigned char *p = buf + sizeof(buf);
	size_t len = 0;
	mbedtls_mpi r, s;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_mpi_read_binary(&r, in, 32);
	mbedtls_mpi_read_binary(&s, in + 32, 32);

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &s));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &r));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	memcpy(sig, p, len);
	*slen = len;

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	return(0);
}

static int _cvm_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size)
{
	int ret;
	const char *sig_oid;
	size_t sig_oid_len = 0;
	unsigned char *c, *c2;
	unsigned char hash[64];
	unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
	unsigned char tmp_buf[2048];
	size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
	size_t len = 0;
	mbedtls_pk_type_t pk_alg;
	unsigned char temp[64];
	size_t tlen;

	/*
	* Prepare data to be signed in tmp_buf
	*/
	c = tmp_buf + sizeof(tmp_buf);

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_extensions(&c, tmp_buf, ctx->extensions));

	if (len)
	{
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, tmp_buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
			MBEDTLS_ASN1_SEQUENCE));

		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, tmp_buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
			MBEDTLS_ASN1_SET));

		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(&c, tmp_buf, MBEDTLS_OID_PKCS9_CSR_EXT_REQ,
			MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS9_CSR_EXT_REQ)));

		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, tmp_buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
			MBEDTLS_ASN1_SEQUENCE));
	}

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, tmp_buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
		MBEDTLS_ASN1_CONTEXT_SPECIFIC));

	MBEDTLS_ASN1_CHK_ADD(pub_len, mbedtls_pk_write_pubkey_der(ctx->key,
		tmp_buf, c - tmp_buf));
	c -= pub_len;
	len += pub_len;

	/*
	*  Subject  ::=  Name
	*/
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, tmp_buf, ctx->subject));

	/*
	*  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	*/
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, tmp_buf, 0));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, tmp_buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
		MBEDTLS_ASN1_SEQUENCE));

	/*
	* Prepare signature
	*/
	mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), c, len, hash);

	pk_alg = mbedtls_pk_get_type(ctx->key);
	if (pk_alg == MBEDTLS_PK_ECKEY)
		pk_alg = MBEDTLS_PK_ECDSA;
	//--Add by cong.peng 2017.05.12
#ifdef MBEDTLS_SM2_C
	if (mbedtls_pk_ec(*(ctx->key))->grp.id = MBEDTLS_ECP_DP_SM2)
		pk_alg = MBEDTLS_PK_SM2;
	if (pk_alg == MBEDTLS_PK_SM2)
		mbedtls_sm2_compute_e(ctx->md_alg, NULL, 0, c, len, mbedtls_pk_ec(*(ctx->key)), hash);
#endif /* MBEDTLS_SM2_C */
	//--End add

	ret = MSC_SM2SignHash(hash, 32, temp, &tlen);
	if (ret != 0x9000)
	{
		return ret;
	}

	_cvm_sm2_write_signature(temp, tlen, sig, &sig_len);

	if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
			&sig_oid, &sig_oid_len)) != 0)
	{
		return(ret);
	}

	/*
	* Write data to output buffer
	*/
	c2 = buf + size;
	MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, mbedtls_x509_write_sig(&c2, buf,
		sig_oid, sig_oid_len, sig, sig_len));

	if (len > (size_t)(c2 - buf))
		return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);

	c2 -= len;
	memcpy(c2, c, len);

	len += sig_and_oid_len;
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c2, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c2, buf, MBEDTLS_ASN1_CONSTRUCTED |
		MBEDTLS_ASN1_SEQUENCE));

	return((int)len);
}


int cvm_csr_write_from_opt(CVM_CSR_WRITE_OPT *opt, unsigned char *creq, int *len)
{
	int ret;
	unsigned char buf[1024];
	mbedtls_x509write_csr req;
	mbedtls_pk_context key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "cvm csr write";
	FILE *fp;

	if (!opt->subject_name || !opt->subject_key)
		return -1;

	mbedtls_x509write_csr_init(&req);
	mbedtls_pk_init(&key);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SM3);

	if (ret = mbedtls_x509write_csr_set_subject_name(&req, opt->subject_name))
		goto clean;

	if (opt->ext_sign)
		ret = mbedtls_pk_parse_public_keyfile(&key, opt->subject_key);
	else
		ret = mbedtls_pk_parse_keyfile(&key, opt->subject_key, opt->subject_pwd);
	if (ret)
		goto clean;
	mbedtls_x509write_csr_set_key(&req, &key);

	if (opt->key_usage)
		mbedtls_x509write_csr_set_key_usage(&req, opt->key_usage);

	if (opt->ns_cert_type)
		mbedtls_x509write_csr_set_ns_cert_type(&req, opt->ns_cert_type);

	//write req
	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers, strlen(pers))) != 0)
		goto clean;

	if (opt->ext_sign)
	{
		ret = _cvm_x509write_csr_der(&req, buf, sizeof(buf));
		if (ret < 0)
			goto clean;
	}
	else
	{
		ret = mbedtls_x509write_csr_der(&req, buf, sizeof(buf), mbedtls_ctr_drbg_random, &ctr_drbg);
		if (ret < 0)
			goto clean;
	}


	if (opt->output_file)
	{
		if (strlen(opt->output_file))
		{
			fp = fopen(opt->output_file, "wb");
			if (fp)
			{
				fwrite(buf + sizeof(buf) - ret, 1, ret, fp);
				fclose(fp);
			}
		}
	}
	if (creq || len)
	{
		memcpy(creq, buf + sizeof(buf) - ret, ret);
		*len = ret;
	}

	ret = 0;

clean:
	mbedtls_x509write_csr_free(&req);
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

int cvm_crt_write_from_opt(CVM_CRT_WRITE_OPT *opt, unsigned char *cert, int *len)
{
	int ret;
	unsigned char buf[1024];
	mbedtls_x509write_cert crt;
	mbedtls_mpi serial;
	mbedtls_x509_csr csr;
	char subject_name[256], issuer_name[256];
	FILE *fp;

	mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
	mbedtls_pk_context *issuer_key, *subject_key;
	mbedtls_x509_crt issuer_crt;

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "vcm crt write";

	if (!opt->serial || !opt->not_befor || !opt->not_after || !opt->issuer_key)
		return -1;
	if (!opt->selfsign && !opt->issuer_crt && !opt->issuer_name)
		return -1;
	if (!opt->request_file && (!opt->subject_name || !opt->subject_pubkey))
		return -1;
	if (!opt->output_file && !cert)
		return -1;

	mbedtls_x509write_crt_init(&crt);
	mbedtls_x509_csr_init(&csr);
	mbedtls_mpi_init(&serial);
	mbedtls_x509_crt_init(&issuer_crt);
	mbedtls_pk_init(&loaded_issuer_key);
	mbedtls_pk_init(&loaded_subject_key);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	//Set version
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	//Set md alg
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SM3);

	//Set serial
	if (ret = mbedtls_mpi_read_string(&serial, 16, opt->serial))
		goto clean;
	if (ret = mbedtls_x509write_crt_set_serial(&crt, &serial))
		goto clean;

	//Set validity
	if (ret = mbedtls_x509write_crt_set_validity(&crt, opt->not_befor, opt->not_after))
		goto clean;

	//Set issuer prikey
	if (ret = mbedtls_pk_parse_keyfile(&loaded_issuer_key, opt->issuer_key, opt->issuer_pwd))
		goto clean;
	issuer_key = &loaded_issuer_key;
	mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

	//Set subject info
	if (opt->request_file)
	{//If request_file is specified, subject_key, subject_pwd and subject_name are ignored!
		if (ret = mbedtls_x509_csr_parse_file(&csr, opt->request_file))
			goto clean;
		ret = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &csr.subject);
		if (ret < 0)
		{
			ret = -1;
			goto clean;
		}
		opt->subject_name = subject_name;
		subject_key = &csr.pk;
	}
	else
	{
		if (!strlen(opt->subject_name))
		{
			ret = -1;
			goto clean;
		}
		if (ret = mbedtls_pk_parse_public_keyfile(&loaded_subject_key, opt->subject_pubkey))
			goto clean;
		subject_key = &loaded_subject_key;
	}

	if (ret = mbedtls_x509write_crt_set_subject_name(&crt, opt->subject_name))
		goto clean;
	mbedtls_x509write_crt_set_subject_key(&crt, subject_key);

	//Set issuer info
	if (opt->selfsign)
	{//If selfsign is enabled, issuer_crt and issuer_name are ignored
		opt->issuer_name = opt->subject_name;
	}
	else
	{
		if (opt->issuer_crt)
		{//If issuer_crt is specified, issuer_name is ignored!
			if (ret = mbedtls_x509_crt_parse_file(&issuer_crt, opt->issuer_crt))
				goto clean;
			ret = mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &issuer_crt.subject);
			if (ret < 0)
			{
				ret = -1;
				goto clean;
			}
			opt->issuer_name = issuer_name;
		}
		else
		{//issuer_name is required!
			if (!strlen(opt->issuer_name))
			{
				ret = -1;
				goto clean;
			}
		}
	}
	if (ret = mbedtls_x509write_crt_set_issuer_name(&crt, opt->issuer_name))
		goto clean;

	//Set extensions
	if (ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt))
		goto clean;
	if (ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt))
		goto clean;
	if (ret = mbedtls_x509write_crt_set_basic_constraints(&crt, opt->is_ca, opt->max_pathlen))
		goto clean;

	if (opt->key_usage)
	{
		if (ret = mbedtls_x509write_crt_set_key_usage(&crt, opt->key_usage))
			goto clean;
	}

	if (opt->ns_cert_type)
	{
		if (ret = mbedtls_x509write_crt_set_ns_cert_type(&crt, opt->ns_cert_type))
			goto clean;
	}

	//Write cert
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers, strlen(pers))) != 0)
		goto clean;

	ret = mbedtls_x509write_crt_der(&crt, buf, sizeof(buf), mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret < 0)
		goto clean;

	//Output
	if (opt->output_file)
	{
		if (strlen(opt->output_file))
		{
			fp = fopen(opt->output_file, "wb");
			if (fp)
			{
				fwrite(buf + sizeof(buf) - ret, 1, ret, fp);
				fclose(fp);
			}
		}
	}
	if (cert && len)
	{
		memcpy(cert, buf + sizeof(buf) - ret, ret);
		*len = ret;
	}

	ret = 0;

clean:
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&loaded_subject_key);
	mbedtls_pk_free(&loaded_issuer_key);
	mbedtls_mpi_free(&serial);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509_csr_free(&csr);
	mbedtls_x509_crt_free(&issuer_crt);
	return ret;
}