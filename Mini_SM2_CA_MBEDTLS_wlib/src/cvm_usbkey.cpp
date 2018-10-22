/** ****************************************************************************
* @copyright						CVM
*               Copyright (c) 2017 - 2018 All Rights Reserved
********************************************************************************
* @file     cvm_usbkey.
* @author   cong.peng <cong.peng@cvchip.com>
* @date     2017-5-15 17:09:24
* @version  v1.0
* @brief    CVM UsbKey SDK Source File
* @defgroup
* @{
*******************************************************************************/
#include <string.h>

#include "cvm_usbkey.h"

#include "mbedtls\config.h"
#include "mbedtls\platform.h"
#include "mbedtls\x509.h"
#include "mbedtls\x509_crt.h"
#include "mbedtls\ecp.h"
#include "mbedtls\sm2.h"

#include "ukeyapi\MSCUKeyAPI.h"

#define CVM_MAX_PIN_LEN		20
#define CVM_MIN_PIN_LEN		6


static	int MSCReader = 0;

static	int VerifyUserPinStatus = 0;	//0表示未验证，1表示已验证
static	int VerifyAdminPinStatus = 0;

int CVM_OpenDevice()
{
	if (!MSC_ConnectReader())
	{
		VerifyUserPinStatus = 0;
		VerifyAdminPinStatus = 0;
		return CVM_OK;
	}
	else
		return CVM_FAIL;
}

int CVM_CloseDevice()
{
	if (!MSC_DisConnectReader())
	{
		VerifyUserPinStatus = 0;
		VerifyAdminPinStatus = 0;
		return CVM_OK;
	}
	else
		return CVM_FAIL;
}

int CVM_ParseCert_Name(unsigned char *cert, int cert_len, 
	int type, const char *attr, 
	char *name, int name_len)
{
	int ret = CVM_OK;
	char buf[100];
	int len = 0;
	mbedtls_x509_crt crt;
	mbedtls_x509_name	*dn;
	char *p, *t;

	if (!cert || !attr || !name)
		return CVM_ERR_BAD_INPUT_DATA;

	mbedtls_x509_crt_init(&crt);

	//parse cert
	if (ret = mbedtls_x509_crt_parse(&crt, cert, cert_len))
	{
		ret = CVM_ERR_CERT_PARSE_FAILED;
		goto end;
	}

	if (type)//issuer Name
		dn = &crt.issuer;
	else//subject Name
		dn = &crt.subject;

	//find attribute
	len = mbedtls_x509_dn_gets(buf, 100, &crt.subject);
	if (len == 0)
	{
		ret = CVM_ERR_CERT_PARSE_FAILED;
		goto end;
	}

	p = buf;
	while (p < buf + len)
	{
		if (p = strstr(p, attr))
		{
			p += strlen(attr);
			if (*p == '=')
			{
				p++;
				break;
			}
		}
		else
		{
			ret = CVM_ERR_CERT_PARSE_FAILED;
			goto end;
		}
	}

	t = strchr(p, ',');
	if (!t)
		t = buf + len;

	if (name_len < t - p)
	{
		ret = CVM_ERR_BUFFER_TOO_SMALL;
		goto end;
	}

	//set name value
	memcpy(name, p, t - p);
	name[t - p] = '\0';

end:
	mbedtls_x509_crt_free(&crt);
	return ret;
}

int CVM_ParseCert_PubKey(unsigned char *cert, int cert_len, unsigned char *pubkey, int *pk_len)
{
	int ret = CVM_OK;
	size_t len = 0;
	mbedtls_x509_crt crt;
	mbedtls_ecp_keypair	*pk;

	if (!cert || !pk_len)
		return CVM_ERR_BAD_INPUT_DATA;

	mbedtls_x509_crt_init(&crt);

	//parse cert
	if (ret = mbedtls_x509_crt_parse(&crt, cert, cert_len))
	{
		ret = CVM_ERR_CERT_PARSE_FAILED;
		goto end;
	}

	pk = mbedtls_pk_ec(crt.pk);
	mbedtls_ecp_point_write_binary(&pk->grp, &pk->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pubkey, 0);
	if (pubkey == NULL)
	{
		*pk_len = len;
		ret = CVM_OK;
		goto end;
	}
	if (*pk_len < len)
	{
		*pk_len = len;
		ret = CVM_ERR_BUFFER_TOO_SMALL;
		goto end;
	}

	ret = mbedtls_ecp_point_write_binary(&pk->grp, &pk->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pubkey, len);
	*pk_len = len;

end:
	mbedtls_x509_crt_free(&crt);
	return ret;
}

int CVM_ParseCert_Validity(unsigned char *cert, int cert_len, char *not_befor, char *not_after)
{
	int ret = CVM_OK;
	size_t len = 0;
	mbedtls_x509_crt crt;

	if (!cert || !not_befor || !not_after)
		return CVM_ERR_BAD_INPUT_DATA;

	mbedtls_x509_crt_init(&crt);

	//parse cert
	if (ret = mbedtls_x509_crt_parse(&crt, cert, cert_len))
	{
		ret = CVM_ERR_CERT_PARSE_FAILED;
		goto end;
	}

	sprintf(not_befor, "%4d-%2d-%2d %2d:%2d:%2d",
		crt.valid_from.year, crt.valid_from.mon,
		crt.valid_from.day,  crt.valid_from.hour,
		crt.valid_from.min,  crt.valid_from.sec);

	sprintf(not_after, "%4d-%2d-%2d %2d:%2d:%2d",
		crt.valid_to.year, crt.valid_to.mon,
		crt.valid_to.day,  crt.valid_to.hour,
		crt.valid_to.min,  crt.valid_to.sec);

end:
	mbedtls_x509_crt_free(&crt);
	return ret;
}

int CVM_ParseCert_Signature(unsigned char *cert, int cert_len, unsigned char *sign, int *sign_len)
{
	int ret = CVM_OK;
	size_t len = 0;
	mbedtls_x509_crt crt;
	mbedtls_mpi r, s;
	unsigned char *p, *end;

	if (!cert)
		return CVM_ERR_BAD_INPUT_DATA;

	*sign_len = 64;
	if (!sign)
		return CVM_OK;

	mbedtls_x509_crt_init(&crt);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	//parse cert
	if (ret = mbedtls_x509_crt_parse(&crt, cert, cert_len))
	{
		ret = CVM_ERR_CERT_PARSE_FAILED;
		goto end;
	}

	p = (unsigned char *)crt.sig.p;
	end = crt.sig.p + crt.sig.len;

	if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
	{
		ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto end;
	}

	if (p + len != end)
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA +
			MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
		goto end;
	}

	if ((ret = mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
		(ret = mbedtls_asn1_get_mpi(&p, end, &s)) != 0)
	{
		ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto end;
	}

	mbedtls_mpi_write_binary(&r, sign, 32);
	mbedtls_mpi_write_binary(&s, sign + 32, 32);
	*sign_len = 64;

end:
	mbedtls_x509_crt_free(&crt);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return ret;
}

int CVM_VerifyCert(unsigned char *cert, int cert_len, unsigned char *trust_ca, int tca_len)
{
	int ret = CVM_OK;
	mbedtls_x509_crt crt;
	mbedtls_x509_crt ca;
	unsigned int flags;

	if (!cert)
		return CVM_ERR_BAD_INPUT_DATA;

	mbedtls_x509_crt_init(&crt);
	mbedtls_x509_crt_init(&ca);

	//parse cert
	if (ret = mbedtls_x509_crt_parse(&crt, cert, cert_len))
	{
		ret = CVM_ERR_CERT_PARSE_FAILED;
		goto end;
	}
	if (ret = mbedtls_x509_crt_parse(&ca, trust_ca, tca_len))
	{
		ret = CVM_ERR_CERT_PARSE_FAILED;
		goto end;
	}

	if ((ret = mbedtls_x509_crt_verify(&crt, &ca, NULL, NULL, &flags, NULL, NULL)) != 0)
	{
		ret = CVM_ERR_CERT_VERIFY_FAILED;
		goto end;
	}

end:
	mbedtls_x509_crt_free(&crt);
	mbedtls_x509_crt_free(&ca);
	return ret;
}

int CVM_GetChallenge(unsigned char *rand, int rand_len)
{
	WORD dwRet;

	if (!rand || rand_len > 256)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_GetChallenge(rand, (BYTE)rand_len);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_VerifyAdminPin(unsigned char *pin, int pin_len)
{
	WORD dwRet;

	if (!pin || pin_len > CVM_MAX_PIN_LEN || pin_len < CVM_MIN_PIN_LEN)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_VerifyAdminPIN(pin, (BYTE)pin_len);
	if (dwRet != 0x9000)
	{
		VerifyAdminPinStatus = 0;
		return (CVM_ERR | dwRet);
	}
	else
	{
		VerifyAdminPinStatus = 1;
		return CVM_OK;
	}
}

int CVM_VerifyUserPin(unsigned char *pin, int pin_len)
{
	WORD dwRet;

	if (!pin || pin_len > CVM_MAX_PIN_LEN || pin_len < CVM_MIN_PIN_LEN)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_VerifyUserPIN(pin, (BYTE)pin_len);
	if (dwRet != 0x9000)
	{
		VerifyUserPinStatus = 0;
		return (CVM_ERR | dwRet);
	}
	else
	{
		VerifyUserPinStatus = 1;
		return CVM_OK;
	}
}

int CVM_ChangeAdminPIN(unsigned char *oldpin, int opin_len, unsigned char *newpin, int npin_len)
{
	WORD dwRet;

	if (!oldpin || opin_len > CVM_MAX_PIN_LEN || opin_len < CVM_MIN_PIN_LEN ||
		!newpin || npin_len > CVM_MAX_PIN_LEN || npin_len < CVM_MIN_PIN_LEN)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_ChangeAdminPIN(oldpin, (BYTE)opin_len, newpin, (BYTE)npin_len);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		VerifyAdminPinStatus = 0;
		return CVM_OK;
	}
}

int CVM_ChangeUserPIN(unsigned char *oldpin, int opin_len, unsigned char *newpin, int npin_len)
{
	WORD dwRet;

	if (!oldpin || opin_len > CVM_MAX_PIN_LEN || opin_len < CVM_MIN_PIN_LEN ||
		!newpin || npin_len > CVM_MAX_PIN_LEN || npin_len < CVM_MIN_PIN_LEN)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!VerifyAdminPinStatus)
		return CVM_ERR_PIN_STATUS;

	dwRet = MSC_ChangeUserPIN(oldpin, (BYTE)opin_len, newpin, (BYTE)npin_len);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		VerifyUserPinStatus = 0;
		return CVM_OK;
	}
}

int CVM_ResetUserPIN(unsigned char *pin, int pin_len)
{
	WORD dwRet;

	if (!pin || pin_len > CVM_MAX_PIN_LEN || pin_len < CVM_MIN_PIN_LEN)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!VerifyAdminPinStatus)
		return CVM_ERR_PIN_STATUS;

	dwRet = MSC_ResetUserPIN(pin, (BYTE)pin_len);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		VerifyUserPinStatus = 0;
		return CVM_OK;
	}
}

int CVM_SM2SignHash(unsigned char *hash, int hash_len, unsigned char *sign, int *sign_len)
{
	WORD dwRet;

	if (!hash || hash_len <= 0 || !sign || !sign_len)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!VerifyUserPinStatus)
		return CVM_ERR_SIGN;

	dwRet = MSC_SM2SignHash(hash, (UINT)hash_len, sign, (UINT*)sign_len);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_SM2VerifyHash(unsigned char *hash, int hash_len, unsigned char *pubkey, int pubk_len, unsigned char *sign, unsigned int sign_len)
{
	WORD dwRet;

	if (!hash || hash_len <= 0  || !pubkey || !sign)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!VerifyUserPinStatus)
		return CVM_ERR_SIGN;

	dwRet = MSC_SM2VerifyHash(hash, hash_len, pubkey, pubk_len, sign, sign_len);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_SM2SignData(unsigned char *data, int data_len, unsigned char *sign, unsigned int *sign_len)
{
	int ret = CVM_OK;
	unsigned char	ucPubKey[65];
	unsigned char	e[32];
	mbedtls_ecp_keypair	pk;
	unsigned int pk_len;
	WORD dwRet;

	if (!data || data_len <= 0 || !sign)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!VerifyUserPinStatus)
		return CVM_ERR_SIGN;

	mbedtls_ecp_keypair_init(&pk);

	//memset(ucPubKey, 0, 65);
	ucPubKey[0] = 0x04;
	dwRet = MSC_SM2ExportPubKey(ucPubKey+1, &pk_len);
	if (dwRet != 0x9000)
	{
		ret = CVM_ERR_READ_PUBKEY;
		goto end;
	}

	if ((ret = mbedtls_ecp_group_load(&pk.grp, MBEDTLS_ECP_DP_SM2)) || 
		(ret = mbedtls_ecp_point_read_binary(&pk.grp, &pk.Q, ucPubKey, 65)))
	{
		ret = CVM_ERR_ECP_INVALID_KEY;
		goto end;
	}

	if (ret = mbedtls_sm2_compute_e(MBEDTLS_MD_SM3, NULL, 0, data, data_len, &pk, e))
	{
		ret = CVM_ERR_BAD_INPUT_DATA;
		goto end;
	}

	dwRet = MSC_SM2SignHash(e, 32, sign, sign_len);
	if (dwRet != 0x9000)
	{
		ret = CVM_ERR_SIGN;
		goto end;
	}

end:
	mbedtls_ecp_keypair_free(&pk);
	return ret;
}

int CVM_SM2VerifyData(unsigned char *data, int dlen, unsigned char *pubk, int klen, unsigned char *sign, unsigned int slen)
{
	int ret = CVM_OK;
	unsigned char	ucPubKey[65];
	mbedtls_ecp_keypair	pk;
	unsigned char	e[32];
	mbedtls_mpi	r, s;

	if (!data || dlen <= 0 || !sign || slen > 64)
		return CVM_ERR_BAD_INPUT_DATA;

	if (klen == 65)
	{
		memcpy(ucPubKey, pubk, 65);
	}
	else if (klen == 64)
	{
		ucPubKey[0] = 0x04;
		memcpy(ucPubKey + 1, pubk, 64);
	}
	else
		return CVM_ERR_ECP_INVALID_KEY;

	mbedtls_ecp_keypair_init(&pk);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if ((ret = mbedtls_ecp_group_load(&pk.grp, MBEDTLS_ECP_DP_SM2)) ||
		(ret = mbedtls_ecp_point_read_binary(&pk.grp, &pk.Q, ucPubKey, 65)))
	{
		ret = CVM_ERR_ECP_INVALID_KEY;
		goto end;
	}

	if (ret = mbedtls_sm2_compute_e(MBEDTLS_MD_SM3, NULL, 0, data, dlen, &pk, e))
	{
		ret = CVM_ERR_BAD_INPUT_DATA;
		goto end;
	}

	if ((ret = mbedtls_mpi_read_binary(&r, sign, 32)) || 
		(ret = mbedtls_mpi_read_binary(&s, sign + 32, 32)))
	{
		ret = CVM_ALLOC_FAILED;
		goto end;
	}

	if (ret = mbedtls_sm2_verify_hash(&pk.grp, e, 32, &pk.Q, &r, &s))
	{
		ret = CVM_ERR_VERIFY;
		goto end;
	}

end:
	mbedtls_ecp_keypair_free(&pk);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return ret;
}

int CVM_SM2GenKey()
{
	WORD dwRet;

	if (!VerifyUserPinStatus)
		return CVM_ERR_PIN_STATUS;

	dwRet = MSC_SM2GenKey();
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_SM2ImportKeyPairToFile(unsigned char *pubkey, int pubk_len, unsigned char *prikey, int prik_len)
{
	WORD dwRet;

	if (!pubkey || !prikey)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!VerifyUserPinStatus)
		return CVM_ERR_PIN_STATUS;

	dwRet = MSC_SM2ImportKeyPairToFile(pubkey, (UINT)pubk_len, prikey, (UINT)prik_len);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_SM2Encrypt(unsigned char *plain, int plen, unsigned char *pubkey, int klen, unsigned char *cipher, int *clen)
{
	WORD dwRet;

	if (!plain || plen > 256 || !pubkey || !cipher || !clen)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_SM2Encrypt(plain, (BYTE)plen, pubkey, (UINT)klen, cipher, (UINT*)(clen));
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_SM2Decrypt(unsigned char *cipher, int clen, unsigned char *plain, int *plen)
{
	WORD dwRet;

	if (!cipher || !plain || !plen)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_SM2Decrypt(cipher, (BYTE)clen, plain, (UINT*)plen);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_SM3Hash(unsigned char *message, int mlen, unsigned char *hash, int *hlen)
{
	WORD dwRet;

	if (!message || !hlen)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!hash)
	{
		*hlen = 32;
		return CVM_OK;
	}

	dwRet = MSC_SM3Hash(message, (UINT)mlen, hash, (UINT*)hlen);
	if (dwRet != 0x9000)
	{
		return (CVM_ERR | dwRet);
	}
	else
	{
		return CVM_OK;
	}
}

int CVM_SM3Init(unsigned char *message, int mlen)
{
	WORD dwRet;
	int len;

	if (!message)
		mlen = 0;

	len = (mlen > 240) ? 240 : mlen;
	dwRet = MSC_SM3Init(message, (BYTE)len);
	message += len;
	mlen -= len;

	while (mlen)
	{
		len = (mlen > 240) ? 240 : mlen;
		dwRet = MSC_SM3Update(message, (BYTE)len);
		message += len;
		mlen -= len;
	}
	if (dwRet != 0x9000)
		return (CVM_ERR | dwRet);
	else
		return CVM_OK;
}

int CVM_SM3Update(unsigned char *message, int mlen)
{
	WORD dwRet;
	int len;

	if (!message)
		return CVM_ERR_BAD_INPUT_DATA;

	while (mlen)
	{
		len = (mlen > 240) ? 240 : mlen;
		dwRet = MSC_SM3Update(message, (BYTE)len);
		message += len;
		mlen -= len;
	}
	if (dwRet != 0x9000)
		return (CVM_ERR | dwRet);
	else
		return CVM_OK;
}

int CVM_SM3Final(unsigned char *message, int mlen, unsigned char *hash, int *hlen)
{
	WORD dwRet;
	int len;

	if (!hash)
	{
		*hlen = 32;
		return CVM_OK;
	}

	if (!message)
		mlen = 0;
	while (mlen > 240)
	{
		len = (mlen > 240) ? 240 : mlen;
		dwRet = MSC_SM3Update(message, (BYTE)len);
		message += len;
		mlen -= len;
	}

	len = (mlen > 240) ? 240 : mlen;
	dwRet = MSC_SM3Final(message, (BYTE)len, hash, (UINT*)hlen);
	message += len;
	mlen -= len;

	if (dwRet != 0x9000)
		return (CVM_ERR | dwRet);
	else
		return CVM_OK;
}

int CVM_SM2ExportPubKey(unsigned char *pubk, int *plen)
{
	int ret = CVM_OK;
	WORD dwRet;

	dwRet = MSC_SM2ExportPubKey(pubk, (UINT*)plen);
	if (dwRet != 0x9000)
	{
		ret = CVM_ERR_READ_PUBKEY;
		goto end;
	}

end:
	return ret;
}

int CVM_ReadCert(unsigned char *cert, int *cert_len)
{
	int ret = CVM_OK;
	WORD dwRet;
	UINT uiClen;

	if (!cert_len)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_ReadCert(NULL, &uiClen);
	if (dwRet != 0x9000)
	{
		ret = CVM_ERR_READ_CERT;
		goto end;
	}
	if (cert == NULL)
	{
		*cert_len = uiClen;
		ret = CVM_OK;
		goto end;
	}
	if (*cert_len < uiClen)
	{
		ret = CVM_ERR_BUFFER_TOO_SMALL;
		goto end;
	}
	dwRet = MSC_ReadCert(cert, &uiClen);
	if (dwRet != 0x9000)
	{
		ret = CVM_ERR_READ_CERT;
		goto end;
	}
	*cert_len = uiClen;

end:
	return ret;
}

int CVM_WriteCert(unsigned char *cert, int cert_len)
{
	int ret = CVM_OK;
	WORD dwRet;

	if (!cert || cert_len > 4096)
		return CVM_ERR_BAD_INPUT_DATA;

	if (!VerifyUserPinStatus)
		return CVM_ERR_SIGN;

	dwRet = MSC_WriteCert(cert, cert_len);
	if (dwRet != 0x9000)
		return (CVM_ERR | dwRet);
	else
		return CVM_OK;

end:
	return ret;
}

int CVM_SBCWriteKeyToFile(unsigned char KeyIndex, unsigned char *key, int klen)
{
	WORD dwRet;

	if (!key)
		return CVM_ERR_BAD_INPUT_DATA;

	dwRet = MSC_SBCWriteKeyToFile(KeyIndex, key, (BYTE)klen);
	if (dwRet != 0x9000)
		return (CVM_ERR | dwRet);
	else
		return CVM_OK;
}

int CVM_SBCInit(unsigned char AlgFlag, unsigned char KeyIndex, unsigned char *key, int klen)
{
	WORD dwRet;

	if (key)
	{
		if (AlgFlag != CVM_ALG_SM1 && AlgFlag != CVM_ALG_SM4)
			return CVM_ERR_BAD_INPUT_DATA;
		dwRet = MSC_SBCInitFromData(AlgFlag, key, klen);
	}
	else
	{
		if (KeyIndex != CVM_KEY_SM1 && AlgFlag != CVM_KEY_SM4)
			return CVM_ERR_BAD_INPUT_DATA;
		dwRet = MSC_SBCInitFromKeyFile(KeyIndex);
	}
	if (dwRet != 0x9000)
		return (CVM_ERR | dwRet);
	else
		return CVM_OK;
}

int CVM_SBCDone(unsigned char type, unsigned char *iv, unsigned char *indata, int ilen, unsigned char *outdata, int *olen)
{
	WORD dwRet;
	int len1, len2;

	*olen = 0;
	switch (type)
	{
	case CVM_SBC_ECB_E:
		dwRet = MSC_SBCEncryptECB(indata, ilen, outdata, (UINT*)olen);
		break;
	case CVM_SBC_ECB_D:
		dwRet = MSC_SBCDecryptECB(indata, ilen, outdata, (UINT*)olen);
		break;
	case CVM_SBC_CBC_E:
		if (iv)
			dwRet = MSC_SBCEncryptCBC(iv, indata, ilen, outdata, (UINT*)olen);
		else
		{
			while (ilen)
			{
				len1 = (ilen > 224) ? 224 : ilen;
				dwRet = MSC_SBCEncryptCBCUpdate(indata, len1, outdata, (UINT*)(&len2));
				indata += len1;		ilen -= len1;
				outdata += len2;	*olen += len2;
				if (dwRet != 0x9000)
					break;
			}
		}
		break;
	case CVM_SBC_CBC_D:
		if (iv)
			dwRet = MSC_SBCDecryptCBC(iv, indata, ilen, outdata, (UINT*)olen);
		else
		{
			while (ilen)
			{
				len1 = (ilen > 224) ? 224 : ilen;
				dwRet = MSC_SBCDecryptCBCUpdate(indata, len1, outdata, (UINT*)(&len2));
				indata += len1;		ilen -= len1;
				outdata += len2;	*olen += len2;
				if (dwRet != 0x9000)
					break;
			}
		}
		break;
	default:
		return CVM_FAIL;
		break;
	}
	if (dwRet != 0x9000)
		return (CVM_ERR | dwRet);
	else
		return CVM_OK;
}