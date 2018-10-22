#ifndef __SM2CERT_H__
#define __SM2CERT_H__

#include <windows.h>
#include <WinCrypt.h>
#include "sm2.h"
#include "sm3.h"
#include "IS_Base64.h"
#include "sm2p10.h"

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define SM2_CERT_OK					0
#define SM2_CERT_MALLOC_ERROR		1
#define SM2_CERT_DECODE_ERROR		2
#define SM2_CERT_ENCODE_ERROR		3

#define SM2_CERT_P10_INVALID		4

#ifdef __cplusplus
extern "C" {
#endif

	int SM2CERT_GetND(
		BYTE *pbCerBuf, 
		DWORD cbCerBuf, 
		char *pszND, 
		DWORD *cszND
		);
	int SM2CERT_GetPubKey(
		BYTE *pbCerBuf, 
		DWORD cbCerBuf, 
		char *pbPubKey, 
		DWORD *cbPubKey);

	int SM2CERT_GenND(
		char *pszDN, 
		BYTE *pbND, 
		DWORD *cbND
		);
	int SM2CERT_GenSerialEncoded(
		int iSerial, 
		BYTE *pbSerialEncoded, 
		DWORD *cbSerialEncoded
		);
	int SM2CERT_GenBodyEncoded(
		BYTE *pbUserND, 
		DWORD cbUserND, 
		BYTE *pbIssuerND, 
		DWORD cbIssuerND,
		BYTE *pbPubKey, 
		DWORD cbPubKey,
		BYTE *pbSerialEncoded, 
		DWORD cbSerialEncoded,
		BYTE *pbBodyEncoded, 
		DWORD *cbBodyEncoded
		);
	int SM2CERT_GenBodyEncoded_Root(BYTE *pbUserND, 
		DWORD cbUserND, 
		BYTE *pbIssuerND, 
		DWORD cbIssuerND,
		BYTE *pbPubKey, 
		DWORD cbPubKey,
		BYTE *pbSerialEncoded, 
		DWORD cbSerialEncoded,
		BYTE *pbBodyEncoded, 
		DWORD *cbBodyEncoded);

	int SM2CERT_GenSigEncoded(
		BYTE *pbSignature, 
		DWORD cbSignature, 
		BYTE *pbSigEncoded, 
		DWORD *cbSigEncoded
		);
	int SM2CERT_GenCertEncoded(
		BYTE *pbBodyEncoded, 
		DWORD cbBodyEncoded, 
		BYTE *pbSigEncoded, 
		DWORD cbSigEncoded,
		BYTE *pbCertEncoded, 
		DWORD *cbCertEncoded
		);

	int SM2CERT_GenRootCert(char *pszDN,
		int iSerial,
		BYTE *pbRootPubKey, 
		DWORD cbRootPubKey, 
		BYTE *pbRootPriKey, 
		DWORD cbRootPriKey, 
		char *pszCert, 
		DWORD *pcbCert);
	int SM2CERT_GenUserCert(char *pszUserDN,
		char *pszRootDN,
		int iSerial,
		BYTE *pbUserPubKey, 
		DWORD cbUserPubKey, 
		BYTE *pbRootPriKey, 
		DWORD cbRootPriKey, 
		BYTE *pbRootPubKey, 
		DWORD cbRootPubKey,
		char *pszCert, 
		DWORD *pcbCert);

	int SM2CERT_UKeyGenRootCert(
		LPSTR CSPName,
		LPSTR Container,
		char *pszRootDN,
		int iSerial,
		BYTE *pbRootPubKey, 
		DWORD cbRootPubKey,
		char *pszCert, 
		DWORD *pcbCert);


#ifdef __cplusplus
}
#endif

#endif