#ifndef __SM2P10_H__
#define __SM2P10_H__

#include <windows.h>
#include <WinCrypt.h>
#include "sm2.h"
#include "sm3.h"
#include "IS_Base64.h"

#define CALG_SM3		  (ALG_CLASS_HASH| ALG_TYPE_ANY | ALG_SID_SM3)
#define ALG_SID_SM3		  15
#define CALG_SM2_SIGN     (ALG_CLASS_SIGNATURE    | ALG_TYPE_SM2 | ALG_SID_SM2_ANY)
#define CALG_SM2_KEYX     (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_SM2 | ALG_SID_SM2_ANY)
#define ALG_TYPE_SM2      (15 << 9)
#define ALG_SID_SM2_ANY   0

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define SM2_P10_OK					0
#define SM2_P10_MALLOC_ERROR		1
#define SM2_P10_DECODE_ERROR		2
#define SM2_P10_ENCODE_ERROR		3

#define SM2_P10_P10_INVALID		4

#ifdef __cplusplus
extern "C" {
#endif

	int SM2P10_GetReq(char *pcCertData, DWORD ccCertData, BYTE *pbReqData, DWORD *cbReqData);
	int SM2P10_GetBodyEncoded(BYTE *pbReqData, DWORD cbReqData, BYTE *pbBodyEncoded, DWORD *cbBodyEncoded);
	int SM2P10_GetSigEncoded(BYTE *pbReqData, DWORD cbReqData, BYTE *pbSigEncoded, DWORD *cbSigEncoded);
	int SM2P10_GetAlgorithm(BYTE *pbReqData, DWORD cbReqData, char *pbAlgName, DWORD *cbAlgName, char *pbAlgParams, DWORD *cbAlgParams);

	int SM2P10_GetBodyDecoded(BYTE *pbBodyEncoded, DWORD cbBodyEncoded, BYTE *pbBodyDecoded, DWORD *cbBodyDecoded);
	int SM2P10_GetND(BYTE *pbBodyDecoded, DWORD cbBodyDecoded, char *pbND, DWORD *cbND);
	int SM2P10_GetPubKey(BYTE *pbBodyDecoded, DWORD cbBodyDecoded, BYTE *pbPubKey, DWORD *cbPubKey);

	int SM2P10_GetSigDecoded(BYTE *pbSigEncoded, DWORD cbSigEncoded, BYTE *pbSigDecoded, DWORD *cbSigDecoded);
	int SM2P10_GetSignature(BYTE *pbSigDecoded, DWORD cbSigDecoded, BYTE *pbSignature, DWORD *cbSignature);

	int SM2P10_VerfiyP10(char *pSTRP10,DWORD cSTRP10);
	int SM2P10_VerfiyP10_Ex(char *pSTRP10,
		DWORD cSTRP10, 
		char *pszND, 
		DWORD *cszND, 
		BYTE *pbPubKey, 
		DWORD *cbPubKey
		);

	int SM2P10_GenND(char *pszDN, BYTE *pbND, DWORD *cbND);
	int SM2P10_GenBodyEncoded(BYTE *pbND, DWORD cbND, BYTE *pbPubKey, DWORD cbPubKey,BYTE *pbBodyEncoded, DWORD *cbBodyEncoded);
	int SM2P10_GenSigEncoded(BYTE *pbSignature, DWORD cbSignature, BYTE *pbSigEncoded, DWORD *cbSigEncoded);
	int SM2P10_GenReqEncoded(BYTE *pbBodyEncoded, DWORD cbBodyEncoded, BYTE *pbSigEncoded, DWORD cbSigEncoded,BYTE *pbReqEncoded, DWORD *cbReqEncoded);
	int SM2P10_GenP10(char *pszDN, BYTE *pbPubKey, DWORD cbPubKey, BYTE *pbPriKey, DWORD cbPriKey, char *pszP10, DWORD *pcbP10);

	int SM2P10_UKeyGenP10(LPSTR CSPName,LPSTR Container,char *pszDN,char *pszP10,DWORD *pcbP10);
	void  DWKeyGenGUID(char *strGUID);
	DWORD DWKeyGetContianerPublicKey(LPSTR CSPName,LPSTR Container,PBYTE pbPublicKey);
	DWORD DWKeySM2Sign(LPSTR CSPName,LPSTR Container,PBYTE bMessage,DWORD dwMessageLen,PBYTE pbSign,PDWORD pdwSignLen);
	DWORD DWKeySM2SignZ(LPSTR CSPName,LPSTR Container,PBYTE bMessage,DWORD dwMessageLen,PBYTE pbSign,PDWORD pdwSignLen);
	DWORD DWKeySM2WriteCert(LPSTR CSPName,LPSTR Container,PBYTE bCert);

	void SM3HashZ(PBYTE bMessage,DWORD dwMessageLen,PBYTE bPubKey,DWORD dwPubKeyLen,PBYTE pbDigest,PDWORD pdwDigestLen);

	

#ifdef __cplusplus
}
#endif

#endif