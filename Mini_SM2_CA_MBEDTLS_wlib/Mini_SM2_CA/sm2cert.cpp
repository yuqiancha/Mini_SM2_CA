#include "sm2cert.h"
//////////////////////////////////////////////////////////////////////////
//输入pbCer信息,得到pszDN
int SM2CERT_GetND(BYTE *pbCerBuf, DWORD cbCerBuf, char *pszND, DWORD *cszND)
{
	PCCERT_CONTEXT pCert = NULL;
	char szND_tmp[500];
	DWORD cszND_tmp = 500;

	if((pCert = CertCreateCertificateContext(MY_ENCODING_TYPE,pbCerBuf,(DWORD)cbCerBuf)) == NULL)
	{
		return SM2_CERT_DECODE_ERROR;
	}

	if ( pszND == NULL )
	{
		cszND_tmp = CertNameToStr(MY_ENCODING_TYPE, &(pCert->pCertInfo->Subject), CERT_X500_NAME_STR, NULL, 0);
		*cszND = cszND_tmp;
		return SM2_P10_OK;
	}

	memset(szND_tmp, 0, sizeof(szND_tmp));
	if ( (*cszND) != 0)
	{
		cszND_tmp = *cszND;
	}

	CertNameToStr(MY_ENCODING_TYPE, &(pCert->pCertInfo->Subject), CERT_X500_NAME_STR, szND_tmp, cszND_tmp);
	strcpy(pszND, szND_tmp);

	return SM2_P10_OK;

}

int SM2CERT_GetPubKey(BYTE *pbCerBuf, DWORD cbCerBuf, char *pbPubKey, DWORD *cbPubKey)
{
	PCCERT_CONTEXT pCert = NULL;
	char szND_tmp[500];
	DWORD cszND_tmp = 500;

	if((pCert = CertCreateCertificateContext(MY_ENCODING_TYPE,pbCerBuf,(DWORD)cbCerBuf)) == NULL)
	{
		return SM2_CERT_DECODE_ERROR;
	}

	*cbPubKey = pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;

	memcpy(pbPubKey, pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, *cbPubKey);

	return SM2_P10_OK;
}

//////////////////////////////////////////////////////////////////////////
//输入pbND信息,得到pbND
int SM2CERT_GenND(char *pszDN, BYTE *pbND, DWORD *cbND)
{
	if ( pbND == NULL )
	{
		if( !(CertStrToName(
			MY_ENCODING_TYPE,
			pszDN, 
			CERT_X500_NAME_STR,
			NULL,
			NULL,          
			cbND,     
			NULL )))
		{
			return SM2_CERT_ENCODE_ERROR;
		}
		return SM2_CERT_OK;
	}

	if( !(CertStrToName(
		MY_ENCODING_TYPE,
		pszDN, 
		CERT_X500_NAME_STR,
		NULL,
		pbND,          
		cbND,     
		NULL )))
	{
		return SM2_CERT_ENCODE_ERROR;
	}

	return SM2_CERT_OK;	
}

//////////////////////////////////////////////////////////////////////////
//输入Serial信息,得到pbSerialEncoded
int SM2CERT_GenSerialEncoded(int iSerial, BYTE *pbSerialEncoded, DWORD *cbSerialEncoded)
{
	if ( pbSerialEncoded == NULL )
	{
		if (!CryptEncodeObjectEx(MY_ENCODING_TYPE, X509_INTEGER, &iSerial, 0, NULL, NULL, cbSerialEncoded))
		{
			return SM2_CERT_ENCODE_ERROR;
		}
		return SM2_CERT_OK;
	}
	if (!CryptEncodeObjectEx(MY_ENCODING_TYPE, X509_INTEGER, &iSerial, 0, NULL, pbSerialEncoded, cbSerialEncoded))
	{
		return SM2_CERT_ENCODE_ERROR;
	}

	return SM2_CERT_OK;

}
//////////////////////////////////////////////////////////////////////////
//输入pbUserND,pbPubKey,pbSerialEncoded,pbIssuerND得到pbBodyEncoded
int SM2CERT_GenBodyEncoded_Root(BYTE *pbUserND, 
						   DWORD cbUserND, 
						   BYTE *pbIssuerND, 
						   DWORD cbIssuerND,
						   BYTE *pbPubKey, 
						   DWORD cbPubKey,
						   BYTE *pbSerialEncoded, 
						   DWORD cbSerialEncoded,
						   BYTE *pbBodyEncoded, 
						   DWORD *cbBodyEncoded)
{
	CERT_INFO		certinfo;
	SYSTEMTIME      stLocal;
	FILETIME        ftBefore,ftAfter;
	CHAR oid_sm2[]="1.2.156.10197.1.301";
	CHAR oid_sm2_sm3[]="1.2.156.10197.1.501";
	CHAR oid_ecc[]="1.2.840.10045.2.1";

	certinfo.dwVersion=CERT_V3;

	certinfo.rgExtension=0;
	certinfo.Subject.pbData=pbUserND;
	certinfo.Subject.cbData=cbUserND;

	certinfo.Issuer.pbData=pbIssuerND;
	certinfo.Issuer.cbData=cbIssuerND;

	certinfo.SubjectPublicKeyInfo.PublicKey.cbData=cbPubKey;
	certinfo.SubjectPublicKeyInfo.PublicKey.pbData=pbPubKey;
	certinfo.SubjectPublicKeyInfo.PublicKey.cUnusedBits=0;


	BYTE para[10]={0x06,0x08,0x2a,0x81,0x1c,0xcf,0x55,0x01,0x82,0x2d};
	certinfo.SubjectPublicKeyInfo.Algorithm.Parameters.cbData=10;
	certinfo.SubjectPublicKeyInfo.Algorithm.Parameters.pbData=para;
	certinfo.SubjectPublicKeyInfo.Algorithm.pszObjId=oid_ecc;


	certinfo.cExtension=0;
	certinfo.SignatureAlgorithm.pszObjId=oid_sm2_sm3;
	certinfo.SignatureAlgorithm.Parameters.cbData=0;
	certinfo.SignatureAlgorithm.Parameters.pbData=0;

	certinfo.IssuerUniqueId.cbData=0;
	certinfo.SubjectUniqueId.cbData=0;

	certinfo.SerialNumber.cbData=cbSerialEncoded;
	certinfo.SerialNumber.pbData=pbSerialEncoded;

	GetSystemTime(&stLocal); 
	SystemTimeToFileTime(&stLocal, &ftBefore);
	certinfo.NotBefore.dwLowDateTime=ftBefore.dwLowDateTime;
	certinfo.NotBefore.dwHighDateTime=ftBefore.dwHighDateTime;
	stLocal.wYear+=20;
	SystemTimeToFileTime(&stLocal, &ftAfter);
	certinfo.NotAfter.dwLowDateTime=ftAfter.dwLowDateTime;
	certinfo.NotAfter.dwHighDateTime=ftAfter.dwHighDateTime;

	if ( pbBodyEncoded == NULL )
	{
		if( !CryptEncodeObjectEx(
			MY_ENCODING_TYPE,        // the encoding/decoding type
			X509_CERT_TO_BE_SIGNED,    
			&certinfo,
			0,                 
			NULL, 
			NULL,
			cbBodyEncoded))
		{
			return SM2_CERT_ENCODE_ERROR;
		}
		return SM2_CERT_OK;
	}

	if( !CryptEncodeObjectEx(
		MY_ENCODING_TYPE,        // the encoding/decoding type
		X509_CERT_TO_BE_SIGNED,    
		&certinfo,
		0,                 
		NULL, 
		pbBodyEncoded,
		cbBodyEncoded))
	{
		return SM2_CERT_ENCODE_ERROR;
	}
	return SM2_CERT_OK;
}

//////////////////////////////////////////////////////////////////////////
//输入pbUserND,pbPubKey,pbSerialEncoded,pbIssuerND得到pbBodyEncoded
int SM2CERT_GenBodyEncoded(BYTE *pbUserND, 
						   DWORD cbUserND, 
						   BYTE *pbIssuerND, 
						   DWORD cbIssuerND,
						   BYTE *pbPubKey, 
						   DWORD cbPubKey,
						   BYTE *pbSerialEncoded, 
						   DWORD cbSerialEncoded,
						   BYTE *pbBodyEncoded, 
						   DWORD *cbBodyEncoded)
{
	CERT_INFO		certinfo;
	SYSTEMTIME      stLocal;
	FILETIME        ftBefore,ftAfter;
	CHAR oid_sm2[]="1.2.156.10197.1.301";
	CHAR oid_sm2_sm3[]="1.2.156.10197.1.501";
	CHAR oid_ecc[]="1.2.840.10045.2.1";

	certinfo.dwVersion=CERT_V3;

	certinfo.rgExtension=0;
	certinfo.Subject.pbData=pbUserND;
	certinfo.Subject.cbData=cbUserND;

	certinfo.Issuer.pbData=pbIssuerND;
	certinfo.Issuer.cbData=cbIssuerND;

	certinfo.SubjectPublicKeyInfo.PublicKey.cbData=cbPubKey;
	certinfo.SubjectPublicKeyInfo.PublicKey.pbData=pbPubKey;
	certinfo.SubjectPublicKeyInfo.PublicKey.cUnusedBits=0;


	BYTE para[10]={0x06,0x08,0x2a,0x81,0x1c,0xcf,0x55,0x01,0x82,0x2d};
	certinfo.SubjectPublicKeyInfo.Algorithm.Parameters.cbData=10;
	certinfo.SubjectPublicKeyInfo.Algorithm.Parameters.pbData=para;
	certinfo.SubjectPublicKeyInfo.Algorithm.pszObjId=oid_ecc;


	certinfo.cExtension=0;
	certinfo.SignatureAlgorithm.pszObjId=oid_sm2_sm3;
	certinfo.SignatureAlgorithm.Parameters.cbData=0;
	certinfo.SignatureAlgorithm.Parameters.pbData=0;

	certinfo.IssuerUniqueId.cbData=0;
	certinfo.SubjectUniqueId.cbData=0;

	certinfo.SerialNumber.cbData=cbSerialEncoded;
	certinfo.SerialNumber.pbData=pbSerialEncoded;

	GetSystemTime(&stLocal); 
	SystemTimeToFileTime(&stLocal, &ftBefore);
	certinfo.NotBefore.dwLowDateTime=ftBefore.dwLowDateTime;
	certinfo.NotBefore.dwHighDateTime=ftBefore.dwHighDateTime;
	stLocal.wYear+=5;
	SystemTimeToFileTime(&stLocal, &ftAfter);
	certinfo.NotAfter.dwLowDateTime=ftAfter.dwLowDateTime;
	certinfo.NotAfter.dwHighDateTime=ftAfter.dwHighDateTime;

	if ( pbBodyEncoded == NULL )
	{
		if( !CryptEncodeObjectEx(
			MY_ENCODING_TYPE,        // the encoding/decoding type
			X509_CERT_TO_BE_SIGNED,    
			&certinfo,
			0,                 
			NULL, 
			NULL,
			cbBodyEncoded))
		{
			return SM2_CERT_ENCODE_ERROR;
		}
		return SM2_CERT_OK;
	}
	
	if( !CryptEncodeObjectEx(
		MY_ENCODING_TYPE,        // the encoding/decoding type
		X509_CERT_TO_BE_SIGNED,    
		&certinfo,
		0,                 
		NULL, 
		pbBodyEncoded,
		cbBodyEncoded))
	{
		return SM2_CERT_ENCODE_ERROR;
	}
	return SM2_CERT_OK;
}


//////////////////////////////////////////////////////////////////////////
//输入pbSignature,得到pbSigEncoded
int SM2CERT_GenSigEncoded(BYTE *pbSignature, DWORD cbSignature, BYTE *pbSigEncoded, DWORD *cbSigEncoded)
{
	CRYPT_UINT_BLOB R,S;
	CRYPT_SEQUENCE_OF_ANY    rsseq;
	DWORD cbREncoded,cbSEncoded;
	BYTE pbREncoded[100];
	BYTE pbSEncoded[100];

	R.cbData = 32;
	R.pbData = pbSignature;
	if( !CryptEncodeObjectEx(
		MY_ENCODING_TYPE,        // the encoding/decoding type
		X509_MULTI_BYTE_UINT,    
		&R,
		0,                 
		NULL, 
		NULL,
		&cbREncoded))    // fill in the length needed for
		// the encoded buffer
	{
		return SM2_CERT_ENCODE_ERROR;
	}

	if(!CryptEncodeObjectEx(
		MY_ENCODING_TYPE,
		X509_MULTI_BYTE_UINT,
		&R,
		0,
		NULL, 
		pbREncoded,
		&cbREncoded))
	{
		return SM2_CERT_ENCODE_ERROR;
	}

	S.cbData=32;
	S.pbData=pbSignature+32;
	if(!CryptEncodeObjectEx(
		MY_ENCODING_TYPE,        // the encoding/decoding type
		X509_MULTI_BYTE_UINT,    
		&S,
		0,                 
		NULL, 
		NULL,
		&cbSEncoded))    // fill in the length needed for
		// the encoded buffer
	{
		return SM2_CERT_ENCODE_ERROR;
	}

	if(!CryptEncodeObjectEx(
		MY_ENCODING_TYPE,
		X509_MULTI_BYTE_UINT,
		&S,
		0,
		NULL, 
		pbSEncoded,
		&cbSEncoded))
	{
		return SM2_CERT_ENCODE_ERROR;
	}

	rsseq.cValue=2;
	CRYPT_DER_BLOB blobs[2];
	rsseq.rgValue=blobs;

	blobs[0].cbData=cbREncoded;
	blobs[0].pbData=pbREncoded;
	blobs[1].cbData=cbSEncoded;
	blobs[1].pbData=pbSEncoded;

	if ( pbSigEncoded == NULL )
	{
		if( !CryptEncodeObjectEx(
			MY_ENCODING_TYPE,        // the encoding/decoding type
			X509_SEQUENCE_OF_ANY,    
			&rsseq,
			0,                 
			NULL, 
			NULL,
			cbSigEncoded))    // fill in the length needed for
			// the encoded buffer
		{
			return SM2_CERT_ENCODE_ERROR;
		}
		return SM2_CERT_OK;
	}	

	if(!CryptEncodeObjectEx(
		MY_ENCODING_TYPE,
		X509_SEQUENCE_OF_ANY,
		&rsseq,
		0,
		NULL, 
		pbSigEncoded,
		cbSigEncoded))
	{
		return SM2_CERT_ENCODE_ERROR;
	}

	return SM2_CERT_OK;
}

//////////////////////////////////////////////////////////////////////////
//输入pbSigEncoded,pbBodyEncoded得到pbCertEncoded
int SM2CERT_GenCertEncoded(BYTE *pbBodyEncoded, 
						   DWORD cbBodyEncoded, 
						   BYTE *pbSigEncoded, 
						   DWORD cbSigEncoded,
						   BYTE *pbCertEncoded, 
						   DWORD *cbCertEncoded)
{
	CERT_SIGNED_CONTENT_INFO	cert;
	BYTE SigTemp[100];
	DWORD i;

	for(i=0;i<cbSigEncoded;i++)
		SigTemp[i]=pbSigEncoded[cbSigEncoded-1-i];

	cert.ToBeSigned.cbData=cbBodyEncoded;
	cert.ToBeSigned.pbData=pbBodyEncoded;

	cert.Signature.cbData=cbSigEncoded;
	cert.Signature.pbData=SigTemp;
	cert.Signature.cUnusedBits=0;

	cert.SignatureAlgorithm.pszObjId="1.2.156.10197.1.501";
	cert.SignatureAlgorithm.Parameters.cbData=0;
	cert.SignatureAlgorithm.Parameters.pbData=0;

	if ( pbCertEncoded == NULL )
	{
		if(!CryptEncodeObjectEx(
			MY_ENCODING_TYPE,        // the encoding/decoding type
			X509_CERT,    
			&cert,
			0,                 
			NULL, 
			NULL,
			cbCertEncoded))
		{
			return SM2_CERT_ENCODE_ERROR;
		}
		return SM2_CERT_OK;
	}

	if(!CryptEncodeObjectEx(
		MY_ENCODING_TYPE,        // the encoding/decoding type
		X509_CERT,    
		&cert,
		0,                 
		NULL, 
		pbCertEncoded,
		cbCertEncoded))
	{
		return SM2_CERT_ENCODE_ERROR;
	}
	return SM2_CERT_OK;
}

//////////////////////////////////////////////////////////////////////////
//输入pbSigEncoded,pbBodyEncoded得到pbCertEncoded
int SM2CERT_GenRootCert(char *pszDN,
						int iSerial,
						BYTE *pbRootPubKey, 
						DWORD cbRootPubKey, 
						BYTE *pbRootPriKey, 
						DWORD cbRootPriKey, 
						char *pszCert, 
						DWORD *pcbCert)
{
	int Ret = SM2_CERT_OK;
	DWORD cbSerialEncoded;
	BYTE  *pbSerialEncoded = NULL;
	DWORD cbDNEncoded;            
	BYTE *pbDNEncoded = NULL;             
	DWORD cbBodyEncoded;
	BYTE *pbBodyEncoded = NULL;
	DWORD cbSigEncoded;
	BYTE  *pbSigEncoded = NULL;
	DWORD cbCertEncoded;
	BYTE  *pbCertEncoded = NULL;

	BYTE bDigest[32];
	BYTE bSignature[64];
	DWORD i = 0;

	FILE *stream;
	errno_t err;

	if( (err  = fopen_s( &stream, "sm2root.cer", "wb" )) !=0 )
		printf( "The file 'sm2.cer' was not opened\n" );
	else
		printf( "The file 'sm2.cer' was opened\n" );

	Ret = SM2CERT_GenND(pszDN, NULL, &cbDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbDNEncoded = (BYTE*)malloc(cbDNEncoded);
	if ( pbDNEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenND(pszDN, pbDNEncoded, &cbDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenSerialEncoded(iSerial, NULL, &cbSerialEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbSerialEncoded = (BYTE*)malloc(cbSerialEncoded);
	if ( pbSerialEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenSerialEncoded(iSerial, pbSerialEncoded, &cbSerialEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenBodyEncoded_Root(pbDNEncoded, cbDNEncoded, pbDNEncoded, cbDNEncoded, pbRootPubKey, 65, pbSerialEncoded, cbSerialEncoded, NULL, &cbBodyEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbBodyEncoded = (BYTE*)malloc(cbBodyEncoded);
	if ( pbBodyEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenBodyEncoded_Root(pbDNEncoded, cbDNEncoded, pbDNEncoded, cbDNEncoded, pbRootPubKey, 65, pbSerialEncoded, cbSerialEncoded, pbBodyEncoded, &cbBodyEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	////////////////////////////////////////////////////////////////////////////////
	int nSignLen = 64;
	unsigned char bSigTmp[64];
	//SM3_Data(pbBodyEncoded, cbBodyEncoded, bDigest, 32);
	DWORD dwDigestLen = 0;
	SM3HashZ(pbBodyEncoded, cbBodyEncoded, pbRootPubKey + 1, 64, bDigest, &dwDigestLen);

	SM2Init();
	SM2SignHash(bDigest, 32, pbRootPriKey, 32, bSigTmp, &nSignLen);

	for ( i = 0; i < 32; i++ )
	{
		bSignature[i] = bSigTmp[ 31 - i ];
		bSignature[i + 32 ] = bSigTmp[ 63 - i ];
	}
	////////////////////////////////////////////////////////////////////////////////

	Ret = SM2CERT_GenSigEncoded(bSignature, 64, NULL, &cbSigEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbSigEncoded = (BYTE*)malloc(cbSigEncoded);
	if ( pbSigEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenSigEncoded(bSignature, 64, pbSigEncoded, &cbSigEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenCertEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, NULL, &cbCertEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbCertEncoded = (BYTE*)malloc(cbCertEncoded);
	if ( pbCertEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenCertEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, pbCertEncoded, &cbCertEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	fwrite(pbCertEncoded,cbCertEncoded,1,stream);

	if( stream)
	{
		if ( fclose( stream ) )
		{
			printf( "The file 'sm2.cer' was not closed\n" );
		}
	}

	int pcbCert_tmp = 0;
	IS_Base64Encode((char *)pbCertEncoded, cbCertEncoded, pszCert, &pcbCert_tmp, false);
	*pcbCert = (DWORD)pcbCert_tmp;

END:
	if ( pbSerialEncoded != NULL )
	{
		free(pbSerialEncoded);
	}

	if ( pbDNEncoded != NULL )
	{
		free(pbDNEncoded);
	}

	if ( pbBodyEncoded != NULL )
	{
		free(pbBodyEncoded);
	}

	if ( pbSigEncoded != NULL )
	{
		free(pbSigEncoded);
	}

	if ( pbCertEncoded != NULL )
	{
		free(pbCertEncoded);
	}
	return Ret;
}

//////////////////////////////////////////////////////////////////////////
//输入pbSigEncoded,pbBodyEncoded得到pbCertEncoded
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
						DWORD *pcbCert)
{
	int Ret = SM2_CERT_OK;
	DWORD cbSerialEncoded;
	BYTE  *pbSerialEncoded = NULL;
	DWORD cbUserDNEncoded;            
	BYTE *pbUserDNEncoded = NULL;             
	DWORD cbRootDNEncoded;            
	BYTE *pbRootDNEncoded = NULL; 
	DWORD cbBodyEncoded;
	BYTE *pbBodyEncoded = NULL;
	DWORD cbSigEncoded;
	BYTE  *pbSigEncoded = NULL;
	DWORD cbCertEncoded;
	BYTE  *pbCertEncoded = NULL;

	BYTE bDigest[32];
	BYTE bSignature[64];
	DWORD i = 0;

	FILE *stream;
	errno_t err;

	if( (err  = fopen_s( &stream, "sm2user.cer", "wb" )) !=0 )
		printf( "The file 'sm2.cer' was not opened\n" );
	else
		printf( "The file 'sm2.cer' was opened\n" );

	Ret = SM2CERT_GenND(pszUserDN, NULL, &cbUserDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbUserDNEncoded = (BYTE*)malloc(cbUserDNEncoded);
	if ( pbUserDNEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenND(pszUserDN, pbUserDNEncoded, &cbUserDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenND(pszRootDN, NULL, &cbRootDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbRootDNEncoded = (BYTE*)malloc(cbRootDNEncoded);
	if ( pbRootDNEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenND(pszRootDN, pbRootDNEncoded, &cbRootDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenSerialEncoded(iSerial, NULL, &cbSerialEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbSerialEncoded = (BYTE*)malloc(cbSerialEncoded);
	if ( pbSerialEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenSerialEncoded(iSerial, pbSerialEncoded, &cbSerialEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenBodyEncoded(pbUserDNEncoded, cbUserDNEncoded, pbRootDNEncoded, cbRootDNEncoded, pbUserPubKey, 65, pbSerialEncoded, cbSerialEncoded, NULL, &cbBodyEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbBodyEncoded = (BYTE*)malloc(cbBodyEncoded);
	if ( pbBodyEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenBodyEncoded(pbUserDNEncoded, cbUserDNEncoded, pbRootDNEncoded, cbRootDNEncoded, pbUserPubKey, 65, pbSerialEncoded, cbSerialEncoded, pbBodyEncoded, &cbBodyEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	////////////////////////////////////////////////////////////////////////////////
	int nSignLen = 64;
	unsigned char bSigTmp[64];
	DWORD bDigestLen = 0;
	//SM3_Data(pbBodyEncoded, cbBodyEncoded, bDigest, 32);
	SM3HashZ(pbBodyEncoded, cbBodyEncoded, pbRootPubKey+1, 64, bDigest, &bDigestLen);
	SM2Init();
	SM2SignHash(bDigest, 32, pbRootPriKey, 32, bSigTmp, &nSignLen);
	for ( i = 0; i < 32; i++ )
	{
		bSignature[i] = bSigTmp[ 31 - i ];
		bSignature[i + 32 ] = bSigTmp[ 63 - i ];
	}
	////////////////////////////////////////////////////////////////////////////////

	Ret = SM2CERT_GenSigEncoded(bSignature, 64, NULL, &cbSigEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbSigEncoded = (BYTE*)malloc(cbSigEncoded);
	if ( pbSigEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenSigEncoded(bSignature, 64, pbSigEncoded, &cbSigEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenCertEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, NULL, &cbCertEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbCertEncoded = (BYTE*)malloc(cbCertEncoded);
	if ( pbCertEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenCertEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, pbCertEncoded, &cbCertEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	fwrite(pbCertEncoded,cbCertEncoded,1,stream);

	if( stream)
	{
		if ( fclose( stream ) )
		{
			printf( "The file 'sm2.cer' was not closed\n" );
		}
	}

	int pcbCert_tmp = 0;
	IS_Base64Encode((char *)pbCertEncoded, cbCertEncoded, pszCert, &pcbCert_tmp, false);
	*pcbCert = (DWORD)pcbCert_tmp;

END:
	if ( pbSerialEncoded != NULL )
	{
		free(pbSerialEncoded);
	}

	if ( pbUserDNEncoded != NULL )
	{
		free(pbUserDNEncoded);
	}
	if ( pbRootDNEncoded != NULL )
	{
		free(pbRootDNEncoded);
	}

	if ( pbBodyEncoded != NULL )
	{
		free(pbBodyEncoded);
	}

	if ( pbSigEncoded != NULL )
	{
		free(pbSigEncoded);
	}

	if ( pbCertEncoded != NULL )
	{
		free(pbCertEncoded);
	}
	return Ret;
}

//////////////////////////////////////////////////////////////////////////
//输入pbSigEncoded,pbBodyEncoded得到pbCertEncoded
int SM2CERT_UKeyGenRootCert(
						LPSTR CSPName,
						LPSTR Container,
						char *pszRootDN,
						int iSerial,
						BYTE *pbRootPubKey, 
						DWORD cbRootPubKey,
						char *pszCert, 
						DWORD *pcbCert)
{
	int Ret = SM2_CERT_OK;
	DWORD cbSerialEncoded;
	BYTE  *pbSerialEncoded = NULL;
	DWORD cbDNEncoded;            
	BYTE *pbDNEncoded = NULL;             
	DWORD cbBodyEncoded;
	BYTE *pbBodyEncoded = NULL;
	DWORD cbSigEncoded;
	BYTE  *pbSigEncoded = NULL;
	DWORD cbCertEncoded;
	BYTE  *pbCertEncoded = NULL;

	BYTE bSignature[64];
	DWORD i = 0;

	FILE *stream;
	errno_t err;

	if( (err  = fopen_s( &stream, "sm2root.cer", "wb" )) !=0 )
		printf( "The file 'sm2.cer' was not opened\n" );
	else
		printf( "The file 'sm2.cer' was opened\n" );

	Ret = SM2CERT_GenND(pszRootDN, NULL, &cbDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbDNEncoded = (BYTE*)malloc(cbDNEncoded);
	if ( pbDNEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenND(pszRootDN, pbDNEncoded, &cbDNEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenSerialEncoded(iSerial, NULL, &cbSerialEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbSerialEncoded = (BYTE*)malloc(cbSerialEncoded);
	if ( pbSerialEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenSerialEncoded(iSerial, pbSerialEncoded, &cbSerialEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenBodyEncoded(pbDNEncoded, cbDNEncoded, pbDNEncoded, cbDNEncoded, pbRootPubKey, 65, pbSerialEncoded, cbSerialEncoded, NULL, &cbBodyEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbBodyEncoded = (BYTE*)malloc(cbBodyEncoded);
	if ( pbBodyEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenBodyEncoded(pbDNEncoded, cbDNEncoded, pbDNEncoded, cbDNEncoded, pbRootPubKey, 65, pbSerialEncoded, cbSerialEncoded, pbBodyEncoded, &cbBodyEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	/*
	////////////////////////////////////////////////////////////////////////////////
	int nSignLen = 64;
	unsigned char bSigTmp[64];
	SM3_Data(pbBodyEncoded, cbBodyEncoded, bDigest, 32);
	SM2Init();
	SM2SignHash(bDigest, 32, pbRootPriKey, 32, bSigTmp, &nSignLen);
	for ( i = 0; i < 32; i++ )
	{
		bSignature[i] = bSigTmp[ 31 - i ];
		bSignature[i + 32 ] = bSigTmp[ 63 - i ];
	}
	////////////////////////////////////////////////////////////////////////////////
	*/

	////////////////////////////////////////////////////////////////////////////////
	DWORD nSignLen = 64;
	Ret = DWKeySM2SignZ(CSPName, Container, pbBodyEncoded, cbBodyEncoded, bSignature, &nSignLen);

	////////////////////////////////////////////////////////////////////////////////


	Ret = SM2CERT_GenSigEncoded(bSignature, 64, NULL, &cbSigEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbSigEncoded = (BYTE*)malloc(cbSigEncoded);
	if ( pbSigEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenSigEncoded(bSignature, 64, pbSigEncoded, &cbSigEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	Ret = SM2CERT_GenCertEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, NULL, &cbCertEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}
	pbCertEncoded = (BYTE*)malloc(cbCertEncoded);
	if ( pbCertEncoded == NULL )
	{
		return SM2_CERT_MALLOC_ERROR;
	}
	Ret = SM2CERT_GenCertEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, pbCertEncoded, &cbCertEncoded);
	if ( Ret != SM2_CERT_OK )
	{
		goto END;
	}

	fwrite(pbCertEncoded,cbCertEncoded,1,stream);

	if( stream)
	{
		if ( fclose( stream ) )
		{
			printf( "The file 'sm2.cer' was not closed\n" );
		}
	}

	int pcbCert_tmp = 0;
	IS_Base64Encode((char *)pbCertEncoded, cbCertEncoded, pszCert, &pcbCert_tmp, false);
	*pcbCert = (DWORD)pcbCert_tmp;

END:
	if ( pbSerialEncoded != NULL )
	{
		free(pbSerialEncoded);
	}

	if ( pbDNEncoded != NULL )
	{
		free(pbDNEncoded);
	}

	if ( pbBodyEncoded != NULL )
	{
		free(pbBodyEncoded);
	}

	if ( pbSigEncoded != NULL )
	{
		free(pbSigEncoded);
	}

	if ( pbCertEncoded != NULL )
	{
		free(pbCertEncoded);
	}
	return Ret;
}

