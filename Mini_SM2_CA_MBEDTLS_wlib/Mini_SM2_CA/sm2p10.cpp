#include "sm2p10.h"
#include "MSCUKeyAPI.h"
#include "sm3.h"

#include "CVSKF.h"



//////////////////////////////////////////////////////////////////////////
//解析base64格式的证书,并得到req信息
int SM2P10_GetReq(char *pcCertData, DWORD ccCertData, BYTE *pbReqData, DWORD *cbReqData)
{
	BYTE pcP10Data[3000];
	int ccP10Data = 0;

	IS_Base64Decode(pcCertData, (DWORD)ccCertData, (char *)pcP10Data, &ccP10Data);

	if ( pbReqData == NULL )
	{
		if(false == CryptDecodeObjectEx(
			MY_ENCODING_TYPE, 
			X509_CERT,
			pcP10Data,
			ccP10Data,
			NULL,
			NULL,
			NULL, 
			cbReqData)
			)
		{
			return SM2_P10_DECODE_ERROR;
		}
		return SM2_P10_OK;
	}

	if(false == CryptDecodeObjectEx(
		MY_ENCODING_TYPE, 
		X509_CERT,
		pcP10Data,
		ccP10Data,
		NULL,
		NULL,
		pbReqData, 
		cbReqData)
		)
	{
		return SM2_P10_DECODE_ERROR;
	}

	return SM2_P10_OK;

}

//////////////////////////////////////////////////////////////////////////
//解析req信息,得到ToBeSigned
int SM2P10_GetBodyEncoded(BYTE *pbReqData, DWORD cbReqData, BYTE *pbBodyEncoded, DWORD *cbBodyEncoded)
{
	PCERT_SIGNED_CONTENT_INFO preq;

	preq = ( CERT_SIGNED_CONTENT_INFO *)pbReqData;

	if (pbBodyEncoded == NULL)
	{
		*cbBodyEncoded = preq->ToBeSigned.cbData;
		return SM2_P10_OK;
	}

	*cbBodyEncoded = preq->ToBeSigned.cbData;
	memcpy(pbBodyEncoded, preq->ToBeSigned.pbData, preq->ToBeSigned.cbData);

	return SM2_P10_OK;
}

/////////////////////////////////////////////////////////////////////////
//解析req信息,得到算法名称与参数
int SM2P10_GetAlgorithm(BYTE *pbReqData, DWORD cbReqData, char *pbAlgName, DWORD *cbAlgName, char *pbAlgParams, DWORD *cbAlgParams)
{
	PCERT_SIGNED_CONTENT_INFO preq;
	DWORD i = 0;

	preq = ( CERT_SIGNED_CONTENT_INFO *)pbReqData;

	if (pbAlgName == NULL)
	{
		*cbAlgName = sizeof(preq->SignatureAlgorithm.pszObjId);
		*cbAlgParams = preq->SignatureAlgorithm.Parameters.cbData;
		return SM2_P10_OK;
	}

	*cbAlgName = (DWORD)strlen(preq->SignatureAlgorithm.pszObjId);
	*cbAlgParams = preq->SignatureAlgorithm.Parameters.cbData;
	memcpy(pbAlgName, preq->SignatureAlgorithm.pszObjId, *cbAlgName);
	memcpy(pbAlgParams, preq->SignatureAlgorithm.Parameters.pbData, *cbAlgParams);

	return SM2_P10_OK;
}

//////////////////////////////////////////////////////////////////////////
//解析pbBodyEncoded信息,得到pbBodyDecoded
int SM2P10_GetBodyDecoded(BYTE *pbBodyEncoded, DWORD cbBodyEncoded, BYTE *pbBodyDecoded, DWORD *cbBodyDecoded)
{
	if ( pbBodyDecoded == NULL )
	{
		if(false == CryptDecodeObjectEx(
			MY_ENCODING_TYPE,
			X509_CERT_REQUEST_TO_BE_SIGNED,
			pbBodyEncoded,     // the buffer to be decoded
			cbBodyEncoded,
			NULL,
			NULL, 
			NULL,
			cbBodyDecoded))
		{
			return SM2_P10_DECODE_ERROR;
		}

		return SM2_P10_OK;
	}

	if(false == CryptDecodeObjectEx(
		MY_ENCODING_TYPE,
		X509_CERT_REQUEST_TO_BE_SIGNED,
		pbBodyEncoded,     // the buffer to be decoded
		cbBodyEncoded,
		NULL,   
		NULL, 
		pbBodyDecoded,
		cbBodyDecoded))
	{
		return SM2_P10_DECODE_ERROR;
	}

	return SM2_P10_OK;
}


//////////////////////////////////////////////////////////////////////////
//解析pbBodyDecoded信息,得到pbND
int SM2P10_GetND(BYTE *pbBodyDecoded, DWORD cbBodyDecoded, char *pbND, DWORD *cbND)
{
	char pbName[500];
	DWORD cbName = 500;
	PCERT_REQUEST_INFO        preqinfo;

	preqinfo = ( CERT_REQUEST_INFO  *)pbBodyDecoded;

	if ( pbND == NULL )
	{
		cbName = CertNameToStr(MY_ENCODING_TYPE, &(preqinfo->Subject), CERT_X500_NAME_STR, NULL, 0);
		*cbND = cbName;
		return SM2_P10_OK;
	}

	memset(pbName, 0, sizeof(pbName));
	if ( (*cbND) != 0)
	{
		cbName = *cbND;
	}
	CertNameToStr(MY_ENCODING_TYPE, &(preqinfo->Subject), CERT_X500_NAME_STR, pbND, cbName);

	return SM2_P10_OK;
}

//////////////////////////////////////////////////////////////////////////
//解析pbBodyDecoded信息,得到公钥
int SM2P10_GetPubKey(BYTE *pbBodyDecoded, DWORD cbBodyDecoded, BYTE *pbPubKey, DWORD *cbPubKey)
{
	PCERT_REQUEST_INFO        preqinfo;
	DWORD cbPubKey_tmp = 0;

	preqinfo = ( CERT_REQUEST_INFO     *)pbBodyDecoded;
	if ( pbPubKey == NULL )
	{
		*cbPubKey = preqinfo->SubjectPublicKeyInfo.PublicKey.cbData;
		return SM2_P10_OK;
	}
	
	cbPubKey_tmp = preqinfo->SubjectPublicKeyInfo.PublicKey.cbData;
	memcpy(pbPubKey,preqinfo->SubjectPublicKeyInfo.PublicKey.pbData, cbPubKey_tmp);
	return SM2_P10_OK;
}

/////////////////////////////////////////////////////////////////////////
//解析req信息,得到Signature
int SM2P10_GetSigEncoded(BYTE *pbReqData, DWORD cbReqData, BYTE *pbSigEncoded, DWORD *cbSigEncoded)
{
	PCERT_SIGNED_CONTENT_INFO preq;
	DWORD i = 0;

	preq = ( CERT_SIGNED_CONTENT_INFO *)pbReqData;

	if (pbSigEncoded == NULL)
	{
		*cbSigEncoded = preq->Signature.cbData;
		return SM2_P10_OK;
	}

	*cbSigEncoded = preq->Signature.cbData;
	for ( i = 0; i < *cbSigEncoded; i++ )
		pbSigEncoded[i]=preq->Signature.pbData[*cbSigEncoded-1-i];

	return SM2_P10_OK;
}

//////////////////////////////////////////////////////////////////////////
//解析pbSigEncoded信息,得到pbSigDecoded
int SM2P10_GetSigDecoded(BYTE *pbSigEncoded, DWORD cbSigEncoded, BYTE *pbSigDecoded, DWORD *cbSigDecoded)
{
	if ( pbSigDecoded == NULL )
	{
		if(false == CryptDecodeObjectEx(
			MY_ENCODING_TYPE,
			X509_SEQUENCE_OF_ANY,
			pbSigEncoded,     // the buffer to be decoded
			cbSigEncoded,
			NULL,
			NULL, 
			NULL,
			cbSigDecoded))
		{
			return SM2_P10_DECODE_ERROR;
		}

		return SM2_P10_OK;
	}

	if(false == CryptDecodeObjectEx(
		MY_ENCODING_TYPE,
		X509_SEQUENCE_OF_ANY,
		pbSigEncoded,     // the buffer to be decoded
		cbSigEncoded,
		NULL,   
		NULL, 
		pbSigDecoded,
		cbSigDecoded))
	{
		return SM2_P10_DECODE_ERROR;
	}

	return SM2_P10_OK;	
}

//////////////////////////////////////////////////////////////////////////
//解析pbSigDecoded信息,得到pbSignature
int SM2P10_GetSignature(BYTE *pbSigDecoded, DWORD cbSigDecoded, BYTE *pbSignature, DWORD *cbSignature)
{
	PCRYPT_SEQUENCE_OF_ANY     pseq;
	PCRYPT_UINT_BLOB pR,pS;
	DWORD cbREncoded;
	BYTE  pbREncoded[50];
	DWORD cbSEncoded;
	BYTE  pbSEncoded[50];
	BYTE  pbRDecoded[50];
	DWORD cbRDecoded;
	BYTE  pbSDecoded[50];
	DWORD cbSDecoded;
	DWORD i = 0;

	if ( pbSignature == NULL )
	{
		*cbSignature = 64;
		return SM2_P10_OK;
	}

	pseq = ( CRYPT_SEQUENCE_OF_ANY  *)pbSigDecoded;
	cbREncoded=pseq->rgValue[0].cbData;
	cbSEncoded=pseq->rgValue[1].cbData;
	memcpy(pbREncoded,pseq->rgValue[0].pbData,cbREncoded);
	memcpy(pbSEncoded,pseq->rgValue[1].pbData,cbSEncoded);

	//得到R
	if(false == CryptDecodeObjectEx(
		MY_ENCODING_TYPE,
		X509_MULTI_BYTE_UINT,
		pbREncoded,     // the buffer to be decoded
		cbREncoded,
		NULL,
		NULL, 
		NULL,
		&cbRDecoded))
	{
		return SM2_P10_DECODE_ERROR;
	}

	if(false == CryptDecodeObjectEx(
		MY_ENCODING_TYPE,
		X509_MULTI_BYTE_UINT,
		pbREncoded,     // the buffer to be decoded
		cbREncoded,
		NULL,
		NULL, 
		pbRDecoded,
		&cbRDecoded))
	{
		return SM2_P10_DECODE_ERROR;
	}
	
	//得到S
	if(false == CryptDecodeObjectEx(
		MY_ENCODING_TYPE,
		X509_MULTI_BYTE_UINT,
		pbSEncoded,     // the buffer to be decoded
		cbSEncoded,
		NULL,
		NULL, 
		NULL,
		&cbSDecoded))
	{
		return SM2_P10_DECODE_ERROR;
	}

	if(false == CryptDecodeObjectEx(
		MY_ENCODING_TYPE,
		X509_MULTI_BYTE_UINT,
		pbSEncoded,     // the buffer to be decoded
		cbSEncoded,
		NULL,
		NULL, 
		pbSDecoded,
		&cbSDecoded))
	{
		return SM2_P10_DECODE_ERROR;
	}

	pR = ( CRYPT_UINT_BLOB     *)pbRDecoded;
	for ( i = 0; i < 32; i++)
	{
		pbSignature[i] = pR->pbData[31-i];
	}

	pS = ( CRYPT_INTEGER_BLOB     *)pbSDecoded;
	for ( i = 0; i < 32; i++)
	{
		pbSignature[32+i] = pS->pbData[31-i];
	}
	//memcpy(pbSignature,pR->pbData,32);
	//memcpy(pbSignature+32,pS->pbData,32);
	return SM2_P10_OK;
}

int SM2P10_VerfiyP10(char *pSTRP10,DWORD cSTRP10)
{
	int Ret = SM2_P10_OK;
	int nP10_Len = 0;
	BYTE bPublicKey[100];
	DWORD cbPublicKey;
	DWORD cbDecoded;            
	BYTE *pbDecoded = NULL;             
	DWORD cbSigEncoded;
	BYTE  pbSigEncoded[100];
	DWORD cbBodyEncoded;
	BYTE  pbBodyEncoded[2000];
	DWORD cbBodyDecoded;
	BYTE  *pbBodyDecoded = NULL;
	DWORD cbSeqDecoded;
	BYTE  *pbSeqDecoded = NULL;
	DWORD i = 0;
	BYTE bID[16]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		          0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
	BYTE bHash[32];
	BYTE bSignature[64];
	DWORD cbMessage;
	BYTE  *pbMessage = NULL;

	//得到Req
	Ret = SM2P10_GetReq(pSTRP10, cSTRP10, NULL, &cbDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbDecoded = (BYTE*)malloc(cbDecoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GetReq(pSTRP10, cSTRP10, pbDecoded, &cbDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//得到BodyEncoded
	Ret = SM2P10_GetBodyEncoded(pbDecoded, cbDecoded, pbBodyEncoded, &cbBodyEncoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbMessage = (BYTE*)malloc(cbBodyEncoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	cbMessage = cbBodyEncoded;
	memcpy(pbMessage,pbBodyEncoded,cbBodyEncoded);

	//得到SigEncoded
	Ret = SM2P10_GetSigEncoded(pbDecoded, cbDecoded, pbSigEncoded, &cbSigEncoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//计算pbBodyEncoded的HASH值
	SM3_Data(pbBodyEncoded, cbBodyEncoded, bHash, 32);

	//得到pbBodyDecoded
	Ret = SM2P10_GetBodyDecoded(pbBodyEncoded, cbBodyEncoded, NULL, &cbBodyDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbBodyDecoded = (BYTE*)malloc(cbBodyDecoded)))
	{
		Ret = SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GetBodyDecoded(pbBodyEncoded, cbBodyEncoded, pbBodyDecoded, &cbBodyDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//得到公钥
	Ret = SM2P10_GetPubKey(pbBodyDecoded, cbBodyDecoded, NULL, &cbPublicKey);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	Ret = SM2P10_GetPubKey(pbBodyDecoded, cbBodyDecoded, bPublicKey, &cbPublicKey);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//得到pbSeqDecoded
	Ret = SM2P10_GetSigDecoded(pbSigEncoded,cbSigEncoded,NULL, &cbSeqDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbSeqDecoded = (BYTE*)malloc(cbSeqDecoded)))
	{
		Ret = SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GetSigDecoded(pbSigEncoded,cbSigEncoded,pbSeqDecoded, &cbSeqDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//得到bSignature
	DWORD cbSignature = 0;
	Ret = SM2P10_GetSignature(pbSeqDecoded, cbSeqDecoded, NULL, &cbSignature);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	Ret = SM2P10_GetSignature(pbSeqDecoded, cbSeqDecoded, bSignature, &cbSignature);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}


	//验证签名的正确性
	SM2Init();

	//默认先进行带ID的验证，如果不通过则再次进行非ID的验证
	if( SM2Verify(bID,16,pbMessage,cbMessage,bPublicKey+1, 64, bSignature, 64)!=SM2_OK)
	{ 
		if ( SM2VerifyHash(bHash, 32, bPublicKey+1, 64, bSignature, 64) == SM2_OK)
		{
			Ret = SM2_P10_OK;
		}
		else
		{
			Ret = SM2_P10_P10_INVALID;
		}
	}
	else
		Ret = SM2_P10_OK;

END:
	if ( pbDecoded != NULL )
	{
		free(pbDecoded);
	}
	if ( pbBodyDecoded != NULL)
	{
		free(pbBodyDecoded);
	}
	if ( pbSeqDecoded!= NULL )
	{
		free(pbSeqDecoded);
	}
	if ( pbMessage!= NULL )
	{
		free(pbMessage);
	}
	return Ret;
}


//////////////////////////////////////////////////////////////////////////
//输入pbND信息,得到pbND
int SM2P10_GenND(char *pszDN, BYTE *pbND, DWORD *cbND)
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
			return SM2_P10_ENCODE_ERROR;
		}
		return SM2_P10_OK;
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
		return SM2_P10_ENCODE_ERROR;
	}

	return SM2_P10_OK;	
}

//////////////////////////////////////////////////////////////////////////
//输入pbND,pbPubKey,得到pbBodyEncoded
int SM2P10_GenBodyEncoded(BYTE *pbND, DWORD cbND, BYTE *pbPubKey, DWORD cbPubKey,BYTE *pbBodyEncoded, DWORD *cbBodyEncoded)
{
	CERT_REQUEST_INFO    reqinfo;
	//BYTE bPubKey[65];
	CHAR oid_ecc[]="1.2.840.10045.2.1";

	//memcpy(bPubKey + 1, pbPubKey, 64);
	//bPubKey[0] = 0x04;

	reqinfo.dwVersion=0;
	reqinfo.Subject.pbData=pbND;
	reqinfo.Subject.cbData=cbND;

	reqinfo.cAttribute=0;
	reqinfo.rgAttribute=0;
	reqinfo.SubjectPublicKeyInfo.PublicKey.cbData=cbPubKey;
	reqinfo.SubjectPublicKeyInfo.PublicKey.pbData=pbPubKey;
	reqinfo.SubjectPublicKeyInfo.PublicKey.cUnusedBits=0;

	BYTE para[10]={0x06,0x08,0x2a,0x81,0x1c,0xcf,0x55,0x01,0x82,0x2d};
	reqinfo.SubjectPublicKeyInfo.Algorithm.Parameters.cbData=10;
	reqinfo.SubjectPublicKeyInfo.Algorithm.Parameters.pbData=para;
	reqinfo.SubjectPublicKeyInfo.Algorithm.pszObjId=oid_ecc;

	if ( pbBodyEncoded == NULL )
	{
		if( !CryptEncodeObjectEx(
			MY_ENCODING_TYPE,        // the encoding/decoding type
			X509_CERT_REQUEST_TO_BE_SIGNED,    
			&reqinfo,
			0,                 
			NULL, 
			NULL,
			cbBodyEncoded))
		{
			return SM2_P10_ENCODE_ERROR;
		}
		return SM2_P10_OK;
	}

	if(!CryptEncodeObjectEx(
		MY_ENCODING_TYPE,
		X509_CERT_REQUEST_TO_BE_SIGNED,
		&reqinfo,
		0,
		NULL, 
		pbBodyEncoded,
		cbBodyEncoded))
	{
		return SM2_P10_ENCODE_ERROR;
	}
	
	return SM2_P10_OK;
}

//////////////////////////////////////////////////////////////////////////
//输入pbSignature,得到pbSigEncoded
int SM2P10_GenSigEncoded(BYTE *pbSignature, DWORD cbSignature, BYTE *pbSigEncoded, DWORD *cbSigEncoded)
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
		return SM2_P10_ENCODE_ERROR;
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
		return SM2_P10_ENCODE_ERROR;
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
		return SM2_P10_ENCODE_ERROR;
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
		return SM2_P10_ENCODE_ERROR;
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
			return SM2_P10_ENCODE_ERROR;
		}
		return SM2_P10_OK;
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
		return SM2_P10_ENCODE_ERROR;
	}

	return SM2_P10_OK;
}

//////////////////////////////////////////////////////////////////////////
//输入pbSigEncoded,pbBodyEncoded得到pbSigEncoded
int SM2P10_GenReqEncoded(BYTE *pbBodyEncoded, DWORD cbBodyEncoded, BYTE *pbSigEncoded, DWORD cbSigEncoded,BYTE *pbReqEncoded, DWORD *cbReqEncoded)
{
	BYTE SigTemp[100];
	CERT_SIGNED_CONTENT_INFO req;
	DWORD i;

	for(i=0;i<cbSigEncoded;i++)
		SigTemp[i]=pbSigEncoded[cbSigEncoded-1-i];

	req.ToBeSigned.cbData=cbBodyEncoded;
	req.ToBeSigned.pbData=pbBodyEncoded;

	req.Signature.cbData=cbSigEncoded;
	req.Signature.pbData=SigTemp;
	req.Signature.cUnusedBits=0;

	req.SignatureAlgorithm.pszObjId="1.2.156.10197.1.501";
	req.SignatureAlgorithm.Parameters.cbData=0;
	req.SignatureAlgorithm.Parameters.pbData=0;

	if ( cbReqEncoded == NULL )
	{
		if(!CryptEncodeObjectEx(
			MY_ENCODING_TYPE,        // the encoding/decoding type
			X509_CERT,    
			&req,
			0,                 
			NULL, 
			NULL,
			cbReqEncoded))
		{
			return SM2_P10_ENCODE_ERROR;
		}
		return SM2_P10_OK;
	}

	if(!CryptEncodeObjectEx(
		MY_ENCODING_TYPE,
		X509_CERT,
		&req,
		0,
		NULL, 
		pbReqEncoded,
		cbReqEncoded))
	{
		return SM2_P10_ENCODE_ERROR;
	}
	return SM2_P10_OK;	
}

int SM2P10_GenP10(char *pszDN,BYTE *pbPubKey, DWORD cbPubKey, BYTE *pbPriKey, DWORD cbPriKey, char *pszP10, DWORD *pcbP10)
{
	BYTE *pbND = NULL;
	DWORD cbND = 0;
	DWORD cbBodyEncoded = 0;
	BYTE *pbBodyEncoded = NULL;
	BYTE bDigest[32];
	DWORD i = 0;
	BYTE bSignature[64];
	BYTE pbSigEncoded[256];
	DWORD cbSigEncoded = 0;
	BYTE *pbreqEncoded = NULL;
	DWORD cbreqEncoded = 0;
	int Ret = SM2_P10_OK;


	Ret = SM2P10_GenND(pszDN, NULL, &cbND);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	if (!(pbND = (BYTE *)malloc(cbND)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GenND(pszDN, pbND, &cbND);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}

	Ret = SM2P10_GenBodyEncoded(pbND, cbND, pbPubKey, 65, NULL, &cbBodyEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	if (!(pbBodyEncoded = (BYTE *)malloc(cbBodyEncoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GenBodyEncoded(pbND, cbND, pbPubKey, 65, pbBodyEncoded, &cbBodyEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}

	SM3_Data(pbBodyEncoded, cbBodyEncoded, bDigest, 32);

	////////////////////////////////////////////////////////////////////////////////
	int nSignLen = 64;
	unsigned char bSigTmp[64];
	SM2Init();
	SM2SignHash(bDigest, 32, pbPriKey, 32, bSigTmp, &nSignLen);
	for ( i = 0; i < 32; i++ )
	{
		bSignature[i] = bSigTmp[ 31 - i ];
		bSignature[i + 32 ] = bSigTmp[ 63 - i ];
	}
	////////////////////////////////////////////////////////////////////////////////

	Ret = SM2P10_GenSigEncoded(bSignature, 64, NULL, &cbSigEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	Ret = SM2P10_GenSigEncoded(bSignature, 64, pbSigEncoded, &cbSigEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}

	Ret = SM2P10_GenReqEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, NULL, &cbreqEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	if (!(pbreqEncoded = (BYTE *)malloc(cbreqEncoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GenReqEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, pbreqEncoded, &cbreqEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}

	//memset(charBuff, 0, sizeof(charBuff));
	int pcbP10_tmp = 0;
	IS_Base64Encode((char *)pbreqEncoded, cbreqEncoded, pszP10, &pcbP10_tmp, false);
	*pcbP10 = (DWORD)pcbP10_tmp;
END:
	if ( pbND != NULL)
	{
		free(pbND);
	}
	if ( pbBodyEncoded != NULL )
	{
		free(pbBodyEncoded);
	}
	if (pbreqEncoded != NULL)
	{
		free(pbreqEncoded);
	}
	return Ret;
}


int SM2P10_VerfiyP10_Ex(char *pSTRP10,
						DWORD cSTRP10, 
						char *pszND, 
						DWORD *cszND, 
						BYTE *pbPubKey, 
						DWORD *cbPubKey
						)
{
	int Ret = SM2_P10_OK;
	int nP10_Len = 0;
	BYTE bPublicKey[100];
	DWORD cbPublicKey;
	DWORD cbDecoded;            
	BYTE *pbDecoded = NULL;             
	DWORD cbSigEncoded;
	BYTE  pbSigEncoded[100];
	DWORD cbBodyEncoded;
	BYTE  pbBodyEncoded[2000];
	DWORD cbBodyDecoded;
	BYTE  *pbBodyDecoded = NULL;
	DWORD cbSeqDecoded;
	BYTE  *pbSeqDecoded = NULL;
	DWORD i = 0;

	BYTE bHash[32];
	BYTE bSignature[64];

	BYTE bID[16]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		          0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
	DWORD cbMessage;
	BYTE  *pbMessage = NULL;

	//得到Req
	Ret = SM2P10_GetReq(pSTRP10, cSTRP10, NULL, &cbDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbDecoded = (BYTE*)malloc(cbDecoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GetReq(pSTRP10, cSTRP10, pbDecoded, &cbDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//得到BodyEncoded
	Ret = SM2P10_GetBodyEncoded(pbDecoded, cbDecoded, pbBodyEncoded, &cbBodyEncoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbMessage = (BYTE*)malloc(cbBodyEncoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	cbMessage = cbBodyEncoded;
	memcpy(pbMessage,pbBodyEncoded,cbBodyEncoded);


	//得到SigEncoded
	Ret = SM2P10_GetSigEncoded(pbDecoded, cbDecoded, pbSigEncoded, &cbSigEncoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//计算pbBodyEncoded的HASH值
	SM3_Data(pbBodyEncoded, cbBodyEncoded, bHash, 32);

	//得到pbBodyDecoded
	Ret = SM2P10_GetBodyDecoded(pbBodyEncoded, cbBodyEncoded, NULL, &cbBodyDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbBodyDecoded = (BYTE*)malloc(cbBodyDecoded)))
	{
		Ret = SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GetBodyDecoded(pbBodyEncoded, cbBodyEncoded, pbBodyDecoded, &cbBodyDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//得到公钥
	Ret = SM2P10_GetPubKey(pbBodyDecoded, cbBodyDecoded, NULL, &cbPublicKey);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	Ret = SM2P10_GetPubKey(pbBodyDecoded, cbBodyDecoded, bPublicKey, &cbPublicKey);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	memcpy(pbPubKey, bPublicKey, cbPublicKey);
	*cbPubKey = cbPublicKey;

	//得到ND
	SM2P10_GetND(pbBodyDecoded, cbBodyDecoded, NULL,cszND);
	SM2P10_GetND(pbBodyDecoded, cbBodyDecoded, pszND, cszND);

	//得到pbSeqDecoded
	Ret = SM2P10_GetSigDecoded(pbSigEncoded,cbSigEncoded,NULL, &cbSeqDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	if(!(pbSeqDecoded = (BYTE*)malloc(cbSeqDecoded)))
	{
		Ret = SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GetSigDecoded(pbSigEncoded,cbSigEncoded,pbSeqDecoded, &cbSeqDecoded);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//得到bSignature
	DWORD cbSignature = 0;
	Ret = SM2P10_GetSignature(pbSeqDecoded, cbSeqDecoded, NULL, &cbSignature);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}
	Ret = SM2P10_GetSignature(pbSeqDecoded, cbSeqDecoded, bSignature, &cbSignature);
	if (Ret != SM2_P10_OK)
	{
		goto END;
	}

	//验证签名的正确性
	SM2Init();

	if( SM2Verify(bID,16,pbMessage,cbMessage,bPublicKey+1, 64, bSignature, 64)!=SM2_OK)
	{ 
		if ( SM2VerifyHash(bHash, 32, bPublicKey+1, 64, bSignature, 64) == SM2_OK)
		{
			Ret = SM2_P10_OK;
		}
		else
		{
			Ret = SM2_P10_P10_INVALID;
		}
	}
	else
		Ret = SM2_P10_OK;

END:
	if ( pbDecoded != NULL )
	{
		free(pbDecoded);
	}
	if ( pbBodyDecoded != NULL)
	{
		free(pbBodyDecoded);
	}
	if ( pbSeqDecoded!= NULL )
	{
		free(pbSeqDecoded);
	}
	return Ret;
}

int SM2P10_UKeyGenP10(LPSTR CSPName,LPSTR Container,char *pszDN,char *pszP10,DWORD *pcbP10)
{
	BYTE pbND[300];
	DWORD cbND = 0;
	DWORD cbBodyEncoded = 0;
	BYTE *pbBodyEncoded = NULL;
	DWORD i = 0;
	BYTE pbSigEncoded[256];
	DWORD cbSigEncoded = 0;
	BYTE *pbreqEncoded = NULL;
	DWORD cbreqEncoded = 0;
	BYTE pbPublicKey[65];
	UINT iPublicKeyLen = 0;
//	BYTE *pbSignature;
//	DWORD dwSignatureLen;
	BYTE bSign[64];
	UINT iSignatureLen = 0;
	int Ret = SM2_P10_OK;
	DWORD dwRet = MSC_ConnectFail;
	BYTE *pbZM = NULL;
	BYTE *pbHash = NULL;
	int   iZMLen,Len;
	BYTE  ZA[SM3256];
	BYTE pbID[16]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		          0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
	unsigned char bSigTmp[64];
	Ret = SM2P10_GenND(pszDN, NULL, &cbND);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	Ret = SM2P10_GenND(pszDN, pbND, &cbND);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	//硬件生成密钥对

	CHAR	szBuf[64 * 2];
	ULONG	ulBufSize;
	ECCPUBLICKEYBLOB	PubKeyBlob;
	GetPrivateProfileString("SKF", "con", NULL, szBuf, 64, CONFIG_FILE);
	dwRet = SKF_DeleteContainer(hApp, szBuf);
	//if (dwRet != SAR_OK)
	//	goto END;
	dwRet = SKF_CreateContainer(hApp, szBuf, &hCon);
	if (dwRet != SAR_OK)
		goto END;
	dwRet = SKF_GenECCKeyPair(hCon, SGD_SM2_1, &PubKeyBlob);
	if (dwRet != SAR_OK)
		goto END;
	pbPublicKey[0] = 0x04;
	memcpy(pbPublicKey + 1, PubKeyBlob.XCoordinate + 32, 32);
	memcpy(pbPublicKey +33, PubKeyBlob.YCoordinate + 32, 32);


	//dwRet = MSC_SM2GenKey();
	//if ( dwRet != 0x9000 )
	//{
	//	goto END;
	//}

	////硬件导出publickey
	//pbPublicKey[0]=0x04;
	//dwRet = MSC_SM2ExportPubKey(pbPublicKey+1, &iPublicKeyLen);
	//if ( dwRet != 0x9000 )
	//{
	//	goto END;
	//}

/*
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	BYTE *pbKeyBlob = NULL;
	DWORD dwBlobLen;

	//Create Container 
	if(!CryptAcquireContextA(&hProv, (LPCSTR)Container, CSPName, PROV_RSA_FULL, 0x08))
	{
		Ret=GetLastError();
		goto END;
	}
	//Gen KeyPair
	if(!CryptGenKey(hProv,0xBE00,0x1000001,&hKey))
	{
		Ret=GetLastError();
		goto END;
	}

	// Determine the size of the key BLOB and allocate memory.
	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB , 0, NULL, &dwBlobLen)) 
	{
		Ret=GetLastError();
		goto END;
	}

	if((pbKeyBlob = (BYTE *)malloc(dwBlobLen)) == NULL) 
	{
		Ret=-1;
		goto END;
	}

	// Export the key into a simple key BLOB.
	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB , 0, pbKeyBlob, &dwBlobLen))
	{
		Ret=GetLastError();
		goto END;
	}

	

	
	DWORD Start=sizeof(BLOBHEADER)+4;
	for(i=0;i<32;i++)
		pbPublicKey[1+i]=pbKeyBlob[Start+31-i];
	for(i=0;i<32;i++)
		pbPublicKey[33+i]=pbKeyBlob[Start+64+31-i];
	if(pbKeyBlob)
		free(pbKeyBlob);
*/

	Ret = SM2P10_GenBodyEncoded(pbND, cbND, pbPublicKey, 65, NULL, &cbBodyEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	if (!(pbBodyEncoded = (BYTE *)malloc(cbBodyEncoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GenBodyEncoded(pbND, cbND, pbPublicKey, 65, pbBodyEncoded, &cbBodyEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	//硬件进行带ID的签名，消息为pbBodyEncoded
	//SM2Init();
	//GetZA(pbID,16,pbPublicKey+1,64,ZA);
	//pbZM=(BYTE *)malloc(SM3256+cbBodyEncoded);
	//GBCombine(ZA,SM3256,pbBodyEncoded,cbBodyEncoded,pbZM,(unsigned long *)&iZMLen);
 //   Len = SM3256;
	//pbHash =(BYTE *)malloc(Len);
	//SM3_Data(pbZM,iZMLen,pbHash,Len);

	HANDLE	hHash = NULL;
	BYTE	pbHashData[32];
	ULONG	ulHashLen = 0;

	dwRet = SKF_DigestInit(hDev, SGD_SM3, &PubKeyBlob, pbID, 16, &hHash);
	if (dwRet != SAR_OK)
	{
		goto END;
	}
	dwRet = SKF_Digest(hHash, pbBodyEncoded, cbBodyEncoded, NULL, &ulHashLen);
	if (dwRet != SAR_OK)
	{
		goto END;
	}
	dwRet = SKF_Digest(hHash, pbBodyEncoded, cbBodyEncoded, pbHashData, &ulHashLen);
	if (dwRet != SAR_OK)
	{
		goto END;
	}

	ECCSIGNATUREBLOB SignBlob;

	dwRet = SKF_ECCSignData(hCon, pbHashData, ulHashLen, &SignBlob);
	if (dwRet != SAR_OK)
	{
		goto END;
	}
	memcpy(bSign     , SignBlob.r + 32, 32);
	memcpy(bSign + 32, SignBlob.s + 32, 32);
	for ( i = 0; i < 32; i++ )
	{
		bSign[i     ] = SignBlob.r[63 - i];
		bSign[i + 32] = SignBlob.s[63 - i];
	}

	//dwRet =  MSC_SM2SignHash(pbHash,Len, bSigTmp,&iSignatureLen);
	//if(dwRet!=0x9000)
	//{
	//	goto END;
	//}

	//for ( i = 0; i < 32; i++ )
	//{
	//	bSign[i] = bSigTmp[ 31 - i ];
	//	bSign[i + 32 ] = bSigTmp[ 63 - i ];
	//}

/*
	HCRYPTHASH hHash;
	// Create the hash object.
	if(!CryptCreateHash(hProv,CALG_SM3,0,0,&hHash)) 
	{
		Ret=GetLastError();
		goto END;
	}

	//Hash the buffer
	if(!CryptHashData(hHash,pbBodyEncoded,cbBodyEncoded,0)) 
	{
		Ret=GetLastError();
		goto END;
	}

	if(!CryptSignHash(hHash,AT_SIGNATURE,NULL,0,NULL,&dwSignatureLen))
	{
		Ret=GetLastError();
		goto END;
	}
	if((pbSignature = (BYTE *)malloc(dwSignatureLen)) == NULL) 
	{
		Ret=-1;
		goto END;
	}

	// Sign the hash object..
	if(!CryptSignHash(hHash,AT_SIGNATURE,NULL,0,pbSignature,&dwSignatureLen))
	{
		Ret=GetLastError();
		goto END;
	}

	memcpy(bSign,pbSignature,dwSignatureLen);

	if(!CryptReleaseContext(hProv,0))
	{
		Ret=GetLastError();
		goto END;
	}


	if(pbSignature)
		free(pbSignature);

*/
	Ret = SM2P10_GenSigEncoded(bSign, 64, NULL, &cbSigEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	Ret = SM2P10_GenSigEncoded(bSign, 64, pbSigEncoded, &cbSigEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}

	Ret = SM2P10_GenReqEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, NULL, &cbreqEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}
	if (!(pbreqEncoded = (BYTE *)malloc(cbreqEncoded)))
	{
		Ret =  SM2_P10_MALLOC_ERROR;
		goto END;
	}
	Ret = SM2P10_GenReqEncoded(pbBodyEncoded, cbBodyEncoded, pbSigEncoded, cbSigEncoded, pbreqEncoded, &cbreqEncoded);
	if ( Ret != SM2_P10_OK )
	{
		goto END;
	}

	//memset(charBuff, 0, sizeof(charBuff));
	int pcbP10_tmp = 0;
	IS_Base64Encode((char *)pbreqEncoded, cbreqEncoded, pszP10, &pcbP10_tmp, false);
	*pcbP10 = (DWORD)pcbP10_tmp;

	dwRet = SKF_CloseContainer(hCon);
	if (dwRet != SAR_OK)
	{
		goto END;
	}

END:
	if ( pbBodyEncoded != NULL )
	{
		free(pbBodyEncoded);
	}
	if (pbreqEncoded != NULL)
	{
		free(pbreqEncoded);
	}
	if ( pbZM != NULL )
	{
		free(pbZM);
	}
	//if (pbHash != NULL)
	//{
	//	free(pbHash);
	//}
	return Ret;
}


void  DWKeyGenGUID(char *strGUID)
{
	GUID guid;
	char TempGuid[65] = {0};
	if (S_OK == ::CoCreateGuid(&guid))
	{
		_snprintf_s(TempGuid, sizeof(TempGuid), 64, 
			"%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X", 
			guid.Data1, 
			guid.Data2, 
			guid.Data3, 
			guid.Data4[0], guid.Data4[1], 
			guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]
		);
	}

	strcpy(strGUID,TempGuid);
}

DWORD DWKeyGetContianerPublicKey(LPSTR CSPName,LPSTR Container,PBYTE pbPublicKey)//65 byte with big endin
{
	DWORD dwRet=S_OK;
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	BYTE *pbKeyBlob = NULL;
	DWORD dwBlobLen;

	if(!CryptAcquireContextA(&hProv, (LPCSTR)Container, CSPName, PROV_RSA_FULL, 0))
	{
		dwRet=GetLastError();
		goto END;
	}
	if(!CryptGetUserKey(hProv,AT_SIGNATURE,&hKey))
	{
		dwRet=GetLastError();
		goto END;
	}

	// Determine the size of the key BLOB and allocate memory.
	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB , 0, NULL, &dwBlobLen)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	if((pbKeyBlob = (BYTE *)malloc(dwBlobLen)) == NULL) 
	{
		dwRet=-1;
		goto END;
	}

	// Export the key into a simple key BLOB.
	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB , 0, pbKeyBlob, &dwBlobLen))
	{
		dwRet=GetLastError();
		goto END;
	}

	if(!CryptReleaseContext(hProv,0))
	{
		dwRet=GetLastError();
		goto END;
	}

	pbPublicKey[0]=0x04;
	DWORD i;
	DWORD Start=sizeof(BLOBHEADER)+4;
	for(i=0;i<32;i++)
		pbPublicKey[1+i]=pbKeyBlob[Start+31-i];
	for(i=0;i<32;i++)
		pbPublicKey[33+i]=pbKeyBlob[Start+64+31-i];
	if(pbKeyBlob)
		free(pbKeyBlob);
END:
	return dwRet;
}


DWORD DWKeySM2Sign(LPSTR CSPName,LPSTR Container,PBYTE bMessage,DWORD dwMessageLen,PBYTE pbSign,PDWORD pdwSignLen)
{
	DWORD dwRet=S_OK;
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	HCRYPTHASH hHash;
	BYTE *pbSignature;
	DWORD dwSignatureLen;

	if(!CryptAcquireContextA(&hProv, (LPCSTR)Container, CSPName, PROV_RSA_FULL, 0))
	{
		dwRet=GetLastError();
		goto END;
	}
	if(!CryptGetUserKey(hProv,AT_SIGNATURE,&hKey))
	{
		dwRet=GetLastError();
		goto END;
	}

	// Create the hash object.
	if(!CryptCreateHash(hProv,CALG_SM3,0,0,&hHash)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	//Hash the buffer
	if(!CryptHashData(hHash,bMessage,dwMessageLen,0)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	if(!CryptSignHash(hHash,AT_SIGNATURE,NULL,0,NULL,&dwSignatureLen))
	{
		dwRet=GetLastError();
		goto END;
	}
	if((pbSignature = (BYTE *)malloc(dwSignatureLen)) == NULL) 
	{
		dwRet=-1;
		goto END;
	}

	// Sign the hash object..
	if(!CryptSignHash(hHash,AT_SIGNATURE,NULL,0,pbSignature,&dwSignatureLen))
	{
		dwRet=GetLastError();
		goto END;
	}

	*pdwSignLen=dwSignatureLen;
	memcpy(pbSign,pbSignature,dwSignatureLen);
	if(pbSignature)
		free(pbSignature);


END:
	return dwRet;
}

DWORD DWKeySM2SignZ(LPSTR CSPName,LPSTR Container,PBYTE bMessage,DWORD dwMessageLen,PBYTE pbSign,PDWORD pdwSignLen)
{
	DWORD dwRet=S_OK;
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	HCRYPTHASH hHash;
	BYTE *pbSignature;
	DWORD dwSignatureLen;
	DWORD HashDataLen;
	BYTE *pbKeyBlob = NULL;
	DWORD dwBlobLen;
	BYTE  bZA[32];
	BYTE  bID[2+16+4*32]={0x00,0x80,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0};
	BYTE  bPubKey[64];

	if(!CryptAcquireContextA(&hProv, (LPCSTR)Container, CSPName, PROV_RSA_FULL, 0))
	{
		dwRet=GetLastError();
		goto END;
	}
	if(!CryptGetUserKey(hProv,AT_SIGNATURE,&hKey))
	{
		dwRet=GetLastError();
		goto END;
	}

	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB , 0, NULL, &dwBlobLen)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	if((pbKeyBlob = (BYTE *)malloc(dwBlobLen)) == NULL) 
	{
		dwRet=-1;
		goto END;
	}

	// Export the key into a simple key BLOB.
	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB , 0, pbKeyBlob, &dwBlobLen))
	{
		dwRet=GetLastError();
		goto END;
	}

	DWORD i;
	DWORD Start=sizeof(BLOBHEADER)+4;
	for(i=0;i<32;i++)
		bPubKey[i]=pbKeyBlob[Start+31-i];
	for(i=0;i<32;i++)
		bPubKey[32+i]=pbKeyBlob[Start+64+31-i];
	if(pbKeyBlob)
		free(pbKeyBlob);

	// Create the hash object.
	if(!CryptCreateHash(hProv,CALG_SM3,0,0,&hHash)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	//Hash the ID
	if(!CryptHashData(hHash,bID,sizeof(bID),0)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	//Hash the bPubkey
	if(!CryptHashData(hHash,bPubKey,sizeof(bPubKey),0)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	if(!CryptGetHashParam(hHash,HP_HASHVAL,bZA,&HashDataLen,0))
	{
		dwRet=GetLastError();
		goto END;
	}

	if(!CryptDestroyHash(hHash))
	{
		dwRet=GetLastError();
		goto END;
	}


	// Create the hash object.
	if(!CryptCreateHash(hProv,CALG_SM3,0,0,&hHash)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	//Hash the ZA
	if(!CryptHashData(hHash,bZA,sizeof(bZA),0)) 
	{
		dwRet=GetLastError();
		goto END;
	}

	//Hash the Message
	if(!CryptHashData(hHash,bMessage,dwMessageLen,0)) 
	{
		dwRet=GetLastError();
		goto END;
	}


	if(!CryptSignHash(hHash,AT_SIGNATURE,NULL,0,NULL,&dwSignatureLen))
	{
		dwRet=GetLastError();
		goto END;
	}
	if((pbSignature = (BYTE *)malloc(dwSignatureLen)) == NULL) 
	{
		dwRet=-1;
		goto END;
	}

	// Sign the hash object..
	if(!CryptSignHash(hHash,AT_SIGNATURE,NULL,0,pbSignature,&dwSignatureLen))
	{
		dwRet=GetLastError();
		goto END;
	}

	*pdwSignLen=dwSignatureLen;
	memcpy(pbSign,pbSignature,dwSignatureLen);
	if(pbSignature)
		free(pbSignature);
END:
	return dwRet;
}

DWORD DWKeySM2WriteCert(LPSTR CSPName,LPSTR Container,PBYTE bCert)
{
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	DWORD dwRet=S_OK;

	if(!CryptAcquireContextA(&hProv, (LPCSTR)Container, CSPName, PROV_RSA_FULL, 0xF0000000))
	{
		dwRet=GetLastError();
		goto END;
	}
	if(!CryptGetUserKey(hProv,AT_SIGNATURE,&hKey))
	{
		dwRet=GetLastError();
		goto END;
	}
	if(!CryptSetKeyParam(hKey,KP_CERTIFICATE,bCert,0))
	{
		dwRet=GetLastError();
		goto END;
	}

END:
	return dwRet;
}

void SM3HashZ(PBYTE bMessage,DWORD dwMessageLen,PBYTE bPubKey,DWORD dwPubKeyLen,PBYTE pbDigest,PDWORD pdwDigestLen)
{
	BYTE  bID[2+16+4*32]={0x00,0x80,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0};
	BYTE  bZA[32];
	BYTE  bDigest[32];
	SM3_CTX sm3_context;

	SM3_Init(&sm3_context);
	SM3Update(&sm3_context, bID, 2+16+4*32);
	SM3Update(&sm3_context, bPubKey, (unsigned int)dwPubKeyLen);
	SM3Final(bZA, &sm3_context, 32);

	SM3_Init(&sm3_context);
	SM3Update(&sm3_context, bZA, 32);
	SM3Update(&sm3_context, bMessage, (unsigned int)dwMessageLen);
	SM3Final(bDigest, &sm3_context, 32);

	*pdwDigestLen = 32;
	memcpy(pbDigest, bDigest, 32);
}
