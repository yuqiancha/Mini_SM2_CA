#ifndef __MSCUKeyAPI_H__
#define __MSCUKeyAPI_H__


#include <windows.h>


// ´íÎó±àÂë ===========================================================
#define MSC_ConnectSuccess 0x00
#define MSC_ConnectFail    0x01
#define MSC_SendFail	   0xCCCC

#define SM1Flag  		   0x11
#define SM4Flag            0x14
#define SM4KeyFlag		   0x00
#define SM1KeyFlag         0x01

EXTERN_C BYTE   MSC_ConnectReader();
EXTERN_C BYTE   MSC_DisConnectReader();
EXTERN_C WORD   MSC_SendAPDU(BYTE *sendBuffer, UINT sendLen, BYTE *receiveBuffer, UINT *dwrLen);

EXTERN_C WORD   MSC_GetChallenge(BYTE *bRand, BYTE RandLen);
EXTERN_C WORD   MSC_VerifyUserPIN(BYTE *bPIN, BYTE PINLen);
EXTERN_C WORD   MSC_VerifyAdminPIN(BYTE *bPIN, BYTE PINLen);
EXTERN_C WORD	MSC_ChangeUserPIN(BYTE *boldPIN, BYTE oldPINLen, BYTE *bnewPIN, BYTE newPINLen);
EXTERN_C WORD	MSC_ChangeAdminPIN(BYTE *boldPIN, BYTE oldPINLen, BYTE *bnewPIN, BYTE newPINLen);
EXTERN_C WORD   MSC_ResetUserPIN(BYTE *bPIN, BYTE PINLen);

EXTERN_C WORD   MSC_SM2GenKey();
EXTERN_C WORD	MSC_SM2ImportKeyPairToFile(BYTE *PubKey, UINT PubKeyLen, BYTE *PriKey, UINT PriKeyLen);
EXTERN_C WORD   MSC_SM2ExportPubKey(BYTE *PubKey, UINT *PubKeyLen);
EXTERN_C WORD   MSC_SM2SignHash(BYTE *Hash, UINT HashLen, BYTE *Sign, UINT *SignLen);
EXTERN_C WORD   MSC_SM2VerifyHash(BYTE *Hash, UINT HashLen, BYTE *PubKey, UINT PubKeyLen, BYTE *Sign, UINT SignLen);
EXTERN_C WORD	MSC_SM2Encrypt(BYTE *Plain, BYTE PlianLen, BYTE *PubKey, UINT PubKeyLen, BYTE *Cipher, UINT *Ciperlen);
EXTERN_C WORD	MSC_SM2Decrypt(BYTE *Cipher, BYTE CipherLen, BYTE *Plain, UINT *PlainLen);

EXTERN_C WORD	MSC_SM3HashSimple(BYTE *Message, BYTE MessageLen, BYTE *Digest, UINT *DigestLen);
EXTERN_C WORD   MSC_SM3Init(BYTE *Message, BYTE MessageLen);
EXTERN_C WORD	MSC_SM3Update(BYTE *Message, BYTE MessageLen);
EXTERN_C WORD	MSC_SM3Final(BYTE *Message, BYTE MessageLen, BYTE *Digest, UINT *DigestLen);
EXTERN_C WORD	MSC_SM3Hash(BYTE *Message, UINT MessageLen, BYTE *Digest, UINT *DigestLen);
EXTERN_C WORD	MSC_SM3HashGetE(BYTE *PubKey, UINT PubKeyLen, BYTE *Message, UINT MessageLen, BYTE *Digest, UINT *DigestLen);

EXTERN_C WORD	MSC_SBCWriteKeyToFile(BYTE KeyIndex, BYTE *Key, BYTE KeyLen);
EXTERN_C WORD	MSC_SBCInitFromKeyFile(BYTE KeyIndex);
EXTERN_C WORD	MSC_SBCInitFromData(BYTE AlgFLag, BYTE *Key, BYTE KeyLen);
EXTERN_C WORD   MSC_SBCEncryptECBSimple(BYTE *Plain, BYTE PlainLen, BYTE *Cipher, UINT *CipherLen);
EXTERN_C WORD   MSC_SBCDecryptECBSimple(BYTE *Cipher, BYTE CipherLen, BYTE *Plain, UINT *PlainLen);
EXTERN_C WORD	MSC_SBCEncryptECB(BYTE *Plain, UINT PlainLen, BYTE *Cipher, UINT *CipherLen);
EXTERN_C WORD	MSC_SBCDecryptECB(BYTE *Cipher, UINT CipherLen, BYTE *Plain, UINT *PlainLen);
EXTERN_C WORD   MSC_SBCEncryptCBCInit(BYTE *IV, BYTE *Plain, BYTE PlainLen, BYTE *Cipher, UINT *CipherLen);
EXTERN_C WORD   MSC_SBCDecryptCBCInit(BYTE *IV, BYTE *Cipher, BYTE CipherLen, BYTE *Plain, UINT *PlainLen);
EXTERN_C WORD   MSC_SBCEncryptCBCUpdate(BYTE *Plain, BYTE PlainLen, BYTE *Cipher, UINT *CipherLen);
EXTERN_C WORD   MSC_SBCDecryptCBCUpdate(BYTE *Cipher, BYTE CipherLen, BYTE *Plain, UINT *PlainLen);
EXTERN_C WORD	MSC_SBCEncryptCBC(BYTE *IV, BYTE *Plain, UINT PlainLen, BYTE *Cipher, UINT *CipherLen);
EXTERN_C WORD	MSC_SBCDecryptCBC(BYTE *IV, BYTE *Cipher, UINT CipherLen, BYTE *Plain, UINT *PlainLen);

EXTERN_C WORD	MSC_WriteCert(BYTE *Cert, UINT CertLen);
EXTERN_C WORD	MSC_ReadCert(BYTE *Cert, UINT *CertLen);

#endif

