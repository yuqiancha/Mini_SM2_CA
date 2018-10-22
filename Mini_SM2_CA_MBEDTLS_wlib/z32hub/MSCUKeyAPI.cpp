#include "MSCUKeyAPI.h"
#include "sm4.h"


extern DWORD MSCReaderConnect();
extern DWORD MSCAPDU(unsigned char * sendBuffer, DWORD sendLen, unsigned char * receiveBuffer, DWORD *dwrLen);
extern DWORD MSCReaderDisConnect();

BYTE MSC_ConnectReader()
{
	DWORD Status;

	Status = MSCReaderConnect();
	if (Status == 0)
		return MSC_ConnectSuccess;
	else
		return MSC_ConnectFail;
}

BYTE MSC_DisConnectReader()
{
	return (BYTE)MSCReaderDisConnect();

}

WORD MSC_SendAPDU(BYTE *sendBuffer, UINT sendLen, BYTE *receiveBuffer, UINT *dwrLen)
{
	BYTE  OData[256];

	MSCAPDU(sendBuffer, sendLen, OData, (DWORD *)dwrLen);

	memcpy(receiveBuffer, OData, *dwrLen - 2);
	*dwrLen -= 2;

	return ((WORD)OData[*dwrLen]) << 8 | OData[*dwrLen + 1];
}

WORD MSC_GetChallenge(BYTE *bRand, BYTE RandLen)
{
	BYTE pApdu[256];
	UINT pLen;
	pApdu[0] = 0x00;
	pApdu[1] = 0x84;
	pApdu[2] = 0x00;
	pApdu[3] = 0x00;
	pApdu[4] = RandLen;

	return MSC_SendAPDU(pApdu, 5, bRand, &pLen);
}

WORD MSC_SelectFile(BYTE FIDH, BYTE FIDL)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;
	pApdu[0] = 0x00;
	pApdu[1] = 0xA4;
	pApdu[2] = 0x00;
	pApdu[3] = 0x00;
	pApdu[4] = 0x02;
	pApdu[5] = FIDH;
	pApdu[6] = FIDL;

	return MSC_SendAPDU(pApdu, 7, pRece, &pLen);
}

WORD MSC_VerifyUserPIN(BYTE *bPIN, BYTE PINLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	MSC_SelectFile(0x50, 0x00);
	pApdu[0] = 0x00;
	pApdu[1] = 0x20;
	pApdu[2] = 0x00;
	pApdu[3] = 0x00;
	pApdu[4] = PINLen;
	memcpy(&pApdu[5], bPIN, PINLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_VerifyAdminPIN(BYTE *bPIN, BYTE PINLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	MSC_SelectFile(0x50, 0x00);
	pApdu[0] = 0x00;
	pApdu[1] = 0x20;
	pApdu[2] = 0x00;
	pApdu[3] = 0x01;
	pApdu[4] = PINLen;
	memcpy(&pApdu[5], bPIN, PINLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_ChangeUserPIN(BYTE *boldPIN, BYTE oldPINLen, BYTE *bnewPIN, BYTE newPINLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0x5E;
	pApdu[2] = 0x01;
	pApdu[3] = 0x00;
	pApdu[4] = oldPINLen + newPINLen + 1;
	memcpy(&pApdu[5], boldPIN, oldPINLen);
	pApdu[5 + oldPINLen] = 0xFF;
	memcpy(&pApdu[6 + oldPINLen], bnewPIN, newPINLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_ChangeAdminPIN(BYTE *boldPIN, BYTE oldPINLen, BYTE *bnewPIN, BYTE newPINLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0x5E;
	pApdu[2] = 0x01;
	pApdu[3] = 0x01;
	pApdu[4] = oldPINLen + newPINLen + 1;
	memcpy(&pApdu[5], boldPIN, oldPINLen);
	pApdu[5 + oldPINLen] = 0xFF;
	memcpy(&pApdu[6 + oldPINLen], bnewPIN, newPINLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_ResetUserPIN(BYTE *UserPin, BYTE UserPinLen)
{
	BYTE pbKeyData[16] = { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x3A };
	BYTE IV[16];
	BYTE MAC[4];
	BYTE pApdu[256];
	UINT dwInLen;
	WORD dwRet;
	BYTE pbResp[256];
	UINT dwOutLen;

	memset(IV, 0, 16);
	sm4_2key_mac((BYTE*)UserPin, (int)UserPinLen, IV, pbKeyData, MAC);
	memcpy(pApdu, "\x80\x5e\x00\x00\x00", 5);
	pApdu[4] = UserPinLen + 4;
	memcpy(pApdu + 5, UserPin, UserPinLen);
	memcpy(pApdu + 5 + UserPinLen, MAC, 4);
	dwInLen = 5 + UserPinLen + 4;
	dwRet = MSC_SendAPDU(pApdu, dwInLen, pbResp, &dwOutLen);
	return dwRet;
}

WORD MSC_SM2GenKey()
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0x40;
	pApdu[2] = 0x01;
	pApdu[3] = 0x00;
	pApdu[4] = 0x04;
	pApdu[5] = 0x50;
	pApdu[6] = 0x10;
	pApdu[7] = 0x50;
	pApdu[8] = 0x11;

	MSC_SelectFile(0x50, 0x00);
	return MSC_SendAPDU(pApdu, 9, pRece, &pLen);
}

WORD MSC_SM2ImportKeyPairToFile(BYTE *PubKey, UINT PubKeyLen, BYTE *PriKey, UINT PriKeyLen)
{
	WORD SW;
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	SW = MSC_SelectFile(0x50, 0x10);
	if (SW != 0x9000)
		return SW;

	pApdu[0] = 0x80;
	pApdu[1] = 0x42;
	pApdu[2] = 0x01;
	pApdu[3] = 0x06;
	pApdu[4] = PubKeyLen / 2;
	memcpy(&pApdu[5], PubKey, pApdu[4]);
	SW = MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen); //导入公钥高32到文件
	if (SW != 0x9000)
		return SW;

	pApdu[3] = 0x07;
	memcpy(&pApdu[5], PubKey + pApdu[4], pApdu[4]);
	SW = MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen); //导入公钥高32到文件
	if (SW != 0x9000)
		return SW;

	SW = MSC_SelectFile(0x50, 0x11);
	if (SW != 0x9000)
		return SW;

	pApdu[0] = 0x80;
	pApdu[1] = 0x42;
	pApdu[2] = 0x01;
	pApdu[3] = 0x08;
	pApdu[4] = PriKeyLen;
	memcpy(&pApdu[5], PriKey, PriKeyLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen); //导入私钥到文件
}

WORD MSC_SM2ExportPubKey(BYTE *PubKey, UINT *PubKeyLen)
{
	WORD SW;
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	MSC_SelectFile(0x50, 0x00);
	MSC_SelectFile(0x50, 0x10);

	pApdu[0] = 0x80;
	pApdu[1] = 0x41;
	pApdu[2] = 0x01;
	pApdu[3] = 0x06;
	pApdu[4] = 0x00;
	SW = MSC_SendAPDU(pApdu, 5, pRece, &pLen);
	if (SW != 0x9000)
		return SW;
	memcpy(PubKey, pRece, pLen);

	pApdu[3] = 0x07;
	SW = MSC_SendAPDU(pApdu, 5, pRece, &pLen);
	if (SW != 0x9000)
		return SW;
	memcpy(PubKey + 32, pRece, pLen);

	*PubKeyLen = 64;
	return SW;
}

WORD MSC_SM2SignHash(BYTE *Hash, UINT HashLen, BYTE *Sign, UINT *SignLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0x43;
	pApdu[2] = 0x50;
	pApdu[3] = 0x11;

	pApdu[4] = HashLen;
	memcpy(&pApdu[5], Hash, HashLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Sign, SignLen);
}

WORD MSC_SM2VerifyHash(BYTE *Hash, UINT HashLen, BYTE *PubKey, UINT PubKeyLen, BYTE *Sign, UINT SignLen)
{
	WORD SW;
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0x42;
	pApdu[2] = 0x00;
	pApdu[3] = 0x06;
	pApdu[4] = 0x20;
	memcpy(&pApdu[5], PubKey, pApdu[4]);
	SW = MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen); //导入公钥高32到缓存
	if (SW != 0x9000)
		return SW;

	pApdu[3] = 0x07;
	memcpy(&pApdu[5], PubKey + pApdu[4], pApdu[4]);
	SW = MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen); //导入公钥低32到缓存
	if (SW != 0x9000)
		return SW;

	pApdu[0] = 0x80;
	pApdu[1] = 0x44;
	pApdu[2] = 0xFF;
	pApdu[3] = 0xFF;
	pApdu[4] = HashLen + SignLen;
	memcpy(&pApdu[5], Hash, HashLen);
	memcpy(&pApdu[5 + HashLen], Sign, SignLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_SM2Encrypt(BYTE *Plain, BYTE PlianLen, BYTE *PubKey, UINT PubKeyLen, BYTE *Cipher, UINT *Ciperlen)
{
	WORD SW;
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0x42;
	pApdu[2] = 0x00;
	pApdu[3] = 0x06;
	pApdu[4] = PubKeyLen / 2;
	memcpy(&pApdu[5], PubKey, pApdu[4]);
	SW = MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen); //导入公钥高32到缓存
	if (SW != 0x9000)
		return SW;

	pApdu[3] = 0x07;
	memcpy(&pApdu[5], PubKey + pApdu[4], pApdu[4]);
	SW = MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen); //导入公钥低32到缓存
	if (SW != 0x9000)
		return SW;

	pApdu[0] = 0x80;
	pApdu[1] = 0x45;
	pApdu[2] = 0xFF;
	pApdu[3] = 0xFF;
	pApdu[4] = PlianLen;
	memcpy(&pApdu[5], Plain, pApdu[4]);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Cipher, Ciperlen);
}

WORD MSC_SM2Decrypt(BYTE *Cipher, BYTE CipherLen, BYTE *Plain, UINT *PlainLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0x46;
	pApdu[2] = 0x50;
	pApdu[3] = 0x11;
	pApdu[4] = CipherLen;
	memcpy(&pApdu[5], Cipher, CipherLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Plain, PlainLen);
}

WORD MSC_SM3HashSimple(BYTE *Message, BYTE MessageLen, BYTE *Digest, UINT *DigestLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0x47;
	pApdu[2] = 0x10;
	pApdu[3] = 0x00;
	pApdu[4] = MessageLen;

	memcpy(&pApdu[5], Message, MessageLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Digest, DigestLen);
}

WORD MSC_SM3Init(BYTE *Message, BYTE MessageLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0x47;
	pApdu[2] = 0x10;
	pApdu[3] = 0x01;
	pApdu[4] = MessageLen;

	memcpy(&pApdu[5], Message, MessageLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_SM3Update(BYTE *Message, BYTE MessageLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0x47;
	pApdu[2] = 0x10;
	pApdu[3] = 0x02;
	pApdu[4] = MessageLen;

	memcpy(&pApdu[5], Message, MessageLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_SM3Final(BYTE *Message, BYTE MessageLen, BYTE *Digest, UINT *DigestLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0x47;
	pApdu[2] = 0x10;
	pApdu[3] = 0x03;
	pApdu[4] = MessageLen;

	memcpy(&pApdu[5], Message, MessageLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Digest, DigestLen);
}

WORD MSC_SM3Hash(BYTE *Message, UINT MessageLen, BYTE *Digest, UINT *DigestLen)
{
	UINT i = 0, Block, Len;

	Block = MessageLen / 240;
	Len = MessageLen % 240;
	if (Len != 0)
		Block++;
	if (Block <= 1)
	{
		return MSC_SM3HashSimple(Message, MessageLen, Digest, DigestLen);
	}
	else
	{
		while (Block)
		{
			if (Block == 1)
			{
				if (Len == 0)
					return MSC_SM3Final(Message + i * 240, 240, Digest, DigestLen);
				else
					return MSC_SM3Final(Message + i * 240, Len, Digest, DigestLen);
			}
			else
			{
				if (i == 0)
					MSC_SM3Init(Message, 240);
				else
					MSC_SM3Update(Message + i * 240, 240);
				i++;
			}
			Block--;
		}
		return 0x9000;
	}
}

const BYTE ZaX[] = { 0x00, 0x80,
0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, //ID
0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //a
0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7, //b
0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94, //Xg
0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53, //Yg
0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0 };

WORD MSC_SM3HashGetE(BYTE *PubKey, UINT PubKeyLen, BYTE *Message, UINT MessageLen, BYTE *Digest, UINT *DigestLen)
{
	WORD SW;
	BYTE Temp[210];
	BYTE Za[32];
	UINT Len;
	BYTE MMessage[3000];

	memcpy(Temp, ZaX, 146);
	memcpy(&Temp[146], PubKey, PubKeyLen);

	SW = MSC_SM3HashSimple(Temp, 210, Za, &Len);
	if (SW != 0x9000)
		return SW;

	memcpy(MMessage, Za, Len);
	memcpy(&MMessage[32], Message, MessageLen);
	MessageLen += 32;

	return MSC_SM3Hash(MMessage, MessageLen, Digest, DigestLen);
}

WORD MSC_SBCWriteKeyToFile(BYTE KeyIndex, BYTE *Key, BYTE KeyLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	memcpy(pApdu, "\x80\xd4\x00\x00", 5);
	pApdu[4] = KeyLen + 8;
	pApdu[5] = KeyIndex;
	memcpy(&pApdu[6], "\x21\x01\x00\x01\x11\x99", 6);
	if (KeyIndex == 0)
		pApdu[8] = SM4Flag;
	else if (KeyIndex == 1)
		pApdu[8] = SM1Flag;
	pApdu[12] = 0x0F;
	memcpy(&pApdu[13], Key, KeyLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_SBCInitFromKeyFile(BYTE KeyIndex)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x84;
	pApdu[1] = 0xC1;
	pApdu[2] = 0x00;
	pApdu[3] = KeyIndex;
	pApdu[4] = 0x00;

	return MSC_SendAPDU(pApdu, 5, pRece, &pLen);
}

WORD MSC_SBCInitFromData(BYTE AlgFLag, BYTE *Key, BYTE KeyLen)
{
	BYTE pApdu[256];
	BYTE pRece[256];
	UINT pLen;

	pApdu[0] = 0x80;
	pApdu[1] = 0xC1;
	pApdu[2] = 0x00;
	pApdu[3] = AlgFLag;
	pApdu[4] = KeyLen;
	memcpy(&pApdu[5], Key, KeyLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], pRece, &pLen);
}

WORD MSC_SBCEncryptECBSimple(BYTE *Plain, BYTE PlainLen, BYTE *Cipher, UINT *CipherLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0xC2;
	pApdu[2] = 0x00;
	pApdu[3] = 0x00;
	pApdu[4] = PlainLen;
	memcpy(&pApdu[5], Plain, PlainLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Cipher, CipherLen);
}

WORD MSC_SBCDecryptECBSimple(BYTE *Cipher, BYTE CipherLen ,BYTE *Plain, UINT *PlainLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0xC2;
	pApdu[2] = 0x01;
	pApdu[3] = 0x00;
	pApdu[4] = CipherLen;
	memcpy(&pApdu[5], Cipher, CipherLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Plain, PlainLen);
}

WORD MSC_SBCEncryptECB(BYTE *Plain, UINT PlainLen, BYTE *Cipher, UINT *CipherLen)
{
	WORD SW;
	UINT i = 0, Block, Len, CLen = 0;

	Block = PlainLen / 240;
	Len = PlainLen % 240;
	if (Len != 0)
		Block++;
	while (Block >= 2)
	{
		SW = MSC_SBCEncryptECBSimple(Plain + i * 240, 240, Cipher + i * 240, CipherLen);
		if (SW != 0x9000)
			return SW;
		CLen += *CipherLen;
		i++;
		Block--;
	}
	if (Len == 0)
		SW = MSC_SBCEncryptECBSimple(Plain + i * 240, 240, Cipher + i * 240, CipherLen);
	else
		SW = MSC_SBCEncryptECBSimple(Plain + i * 240, Len, Cipher + i * 240, CipherLen);
	CLen += *CipherLen;
	*CipherLen = CLen;

	return SW;
}

WORD MSC_SBCDecryptECB(BYTE *Cipher, UINT CipherLen, BYTE *Plain, UINT *PlainLen)
{
	WORD SW;
	UINT i = 0, Block, Len, CLen = 0;

	Block = CipherLen / 240;
	Len = CipherLen % 240;
	if (Len != 0)
		Block++;
	while (Block >= 2)
	{
		SW = MSC_SBCDecryptECBSimple(Cipher + i * 240, 240, Plain + i * 240, PlainLen);
		if (SW != 0x9000)
			return SW;
		CLen += *PlainLen;
		i++;
		Block--;
	}
	if (Len == 0)
		SW = MSC_SBCDecryptECBSimple(Cipher + i * 240, 240, Plain + i * 240, PlainLen);
	else
		SW = MSC_SBCDecryptECBSimple(Cipher + i * 240, Len, Plain + i * 240, PlainLen);
	CLen += *PlainLen;
	*PlainLen = CLen;

	return SW;
}

WORD MSC_SBCEncryptCBCInit(BYTE *IV, BYTE *Plain, BYTE PlainLen, BYTE *Cipher, UINT *CipherLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0xC2;
	pApdu[2] = 0x06;
	pApdu[3] = 0x00;
	pApdu[4] = PlainLen + 16;
	memcpy(&pApdu[5], IV, 16);
	memcpy(&pApdu[21], Plain, PlainLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Cipher, CipherLen);
}

WORD MSC_SBCDecryptCBCInit(BYTE *IV,  BYTE *Cipher, BYTE CipherLen, BYTE *Plain, UINT *PlainLen )
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0xC2;
	pApdu[2] = 0x07;
	pApdu[3] = 0x00;
	pApdu[4] = CipherLen + 16;
	memcpy(&pApdu[5], IV, 16);
	memcpy(&pApdu[21], Cipher, CipherLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Plain, PlainLen);
}

WORD MSC_SBCEncryptCBCUpdate(BYTE *Plain, BYTE PlainLen, BYTE *Cipher, UINT *CipherLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0xC2;
	pApdu[2] = 0x02;
	pApdu[3] = 0x00;
	pApdu[4] = PlainLen ;
	memcpy(&pApdu[5], Plain, PlainLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Cipher, CipherLen);
}

WORD MSC_SBCDecryptCBCUpdate(BYTE *Cipher, BYTE CipherLen, BYTE *Plain, UINT *PlainLen)
{
	BYTE pApdu[256];

	pApdu[0] = 0x80;
	pApdu[1] = 0xC2;
	pApdu[2] = 0x03;
	pApdu[3] = 0x00;
	pApdu[4] = CipherLen ;

	memcpy(&pApdu[5], Cipher, CipherLen);

	return MSC_SendAPDU(pApdu, 5 + pApdu[4], Plain, PlainLen);
}


WORD MSC_SBCEncryptCBC(BYTE *IV, BYTE *Plain, UINT PlainLen, BYTE *Cipher, UINT *CipherLen)
{
	WORD SW;
	UINT i = 0, Block, Len, CLen = 0;

	Block = PlainLen / 224;
	Len = PlainLen % 224;
	if (Len != 0)
		Block++;
	if (Block <= 1)
		return MSC_SBCEncryptCBCInit(IV, Plain, PlainLen, Cipher, CipherLen);
	else
	{
		SW = MSC_SBCEncryptCBCInit(IV, Plain, 224, Cipher, CipherLen);
		if (SW != 0x9000)
			return SW;
		i++;
		Block--;
		CLen = *CipherLen;
		while (Block)
		{
			if (Block >= 2)
				SW = MSC_SBCEncryptCBCUpdate(Plain + i * 224, 224, Cipher + i * 224, CipherLen);
			else
			{
				if (Len == 0)
					SW = MSC_SBCEncryptCBCUpdate(Plain + i * 224, 224, Cipher + i * 224, CipherLen);
				else
					SW = MSC_SBCEncryptCBCUpdate(Plain + i * 224, Len, Cipher + i * 224, CipherLen);
			}
			if (SW != 0x9000)
				return SW;
			i++;
			Block--;
			CLen += *CipherLen;
			*CipherLen = CLen;			
		}
	}

	return SW;
}

WORD MSC_SBCDecryptCBC(BYTE *IV, BYTE *Cipher, UINT CipherLen, BYTE *Plain, UINT *PlainLen)
{
	WORD SW;
	UINT i = 0, Block, Len, CLen = 0;

	Block = CipherLen / 224;
	Len = CipherLen % 224;
	if (Len != 0)
		Block++;
	if (Block <= 1)
		return MSC_SBCDecryptCBCInit(IV, Cipher, CipherLen, Plain, PlainLen);
	else
	{
		SW = MSC_SBCDecryptCBCInit(IV, Cipher, 224, Plain, PlainLen);
		if (SW != 0x9000)
			return SW;
		i++;
		Block--;
		CLen = *PlainLen;
		while (Block)
		{
			if (Block >= 2)
				SW = MSC_SBCDecryptCBCUpdate(Cipher + i * 224, 224, Plain + i * 224, PlainLen);
			else
			{
				if (Len == 0)
					SW = MSC_SBCDecryptCBCUpdate(Cipher + i * 224, 224, Plain + i * 224, PlainLen);
				else
					SW = MSC_SBCDecryptCBCUpdate(Cipher + i * 224, Len, Plain + i * 224, PlainLen);
			}
			if (SW != 0x9000)
				return SW;
			i++;
			Block--;
			CLen += *PlainLen;
			*PlainLen = CLen;
		}
	}

	return SW;
}

WORD MSC_WriteCert(BYTE *Cert, UINT CertLen)
{
	WORD SW;
	BYTE pApdu[256];
	BYTE  pbResp[256];
	UINT InLen, OutLen;
	UINT CertSize;
	WORD bOffset = 0;

	CertSize = CertLen;
	memcpy(pApdu, "\x00\xA4\x00\x00\x02\x50\x00", 7);
	SW = MSC_SendAPDU(pApdu, 7, pbResp, &OutLen);
	if (SW != 0x9000) goto END;
	//set cert length
	memcpy(pApdu, "\x00\xA4\x02\x00\x02\x50\x01", 7);
	SW = MSC_SendAPDU(pApdu, 7, pbResp, &OutLen);
	if (SW != 0x9000) goto END;


	memcpy(pApdu, "\x00\xD6\x00\x00\x02", 5);
	pApdu[5] = (BYTE)((CertSize & 0xFF00) >> 8);
	pApdu[6] = (BYTE)CertSize;
	SW = MSC_SendAPDU(pApdu, 7, pbResp, &OutLen);
	if (SW != 0x9000) goto END;

	bOffset = 2;

	memcpy(pApdu, "\x00\xD6\x00\x00\x00", 5);
	while (1)
	{
		if (CertSize > 240)
		{
			pApdu[2] = (BYTE)((bOffset & 0xFF00) >> 8);
			pApdu[3] = (BYTE)bOffset;
			pApdu[4] = 240;
			memcpy(pApdu + 5, Cert + bOffset - 2, 240);
			InLen = 5 + 240;
			SW = MSC_SendAPDU(pApdu, InLen, pbResp, &OutLen);
			if (SW != 0x9000) goto END;
			bOffset += 240;
			CertSize -= 240;
		}
		else
		{
			pApdu[2] = (BYTE)((bOffset & 0xFF00) >> 8);
			pApdu[3] = (BYTE)bOffset;
			pApdu[4] = (BYTE)CertSize;
			memcpy(pApdu + 5, Cert + bOffset - 2, CertSize);
			InLen = 5 + CertSize;
			SW = MSC_SendAPDU(pApdu, InLen, pbResp, &OutLen);
			if (SW != 0x9000) goto END;
			break;
		}
	}
	SW = 0x9000;
END:
	return SW;
}

WORD MSC_ReadCert(BYTE *Cert, UINT *CertLen)
{
	WORD SW;
	BYTE pApdu[256];
	BYTE pbResp[256];
	UINT dwOutLen;
	BYTE bCert[3000] = { 0 };
	UINT dwCertSize;
	WORD bOffset = 0;

	memcpy(pApdu, "\x00\xA4\x00\x00\x02\x50\x00", 7);
	SW = MSC_SendAPDU(pApdu, 7, pbResp, &dwOutLen);
	if (SW != 0x9000) goto END;

	memcpy(pApdu, "\x00\xA4\x02\x00\x02\x50\x01", 7);
	SW = MSC_SendAPDU(pApdu, 7, pbResp, &dwOutLen);
	if (SW != 0x9000) goto END;

	memcpy(pApdu, "\x00\xB0\x00\x00\x02", 5);
	SW = MSC_SendAPDU(pApdu, 5, pbResp, &dwOutLen);
	if (SW != 0x9000) goto END;
	dwCertSize = (pbResp[0] << 8 | pbResp[1]);
	
	*CertLen = dwCertSize;

	//--Add by cong.peng
	if (Cert == NULL)
		return SW;
	//--End add

	bOffset = 2;
	while (1)
	{

		if (dwCertSize > 235)
		{
			pApdu[2] = (BYTE)((bOffset & 0xff00) >> 8);
			pApdu[3] = (BYTE)(bOffset & 0x00ff);
			pApdu[4] = 235;
			SW = MSC_SendAPDU(pApdu, 5, pbResp, &dwOutLen);
			if (SW != 0x9000) goto END;
			memcpy(bCert + bOffset, pbResp, 235);
			bOffset += 235;
			dwCertSize -= 235;
		}
		else
		{
			pApdu[2] = (BYTE)((bOffset & 0xff00) >> 8);
			pApdu[3] = (BYTE)(bOffset & 0x00ff);
			pApdu[4] = (BYTE)dwCertSize;
			SW = MSC_SendAPDU(pApdu, 5, pbResp, &dwOutLen);
			if (SW != 0x9000) goto END;
			memcpy(bCert + bOffset, pbResp, dwCertSize);
			break;
		}
	}

	memcpy(Cert, bCert+2, *CertLen);
	SW = 0x9000;
END:

	return SW;
}