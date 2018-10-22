#include <stdio.h>

#include "COSAPI.h"



static int MSCReader=0;


DWORD MSCReaderConnect()
{
	DWORD dwRet;

	MSCReader = API_ConnectOneDev();

	if (MSCReader >= 0)
		dwRet = 0;
	else
		dwRet = -1;

	return dwRet;
}


DWORD MSCAPDU(unsigned char * sendBuffer,  DWORD sendLen,unsigned char * receiveBuffer,DWORD *dwrLen)
{
	DWORD dwRet = 0;
	APDUEx pApdu;

	pApdu.cla = sendBuffer[0];
	pApdu.ins = sendBuffer[1];
	pApdu.p1 = sendBuffer[2];
	pApdu.p2 = sendBuffer[3];
	pApdu.lc = 0;
	pApdu.le = 0;
	if (sendLen == 5)
	{
		pApdu.le = sendBuffer[4];
	}
	else
	{
		pApdu.lc = sendBuffer[4];
		memcpy(pApdu.sendbuf, sendBuffer + 5, pApdu.lc);
	}

	dwRet = API_SendApdu(MSCReader, &pApdu);

	*dwrLen = pApdu.le + 2;
	memcpy(receiveBuffer, pApdu.recvbuf, *dwrLen);

	return dwRet;
}

DWORD MSCReaderDisConnect()
{
	DWORD dwRet;

	dwRet = API_Close(MSCReader);
	MSCReader = 0;

	return dwRet;
}