#include <windows.h>
#include "xMutex.h"


xMutex::xMutex()
{
	SynMutex = NULL;
}

xMutex::~xMutex()
{
	if (SynMutex != NULL)
	{
		CloseHandle(SynMutex);
		SynMutex = NULL;
	}
}

void xMutex::Build(LPCTSTR mutexName)
{
	SynMutex = OpenMutex(SYNCHRONIZE, FALSE, mutexName);
	if (SynMutex == NULL)
		SynMutex = CreateMutex(NULL, FALSE, mutexName);
}

bool xMutex::EnterSynCode()
{
	DWORD const WaitState = WaitForSingleObject(SynMutex, INFINITE);
	return(true);
}

bool xMutex::EnterSynCode(DWORD WaitTime)
{
	DWORD const WaitState = WaitForSingleObject(SynMutex, WaitTime);
	if (WAIT_TIMEOUT==WaitState) return(false);
	return(true);
}

bool xMutex::LeaveSynCode()
{
	return(!!ReleaseMutex(SynMutex));
}
