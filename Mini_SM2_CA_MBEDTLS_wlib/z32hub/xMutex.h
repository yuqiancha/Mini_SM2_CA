// 互斥量类
// 关键数据，代码的保护
class xMutex
{
private:
	HANDLE SynMutex;

public:
	xMutex();
	~xMutex();
	void Build(LPCTSTR mutexName); // 建立互斥器
	bool EnterSynCode();	// 进入同步代码区，无限等待
	bool EnterSynCode(DWORD WaitTime);	// 进入同步代码区，有限等待
	bool LeaveSynCode();	// 离开关键代码区
};
