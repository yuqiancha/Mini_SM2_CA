#ifndef __COSAPI_H__
#define __COSAPI_H__

#include <iostream>   
#include <windows.h>
#include <winioctl.h> 
#include <setupapi.h>
#include "xMutex.h"

#define MAX_READERS			10

//APDU 命令收发结构
typedef struct
{
		BYTE		cla;
		BYTE		ins;
		BYTE		p1;
		BYTE		p2;
		BYTE		lc;
		BYTE		sendbuf[288];
		BYTE		le;
		BYTE		recvbuf[288];
} APDUEx, *pAPDUEx;

// 错误编码 ===========================================================

EXTERN_C int WINAPI API_Find();
EXTERN_C int WINAPI API_Open(int index);
EXTERN_C int WINAPI API_SendApdu(int index,pAPDUEx apdu);
EXTERN_C int WINAPI API_Close(int index);
EXTERN_C int WINAPI API_EnumDev(LPSTR szNameList, int *ReaderNum,ULONG *pulSize);
EXTERN_C int WINAPI API_ConnectDev(LPSTR szName);
EXTERN_C int WINAPI API_ConnectOneDev();


#define SCARD_F_NO_CARD                       0x80100003L
#define SCARD_F_BUFFER_TOO_SMALL              0x80100001L 

// 错误编码 ===========================================================
#ifndef SCARD_S_SUCCESS

// 成功，没有错误
#define SCARD_S_SUCCESS 				((DWORD)0x00000000L)

// 内部连接检查失败
#define SCARD_F_INTERNAL_ERROR			((DWORD)0x80100001L)

// 操作被用户中止
#define SCARD_E_CANCELLED				((DWORD)0x80100002L)

// 不正确的操作句柄
#define SCARD_E_INVALID_HANDLE			((DWORD)0x80100003L)

// 不正确的参数(p1, p2)
#define SCARD_E_INVALID_PARAMETER		((DWORD)0x80100004L)

// 注册的启动信息丢失或无效
#define SCARD_E_INVALID_TARGET			((DWORD)0x80100005L)

// 没有足够的内存用于完成命令
#define SCARD_E_NO_MEMORY				((DWORD)0x80100006L)

// 内部超时
#define SCARD_F_WAITED_TOO_LONG			((DWORD)0x80100007L)

// 用户给出的缓冲区太小，不足以放下全部的返回数据
#define SCARD_E_INSUFFICIENT_BUFFER		((DWORD)0x80100008L)

// 未知的读卡器
#define SCARD_E_UNKNOWN_READER			((DWORD)0x80100009L)

// 用户指定的时间超时
#define SCARD_E_TIMEOUT					((DWORD)0x8010000AL)

// 卡正在被其它连接占用
#define SCARD_E_SHARING_VIOLATION		((DWORD)0x8010000BL)

// 在读卡器里面没有卡
#define SCARD_E_NO_SMARTCARD			((DWORD)0x8010000CL)

// 未知的卡类型
#define SCARD_E_UNKNOWN_CARD			((DWORD)0x8010000DL)

// 读卡器无法完成退出卡操作
#define SCARD_E_CANT_DISPOSE			((DWORD)0x8010000EL)

// 当前的卡不支持用户指定的通讯协议
#define SCARD_E_PROTO_MISMATCH			((DWORD)0x8010000FL)

// 卡还没有准备好接收命令
#define SCARD_E_NOT_READY				((DWORD)0x80100010L)

// 某些变量的值不合适
#define SCARD_E_INVALID_VALUE			((DWORD)0x80100011L)

// 操作被系统中止，可能是重新登陆或关机
#define SCARD_E_SYSTEM_CANCELLED		((DWORD)0x80100012L)

// 内部通讯错误
#define SCARD_F_COMM_ERROR				((DWORD)0x80100013L)

// 内部未知错误
#define SCARD_F_UNKNOWN_ERROR			((DWORD)0x80100014L)

// 无效的 ATR 串
#define SCARD_E_INVALID_ATR				((DWORD)0x80100015L)

// 用户尝试结束某个不存在的处理
#define SCARD_E_NOT_TRANSACTED			((DWORD)0x80100016L)

// 指定的读卡器当前无法使用
#define SCARD_E_READER_UNAVAILABLE		((DWORD)0x80100017L)

// 操作被中止，允许服务程序退出
#define SCARD_P_SHUTDOWN				((DWORD)0x80100018L)

// PCI 的接收缓冲区太小
#define SCARD_E_PCI_TOO_SMALL			((DWORD)0x80100019L)

// 读卡器的驱动无法支持当前的读卡器
#define SCARD_E_READER_UNSUPPORTED		((DWORD)0x8010001AL)

// 读卡器的驱动程序无法建立唯一的名字，已经有相同名字的读卡器存在
#define SCARD_E_DUPLICATE_READER		((DWORD)0x8010001BL)

// 卡无法被当前的读卡器支持
#define SCARD_E_CARD_UNSUPPORTED		((DWORD)0x8010001CL)

// 智能卡服务没有开启
#define SCARD_E_NO_SERVICE				((DWORD)0x8010001DL)

// 智能卡服务已经被中止
#define SCARD_E_SERVICE_STOPPED			((DWORD)0x8010001EL)

// 某个意外的智能卡错误产生
#define SCARD_E_UNEXPECTED				((DWORD)0x8010001FL)

// 无法获知智能卡的提供者信息
#define SCARD_E_ICC_INSTALLATION		((DWORD)0x80100020L)

// 无法获知智能卡的生产者信息
#define SCARD_E_ICC_CREATEORDER			((DWORD)0x80100021L)

// 当前的智能卡无法支持用户要求的功能
#define SCARD_E_UNSUPPORTED_FEATURE		((DWORD)0x80100022L)

// 指定的目录不存在
#define SCARD_E_DIR_NOT_FOUND			((DWORD)0x80100023L)

// 指定的文件不存在
#define SCARD_E_FILE_NOT_FOUND			((DWORD)0x80100024L)

// 指定的目录不再是有效的目录
#define SCARD_E_NO_DIR					((DWORD)0x80100025L)

// 指定的文件不再是有效的文件，没有选择文件
#define SCARD_E_NO_FILE					((DWORD)0x80100026L)

// 此文件拒绝访问
#define SCARD_E_NO_ACCESS				((DWORD)0x80100027L)

// 卡的空间已满，无法再写入信息
#define SCARD_E_WRITE_TOO_MANY			((DWORD)0x80100028L)

// 设置文件指针错误
#define SCARD_E_BAD_SEEK				((DWORD)0x80100029L)

// PIN 码错误
#define SCARD_E_INVALID_CHV				((DWORD)0x8010002AL)

// 一个无法识别的错误码从智能卡服务返回
#define SCARD_E_UNKNOWN_RES_MNG			((DWORD)0x8010002BL)

// 请求的证书不存在
#define SCARD_E_NO_SUCH_CERTIFICATE		((DWORD)0x8010002CL)

// 请求的证书不允许获得
#define SCARD_E_CERTIFICATE_UNAVAILABLE	((DWORD)0x8010002DL)

// 找不到任何一个读卡器
#define SCARD_E_NO_READERS_AVAILABLE	((DWORD)0x8010002EL)

// 智能卡通讯过程中发生数据丢失，请再次尝试
#define SCARD_E_COMM_DATA_LOST			((DWORD)0x8010002FL)

// 请求的密钥文件不存在
#define SCARD_E_NO_KEY_CONTAINER		((DWORD)0x80100030L)

// 由于 ATR 配置冲突，读卡器无法跟卡通讯
#define SCARD_W_UNSUPPORTED_CARD		((DWORD)0x80100065L)

// 卡对复位没有响应
#define SCARD_W_UNRESPONSIVE_CARD		((DWORD)0x80100066L)

// 卡没有电
#define SCARD_W_UNPOWERED_CARD			((DWORD)0x80100067L)

// 卡被复位了，因此共享的信息无效了
#define SCARD_W_RESET_CARD				((DWORD)0x80100068L)

// 卡已经被移出了
#define SCARD_W_REMOVED_CARD			((DWORD)0x80100069L)

// 因为安全规则，访问被拒绝了
#define SCARD_W_SECURITY_VIOLATION		((DWORD)0x8010006AL)

// PIN 码没有被验证，访问被拒绝
#define SCARD_W_WRONG_CHV				((DWORD)0x8010006BL)

// 已经到达最大 PIN 码验证次数，访问被拒绝
#define SCARD_W_CHV_BLOCKED				((DWORD)0x8010006CL)

// 已经到达最后的智能卡文件，没有更多的文件可以访问了
#define SCARD_W_EOF						((DWORD)0x8010006DL)

// 操作被用户中止
#define SCARD_W_CANCELLED_BY_USER		((DWORD)0x8010006EL)

// 智能卡 PIN 没有设置
#define SCARD_W_CARD_NOT_AUTHENTICATED	((DWORD)0x8010006FL)

#endif // SCARD_S_SUCCESS


// 文件已经存在
#define SCARD_E_FILE_EXISTS				((DWORD)0xA0100001L)

// 卡内存储器操作出错
#define SCARD_E_EPROM_ERROR				((DWORD)0xA0100002L)

// 用户给出了无效的 CLA
#define SCARD_E_INVALID_CLA				((DWORD)0xA0100003L)

// 用户给出了无效的 INS
#define SCARD_E_INVALID_INS				((DWORD)0xA0100004L)

// VM 地址超界/异常
#define SCARD_E_VM_ADDRESS_ERROR		((DWORD)0xA0100005L)

// 除 0 错
#define SCARD_E_ZERO_DIVIDE				((DWORD)0xA0100006L)

// 卡没有被插入到正确的位置
#define SCARD_E_WRONG_POSITION			((DWORD)0xA0100007L)

// 卡当前处于某种未知的状态
#define SCARD_E_UNKNOWN_STATE			((DWORD)0xA0100008L)

// 卡还没有被打开
#define SCARD_E_CARD_NOT_OPENED			((DWORD)0xA0100009L)

// 未知的命令
#define SCARD_E_UNKNOWN_COMMAND			((DWORD)0xA010000AL)

// 即将设定超级密码的重新设置次数是 0
#define SCARD_E_ZERO_TRYTIME			((DWORD)0xA010000BL)

// 打开了太多的设备
#define SCARD_E_TOO_MANY_DEVICE			((DWORD)0xA010000CL)

// 非法指令错
#define	SCARD_E_INVALID_INSTRUCTION		((DWORD)0xA010000DL)

// 卡还有数据要返回
#define SCARD_W_RESPONSE				((DWORD)0xA01000FFL)

// 内部错误(Windows 错误)
#define SCARD_ERR_SETUP_DI_CLASS_DEVS			0xA0100010

// 内部错误(Windows 错误)
#define SCARD_TOO_LONG_DEVICE_DETAIL			0xA0100013

// 内部错误(Windows 错误)
#define SCARD_SETUP_DI_GET_DEVICE_INTERFACE_DETAIL		0xA010000A

// 打开设备错(Windows 错误)
#define SCARD_ERR_OPEN_DEVICE								0xA0100007

// 没有找到给定要求的设备(参数错误)
#define SCARD_ERR_NO_SUCH_DEVICE							0xA0100001

// 设备再(参数错误)
#define DEVICE_IN_USE							0xA0100046

// 写记录错(Windows 错误)
#define SCARD_ERR_WRITE_REPORT								0xA0100009

// 内部错误(Windows 错误)
#define SCARD_ERR_FLUSH_QUEUE								0xA010000F

// 读记录错(Windows 错误)
#define SCARD_ERR_READ_REPORT								0xA0100008

#endif