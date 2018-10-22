/** ****************************************************************************
* @copyright						CVM
*               Copyright (c) 2017 - 2018 All Rights Reserved
********************************************************************************
* @file     cvm_usbkey.h
* @author   cong.peng <cong.peng@cvchip.com>
* @date     2017-5-15 17:09:24
* @version  v1.0
* @brief    CVM UsbKey SDK Header File
* @defgroup
* @{
*******************************************************************************/
#ifndef	_CVM_USBKEY_H_
#define	_CVM_USBKEY_H_

// ===========================Para Code Define==================================
#define CVM_ALG_SM1		0x11	//SM1算法标识
#define	CVM_ALG_SM4		0x14	//SM4算法标识

#define CVM_KEY_SM1		0x01	//SM1密钥标识
#define	CVM_KEY_SM4		0x00	//SM4密钥标识

#define CVM_SBC_ECB_E	0x00	//ECB加密模式
#define CVM_SBC_ECB_D	0x01	//ECB解密模式
#define CVM_SBC_CBC_E	0x02	//CBC加密模式
#define CVM_SBC_CBC_D	0x03	//CBC解密模式
// =============================================================================

// ===========================Error Code Define=================================
#define	CVM_OK							0			//正常
#define	CVM_FAIL						0xFFFFFFFF	//失败
#define	CVM_ERR							0xFFFF0000	//失败
#define CVM_ALLOC_FAILED				0xFFFF1000	//开辟空间失败
#define	CVM_ERR_CERT_PARSE_FAILED		0xFFFF2100	//证书解析失败
#define	CVM_ERR_CERT_VERIFY_FAILED		0xFFFF2200	//证书解析失败
#define CVM_ERR_BAD_INPUT_DATA			0xFFFF2500	//数据输入错误
#define	CVM_ERR_BUFFER_TOO_SMALL		0xFFFF2400	//缓冲区太小
#define	CVM_ERR_ECP_INVALID_KEY			0xFFFF3100	//密钥无效
#define CVM_ERR_VERIFY_ADMINPIN			0xFFFF4100	//管理员PIN验证失败
#define CVM_ERR_VERIFY_USERPIN			0xFFFF4200	//用户PIN验证失败
#define CVM_ERR_PIN_STATUS				0xFFFF4300	//PIN验证状态无效
#define CVM_ERR_READ_PUBKEY				0xFFFF5101	//读取公钥失败
#define CVM_ERR_READ_CERT				0xFFFF5102	//读取证书失败
#define CVM_ERR_WRITE_CERT				0xFFFF5202	//写入证书失败

#define CVM_ERR_SIGN					0xFFFF6F0C	//私钥签名失败
#define CVM_ERR_VERIFY					0xFFFF6F0D	//公钥验签失败
#define CVM_ERR_ENCRYPT					0xFFFF6F0E	//公钥加密失败
#define CVM_ERR_DECRYPT					0xFFFF6F0F	//私钥解密失败

#define CVM_ERR_UNSUPPORT				0xFFFF6A81	//不支持此功能
#define CVM_ERR_P1_P2					0xFFFF6A86	//参数P1、P2不正确
#define CVM_ERR_CANNOT_USE				0xFFFF6985	//不满足使用条件
#define CVM_ERR_APPLOCKED_FOREVER		0xFFFF9303	//应用被永久锁定
// =============================================================================

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// =============================================================================
// 名称：CVM_OpenDevice
// 功能：打开设备
// 参数：无
// 返回：CVM_OK		正常
//		 CVM_FAIL	失败
// =============================================================================
int CVM_OpenDevice();

// =============================================================================
// 名称：CVM_CloseDevice
// 功能：关闭设备
// 参数：
// 返回：CVM_OK		正常
//       CVM_FAIL	失败
// =============================================================================
int CVM_CloseDevice();

// =============================================================================
// 名称：CVM_GetChallenge
// 功能：获取随机数
// 参数：rand		[OUT]	随机数缓冲区
//		 rand_len	[IN]	随机数长度
// 返回：CVM_OK		正常
//		 CVM_ERR_XXXX	UKEY返回错误指令
// =============================================================================
int CVM_GetChallenge(unsigned char *rand, int rand_len);

// =============================================================================
// 名称：CVM_VerifyAdminPin
// 功能：验证管理员PIN
// 参数：pin		[IN]	PIN数据
//		 pin_len	[IN]	PIN数据长度
// 返回：CVM_OK		正常
//		 CVM_ERR_VERIFY_ADMINPIN	用户口令认证失败
// =============================================================================
int CVM_VerifyAdminPin(unsigned char *pin, int pin_len);

// =============================================================================
// 名称：CVM_VerifyUserPin
// 功能：验证用户PIN
// 参数：pin		[IN]	PIN数据
//		 pin_len	[IN]	PIN数据缓冲区长度
// 返回：CVM_OK		正常
//		 CVM_ERR_VERIFY_USERPIN	用户口令认证失败
// =============================================================================
int CVM_VerifyUserPin(unsigned char *pin, int pin_len);

// =============================================================================
// 名称：CVM_ChangeAdminPIN
// 功能：更换管理员PIN
// 参数：oldpin		[IN]	旧PIN数据
//		 opin_len	[IN]	旧PIN数据长度
//		 newpin		[IN]	新PIN数据
//		 npin_len	[IN]	新PIN数据长度
// 返回：CVM_OK				正常
//		 CVM_ERR_XXXX		UKEY返回错误指令
// 备注：需先验证管理员PIN
// =============================================================================
int CVM_ChangeAdminPIN(unsigned char *oldpin, int opin_len, unsigned char *newpin, int npin_len);

// =============================================================================
// 名称：CVM_ChangeUserPIN
// 功能：更换用户PIN
// 参数：oldpin		[IN]	旧PIN数据
//		 opin_len	[IN]	旧PIN数据长度
//		 newpin		[IN]	新PIN数据
//		 npin_len	[IN]	新PIN数据长度
// 返回：CVM_OK				正常
//		 CVM_ERR_PIN_STATUS	PIN状态错误
//		 CVM_ERR_XXXX		UKEY返回错误指令
// 备注：需先验证管理员PIN
// =============================================================================
int CVM_ChangeUserPIN(unsigned char *oldpin, int opin_len, unsigned char *newpin, int npin_len);

// =============================================================================
// 名称：CVM_ResetUserPIN
// 功能：重置用户PIN
// 参数：pin		[IN]	PIN数据
//		 pin_len	[IN]	PIN数据缓冲区长度
// 返回：CVM_OK		正常
//		 CVM_ERR_PIN_STATUS	PIN状态错误
//		 CVM_ERR_XXXX		UKEY返回错误指令
// 备注：需先验证管理员PIN
// =============================================================================
int CVM_ResetUserPIN(unsigned char *pin, int pin_len);

// =============================================================================
// 名称：CVM_ReadCert
// 功能：从设备中读取用户证书，并返回数据长度
// 参数：cert		[OUT]	存放证书数据的缓冲区，若为NULL，用于取得证书数据长度
//		 cert_len	[IN,OUT]	输入时表示数据缓冲区长度，输出时表示证书数据长度
// 返回：CVM_OK		正常
//		 CVM_ERR_READ_CERT	证书读取失败
//		 CVM_ERR_BUFFER_TOO_SMALL	数据缓冲区长度不够
// =============================================================================
int CVM_ReadCert(unsigned char *cert, int *cert_len);

// =============================================================================
// 名称：CVM_WriteCert
// 功能：写入用户证书到设备
// 参数：cert		[IN]	证书数据
//		 cert_len	[IN]	证书数据长度
// 返回：CVM_OK		正常
//		 CVM_ERR_WRITE_CERT	证书写入失败
// 备注：需先验证用户PIN
// =============================================================================
int CVM_WriteCert(unsigned char *cert, int cert_len);

// =============================================================================
// 名称：CVM_ParseCert_Name
// 功能：从证书中读取名称
// 参数：cert		[IN]	证书数据
//		 cert_len	[IN]	证书数据缓冲区长度
//		 type		[IN]	读取类型：0表示读取subject，1表示读取issuer
//		 attr		[IN]	需读取名称的描述，例如"CN"，"O"，"C"等
//		 name		[OUT]	被读取的名称
//		 name_len	[IN]	名称缓冲区长度
// 返回：CVM_OK		正常
//		 CVM_ERR_CERT_PARSE_FAILED	证书解析失败
//		 CVM_ERR_BUFFER_TOO_SMALL	数据缓冲区长度不够
// =============================================================================
int CVM_ParseCert_Name(unsigned char *cert, int cert_len, int type, 
	const char *attr,	char *name, int name_len);

// =============================================================================
// 名称：CVM_ParseCert_PubKey
// 功能：从证书中读取公钥
// 参数：cert		[IN]	证书数据
//		 cert_len	[IN]	证书数据缓冲区长度
//		 pubkey		[OUT]	公钥数据缓冲区
//		 pk_len		[IN,OUT]	公钥缓冲区长度
// 返回：CVM_OK		正常
//		 CVM_ERR_CERT_PARSE_FAILED	证书解析失败
//		 CVM_ERR_BUFFER_TOO_SMALL	数据缓冲区长度不够
// =============================================================================
int CVM_ParseCert_PubKey(unsigned char *cert, int cert_len, unsigned char *pubkey, int *pk_len);

// =============================================================================
// 名称：CVM_ParseCert_Validity
// 功能：从证书中读取有效时间
// 参数：cert		[IN]	证书数据
//		 cert_len	[IN]	证书数据缓冲区长度
//		 not_befor	[OUT]	有效期起始时间，格式yyyy-mm-dd hh:mm:ss
//		 not_after	[OUT]	有效期截止时间，格式yyyy-mm-dd hh:mm:ss
// 返回：CVM_OK		正常
//		 CVM_ERR_CERT_PARSE_FAILED	证书解析失败
// 备注：输出缓冲区长度大于20比特
// =============================================================================
int CVM_ParseCert_Validity(unsigned char *cert, int cert_len, char *not_befor, char *not_after);

// =============================================================================
// 名称：CVM_VerifyCert
// 功能：用上级证书验证证书有效性
// 参数：cert		[IN]	证书数据
//		 cert_len	[IN]	证书数据缓冲区长度
//		 trust_ca	[IN]	上级证书数据
//		 tca_len	[IN]	上级证书数据缓冲区长度
// 返回：CVM_OK		正常
//		 CVM_ERR_CERT_PARSE_FAILED	证书解析失败
//		 CVM_ERR_CERT_VERIFY_FAILED	证书验证失败
// =============================================================================
int CVM_VerifyCert(unsigned char *cert, int cert_len, unsigned char *trust_ca, int tca_len);

// =============================================================================
// 名称：CVM_SM2GenKey
// 功能：产生设备内的公私钥对
// 参数：无
// 返回：CVM_OK				正常
//		 CVM_ERR_PIN_STATUS	PIN状态错误
//		 CVM_ERR_XXXX		UKEY返回错误指令
// 备注：需先验证用户PIN
// =============================================================================
int CVM_SM2GenKey();

// =============================================================================
// 名称：CVM_SM2ImportKeyPairToFile
// 功能：导入公私钥对到设备
// 参数：pubkey		[IN]	公钥数据
//		 pubk_len	[IN]	公钥数据长度
//		 prikey		[IN]	私钥数据
//		 prik_len	[IN]	私钥数据长度
// 返回：CVM_OK				正常
//		 CVM_ERR_PIN_STATUS	PIN状态错误
//		 CVM_ERR_XXXX		UKEY返回错误指令
// 备注：需先验证用户PIN
// =============================================================================
int CVM_SM2ImportKeyPairToFile(unsigned char *pubkey, int pubk_len, unsigned char *prikey, int prik_len);

// =============================================================================
// 名称：CVM_SM2ExportPubKey
// 功能：导出设备内的公钥
// 参数：pubk		[OUT]	公钥数据
//		 plen		[OUT]	公钥数据缓冲区长度
// 返回：CVM_OK					正常
//		 CVM_ERR_READ_PUBKEY	公钥读取失败
// =============================================================================
int CVM_SM2ExportPubKey(unsigned char *pubk, int *plen);

// =============================================================================
// 名称：CVM_SM2SignHash
// 功能：使用SM2算法对杂凑值进行签名
// 参数：hash		[IN]	待签名杂凑值
//		 hash_len	[IN]	待签名杂凑值长度
//		 sign		[OUT]	签名值缓冲区
//		 sign_len	[OUT]	签名值缓冲区长度指针
// 返回：CVM_OK				正常
//		 CVM_ERR_PIN_STATUS	PIN状态错误
//		 CVM_ERR_XXXX		UKEY返回错误指令
// 备注：需先验证用户PIN
// =============================================================================
int CVM_SM2SignHash(unsigned char *hash, int hash_len, unsigned char *sign, int *sign_len);

// =============================================================================
// 名称：CVM_SM2VerifyHash
// 功能：使用SM2算法对杂凑值的签名数据进行验证
// 参数：hash		[IN]	待签名杂凑值
//		 hash_len	[IN]	待签名杂凑值长度
//		 pubkey		[IN]	公钥
//		 pubk_len	[IN]	公钥数据长度
//		 sign		[IN]	签名值
//		 sign_len	[IN]	签名值长度
// 返回：CVM_OK				正常
//		 CVM_ERR_PIN_STATUS	PIN状态错误
//		 CVM_ERR_XXXX		UKEY返回错误指令
// =============================================================================
int CVM_SM2VerifyHash(unsigned char *hash, int hash_len, unsigned char *pubkey, int pubk_len, unsigned char *sign, unsigned int sign_len);

// =============================================================================
// 名称：CVM_SM2SignData
// 功能：使用SM2算法对数据进行签名
// 参数：data		[IN]	待签名数据
//		 data_len	[IN]	待签名数据长度
//		 sign		[OUT]	签名值缓冲区
//		 sign_len	[OUT]	签名值缓冲区长度指针
// 返回：CVM_OK		正常
//		 CVM_ERR_SIGN			签名失败
//		 CVM_ERR_READ_PUBKEY	公钥读取失败
//		 CVM_ERR_ECP_INVALID_KEY	无效密钥数据
// 备注：需先验证用户PIN
// =============================================================================
int CVM_SM2SignData(unsigned char *data, int data_len, unsigned char *sign, unsigned int *sign_len);

// =============================================================================
// 名称：CVM_SM2VerifyData
// 功能：使用SM2算法对签名数据进行验证
// 参数：data		[IN]	待验签数据
//		 data_len	[IN]	待验签数据长度
//		 pubk		[IN]	公钥
//		 klen		[IN]	公钥数据长度
//		 sign		[IN]	签名值
//		 sign_len	[IN]	签名值长度
// 返回：CVM_OK		正常
//		 CVM_ERR_VERIFY			验签失败
//		 CVM_ERR_ECP_INVALID_KEY	无效密钥数据
// =============================================================================
int CVM_SM2VerifyData(unsigned char *data, int dlen, unsigned char *pubk, int klen, unsigned char *sign, unsigned int slen);

// =============================================================================
// 名称：CVM_SM2Encrypt
// 功能：使用SM2算法和外部公钥对数据进行加密
// 参数：plain		[IN]	明文数据
//		 plen		[IN]	明文数据长度
//		 pubkey		[IN]	公钥
//		 klen		[IN]	公钥数据长度
//		 cipher		[IN]	密文数据
//		 clen		[IN,OUT]	密文数据长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX		UKEY返回错误指令
// =============================================================================
int CVM_SM2Encrypt(unsigned char *plain, int plen, unsigned char *pubkey, int klen, unsigned char *cipher, int *clen);

// =============================================================================
// 名称：CVM_SM2Decrypt
// 功能：使用SM2算法和内部私钥对数据进行解密
// 参数：cipher		[IN]	密文数据
//		 clen		[IN]	密文数据长度
//		 plain		[IN]	明文数据
//		 plen		[IN,OUT]	明文数据长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX		UKEY返回错误指令
// =============================================================================
int CVM_SM2Decrypt(unsigned char *cipher, int clen, unsigned char *plain, int *plen);

// =============================================================================
// 名称：CVM_SM3Hash
// 功能：使用SM3算法对数据进行摘要
// 参数：message	[IN]		数据
//		 mlen		[IN]		数据长度
//		 hash		[IN]		杂凑值缓冲区，若为NULL，表示获取杂凑值长度
//		 hlen		[IN,OUT]	杂凑值缓冲区长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX		UKEY返回错误指令
// =============================================================================
int CVM_SM3Hash(unsigned char *message, int mlen, unsigned char *hash, int *hlen);

// =============================================================================
// 名称：CVM_SM3Init
// 功能：SM3算法初始化
// 参数：message	[IN]		数据
//		 mlen		[IN]		数据长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX		UKEY返回错误指令
// =============================================================================
int CVM_SM3Init(unsigned char *message, int mlen);

// =============================================================================
// 名称：CVM_SM3Update
// 功能：多组数据进行SM3算法杂凑计算
// 参数：message	[IN]		数据
//		 mlen		[IN]		数据长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX		UKEY返回错误指令
// 备注：需先掉用CVM_SM3Init
// =============================================================================
int CVM_SM3Update(unsigned char *message, int mlen);

// =============================================================================
// 名称：CVM_SM3Final
// 功能：结束SM3算法杂凑计算
// 参数：message	[IN]		数据
//		 mlen		[IN]		数据长度
//		 hash		[IN]		杂凑值缓冲区，若为NULL，表示获取杂凑值长度
//		 hlen		[IN,OUT]	杂凑值缓冲区长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX		UKEY返回错误指令
// =============================================================================
int CVM_SM3Final(unsigned char *message, int mlen, unsigned char *hash, int *hlen);

// =============================================================================
// 名称：CVM_SBCWriteKeyToFile
// 功能：对称算法密钥导入
// 参数：KeyIndex	[IN]		密钥标识
//		 key		[IN]		密钥数据
//		 klen		[IN]		密钥数据长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX			UKEY返回错误指令
// =============================================================================
int CVM_SBCWriteKeyToFile(unsigned char KeyIndex, unsigned char *key, int klen);

// =============================================================================
// 名称：CVM_SBCInit
// 功能：对称算法初始化，完成算法和密钥设置
// 参数：AlgFlag	[IN]		算法标识
//		 KeyIndex	[IN]		密钥标识（key为NULL时,有效）
//		 key		[IN]		密钥数据（若为NULL，则使用密钥标识）
//		 klen		[IN]		密钥数据长度
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX			UKEY返回错误指令
// =============================================================================
int CVM_SBCInit(unsigned char AlgFlag, unsigned char KeyIndex, unsigned char *key, int klen);

// =============================================================================
// 名称：CVM_SBCDone
// 功能：对称算法计算
// 参数：type		[IN]		对称算法工作模式
//		 iv			[IN]		初始化向量
//		 indata		[IN]		输入数据
//		 ilen		[IN]		输入数据长度
//		 outdata	[OUT]		输出数据
//		 olen		[OUT]		输出数据长度指针
// 返回：CVM_OK					正常
//		 CVM_ERR_XXXX			UKEY返回错误指令
// 备注：若iv为NULL，表示采用已有IV进行计算
// =============================================================================
int CVM_SBCDone(unsigned char type, unsigned char *iv, unsigned char *indata, int ilen, unsigned char *outdata, int *olen);


int CVM_ParseCert_Signature(unsigned char *cert, int cert_len, unsigned char *sign, int *sign_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CVM_USBKEY_H_ */