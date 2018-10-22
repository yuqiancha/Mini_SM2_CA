/* *Copyright (c) 2007, 武汉大学密码研究中心* 
   *All rights reserved.* 
   *
   *文件名称：types.h
   *摘    要：定义基本公共结构
   *作    者: 孙金龙
   *时    间: 2007.5.3 21:05
   *最新版本: v1.0.0
*/
#ifndef __HEADER_TYPES_H
#define __HEADER_TYPES_H


#ifdef  __cplusplus
extern "C" {
#endif


#define Word   unsigned int
#define WordByteLen 4
#define WordBitLen 32
#define Byte   unsigned char
#define BYTE   unsigned char
#define DWord  unsigned __int64
#define SDWord __int64
#define MSBOfWord	0x80000000
#define LSBOfWord	0x00000001


#define MAXBNWordLen  8
#define MAXBNByteLen  MAXBNWordLen*WordByteLen
#define MAXBNBitLen   MAXBNByteLen*8

//typedef DWord HCRYPTPROV;
	
		
#ifdef  __cplusplus
}
#endif


#endif