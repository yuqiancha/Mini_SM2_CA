/* Copyright (c) Infosec Security Inc., 2000-2002.  All rights reserved.  
 * This work contains proprietary, confidential, and trade secret 
 * information of Infosec Security Inc.  Use, disclosure or reproduction 
 * without the express written authorization of Infosec Security Inc. is
 * prohibited.
 * Author : Peng.C.D <pengcd@infosec.com.cn>
 * Date   : 28/02/2002
 * 
 * IS_BASE64.h
 *
 * 
 *
 */
/*********************************************************************
* NAME             : IS_Base64.h                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64编解码
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 

#ifndef __IS_BASE64_H__
#define __IS_BASE64_H__

#ifdef __cplusplus
extern "C" {
#endif

#define INFOSECPKCSBASEEXPORT

INFOSECPKCSBASEEXPORT int	IS_Base64Encode(char * srcData , int srcLen , char * desData , int *desLen , bool mb_delimiterSet);

INFOSECPKCSBASEEXPORT int	IS_Base64Decode(char * srcData , int srcLen , char * desData , int *desLen);

#ifdef __cplusplus
}
#endif

#endif
