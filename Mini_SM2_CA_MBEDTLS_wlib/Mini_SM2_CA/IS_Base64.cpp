/*********************************************************************
* NAME             : IS_Base64.cpp                            
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
#include "stdafx.h"

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "IS_Base64.h"
//#include "IS_NetSignError.h"
#define   ER_MEMORY_OUT  -1
#define   ER_BASE64DECODE_FAILED -2

/*********************************************************************
* NAME             : STelem_enc                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Encode节点数据结构
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
typedef struct str_type_enc
{
	int length;				
	unsigned char remainchr[2];		
	int linetime;			
}STelem_enc;

/*********************************************************************
* NAME             : STelem_dec                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Decdoe节点数据结构
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
typedef struct str_type_dec
{
	int length;				
	unsigned char remainchr[3];		
}STelem_dec;

/*********************************************************************
* NAME             : encodeini                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Encode初始化
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
void 
encodeini(unsigned char  **e)
{
	STelem_enc *elem;
	elem=(STelem_enc *)malloc(sizeof(STelem_enc));
	elem->length=0;
	elem->remainchr[0]=0;
	elem->remainchr[1]=0;
	elem->linetime=1;
	*e = (unsigned char *)elem;
}

/*********************************************************************
* NAME             : encodeupdate                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Encode编码数据
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
int 
encodeupdate(unsigned char *bufferA,int strlength,unsigned char *bufferB,unsigned char  *tem)
{
	int i=0,j=0,k=0,count=0;
	int num=0;
	unsigned char chr=0;
	unsigned char buffer[3]={0,0};
	unsigned char decode[256];
	unsigned char temp=0;
	unsigned char result1[4]={0,0,0,0};

	memset((unsigned char *)decode , 0 ,256);

	STelem_enc *y;
	y=(STelem_enc *)tem;
	memset(decode,0,256);
	memset(result1,0,4);
	memset(buffer,0,3);
	j=0;
	k=0;
	for(chr=65,num=0;chr<=90;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x1A;
	for(chr=97;chr<=122;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x34;
	for(chr=48;chr<=57;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	decode[0x3E]=43;
	decode[0x3F]=47;
	decode[0x40]=61;
	
	while(j<strlength)
	{
		for(count=0;(count<=2)&&(j<strlength);count++)
		{
			if (y->length==0)
			{
				temp=bufferA[j];
				buffer[count]=temp;
				j=j+1;
			}
			else if(y->length==2)
			{
				buffer[count]=(y->remainchr[0]);
				count=count+1;
				buffer[count]=(y->remainchr[1]);
				count=count+1;
				temp=bufferA[j];
				buffer[count]=temp;
				j=j+1;
				(y->remainchr[0])=0;
				(y->remainchr[1])=0;
				y->length=0;

			}
			else
			{
				buffer[count]=(y->remainchr[0]);
				count=count+1;
				temp=bufferA[j];
				buffer[count]=temp;
				count=count+1;
				j=j+1;
				temp=bufferA[j];
				buffer[count]=temp;
				j=j+1;
				(y->remainchr[0])=0;
				y->length=0;
			}
		}
		if( count == 3 ) 
		{
			result1[0]=buffer[0]>>2;
			result1[1]=((buffer[0]&0x03)<<4)|(buffer[1]>>4);
			result1[2]=((buffer[1]&0x0F)<<2)|(buffer[2]>>6);
			result1[3]=buffer[2]&0x3F;
			for( i = 0;i<=3;i++)
			{
				bufferB[k]=decode[result1[i]];
				k=k+1;
				y->linetime=y->linetime+1;
				if(y->linetime>76)
				{
					y->linetime=1;
				}	
			}
			memset(buffer,0,3);
		}
		else if( count == 2 )
		{	
			(y->remainchr[0])=buffer[0];
			(y->remainchr[1])=buffer[1];
			y->length=2;
			memset(buffer,0,3);

		}
		else if( count == 1 )
		{	
			(y->remainchr[0])=buffer[0];
			(y->remainchr[1])=0;
			y->length=1;
			memset(buffer,0,3);
		}
		else {}
	}
	return (k);
}

/*********************************************************************
* NAME             : encodefinish                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Encode编码后处理
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
int 
encodefinish(unsigned char *bufferC,unsigned char  *temp)
{
	unsigned char result1[4]={0,0,0,0};
	int i=0,j=0;
	int num=0;
	unsigned char chr=0;
	unsigned char decode[256];
	STelem_enc *y=NULL;

	memset((unsigned char *) decode , 0 ,256);
	
	y=(STelem_enc *)temp;
	memset(decode,0,256);
	memset(result1,0,4);
	j=0;
	for(chr=65,num=0;chr<=90;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x1A;
	for(chr=97;chr<=122;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x34;
	for(chr=48;chr<=57;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	decode[0x3E]=43;
	decode[0x3F]=47;
	decode[0x40]=61;
	if(y->length==2)
	{	
		result1[0]=((y->remainchr[0]))>>2;
		result1[1]=((((y->remainchr[0]))&0x03)<<4)|(((y->remainchr[1]))>>4);
		result1[2]=((((y->remainchr[1]))&0x0F)<<2);
		result1[3]=0x40;

		for( i = 0;i<=3;i++)
		{
			bufferC[j]=decode[result1[i]];
			j=j+1;
			y->linetime=y->linetime+1;
			if(y->linetime>76)
			{
				y->linetime=1;
			}						
		}
		memset((y->remainchr),0,2);
	}
	else if(y->length==1)
	{	
		result1[0]=((y->remainchr[0]))>>2;
		result1[1]=(((y->remainchr[0]))&0x03)<<4;
		result1[2]=0x40;
		result1[3]=0x40;

		for( i = 0;i<=3;i++)
		{
			bufferC[j]=decode[result1[i]];
			j=j+1;
			y->linetime=y->linetime+1;
			if(y->linetime>76)
			{
				y->linetime=1;
			}						
		}
		memset(y->remainchr,0,2);
	}
	else{}
		
	return(j);

}

/*********************************************************************
* NAME             : decodeini                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Decode解码初始化
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
int 
decodeini(unsigned char  **e )
{
	STelem_dec *elem=NULL;
	elem=(STelem_dec *)malloc(sizeof(STelem_dec));
	if(elem==NULL) return -1;
	elem->length=0;
	elem->remainchr[0]=0;
	elem->remainchr[1]=0;
	elem->remainchr[2]=0;
	*e = (unsigned char *)elem;
	return 0;
}
/*********************************************************************
* NAME             : decodeupdate                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Decode解码
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
// 需要考虑包的中间出现＝时的处理
int 
decodeupdate(unsigned char *bufferA,int strlength,unsigned char *bufferB,unsigned char  *tem)
{
	unsigned char buffer[4]={0,0,0,0};
	unsigned char bak[4]={0,0,0,0};
	unsigned char encode[256];
	unsigned char resultA[3]={0,0,0};
	unsigned char resultB[2]={0,0};
	unsigned char resultC[1]={0};
	int count=0,i=0,j=0,k=0;
	unsigned char temp=0;
	STelem_dec *y=NULL;	
	
	memset((unsigned char *)encode , 0x00 , 256);

	if(tem==NULL) return 0; // none characters decode.
	if(bufferA == NULL) return 0; // no input , no output
	if(bufferB==NULL) return strlength ; // need atmost strlength memory.

	y=(STelem_dec *)tem;
	j=0;
	k=0;
	memset(buffer,0,4);
	memset(bak,0,4);
	memset(resultA,0,3);
	memset(resultB,0,2);
	memset(resultC,0,1);
	memset(encode,0,256);
	i=0;
	for(count=65;count<=90;count++)
	{
		encode[count]=0x00+i;
		i++;
	}
	i=0;
	for(count=97;count<=122;count++)
	{	
		encode[count]=0x1A+i;
		i++;
	}
	i=0;
	for(count=48;count<=57;count++)
	{
		encode[count]=0x34+i;
		i++;
	}
	encode[43]=0x3E;
	encode[47]=0x3F;
	encode[61]=0x40;
	
	while(j<strlength)
	{
		for(count=0;(count<=3)&&(j<strlength);count++)
		{
			temp=bufferA[j];
			if (((encode[temp]==0)&&(temp!=65))|(temp==0x0a))
			{
				count=count-1;
				j=j+1;
			}
			else
			{
				if(y->length==3)
				{
					buffer[count]=(y->remainchr[0]);
					bak[count]=encode[buffer[count]];
					count=count+1;
					buffer[count]=(y->remainchr[1]);
					bak[count]=encode[buffer[count]];
					count=count+1;
					buffer[count]=(y->remainchr[2]);
					bak[count]=encode[buffer[count]];

					y->remainchr[0]=0;
					y->remainchr[1]=0;
					y->remainchr[2]=0;
					y->length=0;
				}
				else if(y->length==2)
				{
					buffer[count]=(y->remainchr[0]);
					bak[count]=encode[buffer[count]];
					count=count+1;
					buffer[count]=(y->remainchr[1]);
					bak[count]=encode[buffer[count]];

					(y->remainchr[0])=0;
					(y->remainchr[1])=0;
					y->length=0;
				}
				else if(y->length==1)
				{
					buffer[count]=(y->remainchr[0]);
					bak[count]=encode[buffer[count]];

					(y->remainchr[0])=0;
					y->length=0;	
				}
				else // include (y->length==0) , so update by pengcd.
				{
					buffer[count]=temp;
					bak[count]=encode[buffer[count]];
					j=j+1;
				}
			}
		}
		if (count==4)
		{
			if((buffer[0]!=61)&&(buffer[1]!=61)&&(buffer[2]!=61)&&(buffer[3]!=61))		
			{
				resultA[0]=(bak[0]<<2)|((bak[1]&0xf0)>>4);
				resultA[1]=((bak[1]&0x0F)<<4)|((bak[2]&0xfc)>>2);
				resultA[2]=((bak[2]&0x03)<<6)|bak[3];
				for( i = 0;i<=2;i++)
				{
					bufferB[k]=resultA[i];
					k=k+1;
				}
				memset(buffer,0,4);
				memset(bak,0,4);
			}
			else if((buffer[0]!=61)&&(buffer[1]!=61)&&(buffer[2]!=61)&&(buffer[3]==61))
			{
				resultB[0]=(bak[0]<<2)|((bak[1]&0xf0)>>4);
				resultB[1]=((bak[1]&0x0F)<<4)|((bak[2]&0xfc)>>2);
				for( i = 0;i<=1;i++)
				{
					bufferB[k]=resultB[i];
					k=k+1;
				}
				memset(buffer,0,4);
				memset(bak,0,4);
				break; // packge end for detect the '='.
			}
			else if ((buffer[0]!=61)&&(buffer[1]!=61)&&(buffer[2]==61)&&(buffer[3]==61))
			{
				resultC[0]=(bak[0]<<2)|((bak[1]&0xf0)>>4);
				bufferB[k]=resultC[0];
				k=k+1;	
				memset(buffer,0,4);
				memset(bak,0,4);
				break; // packge end for detect the '='.
			}
			else
			{
				// when '=' is present in other place , maybe error occured , update by pengcd.
				k=0;
				break;
			}
				
		}
		else if( count == 3 ) 
		{	
			y->remainchr[0]=buffer[0];
			y->remainchr[1]=buffer[1];
			y->remainchr[2]=buffer[2];
			y->length=3;
			memset(buffer,0,4);
		}
		else if( count == 2 )
		{	
			(y->remainchr[0])=buffer[0];
			(y->remainchr[1])=buffer[1];
			y->length=2;
			memset(buffer,0,4);

		}
		else if( count == 1 )
		{	
			y->remainchr[0]=buffer[0];
			y->length=1;
			memset(buffer,0,4);
		}
		else {}
			
	}
	return (k); // k is the deocde length.
}
/*********************************************************************
* NAME             : decodeupdate                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Decode解码后处理
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
int 
decodefinish(unsigned char *bufferC,unsigned char  **temp)
{
	int i=0,len=0;
	STelem_dec *y=NULL;	
	
	if(temp == NULL) return 0;
	if(*temp == NULL) return 0;

	y=(STelem_dec *)*temp;
	if(y->length > 0 && y->length <4)
	{
		for(i=0;i<y->length;i++)
			bufferC[i]=y->remainchr[i];
		len = y->length;
	}
	else
	{
		len = 0;
	}
	free(*temp);
	*temp=NULL;

	return len;
}

/*********************************************************************
* NAME             : IS_Base64Encode                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : Base64Encode 方法，OnePass
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
int	IS_Base64Encode(char * srcData , int srcLen , char * desData , int *desLen , bool mb_delimiterSet)
{
	int i=0,j=0,k=0;
	unsigned char * x=NULL;
	unsigned char * tmp=NULL;
	int tmpLen=0;

	tmp=(unsigned char *)malloc(srcLen*2+4);
	if(tmp == NULL) return ER_MEMORY_OUT;

	encodeini(&x);
	
	j=encodeupdate((unsigned char *)srcData,srcLen,(unsigned char *)tmp,x);
	
	k=encodefinish((unsigned char *)tmp+j,x);

	tmpLen=k+j;
	
	free(x);
	
	if(mb_delimiterSet!=true)
	{
		*desLen = tmpLen ;
		if(desData==NULL)
		{
			free(tmp);
			return 0;
		}
		memcpy((unsigned char *)desData , (unsigned char *)tmp , tmpLen);
		free(tmp);
	}
	else
	{
		*desLen = tmpLen +  ((tmpLen-1)/64 + 1);
		if(desData==NULL)
		{
			free(tmp);
			return 0;
		}
		for(i=0,j=0;i<tmpLen;i++)
		{
			*(desData+j) = *(tmp + i);
			j++;
			if((i+1)%64 == 0) 
			{
				*(desData+j)='\n';// '\n' == 0x0a 
				j++;
			}
		}
		*(desData+j)='\n';
		free(tmp);
	}

	return 0;
}
/*********************************************************************
* NAME             : IS_Base64Decode                            
* Copyright (c) 1998 - 2003 Beijing Infosec Technologiess Co., Ltd.
* All Rights Reserved    
* FUNCTION         : IS_Base64Decode 方法，OnePass
* PROGRAMER        : PengCD
* DATE(ORG)        : 2003.08.26
* PROJECT          : NetSign
* OS               : Microsoft Windows 2000 Server 5.00.2195
* HISTORY          :
* ID --- DATE -----------NOTE----------------------------------------
* 00  2003.08.26 初期作成
*********************************************************************/// 
int	IS_Base64Decode(char * srcData , int srcLen , char * desData , int *desLen)
{
	int j=0,k=0;
	
	unsigned char  * x=NULL;
	
	if(desData==NULL)
	{
		*desLen = srcLen ;
		return 0;
	}

	if(0!=decodeini(&x))
	{
		*desLen=0;
		return ER_MEMORY_OUT; //no memory
	}

	j=decodeupdate((unsigned char *)srcData,srcLen,(unsigned char *)desData,x);
	
	k=decodefinish((unsigned char *)&desData[j],&x);

	if (k!=0)
	{
		*desLen= 0;
		return ER_BASE64DECODE_FAILED; // left the byte to be decode , if  you want no error report , remove this sentence.
	}
	else 
	{
		*desLen=j;
	}

	return 0;
}
