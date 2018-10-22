#ifndef __HEADER_SM3_H
#define __HEADER_SM3_H

typedef struct _SM3_CTX
{
    unsigned long state[8];
    unsigned long count[2];
    unsigned char buffer[64];
} SM3_CTX;


#ifdef __cplusplus
extern "C"
{
#endif
	
	void SM3Init(SM3_CTX* context);
	void SM3Update(SM3_CTX* context, unsigned char* data, unsigned int len);
	void SM3Final(SM3_CTX* context,unsigned char *pbDigest);
	void SM3Simple( unsigned char* data, unsigned int charlen,unsigned char *digest);
	void GBCombine(unsigned char *X,unsigned int bytelen1,unsigned char *Y,unsigned int bytelen2,unsigned char *XY,unsigned int *bytelen3);
	int GBKDF(unsigned char *Z,unsigned int bytelen,unsigned char *ZOut,unsigned int klen);





#ifdef __cplusplus
}
#endif /* __cplusplus */



#endif /* __SM3_H_INCLUDED__ */