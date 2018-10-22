
#ifndef _SM4_H__
#define _SM4_H__



#ifdef __cplusplus //|| defined(c_plusplus)
extern "C"{
#endif
	void SM4KeyExt(unsigned char *Key,unsigned int *rk,unsigned int CryptFlag);
	void SM4Crypt(unsigned char *Input,unsigned char *Output,unsigned int *rk);
	void sm4_enc(unsigned char *Key,unsigned char *Input,unsigned char *Output);
	void sm4_dec(unsigned char *Key,unsigned char *Input,unsigned char *Output);
	void sm4_2key_encIV(unsigned  char *pbIV,
		unsigned  char *pbInput,
		int cbInput, 
		unsigned  char *pbKey, 
		unsigned  char *pbOutput, 
		int *pcbOutput);

	int sm4_2key_decIV(	unsigned  char *pbIV,
		unsigned  char *pbInput, 
		int cbInput, 
		unsigned  char *pbKey, 
		unsigned  char *pbOutput, 
		int *pcbOutput);

	void sm4_2key_enc(unsigned  char *pbInput,
		int cbInput, 
		unsigned  char *pbKey, 
		unsigned  char *pbOutput, 
		int *pcbOutput);

	int sm4_2key_dec(unsigned  char *pbInput, 
		int cbInput, 
		unsigned  char *pbKey, 
		unsigned  char *pbOutput, 
		int *pcbOutput);

	void sm4_2key_mac(unsigned  char *pbInput, 
		int cbInput, 
		unsigned  char *pbIV,
		unsigned  char *pbKey, 
		unsigned  char *pbOutput);

#ifdef __cplusplus //|| defined(c_plusplus)
}
#endif

#endif
