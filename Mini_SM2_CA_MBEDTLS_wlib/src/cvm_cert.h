#ifndef _CVM_CERT_H_
#define _CVM_CERT_H_

#ifdef __cplusplus
extern "C" {
#endif

#define	CVM_X509_CRT_VERSION_1	0
#define	CVM_X509_CRT_VERSION_2	1
#define	CVM_X509_CRT_VERSION_3	2


int cvm_pk_write_pubkey_file(char *filename, unsigned char *pubkey, int plen);

typedef struct _cvm_ecp_gen_options
{
	const char *pri_file;       /* filename of the pri_key file             */
	const char *pub_file;       /* filename of the pub_key file             */
} CVM_ECP_GEN_OPT;

int cvm_ecp_gen_key(CVM_ECP_GEN_OPT *opt, unsigned char *prikey, int *prilen, unsigned char *pubkey, int *publen);

typedef struct _cvm_csr_write_options
{
	int ext_sign;				/* use extern sign                      */
	const char *subject_key;    /* filename of the key file             */
	const char *subject_name;   /* subject name for certificate request */
	const char *subject_pwd;    /* password for the subject key file    */
	unsigned char key_usage;    /* key usage flags                      */
	unsigned char ns_cert_type; /* NS cert type                         */

	const char *output_file;    /* where to store the constructed key file  */
} CVM_CSR_WRITE_OPT;

int cvm_csr_write_from_opt(CVM_CSR_WRITE_OPT *opt, unsigned char *creq, int *len);

int cvm_csr_verify(unsigned char *creq, int len);


typedef struct _cvm_crt_write_options
{
	const char *serial;         /* serial number string(hex)            */
	const char *not_befor;      /* validity period not before           */
	const char *not_after;      /* validity period not after            */
	const char *issuer_key;     /* filename of the issuer key file      */
	const char *issuer_pwd;     /* password for the issuer key file     */

	int selfsign;               /* selfsign the certificate.            If selfsign is enabled, issuer_crt and issuer_name are ignored!*/
	const char *issuer_crt;     /* filename of the issuer certificate.  If issuer_crt is specified, issuer_name is ignored!*/
	const char *issuer_name;    /* issuer name for certificate          */

	const char *request_file;   /* filename of the certificate request. If request_file is specified, subject_key, subject_pwd and subject_name are ignored!*/
	const char *subject_name;   /* subject name for certificate         */
	const char *subject_pubkey; /* filename of the subject pubkey file  */
//	const char *subject_pwd;    /* password for the subject key file    */

	int is_ca;                  /* is a CA certificate                  */
	int max_pathlen;            /* maximum CA path length               */
	unsigned char key_usage;    /* key usage flags                      */
	unsigned char ns_cert_type; /* NS cert type                         */

	const char *output_file;    /* where to store the constructed key file  */
} CVM_CRT_WRITE_OPT;

int cvm_crt_write_from_opt(CVM_CRT_WRITE_OPT *opt, unsigned char *cert, int *len);

#ifdef __cplusplus
}
#endif

#endif // !_CVM_CERT_H_
