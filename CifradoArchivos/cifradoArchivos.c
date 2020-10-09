#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

//se definen los errores del evp
#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEX -4

//definicion para el cifrado de AES
#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

typedef struct _cipher_params_t{
	unsigned char *key;
	unsigned char *iv;
	unsigned int encrypt;
	const EVP_CIPHER *cipher_type;
}cipher_params_t;

//limpieza de la memoria reservada
void cleanup(cipher_params_t *params, FILE *ifp, FILE *ofp, int rc){
	free(params);
	free(ifp);
	free(ofp);
	exit(rc);
}

//
void file_encrypt_decrypt(cipher_params_t *params, FILE *ifp, FILE *ofp){
	int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
	unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
	
	int num_bytes_read, out_len;
	EVP_CIPHER_CTX *ctx;
	
	//primero se crea un nuevo contexto del cifrador
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",	ERR_error_string(ERR_get_error(), NULL));
		cleanup(params,ifp,ofp,ERR_EVP_CIPHER_INIT);
	}
	
	//antes de generar la llave es necesario revisar la longitud
	if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(),NULL));
		cleanup(params,ifp,ofp,ERR_EVP_CIPHER_INIT);
	}
	
	//se inicialzan el IV y la llave
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);
	
	//se establecen el IV y la llave
	if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(),NULL));
		EVP_CIPHER_CTX_cleanup(ctx);
		cleanup(params,ifp,ofp,ERR_EVP_CIPHER_INIT);
	}
	
	while(1){
		//lee los datos del fichero hasta que llegue a un EOF, actualizando el cifrado en cada lectura
		num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
		
		//se manejan poosibles errores en la lectura del fichero
		if(ferror(ifp)){
			fprintf(stderr, "ERROR read error: %s\n", strerror(errno));
			EVP_CIPHER_CTX_cleanup(ctx);
			cleanup(params,ifp,ofp,errno);
		}
		
		//manejo de posibles errores al hacer el cifrado
		if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
			fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			EVP_CIPHER_CTX_cleanup(ctx);
			cleanup(params,ifp,ofp,ERR_EVP_CIPHER_INIT);
		}
		
		fwrite (out_buf, sizeof(unsigned char), out_len, ofp);
		if(ferror(ofp)){
			fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
			EVP_CIPHER_CTX_cleanup(ctx);
			cleanup(params,ifp,ofp,errno);
		}
		
		//si ya llego a su EOF
		if(num_bytes_read < BUFSIZE)
			break;
	}
	
	//finalmente se hace un cifrado del bloque final y se escribe en el nuevo fichero
	if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
		fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
   		EVP_CIPHER_CTX_cleanup(ctx);
		cleanup(params,ifp,ofp,ERR_EVP_CIPHER_FINAL);
	}
	
	fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
	if(ferror(ofp)){
		fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
		EVP_CIPHER_CTX_cleanup(ctx);
		cleanup(params,ifp,ofp,errno);
	}
	
	//se hace limpeza de memoria para ctx
	EVP_CIPHER_CTX_cleanup(ctx);
}

int main(int argc, char *argv[]){
	FILE *f_input, *f_enc, *f_dec;
	
	//debe de referenciar el fichero en los argumentos
	if(argc != 2){
		printf("Usage %s /path/to/file\n", argv[0]);
		return -1;
	}
	
	cipher_params_t *params = (cipher_params_t *) malloc(sizeof(cipher_params_t));
	
	if(!params){
		fprintf(stderr, "ERROR: malloc error cannot allocate memory on heap: %s\n", strerror(errno));
		return errno;
	}
	
	unsigned char key[AES_256_KEY_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	
	if(!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))){
		fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
		return errno;
	}
	
	params->key = key;
	params->iv = iv;
	
	//se inicia encriptando el documento
	params->encrypt = 1;
	
	//se estrablece el cifrado
	params->cipher_type = EVP_aes_256_cbc();
	
	f_input = fopen(argv[1], "rb");
	if(!f_input){
		fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		return errno;
	}
	
	//se crea un fichero para el cifrado
	f_enc = fopen("encrypted_file", "wb");
	if(!f_enc){
		fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		return errno;
	}
	
	//se encripta el texto dado
	file_encrypt_decrypt(params, f_input, f_enc);
	
	fclose(f_input);
	fclose(f_enc);
	
	//ahora se debe desencriptar el fichero
	params->encrypt = 0;
	f_input = fopen("encrypted_file", "rb");
	if(!f_input){
		fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		return errno;
	}
	
	f_dec = fopen("decrypted_file", "wb");
	if(!f_dec){
		fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		return errno;
	}
	
	//llamar funcion de encriptado desecriptado
	file_encrypt_decrypt(params, f_input, f_dec);
	
	fclose(f_input);
	fclose(f_dec);
	
	free(params);
	

	return EXIT_SUCCESS;
}

