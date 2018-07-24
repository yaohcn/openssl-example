/*  gcc ./openssl_sign.c -lssl */

#include <stdio.h>
#include <string.h>
#include <error.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>


int pass_cb( char *buf, int size, int rwflag, void *u )
{
  if ( rwflag == 1 ) {
    /* What does this really means? */
  }

  int len;
  char tmp[1024];
  printf( "Enter pass phrase for '%s': ", (char*)u );
  scanf( "%s", tmp );
  len = strlen( tmp );

  if ( len <= 0 ) return 0;
  if ( len > size ) len = size;

  memset( buf, '\0', size );
  memcpy( buf, tmp, len );
  return len;
}

RSA* getRsaFp( const char* rsaprivKeyPath )
{
  FILE* fp;
  fp = fopen( rsaprivKeyPath, "r" );
  if ( fp == 0 ) {
    fprintf( stderr, "Couldn't open RSA priv key: '%s'. %s\n",
             rsaprivKeyPath, strerror(errno) );
    exit(1);
  }

  RSA *rsa = 0;
  rsa = RSA_new();
  if ( rsa == 0 ) {
    fprintf( stderr, "Couldn't create new RSA priv key obj.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    fclose( fp );
    exit( 1 );
  }

  rsa = PEM_read_RSAPrivateKey(fp, 0, pass_cb, (char*)rsaprivKeyPath);
  if ( rsa == 0 ) {
    fprintf( stderr, "Couldn't use RSA priv keyfile.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    fclose( fp );
    exit( 1 );
  }
  fclose( fp );
  return rsa;
}


int main( int argc, char* argv[] )
{
  if ( argc != 2 ) {
    fprintf( stderr, "Usage: %s <text to sign>\n", argv[0] );
    exit( 1 );
  }
  const char *clearText = argv[1];

  char rsaprivKeyPath[1024];
  sprintf( rsaprivKeyPath, "%s/.ssh/id_rsa",  getenv ("HOME") );

  SSL_load_error_strings();

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  RSA *rsa = 0;
  rsa = getRsaFp( rsaprivKeyPath );

  SHA256_CTX context;
  unsigned char msgDigest[SHA256_DIGEST_LENGTH];  // 32

  SHA256_Init(&context);
  SHA256_Update(&context, (unsigned char*)clearText, strlen(clearText));
  SHA256_Final(msgDigest, &context);

  int i;
  printf("Digest: ");
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    printf("%02x", msgDigest[i]);
  }
  printf("\n");


  const int MAX_LEN = RSA_size(rsa);  //256
  unsigned char sigRet[MAX_LEN];
  unsigned int sigLen = 0;
  memset(sigRet, 0, MAX_LEN);

  if ( RSA_sign(NID_sha1, msgDigest, SHA256_DIGEST_LENGTH, sigRet, &sigLen, rsa) == 0 ) {
    fprintf( stderr, "Couldn't sign message digest.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    exit( 1 );
  }

  printf("Signature: ");
  for (i = 0; i < MAX_LEN; i++) {
    printf("%02x", sigRet[i]);
  }
  printf("\n");

  RSA_free( rsa );
  ERR_free_strings();
  return 0;
}
