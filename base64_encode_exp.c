#include <string.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


char *base64(const unsigned char *input, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  //不要加入换行符
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  return buff;
}


int main()
{
  const unsigned char clearText[] = "disu isu supaaataa";

  char *output = base64((unsigned char*)clearText, sizeof(clearText));
  printf("Base64: '%s'\n", output);
  free(output);

  return 0;
}
