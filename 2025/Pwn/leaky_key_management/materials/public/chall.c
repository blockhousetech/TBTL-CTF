// Runnign on Ubuntu 18.04
// gcc -o chall chall.c -lcrypto

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

struct wrapped_key {
  char type;
  int64_t nonce;
  unsigned char ciphertext[16];
};

const int WK_SIZE = sizeof(struct wrapped_key);
const int WK_HEX_SIZE = 2*sizeof(struct wrapped_key)+1;

void to_hex(const unsigned char* in, int in_len, char* out, int out_len) {
  assert(2*in_len+1 == out_len);
  for (int i = 0; i < in_len; i++) {
    sprintf(out + i * 2, "%02x", in[i]);
  }
  out[out_len-1] = 0;
}

void from_hex(const char* in, int in_len, unsigned char* out, int out_len) {
  assert(2*out_len+1 == in_len);
  for (int i = 0; i < out_len; i++) {
    int temp;
    sscanf(in + i * 2, "%02x", &temp);
    out[i] = temp;
  }
}

void wk_to_hex(const struct wrapped_key* wk, char* out, int out_len) {
  to_hex((const unsigned char*)wk, sizeof(*wk), out, out_len);
}

void wk_from_hex(const char* in, int in_len, struct wrapped_key* wk) {
  from_hex(in, in_len, (unsigned char*)wk, sizeof(*wk));
}

void encdec(const unsigned char* data, int data_len, unsigned char* key, int64_t nonce, unsigned char* out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  unsigned char iv[16] = {0};
  memcpy(iv, &nonce, sizeof(nonce));
  int outlen = 0;
  EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, out, &outlen, data, data_len);
  EVP_CIPHER_CTX_free(ctx);
}

unsigned char MASTER_KEY[16];

void init_master_key() {
  RAND_bytes(MASTER_KEY, sizeof MASTER_KEY);
}

struct wrapped_key new_key() {
  struct wrapped_key wk;
  unsigned char key[16];
  wk.type = 'A';
  RAND_bytes((unsigned char*)&wk.nonce, sizeof wk.nonce);
  RAND_bytes(key, sizeof key);
  encdec(key, 16, MASTER_KEY, wk.nonce, wk.ciphertext);
  return wk;
}   

void encdec_with_wrapped_key(const struct wrapped_key* wk, int64_t nonce, const unsigned char* data, int data_len, unsigned char* out) {
  unsigned char key[16];
  unsigned char master_key[16];
  memcpy(master_key, MASTER_KEY, sizeof MASTER_KEY);
  encdec(wk->ciphertext, 16, MASTER_KEY, wk->nonce, key);
  encdec(data, data_len, key, nonce, out);
}

void test_kms(const char *data, int data_len, int verbose) {
  unsigned char ciphertext[data_len];
  struct wrapped_key wk = new_key();
  int64_t nonce;
  encdec_with_wrapped_key(&wk, nonce, data, data_len, ciphertext);
  if (verbose) {
    char ciphertext_hex[2*data_len+1];
    to_hex(ciphertext, data_len, ciphertext_hex, 2*data_len+1);
    char wk_hex[WK_HEX_SIZE];
    wk_to_hex(&wk, wk_hex, WK_HEX_SIZE);
    printf("Wrapped key: %s\n", wk_hex);
    printf("Nonce: %016lx\n", nonce);
    printf("Ciphertext: %s\n", ciphertext_hex);
  }
}

void dump_flag() {
  FILE *f = fopen("flag.txt", "r");
  assert(f);
  char flag[128];
  fgets(flag, sizeof flag, f);
  int len = strlen(flag);
  test_kms(flag, len, 1);
}

void demo() {
  char buf[1025];
  init_master_key();
  dump_flag();
  while (1) {
    printf("Data to encrypt (max 1024 hex chars) > ");
    if (scanf("%1024s", buf) != 1) 
      break ;
    int verbose;
    printf("Verbose output (0 or 1) > ");
    if (scanf("%d", &verbose) != 1) 
      break ;
    int len = strlen(buf);
    int data_len = len / 2;
    unsigned char data[data_len];
    from_hex(buf, len+1, data, data_len);
    test_kms(data, data_len, verbose);
  }
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  demo();
  return 0;
}
