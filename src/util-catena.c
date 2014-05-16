#include <stdio.h>
#include <string.h>

#include "catena.h"

#define SALT_LEN 16

void print_hex(const char *message, const uint8_t *x, const int len)
{
  int i;
  puts(message);
    for(i=0; i< len; i++)
      {
	if((i!=0) && (i%8 == 0)) puts("");
	printf("%02x ",x[i]);
      }
    printf("     %d (octets)\n\n", len);
}


int main(int argc, char *argv[])
{
  const size_t hashlen = H_LEN;
  char *s = argv[2];
  char *salt = malloc((strlen(s) + 1) / 2);
  int i = 0;
  for (i=0; i<64 && isxdigit(*s); i++) salt[i]=strtoul(s, &s, 16);
  char *password = argv[1];
  const char *data     = "";
  const uint8_t lambda = 4;
  uint8_t min_garlic = atoi(argv[3]);
  uint8_t garlic = min_garlic;


  uint8_t hash1[H_LEN];

#ifdef CATENA_INFO
  uint8_t hash2[H_LEN];
  uint8_t hash3[H_LEN];
  uint8_t hash4[H_LEN];
  uint8_t x[H_LEN];

  uint8_t key1[H_LEN];
  uint8_t key2[H_LEN/4];
  uint8_t key3[3*H_LEN+10];
  memset(hash2,0,H_LEN);
  memset(hash3,0,H_LEN);
  memset(hash4,0,H_LEN);
  memset(x,0,H_LEN);
#endif

  memset(hash1,0,H_LEN);

  Catena((uint8_t *) password, strlen(password) ,salt, strlen(salt),
	 (uint8_t *) data, strlen(data), lambda, min_garlic, garlic,
	 hashlen, hash1);
  print_hex("Hash: ", hash1, hashlen);
  print_hex("Hash: ", password, strlen(password));
  print_hex("Hash: ", salt, strlen(salt));
  print_hex("Hash: ", data, strlen(data));

#ifdef CATENA_INFO
  Catena_Client((uint8_t *) password, strlen(password), salt, SALT_LEN,
		(uint8_t *) data, strlen(data), lambda, min_garlic, garlic,
		hashlen, x);
  Catena_Server(garlic, x, hashlen, hash2);
  print_hex(hash2, hashlen);

  Catena((uint8_t *) password, strlen(password) ,salt, SALT_LEN,
	 (uint8_t *) data, strlen(data), lambda, min_garlic, garlic-1,
	 hashlen, x);
  CI_Update(x, lambda, garlic-1, garlic, hashlen, hash3);
  print_hex(hash3, hashlen);

  Catena((uint8_t *) password, strlen(password) ,salt, SALT_LEN,
	 (uint8_t *) "", 0, lambda, garlic, garlic, hashlen, hash1);
  print_hex(hash1, hashlen);


  PHS(hash4, hashlen, password, strlen(password), salt, SALT_LEN, lambda,
      garlic);
  print_hex(hash4, hashlen);


  puts("");
  puts("Keys");

  Catena_KG((uint8_t *) password, strlen(password) ,salt, SALT_LEN,
	    (uint8_t *) data, strlen(data), lambda, min_garlic, garlic,
	    H_LEN, 1,  key1);
  print_hex(key1, H_LEN);

  Catena_KG((uint8_t *) password, strlen(password) ,salt, SALT_LEN,
	    (uint8_t *) data, strlen(data), lambda, min_garlic, garlic,
	    H_LEN/4, 2,  key2);
  print_hex(key2, H_LEN/4);


  Catena_KG((uint8_t *) password, strlen(password) ,salt, SALT_LEN,
	    (uint8_t *) data, strlen(data), lambda, min_garlic, garlic,
	    3*H_LEN+10 , 3,  key3);
  print_hex(key3, 3*H_LEN+10);

#endif

  return 0;
}
