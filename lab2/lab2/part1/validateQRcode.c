#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#include <time.h>
#include <stdlib.h>


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{	
	uint8_t key[SHA1_BLOCKSIZE];

	memset(key, 0, SHA1_BLOCKSIZE);

	for (int i = 0; i < SHA1_DIGEST_LENGTH / 2; i++) {
		sscanf(secret_hex + 2 * i, "%02x", &key[i]);
	}

	uint8_t inner_key[SHA1_BLOCKSIZE];
    uint8_t outer_key[SHA1_BLOCKSIZE];

	for (int i = 0; i < SHA1_BLOCKSIZE; i++) {
		inner_key[i] = key[i] ^ 0x36;
		outer_key[i] = key[i] ^ 0x5c;
	}

	uint8_t message[8];

	uint64_t steps = time(NULL) / 30;

	for (int i = 7; i >= 0; i--) {
        message[i] = steps;
        steps >>= 8;
    }

	SHA1_INFO ctx;

	uint8_t inner_hash[SHA1_DIGEST_LENGTH];
	uint8_t outer_hash[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, inner_key, SHA1_BLOCKSIZE);
	sha1_update(&ctx, message, 8);
	sha1_final(&ctx, inner_hash);

	sha1_init(&ctx);
	sha1_update(&ctx, outer_key, SHA1_BLOCKSIZE);
	sha1_update(&ctx, inner_hash, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, outer_hash);

	int offset = outer_hash[SHA1_DIGEST_LENGTH - 1] & 0xf;

	int binary =
    	((outer_hash[offset] & 0x7f) << 24) |
    	((outer_hash[offset + 1] & 0xff) << 16) |
      	((outer_hash[offset + 2] & 0xff) << 8) |
      	(outer_hash[offset + 3] & 0xff);

	int otp = binary % 1000000;

	int TOTP_integer = atoi(TOTP_string);

    return otp == TOTP_integer;
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
