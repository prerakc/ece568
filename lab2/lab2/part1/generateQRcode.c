#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	const char *encodedIssuer = urlEncode(issuer);
	const char *encodedAccountName = urlEncode(accountName);

	char *encodedSecretHex;
	base32_encode(secret_hex, 20, encodedSecretHex, 16);

	const char *format = "otpauth://totp/%s?issuer=%s&secret=%s&period=30";
	
	int length = snprintf(NULL, 0, format, encodedAccountName, encodedIssuer, encodedSecretHex);
	length = length + 1;

	char uri[length];
	snprintf(uri, length, format, encodedAccountName, encodedIssuer, encodedSecretHex);

	displayQRcode(uri);

	return (0);
}
