/* David Gluckman
 * CS 344 Section 400 Winter 2017
 * Program OTP
 * keygen.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	// Check for one argument
	if(argc != 2)
	{
		// Print error and exit
		printf("Usage: %s keylength\n", argv[0]);
		exit(1);
	}

	// Create empty string with newline characters
	char newKey[atoi(argv[1]) + 1];
	memset(newKey, '\n', sizeof(newKey));

	// Seed random numbers
	srand(time(NULL));

	// Generate random key
	int i;
	for (i = 0; i < sizeof(newKey) - 1; i++)
	{
		// Generate random number between 0 and 26
		int randInt = rand() % 27;;

		// If number is 0 it's a space
		if(randInt == 0)
		{
			newKey[i] = ' ';
		}
		// Else it's a letter
		else
		{
			// Set it to the corresponding uppercase letter
			newKey[i] = randInt + '@';
		}
	}


	// Send key to stdout
	printf("%s", newKey);

	return 0;
}
