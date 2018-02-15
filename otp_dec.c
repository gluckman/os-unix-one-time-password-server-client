/* David Gluckman
 * CS 344 Section 400 Winter 2017
 * Program OTP
 * otp_dec.c
 */

// Adapted from client.c by Ben Brewster

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char sendBuffer[200000], cipherBuffer[100000], keyBuffer[100000], recBuffer[100000];
    
	if (argc < 4) { fprintf(stderr,"USAGE: %s ciphertext key port\n", argv[0]); exit(0); } // Check usage & args

	// Open the ciphertext file
	int cipherFile = open(argv[1], O_RDONLY);
	// Find its length and read to buffer
	memset(cipherBuffer, '\0', sizeof(cipherBuffer));
	int cipherLength = read(cipherFile, cipherBuffer, sizeof(cipherBuffer));
	cipherBuffer[strcspn(cipherBuffer, "\n")] = '\0';
	//printf("ciphertext length: %d\n", cipherLength);

	// Open the key file
	int keyFile = open(argv[2], O_RDONLY);
	// Find its length and read to buffer
	memset(keyBuffer, '\0', sizeof(keyBuffer));
	int keyLength = read(keyFile, keyBuffer, sizeof(keyBuffer));
	keyBuffer[strcspn(keyBuffer, "\n")] = '\0';
	//printf("Key length: %d\n", keyLength);

	// Check key length
	if(keyLength < cipherLength)
	{
		// If key is too short, print error and exit
		fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
		exit(1);
	}

	// Check for bad characters in ciphertext
	int i;
	for(i = 0; i < strlen(cipherBuffer); i++)
	{
		// If character is out of range
		if(cipherBuffer[i] != 32 && !(cipherBuffer[i] >= 65 && cipherBuffer[i] <= 90))
		{
			// Print error
			fprintf(stderr, "%s error: %s contains bad characters\n", argv[0], argv[1]);
			exit(1);
		}
	}

	// Check for bad characters in key
	for(i = 0; i < strlen(keyBuffer); i++)
	{
		// If character is out of range
		if(keyBuffer[i] != 32 && !(keyBuffer[i] >= 65 && keyBuffer[i] <= 90))
		{
			// Print error
			fprintf(stderr, "%s error: %s contains bad characters\n", argv[0], argv[2]);
			exit(1);
		}
	}

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

	// Prepare buffer for send
	memset(sendBuffer, '\0', sizeof(sendBuffer)); // Clear out the buffer array
	strcat(sendBuffer, "dec**");	// for handshake purposes
	strcat(sendBuffer, cipherBuffer);
	strcat(sendBuffer, "##");	// ciphertext terminator
	strcat(sendBuffer, keyBuffer);
	strcat(sendBuffer, "@@");	// key terminator
	
	//printf("Buffer: %s\n", sendBuffer);

	// Send message to server
	charsWritten = send(socketFD, sendBuffer, strlen(sendBuffer), 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(sendBuffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");

	// Get return message from server
	memset(recBuffer, '\0', sizeof(recBuffer)); // Clear out the buffer
	charsRead = recv(socketFD, recBuffer, sizeof(recBuffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	// If the connection was denied
    if (strcmp(recBuffer, "@@@") == 0)
    {
        // Print error
        fprintf(stderr, "Error: could not contact otp_dec_d on port %s\n", argv[3]);
    }
    // Else print send received to standard output
    else
    {
        fprintf(stdout, "%s\n", recBuffer);
    }
    
	close(socketFD); // Close the socket
	
    return 0;
}
