/* David Gluckman
 * CS 344 Section 400 Winter 2017
 * Program OTP
 * otp_enc.c
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
	char sendBuffer[200000], plainBuffer[100000], keyBuffer[100000], recBuffer[100000];
    
	if (argc < 4) { fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); exit(0); } // Check usage & args

	// Open the plaintext file
	int plainFile = open(argv[1], O_RDONLY);
	// Find its length and read to buffer
	memset(plainBuffer, '\0', sizeof(plainBuffer));
	int plainLength = read(plainFile, plainBuffer, sizeof(plainBuffer));
	plainBuffer[strcspn(plainBuffer, "\n")] = '\0';
	//printf("Plaintext length: %d\n", plainLength);

	// Open the key file
	int keyFile = open(argv[2], O_RDONLY);
	// Find its length and read to buffer
	memset(keyBuffer, '\0', sizeof(keyBuffer));
	int keyLength = read(keyFile, keyBuffer, sizeof(keyBuffer));
	keyBuffer[strcspn(keyBuffer, "\n")] = '\0';
	//printf("Key length: %d\n", keyLength);

	// Check key length
	if(keyLength < plainLength)
	{
		// If key is too short, print error and exit
		fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
		exit(1);
	}

	// Check for bad characters in plaintext
	int i;
	for(i = 0; i < strlen(plainBuffer); i++)
	{
		// If character is out of range
		if(plainBuffer[i] != 32 && !(plainBuffer[i] >= 65 && plainBuffer[i] <= 90))
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
	strcat(sendBuffer, "enc**");	// for handshake purposes
	strcat(sendBuffer, plainBuffer);
	strcat(sendBuffer, "##");	// plaintext terminator
	strcat(sendBuffer, keyBuffer);
	strcat(sendBuffer, "@@");	// key terminator
	
	//printf("Buffer: %s\n", sendBuffer);

	// Send message to server
	charsWritten = send(socketFD, sendBuffer, strlen(sendBuffer), 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(sendBuffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");

	// Get return message from server
	memset(recBuffer, '\0', sizeof(recBuffer)); // Clear out the buffer
	char* buff = recBuffer;
	char fullMessage[100000];
	memset(fullMessage, '\0', sizeof(fullMessage));
	while(strstr(fullMessage, "#") == NULL)
	{
		memset(recBuffer, '\0', sizeof(recBuffer));
		charsRead = recv(socketFD, buff, sizeof(recBuffer) - 1, 0); // Read data from the socket, leaving \0 at end
		strcat(fullMessage, recBuffer); // Copy it to the message
		if (charsRead < 0) 
		{
			error("CLIENT: ERROR reading from socket");
			break;
		}
		buff += charsRead;
	}
	fullMessage[strcspn(fullMessage, "#")] = '\0';	

	fprintf(stdout, "%s\n", fullMessage);

	close(socketFD); // Close the socket
	return 0;
}
