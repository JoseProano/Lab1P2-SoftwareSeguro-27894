/*
 * TEST FILE: Another Vulnerable C Code
 * This file contains INTENTIONAL security vulnerabilities for CI/CD testing
 * Expected outcome: CI/CD pipeline should REJECT this code
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SIZE 20

// Vulnerability: sprintf without bounds checking (CWE-787)
void format_message(char* username) {
    char message[50];
    sprintf(message, "Welcome %s to the system!", username); // VULNERABLE
    printf("%s\n", message);
}

// Vulnerability: strcpy without bounds checking (CWE-120)
void copy_data(char* source) {
    char dest[10];
    strcpy(dest, source); // VULNERABLE: Buffer overflow
    printf("Copied: %s\n", dest);
}

// Vulnerability: gets() dangerous function (CWE-676)
void read_password() {
    char password[SIZE];
    printf("Enter password: ");
    gets(password); // VULNERABLE: No bounds checking
    printf("Password received\n");
}

int main() {
    char input[100];
    
    printf("Testing vulnerable code...\n");
    
    // Test format_message
    format_message("ThisIsAVeryLongUsernameThatWillCauseBufferOverflow");
    
    // Test copy_data
    copy_data("This string is way too long for the destination buffer");
    
    // Test read_password
    read_password();
    
    return 0;
}
