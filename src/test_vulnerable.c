/*
 * VULNERABLE CODE - FOR TESTING CI/CD DETECTION
 * This code intentionally contains multiple security vulnerabilities
 * Expected: ML model should detect and BLOCK this code
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 64

// CWE-787: Buffer Overflow via strcpy
void process_username(char* username) {
    char buffer[32];
    strcpy(buffer, username);  // VULNERABLE: No bounds checking
    printf("Welcome, %s!\n", buffer);
}

// CWE-676: Use of Dangerous Function (gets)
void read_password() {
    char password[50];
    printf("Enter password: ");
    gets(password);  // VULNERABLE: Dangerous function
    printf("Password length: %zu\n", strlen(password));
}

// CWE-78: OS Command Injection
void execute_command(char* filename) {
    char command[128];
    sprintf(command, "cat %s", filename);  // VULNERABLE: No sanitization
    system(command);  // VULNERABLE: Command injection
}

// CWE-120: Buffer Copy without Bounds Check
void concatenate_strings(char* str1, char* str2) {
    char result[64];
    strcpy(result, str1);
    strcat(result, str2);  // VULNERABLE: No size check
    printf("Result: %s\n", result);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <username>\n", argv[0]);
        return 1;
    }
    
    // Test vulnerable functions
    process_username(argv[1]);
    read_password();
    
    if (argc > 2) {
        execute_command(argv[2]);
    }
    
    concatenate_strings("Hello ", "World with very long string that causes overflow");
    
    return 0;
}
