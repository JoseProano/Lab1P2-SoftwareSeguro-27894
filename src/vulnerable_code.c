#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// This file contains INTENTIONAL VULNERABILITIES for testing the CI/CD pipeline
// CWE-787: Buffer Overflow
// CWE-78: OS Command Injection  
// CWE-676: Use of Potentially Dangerous Function

void vulnerable_function(char* user_input) {
    char buffer[10];
    
    // CWE-787: Buffer overflow - no bounds checking
    strcpy(buffer, user_input);
    
    // CWE-78: OS command injection
    system(buffer);
    
    printf("Executed: %s\n", buffer);
}

int main(int argc, char** argv) {
    char input[256];
    
    // CWE-676: Dangerous function - gets() has no bounds checking
    printf("Enter command: ");
    gets(input);
    
    vulnerable_function(input);
    
    return 0;
}
