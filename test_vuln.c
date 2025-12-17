/*
 * TEST: Vulnerable C code for ML model validation
 */

#include <stdio.h>
#include <string.h>

void vulnerable_buffer_overflow(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // CWE-787: Buffer overflow
    printf("%s\n", buffer);
}

void vulnerable_command_injection(char* cmd) {
    char command[100];
    sprintf(command, "ls %s", cmd);  // CWE-787: No bounds check
    system(command);  // CWE-78: Command injection
}

int main() {
    char user_input[256];
    
    gets(user_input);  // CWE-676: Dangerous function
    
    vulnerable_buffer_overflow(user_input);
    vulnerable_command_injection(user_input);
    
    return 0;
}
