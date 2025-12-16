// Test: Código vulnerable para probar el pipeline
#include <stdio.h>
#include <string.h>

void vulnerable_function(char* user_input) {
    char buffer[10];
    strcpy(buffer, user_input);  // CWE-787: Buffer overflow vulnerability
    system(buffer);               // CWE-78: OS command injection
}

int main() {
    char input[100];
    gets(input);  // CWE-676: Dangerous function
    vulnerable_function(input);
    return 0;
}
