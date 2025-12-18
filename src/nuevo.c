// Test: Código seguro para probar el pipeline
#include <stdio.h>
#include <string.h>

void safe_function(char* user_input, size_t input_len) {
    char buffer[256];
    
    // Input validation
    if (user_input == NULL || input_len == 0) {
        return;
    }
    
    // Bounds checking
    if (input_len >= sizeof(buffer)) {
        input_len = sizeof(buffer) - 1;
    }
    
    // Safe copy
    strncpy(buffer, user_input, input_len);
    buffer[input_len] = '\0';
    
    printf("Safe output: %s\n", buffer);
}

int main() {
    char input[100];
    
    // Safe input
    if (fgets(input, sizeof(input), stdin) != NULL) {
        size_t len = strlen(input);
        safe_function(input, len);
    }
    
    return 0;
}
