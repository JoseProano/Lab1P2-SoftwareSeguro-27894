#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// This file contains SAFE CODE for testing the CI/CD pipeline
// Should PASS all security checks

#define MAX_BUFFER_SIZE 256
#define MAX_INPUT_SIZE 100

// Safe function with bounds checking
int safe_function(const char* user_input, size_t input_len) {
    char buffer[MAX_BUFFER_SIZE];
    
    // Input validation
    if (user_input == NULL) {
        fprintf(stderr, "Error: NULL input\n");
        return -1;
    }
    
    if (input_len == 0 || input_len >= MAX_BUFFER_SIZE) {
        fprintf(stderr, "Error: Invalid input length\n");
        return -1;
    }
    
    // Safe copy with bounds checking
    strncpy(buffer, user_input, MAX_BUFFER_SIZE - 1);
    buffer[MAX_BUFFER_SIZE - 1] = '\0';
    
    printf("Safe output: %s\n", buffer);
    
    return 0;
}

int main(int argc, char** argv) {
    char input[MAX_INPUT_SIZE];
    
    printf("Enter text (max %d chars): ", MAX_INPUT_SIZE - 1);
    
    // Safe input with bounds checking
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }
    
    // Remove trailing newline
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
        len--;
    }
    
    // Process with safe function
    if (safe_function(input, len) != 0) {
        return 1;
    }
    
    return 0;
}
