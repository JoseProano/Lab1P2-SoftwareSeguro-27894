/*
 * DEMOSTRACIÓN DE CÓDIGO VULNERABLE
 * Este archivo contiene múltiples vulnerabilidades detectables por ML
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// VULNERABILIDAD 1: Buffer Overflow con strcpy
void process_user_input(char *input) {
    char buffer[16];
    strcpy(buffer, input);  // CWE-787: No verifica tamaño
    printf("Procesado: %s\n", buffer);
}

// VULNERABILIDAD 2: Command Injection con system
void execute_command(char *cmd) {
    char command[128];
    sprintf(command, "ls %s", cmd);  // CWE-78: Inyección de comandos
    system(command);  // Ejecuta comando del usuario
}

// VULNERABILIDAD 3: Use after free
void memory_error() {
    char *data = (char*)malloc(32);
    strcpy(data, "sensitive data");
    free(data);
    printf("%s\n", data);  // CWE-416: Usa memoria liberada
}

// VULNERABILIDAD 4: Buffer overflow con gets
void read_password() {
    char password[8];
    printf("Password: ");
    gets(password);  // CWE-676: gets es peligroso
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        process_user_input(argv[1]);
        execute_command(argv[1]);
    }
    
    memory_error();
    read_password();
    
    return 0;
}
