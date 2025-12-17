/*
 * PROGRAMA VULNERABLE A PROPÓSITO
 * USO EXCLUSIVAMENTE EDUCATIVO
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function() {
    char buffer[32];

    // 1. BUFFER OVERFLOW (uso de gets)
    printf("Ingresa tu nombre: ");
    gets(buffer);  // ❌ Vulnerable: no controla el tamaño de entrada

    // 2. FORMAT STRING VULNERABILITY
    printf(buffer);  // ❌ El usuario controla el formato
    printf("\n");
}

void integer_overflow() {
    int a;
    printf("Ingresa un numero grande: ");
    scanf("%d", &a);

    // 3. INTEGER OVERFLOW
    int result = a * 1000;  // ❌ Puede desbordarse
    printf("Resultado: %d\n", result);
}

void use_after_free() {
    char *data = malloc(16);
    strcpy(data, "hola");

    free(data);

    // 4. USE AFTER FREE
    printf("Dato liberado: %s\n", data);  // ❌ Uso de memoria ya liberada
}

void command_injection() {
    char command[64];

    printf("Ingresa un comando: ");
    scanf("%s", command);

    // 5. COMMAND INJECTION
    system(command);  // ❌ Ejecuta comandos arbitrarios
}

int main() {
    printf("=== PROGRAMA INSEGURO ===\n");

    vulnerable_function();
    integer_overflow();
    use_after_free();
    command_injection();

    return 0;
}
