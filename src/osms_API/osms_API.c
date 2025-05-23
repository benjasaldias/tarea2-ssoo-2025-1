#include <stdio.h>	// FILE, fopen, fclose, etc.
#include <stdlib.h> // malloc, calloc, free, etc
#include <string.h> //para strcmp
#include <stdbool.h> // bool, true, false

char* path;
FILE* memory_file = NULL; 

// funciones generales 
void os_mount(char* memory_path) {
    printf("OS_MOUNT - Abriendo memoria...\n");
    memory_file = fopen(memory_path, "rb+");
    if (!memory_file) {
        perror("Error al abrir la memoria");
        exit(EXIT_FAILURE);
    }
}

#define PCB_START 0
#define PCB_ENTRY_SIZE 256
#define PCB_COUNT 32

int os_start_process(int process_id, char* process_name) {
    if (!memory_file) {
        fprintf(stderr, "Memoria no montada.\n");
        return -1;
    }

    if (strlen(process_name) > 14) return -1;

    for (int i = 0; i < PCB_COUNT; i++) {
        long offset = PCB_START + i * PCB_ENTRY_SIZE;

        fseek(memory_file, offset, SEEK_SET);
        unsigned char estado;
        fread(&estado, 1, 1, memory_file);

        if (estado == 0x00) {
            // Entrada libre encontrada
            fseek(memory_file, offset, SEEK_SET);
            unsigned char entrada[PCB_ENTRY_SIZE] = {0};

            entrada[0] = 0x01; // Estado
            strncpy((char*)&entrada[1], process_name, 14); // Nombre
            entrada[15] = (unsigned char)process_id; // ID

            printf("\nOS_START_PROCESS - Comenzando Proceso: %s\n", process_name);

            // Tabla de archivos ya está en 0 (entrada inicializada en 0)
            fwrite(entrada, 1, PCB_ENTRY_SIZE, memory_file);
            fflush(memory_file);

            return 0;
        }
    }

    // No hay espacio disponible
    return -1;
}

void os_ls_processes() {
    printf("\nOS_LS_PROCESSES - Lista de Procesos:\n");
    if (!memory_file) {
        fprintf(stderr, "Memoria no montada.\n");
        return;
    }

    for (int i = 0; i < PCB_COUNT; i++) {
        long offset = PCB_START + i * PCB_ENTRY_SIZE;
        fseek(memory_file, offset, SEEK_SET);

        unsigned char entrada[16]; // 1 byte estado + 14 nombre + 1 ID
        fread(entrada, 1, 16, memory_file);

        if (entrada[0] == 0x01) {
            char nombre[15] = {0};
            memcpy(nombre, &entrada[1], 14); // nombre[14] ya es \0

            int id = entrada[15];
            printf("%d %s\n", id, nombre);
        }
    }
}

int os_exists(int process_id, char* file_name) {
    if (!memory_file) {
        fprintf(stderr, "Memoria no montada.\n");
        return 0;
    }

    for (int i = 0; i < PCB_COUNT; i++) {
        long pcb_offset = PCB_START + i * PCB_ENTRY_SIZE;

        fseek(memory_file, pcb_offset, SEEK_SET);
        unsigned char entrada[16];
        fread(entrada, 1, 16, memory_file);

        if (entrada[0] != 0x01) continue; // proceso no válido
        if (entrada[15] != (unsigned char)process_id) continue;

        // Proceso encontrado — revisar sus archivos
        for (int j = 0; j < 10; j++) {
            long archivo_offset = pcb_offset + 16 + j * 24;

            fseek(memory_file, archivo_offset, SEEK_SET);
            unsigned char validez;
            fread(&validez, 1, 1, memory_file);
            if (validez != 0x01) continue;

            char nombre[15] = {0};
            fread(nombre, 1, 14, memory_file);  // no incluye \0, pero le agregamos
            if (strncmp(nombre, file_name, 14) == 0) {
                return 1;
            }
        }

        return 0; // proceso existe pero archivo no
    }

    return 0; // proceso no encontrado
}

// // funciones procesos

// // funciones archivos