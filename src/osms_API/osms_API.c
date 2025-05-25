#include <stdio.h>	
#include <stdint.h>
#include <stdlib.h> 
#include <string.h>
#include <stdbool.h> 

#define PCB_START 0
#define PCB_ENTRY_SIZE 256
#define PCB_COUNT 32
#define FRAME_BITMAP_OFFSET (8 * 1024 + 192 * 1024)  // 204800
#define FRAME_BITMAP_SIZE 8192  // 8 KB = 65536 bits

char* path;
FILE* memory_file = NULL; 

// auxiliares
void execute_os_exists(int process_id, char* file_name) {  
    if (os_exists(process_id, file_name) == 1) {
        printf("\nOS_EXISTS - Archivo '%s' existe en proceso %d.\n", file_name, process_id);
        return;
    }
    printf("\nOS_EXISTS - Archivo '%s' NO existe en proceso %d.\n", file_name, process_id);
}

// funciones generales
void os_mount(char* memory_path) {
    printf("OS_MOUNT - Abriendo memoria...\n");
    memory_file = fopen(memory_path, "rb+");
    if (!memory_file) {
        perror("Error al abrir la memoria");
        exit(EXIT_FAILURE);
    }
}

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

void os_ls_files(int process_id) {
    printf("\nOS_LS_FILES: Proceso %d\n", process_id);
    if (!memory_file) {
        fprintf(stderr, "Memoria no montada.\n");
        return;
    }
    const int FILE_ENTRY_SIZE = 24;
    const int FILE_TABLE_OFFSET = 16;

    for (int i = 0; i < PCB_COUNT; i++) {
        long pcb_offset = PCB_START + i * PCB_ENTRY_SIZE;

        fseek(memory_file, pcb_offset, SEEK_SET);
        unsigned char header[16];
        fread(header, 1, 16, memory_file);

        if (header[0] != 0x01 || header[15] != (unsigned char)process_id)
            continue;

        // Proceso encontrado, recorrer archivos
        for (int j = 0; j < 10; j++) {
            long entry_offset = pcb_offset + FILE_TABLE_OFFSET + j * FILE_ENTRY_SIZE;

            fseek(memory_file, entry_offset, SEEK_SET);

            unsigned char entrada[24];
            fread(entrada, 1, 24, memory_file);

            if (entrada[0] != 0x01) continue; // entrada inválida

            // Nombre
            char nombre[15] = {0};
            memcpy(nombre, &entrada[1], 14);

            // Tamaño (5 bytes) → convertir a uint64_t manualmente
            uint64_t tam = 0;
            for (int b = 0; b < 5; b++) {
                tam |= ((uint64_t)entrada[15 + b]) << (8 * b); // little endian
            }

            // Dirección virtual (4 bytes)
            uint32_t dir_virtual = 0;
            for (int b = 0; b < 4; b++) {
                dir_virtual |= ((uint32_t)entrada[6 + b + 9]) << (8 * b);
            }

            // Extraer VPN: bits 15 al 26
            uint32_t vpn = (dir_virtual >> 15) & 0xFFF;

            printf("0x%03X %lu 0x%08X %s\n", vpn, tam, dir_virtual, nombre);
        }

        return;
    }

    // No se encontró el proceso
    fprintf(stderr, "Proceso %d no encontrado.\n", process_id);
}

void os_frame_bitmap() {
    printf("\nOS_FRAME_BITMAP:\n");
    if (!memory_file) {
        fprintf(stderr, "Memoria no montada.\n");
        return;
    }

    fseek(memory_file, FRAME_BITMAP_OFFSET, SEEK_SET);
    unsigned char bitmap[FRAME_BITMAP_SIZE];
    fread(bitmap, 1, FRAME_BITMAP_SIZE, memory_file);

    int usados = 0, libres = 0;

    for (int i = 0; i < 65536; i++) {
        int byte_index = i / 8;
        int bit_index = i % 8;

        int bit = (bitmap[byte_index] >> bit_index) & 1;
        printf("%d", bit);

        if ((i + 1) % 64 == 0) printf("\n");
        if (bit) usados++;
        else libres++;
    }

    printf("USADOS %d\n", usados);
    printf("LIBRES %d\n", libres);
}

// // funciones procesos

// // funciones archivos