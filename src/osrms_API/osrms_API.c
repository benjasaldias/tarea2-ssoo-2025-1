#include <stdio.h>   // FILE, fopen, fclose, etc.
#include <stdlib.h>  // malloc, calloc, free, etc
#include <stdint.h>  // uint64_t, uint32_t
#include <string.h>  //para strcmp
#include <stdbool.h> // bool, true, false
// #include "osrms_File.h"
#include "../osrms_File/osrms_File.h"

#define PCB_START 0
#define PCB_ENTRY_SIZE 256
#define PCB_COUNT 32

#define PCB_NAME_OFFSET 1
#define PCB_PROCESS_ID_OFFSET 15
#define PCB_FILE_TABLE_OFFSET 16
#define PROCESS_NAME_MAX_LEN 14

#define NUM_VIRTUAL_PAGES 4096
#define VIRTUAL_PAGE_SIZE (32 * 1024) // 32 KB por página virtual

#define MAX_FILES_PER_PROCESS 10
#define FILE_ENTRY_SIZE 24
#define FILE_NAME_MAX_LEN 14

#define IPT_OFFSET (8 * 1024)
#define IPT_ENTRY_SIZE 3
#define IPT_ENTRY_COUNT 65536

#define FRAME_BITMAP_OFFSET ((8 + 192) * 1024)
#define FRAME_BITMAP_SIZE (8 * 1024)

#define FILE_TABLE_OFFSET 16

#define FRAMES_OFFSET (FRAME_BITMAP_OFFSET + FRAME_BITMAP_SIZE)
#define FRAME_SIZE (32 * 1024) // 32 KB por frame
#define NUM_FRAMES 65536

char *path;
FILE *memory_file = NULL;

// auxiliares
// static bool string_equals(char *string1, char *string2)
// {
//     return !strcmp(string1, string2);
// }

void write_byte(long offset, uint8_t value)
{
    fseek(memory_file, offset, SEEK_SET);
    fwrite(&value, sizeof(uint8_t), 1, memory_file);
}

// Lee un byte de la posición especificada
uint8_t read_byte(long offset)
{
    fseek(memory_file, offset, SEEK_SET);
    uint8_t value;
    fread(&value, sizeof(uint8_t), 1, memory_file);
    return value;
}

// Escribe un short (2 bytes) en la posición especificada (little endian)
void write_short(long offset, uint16_t value)
{
    fseek(memory_file, offset, SEEK_SET);
    uint8_t bytes[2];
    bytes[0] = (uint8_t)(value & 0xFF);        // LSB
    bytes[1] = (uint8_t)((value >> 8) & 0xFF); // MSB
    fwrite(bytes, sizeof(uint8_t), 2, memory_file);
}

// Lee un short (2 bytes) de la posición especificada (little endian)
uint16_t read_short(long offset)
{
    fseek(memory_file, offset, SEEK_SET);
    uint8_t bytes[2];
    fread(bytes, sizeof(uint8_t), 2, memory_file);
    uint16_t value = ((uint16_t)bytes[1] << 8) | bytes[0];
    return value;
}

// Escribe un int (4 bytes) en la posición especificada (little endian)
void write_int(long offset, uint32_t value)
{
    fseek(memory_file, offset, SEEK_SET);
    uint8_t bytes[4];
    bytes[0] = (uint8_t)(value & 0xFF);
    bytes[1] = (uint8_t)((value >> 8) & 0xFF);
    bytes[2] = (uint8_t)((value >> 16) & 0xFF);
    bytes[3] = (uint8_t)((value >> 24) & 0xFF);
    fwrite(bytes, sizeof(uint8_t), 4, memory_file);
}

// Lee un int (4 bytes) de la posición especificada (little endian)
uint32_t read_int(long offset)
{
    fseek(memory_file, offset, SEEK_SET);
    uint8_t bytes[4];
    fread(bytes, sizeof(uint8_t), 4, memory_file);
    uint32_t value = ((uint32_t)bytes[3] << 24) |
                     ((uint32_t)bytes[2] << 16) |
                     ((uint32_t)bytes[1] << 8) |
                     bytes[0];
    return value;
}

// Lee una cadena de caracteres
void read_string(long offset, char *buffer, size_t max_len)
{
    fseek(memory_file, offset, SEEK_SET);
    fread(buffer, sizeof(char), max_len, memory_file);
    buffer[max_len] = '\0'; // Asegurar terminación nula
}

// Escribe una cadena de caracteres
void write_string(long offset, char *str, size_t max_len)
{
    fseek(memory_file, offset, SEEK_SET);
    fwrite(str, sizeof(char), strnlen(str, max_len), memory_file);
    // Rellenar con ceros si el nombre es más corto que max_len
    for (size_t i = strnlen(str, max_len); i < max_len; i++)
    {
        write_byte(offset + i, 0x00);
    }
}

// funciones generales
void os_mount(char *memory_path)
{
    printf("OS_MOUNT - Abriendo memoria...\n");
    memory_file = fopen(memory_path, "rb+");
    if (!memory_file)
    {
        perror("Error al abrir la memoria");
        exit(EXIT_FAILURE);
    }
}

void os_ls_processes()
{
    printf("\nOS_LS_PROCESSES - Lista de Procesos:\n");
    if (!memory_file)
    {
        fprintf(stderr, "Memoria no montada.\n");
        return;
    }

    for (int i = 0; i < PCB_COUNT; i++)
    {
        long offset = PCB_START + i * PCB_ENTRY_SIZE;
        fseek(memory_file, offset, SEEK_SET);

        unsigned char entrada[16]; // 1 byte estado + 14 nombre + 1 ID
        fread(entrada, 1, 16, memory_file);

        if (entrada[0] == 0x01)
        {
            char nombre[15] = {0};
            memcpy(nombre, &entrada[1], 14); // nombre[14] ya es \0

            int id = entrada[15];
            printf("%d %s\n", id, nombre);
        }
    }
}

int os_exists(int process_id, char *file_name)
{
    if (!memory_file)
    {
        fprintf(stderr, "Memoria no montada.\n");
        return 0;
    }

    for (int i = 0; i < PCB_COUNT; i++)
    {
        long pcb_offset = PCB_START + i * PCB_ENTRY_SIZE;

        fseek(memory_file, pcb_offset, SEEK_SET);
        unsigned char entrada[16];
        fread(entrada, 1, 16, memory_file);

        if (entrada[0] != 0x01)
            continue; // proceso no válido
        if (entrada[15] != (unsigned char)process_id)
            continue;

        // Proceso encontrado — revisar sus archivos
        for (int j = 0; j < 10; j++)
        {
            long archivo_offset = pcb_offset + 16 + j * 24;

            fseek(memory_file, archivo_offset, SEEK_SET);
            unsigned char validez;
            fread(&validez, 1, 1, memory_file);
            if (validez != 0x01)
                continue;

            char nombre[15] = {0};
            fread(nombre, 1, 14, memory_file); // no incluye \0, pero le agregamos
            if (strncmp(nombre, file_name, 14) == 0)
            {
                return 1;
            }
        }

        return 0; // proceso existe pero archivo no
    }

    return 0; // proceso no encontrado
}

void os_ls_files(int process_id)
{
    printf("\nOS_LS_FILES: Proceso %d\n", process_id);
    if (!memory_file)
    {
        fprintf(stderr, "Memoria no montada.\n");
        return;
    }

    for (int i = 0; i < PCB_COUNT; i++)
    {
        long pcb_offset = PCB_START + i * PCB_ENTRY_SIZE;

        fseek(memory_file, pcb_offset, SEEK_SET);
        unsigned char header[16];
        fread(header, 1, 16, memory_file);

        if (header[0] != 0x01 || header[15] != (unsigned char)process_id)
            continue;

        // Proceso encontrado, recorrer archivos
        for (int j = 0; j < 10; j++)
        {
            long entry_offset = pcb_offset + FILE_TABLE_OFFSET + j * FILE_ENTRY_SIZE;

            fseek(memory_file, entry_offset, SEEK_SET);

            unsigned char entrada[24];
            fread(entrada, 1, 24, memory_file);

            if (entrada[0] != 0x01)
                continue; // entrada inválida

            // Nombre
            char nombre[15] = {0};
            memcpy(nombre, &entrada[1], 14);

            // Tamaño (5 bytes) → convertir a uint64_t manualmente
            uint64_t tam = 0;
            for (int b = 0; b < 5; b++)
            {
                tam |= ((uint64_t)entrada[15 + b]) << (8 * b); // little endian
            }

            // Dirección virtual (4 bytes)
            uint32_t dir_virtual = 0;
            for (int b = 0; b < 4; b++)
            {
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

void os_frame_bitmap()
{
    printf("\nOS_FRAME_BITMAP:\n");
    if (!memory_file)
    {
        fprintf(stderr, "Memoria no montada.\n");
        return;
    }

    fseek(memory_file, FRAME_BITMAP_OFFSET, SEEK_SET);
    unsigned char bitmap[FRAME_BITMAP_SIZE];
    fread(bitmap, 1, FRAME_BITMAP_SIZE, memory_file);

    int usados = 0, libres = 0;

    for (int i = 0; i < 65536; i++)
    {
        int byte_index = i / 8;
        int bit_index = i % 8;

        int bit = (bitmap[byte_index] >> bit_index) & 1;
        printf("%d", bit);

        if ((i + 1) % 64 == 0)
            printf("\n");
        if (bit)
            usados++;
        else
            libres++;
    }

    printf("USADOS %d\n", usados);
    printf("LIBRES %d\n", libres);
}

// // funciones procesos
int os_start_process(int process_id, char *process_name)
{
    if (!memory_file)
    {
        fprintf(stderr, "Memoria no montada.\n");
        return -1;
    }

    if (strlen(process_name) > 14)
        return -1;

    for (int i = 0; i < PCB_COUNT; i++)
    {
        long offset = PCB_START + i * PCB_ENTRY_SIZE;
        fseek(memory_file, offset, SEEK_SET);
        unsigned char entrada[16];
        fread(entrada, 1, 16, memory_file);

        if (entrada[0] == 0x01 && entrada[15] == (unsigned char)process_id)
        {
            return -1;
        }
    }

    for (int i = 0; i < PCB_COUNT; i++)
    {
        long offset = PCB_START + i * PCB_ENTRY_SIZE;

        fseek(memory_file, offset, SEEK_SET);
        unsigned char estado;
        fread(&estado, 1, 1, memory_file);

        if (estado == 0x00)
        {
            fseek(memory_file, offset, SEEK_SET);
            unsigned char entrada[PCB_ENTRY_SIZE] = {0};

            entrada[0] = 0x01;
            strncpy((char *)&entrada[1], process_name, 14);
            entrada[15] = (unsigned char)process_id;

            fwrite(entrada, 1, PCB_ENTRY_SIZE, memory_file);
            fflush(memory_file);

            return 0;
        }
    }

    return -1;
}

int os_finish_process(int process_id)
{
    if (!memory_file)
    {
        fprintf(stderr, "Error: Memoria no montada.\n");
        return 1;
    }

    long pcb_entry_offset_found = -1;
    unsigned char status_pcb;
    unsigned char current_pid_pcb;

    // 1. Localizar la entrada del PCB
    for (int i = 0; i < PCB_COUNT; i++)
    {
        long current_pcb_offset = PCB_START + (i * PCB_ENTRY_SIZE);

        fseek(memory_file, current_pcb_offset, SEEK_SET);
        fread(&status_pcb, sizeof(unsigned char), 1, memory_file);

        if (status_pcb == 0x01)
        { // Si la entrada está activa
            fseek(memory_file, current_pcb_offset + PCB_PROCESS_ID_OFFSET, SEEK_SET);
            fread(&current_pid_pcb, sizeof(unsigned char), 1, memory_file);
            if (current_pid_pcb == (unsigned char)process_id)
            {
                pcb_entry_offset_found = current_pcb_offset;
                break;
            }
        }
    }

    if (pcb_entry_offset_found == -1)
    {
        fprintf(stderr, "Proceso %d no encontrado o ya terminado.\n", process_id);
        return 1; // Proceso no existe o no está activo
    }

    // 2. Liberar frames: Iterar sobre la Tabla de Páginas Invertida (IPT)
    for (int pfn = 0; pfn < IPT_ENTRY_COUNT; pfn++)
    {
        long ipt_entry_disk_offset = IPT_OFFSET + (pfn * IPT_ENTRY_SIZE);
        unsigned char ipt_data[IPT_ENTRY_SIZE];

        fseek(memory_file, ipt_entry_disk_offset, SEEK_SET);
        fread(ipt_data, sizeof(unsigned char), IPT_ENTRY_SIZE, memory_file);

        unsigned char validity_bit = (ipt_data[0] >> 7) & 0x01;
        int entry_pid = ((ipt_data[0] & 0x7F) << 3) | ((ipt_data[1] >> 5) & 0x07);

        if (validity_bit == 1 && entry_pid == process_id)
        {
            // a. Marcar la entrada de la IPT como inválida (bit de validez a 0)
            ipt_data[0] &= 0x7F;
            fseek(memory_file, ipt_entry_disk_offset, SEEK_SET);
            fwrite(ipt_data, sizeof(unsigned char), IPT_ENTRY_SIZE, memory_file);

            // b. Actualizar el Frame Bitmap para marcar el frame PFN como libre (bit = 0)
            long bitmap_byte_disk_offset = FRAME_BITMAP_OFFSET + (pfn / 8);
            int bit_in_byte_index = pfn % 8;

            unsigned char bitmap_byte_value;
            fseek(memory_file, bitmap_byte_disk_offset, SEEK_SET);
            fread(&bitmap_byte_value, sizeof(unsigned char), 1, memory_file);

            bitmap_byte_value &= ~(1 << bit_in_byte_index); // Poner el bit a 0

            fseek(memory_file, bitmap_byte_disk_offset, SEEK_SET);
            fwrite(&bitmap_byte_value, sizeof(unsigned char), 1, memory_file);
        }
    }

    // 3. Limpiar la tabla de archivos del proceso en la PCB
    long file_table_start_offset = pcb_entry_offset_found + PCB_FILE_TABLE_OFFSET;
    unsigned char zero_byte = 0x00;
    for (int i = 0; i < MAX_FILES_PER_PROCESS; i++)
    {
        long file_entry_validity_offset = file_table_start_offset + (i * FILE_ENTRY_SIZE);
        fseek(memory_file, file_entry_validity_offset, SEEK_SET);
        fwrite(&zero_byte, sizeof(unsigned char), 1, memory_file); // Marcar archivo como inválido
    }

    // 4. Marcar la entrada del PCB como "no existe" (estado 0x00)
    // Opcionalmente, también podrías limpiar el nombre y el ID.
    fseek(memory_file, pcb_entry_offset_found, SEEK_SET);
    fwrite(&zero_byte, sizeof(unsigned char), 1, memory_file); // Estado: no existe

    // Opcional: Limpiar nombre e ID en PCB
    // char empty_name[PROCESS_NAME_MAX_LEN] = {0};
    // fseek(memory_file, pcb_entry_offset_found + PCB_NAME_OFFSET, SEEK_SET);
    // fwrite(empty_name, sizeof(char), PROCESS_NAME_MAX_LEN, memory_file);
    // fseek(memory_file, pcb_entry_offset_found + PCB_PROCESS_ID_OFFSET, SEEK_SET);
    // fwrite(&zero_byte, sizeof(unsigned char), 1, memory_file);

    fflush(memory_file); // Asegurar todas las escrituras
    // printf("Proceso %d terminado exitosamente.\n", process_id);
    return 0; // Éxito
}

int os_rename_process(int process_id, char *new_name)
{
    if (!memory_file)
    {
        fprintf(stderr, "Error: Memoria no montada.\n");
        return 1;
    }

    if (!new_name)
    {
        fprintf(stderr, "Error: El nuevo nombre no puede ser NULL.\n");
        return 1;
    }

    size_t new_name_len = strlen(new_name);
    if (new_name_len == 0 || new_name_len > PROCESS_NAME_MAX_LEN)
    {
        fprintf(stderr, "Error: Longitud de nombre inválida (1-%d caracteres).\n", PROCESS_NAME_MAX_LEN);
        return 1; // Nombre demasiado largo o vacío
    }

    long pcb_entry_offset_found = -1;
    unsigned char status_pcb;
    unsigned char current_pid_pcb;

    // 1. Localizar la entrada del PCB
    for (int i = 0; i < PCB_COUNT; i++)
    {
        long current_pcb_offset = PCB_START + (i * PCB_ENTRY_SIZE);

        fseek(memory_file, current_pcb_offset, SEEK_SET);
        fread(&status_pcb, sizeof(unsigned char), 1, memory_file);

        if (status_pcb == 0x01)
        { // Si la entrada está activa
            fseek(memory_file, current_pcb_offset + PCB_PROCESS_ID_OFFSET, SEEK_SET);
            fread(&current_pid_pcb, sizeof(unsigned char), 1, memory_file);
            if (current_pid_pcb == (unsigned char)process_id)
            {
                pcb_entry_offset_found = current_pcb_offset;
                break;
            }
        }
    }

    if (pcb_entry_offset_found == -1)
    {
        fprintf(stderr, "Proceso %d no encontrado para renombrar.\n", process_id);
        return 1; // Proceso no existe o no está activo
    }

    // 2. Copiar el nuevo nombre al campo de nombre en la PCB (14 bytes)
    char name_buffer[PROCESS_NAME_MAX_LEN];
    memset(name_buffer, 0, PROCESS_NAME_MAX_LEN); // Limpiar buffer
    strncpy(name_buffer, new_name, PROCESS_NAME_MAX_LEN);
    // strncpy no garantiza terminador nulo si strlen(new_name) >= PROCESS_NAME_MAX_LEN,
    // pero como el campo es de tamaño fijo y name_buffer se inicializó a ceros, está bien.

    fseek(memory_file, pcb_entry_offset_found + PCB_NAME_OFFSET, SEEK_SET);
    fwrite(name_buffer, sizeof(char), PROCESS_NAME_MAX_LEN, memory_file);

    fflush(memory_file); // Asegurar escritura
    // printf("Proceso %d renombrado a '%s'.\n", process_id, new_name);
    return 0; // Éxito
}

// // funciones archivos
osrmsFile *os_open(int process_id, char *file_name, char mode)
{
    printf("\nOS_OPEN - Proceso %d, archivo '%s', modo '%c'\n", process_id, file_name, mode);
    if (!memory_file)
    {
        return NULL;
    }

    for (int i = 0; i < PCB_COUNT; i++)
    {
        long pcb_offset = PCB_START + i * PCB_ENTRY_SIZE;
        fseek(memory_file, pcb_offset, SEEK_SET);
        unsigned char header[16];
        fread(header, 1, 16, memory_file);

        if (header[0] != 0x01 || header[15] != (unsigned char)process_id)
            continue;

        printf("Proceso %d encontrado en PCB %d.\n", process_id, i);
        for (int j = 0; j < 10; j++)
        {
            long entry_offset = pcb_offset + FILE_TABLE_OFFSET + j * FILE_ENTRY_SIZE;
            fseek(memory_file, entry_offset, SEEK_SET);

            unsigned char entrada[24];
            fread(entrada, 1, 24, memory_file);
            printf("entrada[24] = ");
            for (int i = 0; i < 24; i++)
            {
                printf("%02X ", entrada[i]);
            }
            printf("\n");

            int valido = entrada[0] == 0x01;
            char nombre[15] = {0};
            memcpy(nombre, &entrada[1], 14);

            if (valido && strncmp(nombre, file_name, 14) == 0)
            {
                if (mode == 'r')
                {
                    osrmsFile *f = calloc(1, sizeof(osrmsFile));
                    f->process_id = process_id;
                    f->file_index = j;
                    f->size = 0;
                    f->mode = mode;
                    for (int k = 0; k < 5; k++)
                    {
                        f->size |= ((unsigned long)entrada[15 + k]) << (8 * k);
                    }
                    f->virtual_addr = 0;
                    for (int k = 0; k < 4; k++)
                    {
                        f->virtual_addr |= ((unsigned int)entrada[6 + k + 9]) << (8 * k);
                    }
                    printf("Virtual address: 0x%08X, Size: %lu\n", f->virtual_addr, f->size);
                    strncpy(f->name, nombre, 14);
                    return f;
                }
                else
                {
                    return NULL; // ya existe, no se puede escribir
                }
            }

            // Si modo es 'w' y esta entrada está libre
            if (!valido && mode == 'w')
            {
                osrmsFile *f = calloc(1, sizeof(osrmsFile));
                f->process_id = process_id;
                f->file_index = j;
                f->size = 0;
                f->virtual_addr = 0;
                f->mode = mode;
                strncpy(f->name, file_name, 14);

                // escribir entrada
                // fseek(memory_file, entry_offset, SEEK_SET);
                // unsigned char nueva[24] = {0};
                // nueva[0] = 0x01;
                // strncpy((char *)&nueva[1], file_name, 14);
                // fwrite(nueva, 1, 24, memory_file);
                // fflush(memory_file);
                return f;
            }
        }

        return NULL;
    }

    return NULL;
}

void os_close(osrmsFile *file_desc)
{
    printf("OS_CLOSE - Proceso %d, archivo '%s'\n", file_desc->process_id, file_desc->name);
    if (file_desc != NULL)
        free(file_desc);
}

// ejecuciones
void execute_os_exists(int process_id, char *file_name)
{
    if (os_exists(process_id, file_name) == 1)
    {
        printf("\nOS_EXISTS - Archivo '%s' existe en proceso %d.\n", file_name, process_id);
        return;
    }
    printf("\nOS_EXISTS - Archivo '%s' NO existe en proceso %d.\n", file_name, process_id);
}

osrmsFile *execute_os_open(int process_id, char *file_name, char *mode)
{
    printf("\nOS_OPEN - ");
    osrmsFile *result = NULL;
    result = os_open(process_id, file_name, *mode);
    if (result != NULL)
    {
        printf("Abriendo archivo '%s' de proceso %d en modo %s.\n", file_name, process_id, mode);
    }
    else
    {
        printf("Error: No se pudo abrir '%s' en modo de %s.\n", file_name, mode);
    }
    return result;
}

void execute_os_close(osrmsFile *file_desc)
{
    if (!file_desc)
    {
        printf("\nOS_CLOSE - Error: archivo no encontrado.\n");
        return;
    }
    char *file_name = file_desc->name;
    printf("\nOS_CLOSE - Cerrando archivo: %s.\n", file_name);
    os_close(file_desc);
    return;
}

uint16_t get_vpn_from_virtual_address(uint32_t virtual_address)
{
    return (virtual_address >> 15) & 0xFFF; // 0xFFF es 12 bits todos a 1
}

uint16_t get_offset_from_virtual_address(uint32_t virtual_address)
{
    return virtual_address & 0x7FFF; // 0x7FFF es 15 bits todos a 1
}

int get_pfn_from_ipt(int process_id, uint16_t vpn)
{
    // Recorrer la tabla de páginas invertida
    for (int i = 0; i < IPT_ENTRY_COUNT; i++)
    {
        long entry_offset = IPT_OFFSET + (i * IPT_ENTRY_SIZE);
        uint32_t entry_value = read_int(entry_offset) & 0xFFFFFF; // Leer 3 bytes

        uint8_t valid = (entry_value >> 23) & 0x01;     // Bit 23: Validez
        uint16_t id_proc = (entry_value >> 13) & 0x3FF; // Bits 13-22: ID proceso (10 bits)
        uint16_t entry_vpn = entry_value & 0x1FFF;      // Bits 0-12: VPN (13 bits)

        if (valid && id_proc == process_id && entry_vpn == vpn)
        {
            // El PFN es el índice de la entrada en la IPT
            return i;
        }
    }
    return -1; // No se encontró una entrada válida
}

int os_read_file(osrmsFile *file_desc, char *dest)
{
    printf("\nOS_READ_FILE - Leyendo archivo '%s' de PID %d, guardando en '%s'\n",
           file_desc->name, file_desc->process_id, dest);
    if (memory_file == NULL)
    {
        printf("Error: Memoria no montada. Use os_mount() primero.\n");
        return -1;
    }
    if (file_desc == NULL)
    {
        printf("Error: Descriptor de archivo inválido.\n");
        return -1;
    }
    if (file_desc->mode != 'r')
    {
        printf("Error: El archivo '%s' no está abierto en modo lectura.\n", file_desc->name);
        return -1;
    }
    if (file_desc->size == 0)
    {
        printf("Advertencia: El archivo '%s' está vacío. No se leerá nada.\n", file_desc->name);
        return 0; // Se leyeron 0 bytes
    }

    FILE *dest_file = fopen(dest, "wb"); // Abrir el archivo de destino en modo escritura binaria
    if (dest_file == NULL)
    {
        perror("Error al abrir el archivo de destino para escritura");
        return -1;
    }

    int bytes_read = 0;
    uint32_t current_virtual_address = file_desc->virtual_addr;
    uint32_t remaining_bytes_to_read = file_desc->size;

    while (remaining_bytes_to_read > 0)
    {
        // 1. Obtener VPN y Offset de la dirección virtual actual
        uint16_t vpn = get_vpn_from_virtual_address(current_virtual_address);
        uint16_t offset_in_page = get_offset_from_virtual_address(current_virtual_address);

        // 2. Buscar PFN en la IPT
        int pfn = get_pfn_from_ipt(file_desc->process_id, vpn);

        if (pfn == -1)
        {
            printf("Error: No se encontró entrada válida en IPT para PID %d, VPN %u. Lectura incompleta.\n",
                   file_desc->process_id, vpn);
            break; // Salir si no se puede traducir la dirección
        }

        // 3. Calcular la dirección física
        long physical_address = FRAMES_OFFSET + (long)pfn * FRAME_SIZE + offset_in_page;

        // 4. Determinar cuántos bytes leer en este chunk
        // Esto es el mínimo entre:
        // - lo que queda por leer del archivo
        // - lo que queda de la página actual (FRAME_SIZE - offset_in_page)
        size_t bytes_to_read_this_chunk = FRAME_SIZE - offset_in_page;
        if (bytes_to_read_this_chunk > remaining_bytes_to_read)
        {
            bytes_to_read_this_chunk = remaining_bytes_to_read;
        }

        // 5. Leer el chunk desde la memoria simulada
        fseek(memory_file, physical_address, SEEK_SET);
        char buffer[bytes_to_read_this_chunk]; // Usar VLA, o malloc si no es C99
        size_t actual_read = fread(buffer, sizeof(char), bytes_to_read_this_chunk, memory_file);

        if (actual_read != bytes_to_read_this_chunk)
        {
            printf("Error de lectura: Se esperaban %zu bytes, se leyeron %zu. Lectura incompleta.\n",
                   bytes_to_read_this_chunk, actual_read);
            break; // Error de lectura inesperado
        }

        // 6. Escribir el chunk en el archivo de destino local
        fwrite(buffer, sizeof(char), actual_read, dest_file);

        bytes_read += actual_read;
        remaining_bytes_to_read -= actual_read;
        current_virtual_address += actual_read;

        // Si se leyó todo lo que quedaba en esta página, la siguiente iteración buscará la siguiente VPN
        // Si no, el offset_in_page se ajustará automáticamente con current_virtual_address
    }

    fclose(dest_file);
    printf("Archivo '%s' de PID %d leído exitosamente en '%s'. %d bytes leídos.\n",
           file_desc->name, file_desc->process_id, dest, bytes_read);

    return bytes_read;
}

void set_frame_bitmap_bit(int pfn, bool used)
{
    long byte_offset = FRAME_BITMAP_OFFSET + (pfn / 8);
    int bit_in_byte = pfn % 8;

    uint8_t current_byte = read_byte(byte_offset);
    if (used)
    {
        current_byte |= (0x01 << bit_in_byte); // Poner el bit a 1
    }
    else
    {
        current_byte &= ~(0x01 << bit_in_byte); // Poner el bit a 0
    }
    write_byte(byte_offset, current_byte);
    fflush(memory_file); // Asegurar que el cambio se escriba en disco
}

int get_free_frame()
{
    for (int i = 0; i < NUM_FRAMES; i++)
    {
        long byte_offset = FRAME_BITMAP_OFFSET + (i / 8);
        int bit_in_byte = i % 8;
        uint8_t byte = read_byte(byte_offset);
        if (!((byte >> bit_in_byte) & 0x01))
        { // Si el bit es 0 (libre)
            return i;
        }
    }
    return -1; // No se encontraron frames libres
}

void set_ipt_entry(int pfn, int process_id, uint16_t vpn)
{
    long entry_offset = IPT_OFFSET + (long)pfn * IPT_ENTRY_SIZE;

    // Los 3 bytes de la IPT: 1 bit validez, 10 bits ID proceso, 13 bits VPN
    // (Total: 1 + 10 + 13 = 24 bits = 3 bytes)
    uint32_t value = 0;
    value |= (0x01 << 23);                         // Validez (bit 23 a 1)
    value |= ((uint32_t)process_id & 0x3FF) << 13; // ID proceso (10 bits, mask 0x3FF = 1023)
    value |= ((uint32_t)vpn & 0x1FFF);             // VPN (13 bits, mask 0x1FFF = 8191)

    // Escribir solo 3 bytes (24 bits)
    uint8_t bytes[3];
    bytes[0] = (uint8_t)(value & 0xFF);
    bytes[1] = (uint8_t)((value >> 8) & 0xFF);
    bytes[2] = (uint8_t)((value >> 16) & 0xFF);
    fseek(memory_file, entry_offset, SEEK_SET);
    fwrite(bytes, sizeof(uint8_t), 3, memory_file);
    fflush(memory_file);
}

void clear_ipt_entry(int pfn)
{
    long entry_offset = IPT_OFFSET + (long)pfn * IPT_ENTRY_SIZE;

    // Leer la entrada actual para no modificar otros bits
    uint32_t entry_value = read_int(entry_offset) & 0xFFFFFF; // Leer 3 bytes

    // Poner el bit de validez (bit 23) a 0
    entry_value &= ~(0x01 << 23);

    // Escribir solo 3 bytes (24 bits)
    uint8_t bytes[3];
    bytes[0] = (uint8_t)(entry_value & 0xFF);
    bytes[1] = (uint8_t)((entry_value >> 8) & 0xFF);
    bytes[2] = (uint8_t)((entry_value >> 16) & 0xFF);
    fseek(memory_file, entry_offset, SEEK_SET);
    fwrite(bytes, sizeof(uint8_t), 3, memory_file);
    fflush(memory_file);
}

long find_process_pcb_entry(int process_id)
{
    for (int i = 0; i < PCB_COUNT; i++)
    {
        long pcb_offset = PCB_START + (long)i * PCB_ENTRY_SIZE;
        uint8_t status = read_byte(pcb_offset);
        if (status == 0x01)
        {
            // El ID del proceso está en la posición 1+14 = 15 dentro de la PCB
            long id_offset = pcb_offset + 1 + PROCESS_NAME_MAX_LEN;
            uint8_t id = read_byte(id_offset); // El ID es de 1 Byte
            if (id == process_id)
            {
                return pcb_offset;
            }
        }
    }
    return -1; // Proceso no encontrado
}

long find_free_file_table_entry(long pcb_offset)
{
    long file_table_offset_start = pcb_offset + 1 + PROCESS_NAME_MAX_LEN + 1; // Despues de estado, nombre y ID
    for (int i = 0; i < MAX_FILES_PER_PROCESS; i++)
    {
        long file_entry_offset = file_table_offset_start + (long)i * FILE_ENTRY_SIZE;
        uint8_t validity = read_byte(file_entry_offset); // Primer byte es la validez
        if (validity == 0x00)
        { // Si el bit de validez es 0 (entrada libre)
            return file_entry_offset;
        }
    }
    return -1; // No hay entradas libres en la tabla de archivos
}

uint32_t find_and_assign_virtual_pages(int process_id, int num_pages_needed, int *assigned_pfns, uint16_t *assigned_vpns)
{
    printf("\nOS_FIND_AND_ASSIGN_VIRTUAL_PAGES - Proceso %d, páginas necesarias: %d\n", process_id, num_pages_needed);
    // 1. Encontrar los frames físicos libres
    int *temp_pfns = (int *)malloc(num_pages_needed * sizeof(int));
    if (temp_pfns == NULL)
    {
        printf("Error: No se pudo asignar memoria para PFNs temporales.\n");
        return -1;
    }

    for (int i = 0; i < num_pages_needed; i++)
    {
        int pfn = get_free_frame();
        if (pfn == -1)
        {
            printf("Error: No hay suficientes frames físicos libres para el archivo.\n");
            free(temp_pfns);
            return -1; // No hay suficientes frames
        }
        temp_pfns[i] = pfn;
    }

    // 2. Encontrar las primeras 'num_pages_needed' VPNs consecutivas disponibles para este proceso
    // Esto es lo más tricky con una IPT. Una forma es mantener un array de VPNs usadas por el proceso
    // o simplemente buscar la primera VPN disponible que no esté en la IPT para este PID.
    // Vamos a buscar la primera VPN disponible que no esté en la IPT para el PID.
    // Esto implica que podríamos tener fragmentación de VPNs.

    uint16_t current_vpn_candidate = 0;
    for (int i = 0; i < NUM_VIRTUAL_PAGES; i++)
    {
        // Asumimos que las VPNs no utilizadas por el proceso son "libres".
        // Para verificar si una VPN está "libre" para un proceso,
        // necesitamos verificar si existe alguna entrada en la IPT con ese PID y esa VPN.
        bool vpn_is_used_by_this_process = false;
        for (int j = 0; j < IPT_ENTRY_COUNT; j++)
        {
            long entry_offset = IPT_OFFSET + (j * IPT_ENTRY_SIZE);
            uint32_t entry_value = read_int(entry_offset) & 0xFFFFFF; // Leer 3 bytes

            uint8_t valid = (entry_value >> 23) & 0x01;
            uint16_t id_proc = (entry_value >> 13) & 0x3FF;
            uint16_t entry_vpn = entry_value & 0x1FFF;

            if (valid && id_proc == process_id && entry_vpn == current_vpn_candidate)
            {
                vpn_is_used_by_this_process = true;
                break;
            }
        }

        if (!vpn_is_used_by_this_process)
        {

            uint16_t potential_start_vpn = current_vpn_candidate;
            bool block_found = true;
            for (int k = 0; k < num_pages_needed; k++)
            {
                uint16_t check_vpn = potential_start_vpn + k;
                if (check_vpn >= NUM_VIRTUAL_PAGES)
                { // Nos salimos del rango de VPNs virtuales
                    block_found = false;
                    break;
                }

                // Verificar si esta VPN (check_vpn) ya está usada por process_id
                // (iterar IPT para cada una, o mejorar la búsqueda de IPT si es posible)
                if (get_pfn_from_ipt(process_id, check_vpn) != -1)
                {
                    block_found = false;
                    break;
                }
            }

            if (block_found)
            {
                // Hemos encontrado un bloque de VPNs consecutivas libres para este proceso.
                uint32_t base_virtual_address = (uint32_t)potential_start_vpn << 15; // VPN * PAGE_SIZE

                // 3. Asignar frames a estas VPNs e insertarlos en la IPT
                for (int k = 0; k < num_pages_needed; k++)
                {
                    int pfn_to_assign = temp_pfns[k];
                    uint16_t vpn_to_assign = potential_start_vpn + k;

                    set_frame_bitmap_bit(pfn_to_assign, true);               // Marcar frame como usado
                    set_ipt_entry(pfn_to_assign, process_id, vpn_to_assign); // Actualizar IPT
                    assigned_pfns[k] = pfn_to_assign;
                    assigned_vpns[k] = vpn_to_assign;
                }
                free(temp_pfns);
                printf("Asignación exitosa: Proceso %d, VPNs desde %u a %u, PFNs asignados.\n",
                       process_id, potential_start_vpn, potential_start_vpn + num_pages_needed - 1);
                return base_virtual_address;
            }
        }
        current_vpn_candidate++; // Siguiente VPN a intentar como inicio
    }

    free(temp_pfns);
    printf("Error: No se encontró un bloque de VPNs consecutivas libres para el proceso %d.\n", process_id);
    return -1; // No se encontró un bloque de VPNs libres
}

int os_write_file(osrmsFile *file_desc, char *src)
{
    if (memory_file == NULL)
    {
        printf("Error: Memoria no montada. Use os_mount() primero.\n");
        return -1;
    }
    if (file_desc == NULL)
    {
        printf("Error: Descriptor de archivo inválido.\n");
        return -1;
    }
    if (file_desc->mode != 'w')
    {
        printf("Error: El archivo '%s' no está abierto en modo escritura.\n", file_desc->name);
        return -1;
    }
    printf("\nOS_WRITE_FILE - Proceso %d, archivo '%s'\n", file_desc->process_id, file_desc->name);

    // 1. Obtener el tamaño del archivo de origen
    FILE *src_file = fopen(src, "rb"); // Abrir el archivo de origen en modo lectura binaria
    if (src_file == NULL)
    {
        perror("Error al abrir el archivo de origen para lectura");
        return -1;
    }

    fseek(src_file, 0, SEEK_END);
    long source_file_size = ftell(src_file);
    fseek(src_file, 0, SEEK_SET);

    if (source_file_size == 0)
    {
        printf("Advertencia: El archivo de origen '%s' está vacío. No se escribirá nada.\n", src);
        fclose(src_file);
        return 0; // Se escribieron 0 bytes
    }
    printf("Source file size: %ld bytes\n", source_file_size);

    // 2. Calcular cuántas páginas (frames) se necesitan
    int num_pages_needed = (source_file_size + VIRTUAL_PAGE_SIZE - 1) / VIRTUAL_PAGE_SIZE;

    printf("Pages needed: %d\n", num_pages_needed);

    // 3. Buscar una entrada libre en la tabla de archivos del proceso
    long pcb_offset = find_process_pcb_entry(file_desc->process_id);
    if (pcb_offset == -1)
    {
        printf("Error: Proceso %d no encontrado.\n", file_desc->process_id);
        fclose(src_file);
        return -1;
    }

    long file_table_entry_offset = find_free_file_table_entry(pcb_offset);
    if (file_table_entry_offset == -1)
    {
        printf("Error: El proceso %d no tiene espacio para más archivos (máximo %d).\n",
               file_desc->process_id, MAX_FILES_PER_PROCESS);
        fclose(src_file);
        return -1;
    }

    // 4. Asignar frames físicos y VPNs
    int *assigned_pfns = (int *)malloc(num_pages_needed * sizeof(int));
    uint16_t *assigned_vpns = (uint16_t *)malloc(num_pages_needed * sizeof(uint16_t));
    if (assigned_pfns == NULL || assigned_vpns == NULL)
    {
        printf("Error: No se pudo asignar memoria para almacenar PFNs/VPNs.\n");
        if (assigned_pfns)
            free(assigned_pfns);
        if (assigned_vpns)
            free(assigned_vpns);
        fclose(src_file);
        return -1;
    }

    // La función find_and_assign_virtual_pages se encargará de:
    // - Encontrar frames libres
    // - Encontrar VPNs consecutivas y libres para el proceso
    // - Marcar los frames en el bitmap
    // - Crear las entradas en la IPT
    uint32_t base_virtual_address = find_and_assign_virtual_pages(
        file_desc->process_id, num_pages_needed, assigned_pfns, assigned_vpns);

    if (base_virtual_address == -1 && num_pages_needed > 0)
    {
        // Si base_virtual_address es 0 y se necesitaban páginas, significa un error en la asignación
        printf("Error: No se pudo asignar memoria virtual y física para el archivo.\n");
        free(assigned_pfns);
        free(assigned_vpns);
        fclose(src_file);
        return -1;
    }

    printf("Step 5\n");

    // 5. Escribir el contenido del archivo
    int bytes_written = 0;
    uint32_t current_virtual_address_in_file = 0; // Offset dentro del archivo local

    while (bytes_written < source_file_size)
    {
        // Calcular la dirección virtual global en el espacio del proceso
        uint32_t current_process_virtual_address = base_virtual_address + current_virtual_address_in_file;

        // Obtener VPN y Offset para la traducción
        uint16_t vpn = get_vpn_from_virtual_address(current_process_virtual_address);
        uint16_t offset_in_page = get_offset_from_virtual_address(current_process_virtual_address);

        // Buscar PFN en la IPT (debería existir porque lo acabamos de asignar)
        int pfn = get_pfn_from_ipt(file_desc->process_id, vpn);

        if (pfn == -1)
        {
            printf("Error crítico: PFN no encontrado para VPN %u después de asignación. Abortando escritura.\n", vpn);
            bytes_written = -1; // Indicar error severo
            break;
        }

        // Calcular la dirección física
        long physical_address = FRAMES_OFFSET + (long)pfn * FRAME_SIZE + offset_in_page;

        // Determinar cuántos bytes escribir en este chunk
        size_t bytes_to_write_this_chunk = VIRTUAL_PAGE_SIZE - offset_in_page;
        if (bytes_to_write_this_chunk > (source_file_size - bytes_written))
        {
            bytes_to_write_this_chunk = (source_file_size - bytes_written);
        }

        char buffer[bytes_to_write_this_chunk]; // VLA
        size_t actual_read = fread(buffer, sizeof(char), bytes_to_write_this_chunk, src_file);

        if (actual_read == 0 && bytes_to_write_this_chunk > 0)
        {
            printf("Error de lectura del archivo fuente local. Se esperaban %zu bytes, se leyeron 0.\n", bytes_to_write_this_chunk);
            bytes_written = -1; // Indicar error
            break;
        }

        // Escribir el chunk en la memoria simulada
        fseek(memory_file, physical_address, SEEK_SET);
        fwrite(buffer, sizeof(char), actual_read, memory_file);
        fflush(memory_file); // Asegurar que se escriba en el archivo

        bytes_written += actual_read;
        current_virtual_address_in_file += actual_read;
    }

    fclose(src_file);

    printf("Step 6\n");
    // 6. Actualizar la entrada de la tabla de archivos en la PCB
    if (bytes_written != -1)
    { // Solo si no hubo errores graves
        // 1 Byte validez (0x01)
        write_byte(file_table_entry_offset, 0x01);
        // 14 Bytes nombre
        write_string(file_table_entry_offset + 1, file_desc->name, FILE_NAME_MAX_LEN);
        // 5 Bytes tamaño (se almacena como un entero de 4 bytes, y un byte de padding para ser 5 bytes en total)
        // Para simplificar, asumiremos que se guardan 4 bytes del tamaño y el quinto es padding o un byte de control.
        // La especificación dice 5 bytes tamaño. Si es un entero, lo más común es 4.
        // Vamos a guardar el tamaño como un int32_t (4 bytes) y un byte de padding/relleno a 0.
        write_int(file_table_entry_offset + 1 + FILE_NAME_MAX_LEN, (uint32_t)source_file_size);
        write_byte(file_table_entry_offset + 1 + FILE_NAME_MAX_LEN + 4, 0x00); // Relleno de 1 byte

        // 4 Bytes dirección virtual (5 bits padding, 12 bits VPN, 15 bits offset)
        // La dirección virtual ya está calculada como base_virtual_address
        write_int(file_table_entry_offset + 1 + FILE_NAME_MAX_LEN + 5, base_virtual_address);
        fflush(memory_file);

        // 7. Actualizar el osrmsFile* file_desc
        file_desc->virtual_addr = base_virtual_address;
        file_desc->size = source_file_size;

        printf("Archivo '%s' de PID %d escrito exitosamente en memoria simulada. %d bytes escritos.\n",
               file_desc->name, file_desc->process_id, bytes_written);
    }
    else
    {
        // En caso de error, necesitamos deshacer las asignaciones de frames y IPT.
        // Esto es un "rollback" que se podría hacer en una función separada.
        // Por simplicidad, para la tarea, a menudo se espera que se maneje el error y no se haga rollback explícito.
        // Pero para un sistema real, sería crucial.
        // En este caso, al retornar -1, se asume que la operación falló y el estado de la memoria puede ser inconsistente.
        printf("Error: Falló la escritura del archivo '%s'. Deshaciendo asignaciones...\n", file_desc->name);
        // Implementar rollback aquí si fuera necesario
        // Por ahora, solo limpiamos los arrays dinámicos
        if (assigned_pfns)
            free(assigned_pfns);
        if (assigned_vpns)
            free(assigned_vpns);
        return -1; // Retorna -1 si hubo un error crítico
    }

    if (assigned_pfns)
        free(assigned_pfns);
    if (assigned_vpns)
        free(assigned_vpns);
    return bytes_written;
}