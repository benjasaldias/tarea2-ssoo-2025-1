#include <stdio.h>   // FILE, fopen, fclose, etc.
#include <stdlib.h>  // malloc, calloc, free, etc
#include <string.h>  //para strcmp
#include <stdbool.h> // bool, true, false

char *path;
FILE *memory_file = NULL;

// funciones generales
void os_mount(char *memory_path)
{
    memory_file = fopen(memory_path, "rb+");
    if (!memory_file)
    {
        perror("Error al abrir la memoria");
        exit(EXIT_FAILURE);
    }
}

#define PCB_START 0
#define PCB_ENTRY_SIZE 256
#define PCB_COUNT 32

#define PCB_NAME_OFFSET 1
#define PCB_PROCESS_ID_OFFSET 15
#define PCB_FILE_TABLE_OFFSET 16
#define PROCESS_NAME_MAX_LEN 14

#define MAX_FILES_PER_PROCESS 10
#define FILE_ENTRY_SIZE 24

#define IPT_OFFSET (8 * 1024)
#define IPT_ENTRY_SIZE 3
#define IPT_ENTRY_COUNT 65536

#define FRAME_BITMAP_OFFSET ((8 + 192) * 1024)
#define FRAME_BITMAP_SIZE (8 * 1024)

int os_start_process(int process_id, char *process_name)
{
    if (!memory_file)
    {
        fprintf(stderr, "Memoria no montada.\n");
        return -1;
    }

    if (strlen(process_name) > 14)
        return -1;

    // Falta asegurar que no exista un proceso con el mismo id

    for (int i = 0; i < PCB_COUNT; i++)
    {
        long offset = PCB_START + i * PCB_ENTRY_SIZE;

        fseek(memory_file, offset, SEEK_SET);
        unsigned char estado;
        fread(&estado, 1, 1, memory_file);

        if (estado == 0x00)
        {
            // Entrada libre encontrada
            fseek(memory_file, offset, SEEK_SET);
            unsigned char entrada[PCB_ENTRY_SIZE] = {0};

            entrada[0] = 0x01;                              // Estado
            strncpy((char *)&entrada[1], process_name, 14); // Nombre
            entrada[15] = (unsigned char)process_id;        // ID

            // Tabla de archivos ya está en 0 (entrada inicializada en 0)
            fwrite(entrada, 1, PCB_ENTRY_SIZE, memory_file);
            fflush(memory_file);

            return 0;
        }
    }

    // No hay espacio disponible
    return -1;
}

void os_ls_processes()
{
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
// // funciones procesos

// // funciones archivos