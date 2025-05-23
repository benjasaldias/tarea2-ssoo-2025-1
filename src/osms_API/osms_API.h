#include "../osms_File/osms_File.h"
#include <stdio.h>
#include <stdlib.h>

#pragma once

extern FILE* memory_file;

// auxiliares
void execute_os_exists(int process_id, char* file_name) {  
    if (os_exists(process_id, file_name) == 1) {
        printf("\nOS_EXISTS - Archivo '%s' existe en proceso %d.\n", file_name, process_id);
        return;
    }
    printf("\nOS_EXISTS - Archivo '%s' NO existe en proceso %d.\n", file_name, process_id);
}

// funciones generales
void os_mount(char* memory_path);

void os_ls_processes();

int os_exists(int process_id, char* file_name);

// void os_ls_files(int process_id);

// void os_frame_bitmap();

// // funciones procesos

int os_start_process(int process_id, char* process_name);

// int os_finish_process(int process_id);

// int os_rename process(int process id, char* new name);

// // funciones archivos

// OsmsFile* os_open(int process_id, char* file_name, char mode);

// int os_read_file(osrmsFile* file desc, char* dest);

// int os_write_file(osrmsFile* file desc, char* src);

// void os_delete_file(int process id, char* file name);

// void os_close(OsmsFile* file_desc);

// BONUS

// int os_cp(int pid src, char* fname src, int pid dst, char* fname dst);

