#include <stdio.h>
#include <stdlib.h>
// #include "osrms_File.h"
#include "../osrms_File/osrms_File.h"

#pragma once

extern FILE *memory_file;

// funciones generales
void os_mount(char *memory_path);

void os_ls_processes();

int os_exists(int process_id, char *file_name);

void os_ls_files(int process_id);

void os_frame_bitmap();

// funciones procesos

int os_start_process(int process_id, char *process_name);

int os_finish_process(int process_id);

int os_rename_process(int process_id, char *new_name);

// funciones archivos

osrmsFile *os_open(int process_id, char *file_name, char mode);

int os_read_file(osrmsFile *file_desc, char *dest);

int os_write_file(osrmsFile *file_desc, char *src);

void os_delete_file(int process_id, char *file_name);

void os_close(osrmsFile *file_desc);

// BONUS

// int os_cp(int pid src, char* fname src, int pid dst, char* fname dst);

// ejecuciones
void execute_os_exists(int process_id, char *file_name);

osrmsFile *execute_os_open(int process_id, char *file_name, char *mode);

void execute_os_close(osrmsFile *file_desc);