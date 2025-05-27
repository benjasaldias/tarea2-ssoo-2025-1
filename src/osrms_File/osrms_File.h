#pragma once

typedef struct osrmsFile
{
    int process_id;
    int file_index;            // índice en la tabla de archivos (0 a 9)
    unsigned int virtual_addr; // dirección virtual del archivo
    unsigned long size;        // tamaño en bytes
    char name[15];             // nombre del archivo
    char mode;                 // 'r' para lectura, 'w' para escritura
} osrmsFile;
