#include <stdlib.h>
#include "../osms_API/osms_API.h"

int main(int argc, char const *argv[])
{

    // montar la memoria
    os_mount((char *)argv[1]);
    os_ls_processes();
    os_start_process(3, "ventas");
    os_start_process(7, "ventas 2");
    os_start_process(10, "ventas 3");
    os_ls_processes();
    os_rename_process(10, "Nuevo ventas");
    os_ls_processes();
    os_finish_process(3);
    os_finish_process(7);
    os_finish_process(10);
    os_ls_processes();
    fclose(memory_file);
    return 0;
}