#include <stdlib.h>
#include "../osms_API/osms_API.h"

int main(int argc, char const *argv[])
{

    // montar la memoria
    os_mount((char *)argv[1]);
    os_start_process(3, "ventas");
    os_ls_processes();
    fclose(memory_file);
    return 0;
}