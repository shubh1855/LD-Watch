#define _DEFAULT_SOURCE
#include <dlfcn.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    usleep(1500000);
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    int (*marker)(int) = (int (*)(int))dlsym(handle, "ldwatch_lifecycle_marker");
    int result = !marker || marker(1) != 2;
    if (dlclose(handle) != 0)
        return 4;
    return result ? 5 : 0;
}
