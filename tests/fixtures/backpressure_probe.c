#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>

#define ITERATIONS 512

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    for (int i = 0; i < ITERATIONS; i++)
    {
        void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!handle)
            return 3;
        int (*marker)(int) = (int (*)(int))dlsym(handle, "ldwatch_lifecycle_marker");
        if (!marker || marker(i) != i + 1)
        {
            dlclose(handle);
            return 4;
        }
        if (dlclose(handle) != 0)
            return 5;
    }
    return 0;
}
