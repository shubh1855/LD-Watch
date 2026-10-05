#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define ITERATIONS 8

static const char *library_path;

static void *load_and_unload(void *arg)
{
	(void)arg;
    for (int i = 0; i < ITERATIONS; i++)
    {
        void *handle = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
        if (!handle)
            return (void *)1;
        int (*marker)(int) = (int (*)(int))dlsym(handle, "ldwatch_lifecycle_marker");
        if (!marker || marker(i) != i + 1)
        {
            dlclose(handle);
            return (void *)1;
        }
        if (dlclose(handle) != 0)
            return (void *)1;
    }
	return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    library_path = argv[1];
    pthread_t threads[2];
    for (long i = 0; i < 2; i++)
        if (pthread_create(&threads[i], NULL, load_and_unload, (void *)i) != 0)
            return 3;
    for (int i = 0; i < 2; i++)
    {
        void *result = NULL;
        if (pthread_join(threads[i], &result) != 0 || result == (void *)1)
            return 4;
    }
    return 0;
}
