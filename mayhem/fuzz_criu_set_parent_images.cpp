#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int criu_init_opts(void);
extern "C" void criu_free_opts(void);
extern "C" int criu_set_parent_images(const char *path);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    criu_init_opts();
    criu_set_parent_images(str.c_str());
    criu_free_opts();

    return 0;
}
