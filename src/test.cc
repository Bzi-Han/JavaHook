#include "JavaHook.h"

#include <iostream>

int main()
{
    auto &runtime = android::Runtime::Instance();

    std::cout << "codename:" << runtime.codename << std::endl
              << "release:" << runtime.release << std::endl
              << "sdk:" << runtime.sdk << std::endl;

    return 0;
}