#include <Windows.h>

#include "minhook/include/MinHook.h"

#if defined(_M_X64) || defined(__x86_64__)
    #include "minhook/src/hde/hde64.h"
    typedef hde64s HDE;
    #define HDE_DISASM(code, hs) hde64_disasm(code, hs)
#else
    #include "minhook/src/hde/hde32.h"
    typedef hde32s HDE;
    #define HDE_DISASM(code, hs) hde32_disasm(code, hs)
#endif

#include <map>
#include <string>
#include <iostream>
#include <memory>
#include <vector>

using namespace std;



struct FuncDescriptor
{
    FuncDescriptor(const char* _name, int acount) : name(_name), argCount(acount) 
    {}
    const char* name = nullptr;
    int argCount = 0;
    void* trampoline = nullptr;
};


typedef uintptr_t (WINAPI * FuncPtr0)();
typedef uintptr_t (WINAPI * FuncPtr1)(uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr2)(uintptr_t, uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr3)(uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr4)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr5)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr6)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr7)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr8)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef uintptr_t (WINAPI * FuncPtr9)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);


uintptr_t callOriginal(FuncDescriptor* d, uintptr_t args[])
{
    void* t = d->trampoline;
    switch(d->argCount)
    {
    case 0: return ((FuncPtr0)t)();
    case 1: return ((FuncPtr1)t)(args[0]);
    case 2: return ((FuncPtr2)t)(args[0], args[1]);
    case 3: return ((FuncPtr3)t)(args[0], args[1], args[2]);
    case 4: return ((FuncPtr4)t)(args[0], args[1], args[2], args[3]);
    case 5: return ((FuncPtr5)t)(args[0], args[1], args[2], args[3], args[4]);
    case 6: return ((FuncPtr6)t)(args[0], args[1], args[2], args[3], args[4], args[5]);
    case 7: return ((FuncPtr7)t)(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
    case 8: return ((FuncPtr8)t)(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
    case 9: return ((FuncPtr9)t)(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]);
    };
    return 0;
}


uintptr_t generic_hook(FuncDescriptor* d, uintptr_t args[])
{
    cout << d->name << endl;
    return callOriginal(d, args);
};



#define MAX_ARGS 10
#define DESCRIPTOR_PLACEHOLDER 0x42434445

uintptr_t WINAPI hook_entry4(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    FuncDescriptor* d = (FuncDescriptor*)DESCRIPTOR_PLACEHOLDER;
    uintptr_t args[4] = {a1,a2,a3,a4};
    return generic_hook(d, args);
}

LPVOID g_entryFuncs[10] = { nullptr, nullptr, nullptr, nullptr, hook_entry4, nullptr, nullptr, nullptr, nullptr, nullptr };



class WinHooks
{
private:
    // key is "module.dll!FuncName" where module is lower case
    map<string, unique_ptr<FuncDescriptor>> m_knownFuncs;
    
    struct EntryFunc {
        LPVOID start;
        int sz ;
        int placeHolderAt;
        int relCalls[5];
        int relCallsCount;
    };

    EntryFunc m_entryFuncs[MAX_ARGS]; // hook entry funcs indexed by the number of arguments

    // char* since we do arithmatics using byte size
    char *m_writePos = nullptr, *m_allocEnd = nullptr;
    vector<char*> m_allocs; 

public:
    bool init();
    bool createHook(const char* moduleName, const char* funcName);
};


#define PAGE_SIZE 4096

bool WinHooks::init()
{
    m_knownFuncs["user32.dll!MessageBoxW"].reset( new FuncDescriptor("MessageBoxW", 4) );

    // initialize the entries 
    LPVOID lastPage = nullptr;
    for(int i = 0; i < MAX_ARGS; ++i)
    {
        char* ip = (char*)g_entryFuncs[i];
        if (ip == nullptr)
            continue;
        auto& entry = m_entryFuncs[i];
        memset(&entry, 0, sizeof(entry));
        entry.start = ip;

        int sz = 0;
        // read the function untill getting to ret to find its size
        while(true) 
        {
            LPVOID thisPage = (LPVOID)((uintptr_t)ip & ~(PAGE_SIZE-1));
            if (thisPage != lastPage) {
                DWORD prev = 0;
                VirtualProtect(thisPage, PAGE_SIZE, PAGE_EXECUTE_READ, &prev);
                lastPage = thisPage;
            }

            HDE hde;
            HDE_DISASM(ip, &hde);
            if (sz == 0 && hde.opcode == 0xe9) { // function pointer points to a jmp, go there. happens in VS in debug
                ip = ip + hde.imm.imm32 + 5; // 5 skip this opcode
                entry.start = ip; // set it to the real pointer where the function is
                continue;
            }
            if (hde.opcode == 0xe8) {
                entry.relCalls[entry.relCallsCount++] = sz+1;
            }

            sz += hde.len;
            ip += hde.len;

            if (hde.opcode == 0xc2 || hde.opcode == 0xc3)
                break;

            if (sz > 1000)
                return false; // didn't find
        }
        entry.sz = sz;

        if (entry.relCallsCount == 0)
            return false;
        
        // search for the descriptor pointer place-holder

        ip = (char*)m_entryFuncs[i].start;
        char* endp = ip + sz - sizeof(uintptr_t);
        for (;ip < endp; ++ip) {
            uintptr_t *uip = (uintptr_t*)ip;
            if ( *uip == DESCRIPTOR_PLACEHOLDER) {
                entry.placeHolderAt = ip - (char*)entry.start;
                break;
            }
        }
        if (ip == endp)
            return false;
    }

    if (MH_Initialize() != MH_OK)
        return false;

    return true;
}

bool WinHooks::createHook(const char* moduleName, const char* funcName)
{
    string name = string(moduleName) + "!" + funcName;
    auto it = m_knownFuncs.find(name);
    if (it == m_knownFuncs.end())
        return false;
    auto* descriptor = it->second.get();

    auto& entry = m_entryFuncs[descriptor->argCount];

    if (m_writePos == nullptr || m_writePos + entry.sz) { 
        m_writePos = (char*)VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (m_writePos == NULL)
            return false;
        m_allocEnd = m_writePos + PAGE_SIZE;
        m_allocs.push_back(m_writePos);
    }

    char* newFuncAt = m_writePos;
    m_writePos += entry.sz;

    memcpy(newFuncAt, entry.start, entry.sz);
    // place the descriptor in the function
    *(LPVOID*)(newFuncAt + entry.placeHolderAt) = descriptor;
    // fix the relative calls
    for(int i = 0; i < entry.relCallsCount; ++i) {
        intptr_t* at = (intptr_t*)(newFuncAt + entry.relCalls[i]);
        *at = (char*)entry.start + *at - (char*)newFuncAt;
    }


    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL)
        return false;

    LPVOID pTarget = (LPVOID)GetProcAddress(hModule, funcName);
    if (pTarget == NULL)
        return false;


    if (MH_CreateHook(pTarget, newFuncAt, &descriptor->trampoline) != MH_OK)
        return false;

    if (MH_EnableHook(pTarget) != MH_OK)
        return false;

    return true;

}


int main(int argc, char* argv[])
{
    uintptr_t fp = (uintptr_t)hook_entry4;

    WinHooks whook;
    whook.init();

    whook.createHook("user32.dll", "MessageBoxW");

    MessageBoxW(NULL, L"Message...", L"MinHook Sample", MB_OK);


    return 0;
}



typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);

// Pointer for calling original MessageBoxW.
MESSAGEBOXW fpMessageBoxW = NULL;

// Detour function which overrides MessageBoxW.
int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}

int xmain()
{
    // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
        return 1;

    // Create a hook for MessageBoxW, in disabled state.
    if (MH_CreateHook(&MessageBoxW, &DetourMessageBoxW, (void**)(&fpMessageBoxW)) != MH_OK)
        return 1;

    // Enable the hook for MessageBoxW.
    if (MH_EnableHook(&MessageBoxW) != MH_OK)
        return 1;

    // Expected to tell "Hooked!".
    MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);


    return 0;
}