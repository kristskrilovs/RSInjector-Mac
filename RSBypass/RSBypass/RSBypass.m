#include <sys/mman.h>
#include <mach/mach.h>

#import "RSBypass.h"

typedef uint32_t DWORD;
typedef int8_t  BYTE;


// These numbers come from otool -lv
const DWORD  segStart = 0x001000;
const size_t segLen   = 0x013ce000;

bool bCompare(const BYTE* pData, const BYTE * bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return 0;
    return (*szMask) == 0;
}

void* FindPattern(DWORD dwAddress, size_t dwLen, BYTE* bMask, char* szMask) {
    for (DWORD i = 0; i < dwLen; i++)
        if (bCompare((BYTE*)(dwAddress + i), bMask, szMask))
            return (void*)(dwAddress + i);
    return NULL;
}


@implementation RSBypass
+(void)load
{
    void* ptr;
    long page_size;
    void* page_start;

//    NSLog(@"RSBypass: load()");

    page_size = sysconf(_SC_PAGESIZE);

    ptr = FindPattern(segStart, segLen,
        (BYTE*)"\x84\xdb\x0f\x84\xde\x0a\x00\x00",
        "xxxxxxxx");

    if (ptr) {
        page_start = (long)ptr & -page_size;
        
        // Removing memory protection
        mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
        
//        NSLog(@"RSInjector: Bypassing signature check at %p", ptr);
        memset(ptr, 0x90, 8);
        msync(ptr, 8, MS_SYNC);
        
        // Restoring memory protection
        mprotect(page_start, page_size, PROT_READ | PROT_EXEC);
    }

    ptr = FindPattern(segStart, segLen,
        (BYTE*)"\x81\xff\xf0\x61\x03\x00\x75\x6f",
        "xxxxxxxx");

    if (ptr) {
        page_start = (long)ptr & -page_size;
        
        // Removing memory protection
        mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
        
//        NSLog(@"RSInjector: Bypassing APP_ID check at %p", ptr);
        memset(ptr, 0x90, 8);
        msync(ptr, 8, MS_SYNC);
        
        // Restoring memory protection
        mprotect(page_start, page_size, PROT_READ | PROT_EXEC);
    }
}
@end
