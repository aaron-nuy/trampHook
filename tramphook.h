#pragma once
#include <windows.h>






#ifndef _WIN64
BYTE* TrampHook32(BYTE* patchAddress, BYTE* funToHook, SIZE_T len) {
    DWORD tmp = 0;
    BYTE* gatewayAdr = nullptr;

    constexpr UINT_PTR jmpOpSize = 5;

    if (len < jmpOpSize)
        return nullptr;

    // Set up gateway
    gatewayAdr = (BYTE*)VirtualAlloc(nullptr, len + jmpOpSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!gatewayAdr) 
        return nullptr;

    memset(gatewayAdr, 0x90, 0x100); // Arbitrary number
    memcpy(gatewayAdr, patchAddress, len);

    INT_PTR relativeAddress = patchAddress - gatewayAdr - jmpOpSize;
    *(char*)(gatewayAdr + len) = 0xE9;
    *(INT_PTR*)(gatewayAdr + len + 1) = relativeAddress;



	// Set up hook



	DWORD oProt;
    if (!VirtualProtect(patchAddress, len, PAGE_EXECUTE_READWRITE, &oProt)) {
        VirtualFree(gatewayAdr, len + jmpOpSize, MEM_RELEASE);
        return nullptr;
    }


	relativeAddress = funToHook - patchAddress - jmpOpSize;
	*patchAddress = 0xE9;
	*(INT_PTR*)(patchAddress + 1) = relativeAddress;

	if (!VirtualProtect(patchAddress, len, oProt, &tmp)) {
        VirtualFree(gatewayAdr, len + jmpOpSize, MEM_RELEASE);
        return nullptr;
    }

	return gatewayAdr;
}
#else
BYTE* TrampHook64(BYTE* patchAddress, BYTE* funToHook, SIZE_T len) {
    DWORD tmp = 0;
    BYTE* gatewayAdr = nullptr;

    constexpr UINT_PTR jmpOpSize = 14;

    if (len < jmpOpSize)
        return nullptr;

    // Set up gateway
    gatewayAdr = (BYTE*)VirtualAlloc(nullptr, len + jmpOpSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!gatewayAdr)
        return nullptr;

    memset(gatewayAdr, 0x90, 0x100); // Arbitrary number
    memcpy(gatewayAdr, patchAddress, len);

    UINT64 relativeAddress = (UINT64)patchAddress + len;
    *(UINT64*)(gatewayAdr + len) = 0x25FF; // jmp is FF 25 and 0 offset from rip, converted to little endian
    *(INT_PTR*)(gatewayAdr + len + 6) = relativeAddress;



    // Set up hook

        /*
            Better to change the hook to
            pusha
            call myFunc
            popa
            jmp gateway
        */

    DWORD oProt;
    if (!VirtualProtect(patchAddress, len, PAGE_EXECUTE_READWRITE, &oProt)) {
        VirtualFree(gatewayAdr, len + jmpOpSize, MEM_RELEASE);
        return nullptr;
    }


    relativeAddress = (INT_PTR)funToHook;
    *(UINT64*)patchAddress = 0x25FF;
    *(INT_PTR*)(patchAddress + 6) = relativeAddress;


    
    for (UINT64 i = jmpOpSize; i < len; i++)
        *(patchAddress + i) = 0x90;


    if (!VirtualProtect(patchAddress, len, oProt, &tmp)) {
        VirtualFree(gatewayAdr, len + jmpOpSize, MEM_RELEASE);
        return nullptr;
    }

    return gatewayAdr;
}
#endif

