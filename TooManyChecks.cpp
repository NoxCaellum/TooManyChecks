/////////////////////////////////////////////////////////////////////////////
/// Author: NoxCaellum
/// Date: 01/18/2026
/// Format: PE x86_64
/// Compilation: cl /EHsc /W3 debugger_detector.cpp bcrypt.lib user32.lib advapi32.lib
///
/// This binary is suspicious of humans. And debuggers.
/// Beat all the anti-analysis tricks to find the flag. Maybe.
/////////////////////////////////////////////////////////////////////////////


#include <windows.h>
#include <winreg.h>
#include <winternl.h>
#include <iostream>
#include <bcrypt.h>
#include <vector>
#include <tlhelp32.h>
#include <string>
#include <mutex>
#include <condition_variable>

#pragma comment(lib, "bcrypt.lib")




bool zldkede(){
    std::string zadz = "XOR rax, rax";
    return true;
}

void lkezszpd(){
    std::string passwd = "LEA rsp, [rip]";
    std::string cmp_d = "POP rip";
    std::string strng_cmp_d = "JMP _rabithole";
    zldkede();
}


void dezdedezzokf(){
    static std::mutex m;
    static std::condition_variable cv;
    std::unique_lock<std::mutex> lock(m);
    cv.wait(lock); 
}


typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);



std::string x75de;

void mlcdskcdazd(){
    lkezszpd();
    ExitProcess(0);
    std::string exit_h = "ADD rsp, 99";
    std::string exiejz = "edezqdzdzzd";
    std::string exit_a = "CALL _exit";

};


std::string tedze;

void zadzedze(){
    std::swap(tedze, x75de);
};



struct lkdqdz {

    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    ULONG result = 0;

    DWORD hash_length = 0;    
    BYTE pe_hash[32] = {0};   

    DWORD hash_length2 = 0;   
    BYTE pe_hash2[32] = {0};   

    DWORD text_section_size = 0;
    BYTE* text_section_base = nullptr;



    bool calcul_hash_of_reference() {
        auto hmodule = GetModuleHandleA(NULL);
        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(hmodule);
        auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hmodule) + dos_header -> e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers); 
        WORD number_of_sections = nt_headers -> FileHeader.NumberOfSections; 

        for (WORD i = 0; i < number_of_sections; i++) {
            if (memcmp(section[i].Name, ".text", 5) == 0) {
                text_section_base = (reinterpret_cast<BYTE*>(hmodule) + section[i].VirtualAddress);
                text_section_size = section[i].Misc.VirtualSize;         
            }
        }

        BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        BCryptGetProperty( hAlgorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(DWORD), &result, 0);
        BCryptHash(hAlgorithm, NULL, 0, text_section_base, text_section_size, pe_hash, hash_length);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);

        return true;
    }



    bool calcul_new_hash(){
        
        auto hmodule = GetModuleHandleA(NULL);
        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(hmodule);
        auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hmodule) + dos_header -> e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers); 
        WORD number_of_sections = nt_headers -> FileHeader.NumberOfSections; 

        for (WORD i = 0; i < number_of_sections; i++) {
            if (memcmp(section[i].Name, ".text", 5) == 0) {
                text_section_base = (reinterpret_cast<BYTE*>(hmodule) + section[i].VirtualAddress);
                text_section_size = section[i].Misc.VirtualSize;         
            }
        }

        BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        BCryptGetProperty( hAlgorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length2), sizeof(DWORD), &result, 0);
        BCryptHash(hAlgorithm, NULL, 0, text_section_base, text_section_size, pe_hash2, hash_length2);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);

        if (memcmp(pe_hash, pe_hash2, 32) == 0) {
            return true;
        }

        else {
            std::cout << "Code modification detected: .text section looks funny. I don't like funny.";
            mlcdskcdazd();
            
            zadzedze();
            lkezszpd();
            return false;
        }
        return true;
    };

    

    bool mlxeokazs(){

        PVOID pRetAddress = _ReturnAddress();                       

        if (*(PBYTE)pRetAddress == 0xCC) {                          
            std::cout << "[!] Debugger behavior detected. Nice step over.\n";
            DWORD dwOldProtect;

            if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect)){
                *(PBYTE)pRetAddress = 0x90;                         
                VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
            }

            mlcdskcdazd();
            zadzedze();
            lkezszpd();
        }

        else {
            return true;
        }
        return true;
    };



    bool mlcdscedsq(){
        CONTEXT ctx;

        ZeroMemory(&ctx, sizeof(CONTEXT));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);

        bool debug_registers_state = ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;

        if (debug_registers_state == true) {
            std::cout << "[!] Hardware Breakpoint detected: Try again. And maybe don't touch the CPU this time.\n";
            mlcdskcdazd();
            lkezszpd();
            zadzedze();
            return false;
        }

        else {
            return true;
        }
        return true;
    }   
};




struct sfmklfr {
    std::vector<std::string> tools_blacklist = {
        "wireshark.exe", "ida.exe", "ghidra.exe", "javaw.exe",
        "binaryninja.exe", "x64dbg.exe", "Ollydbg.exe", "PEiD.exe",
        "CFF Explorer.exe", "PE-bear.exe", "SystemInformer.exe", "procmon.exe", "procmon64.exe"
    };

    std::vector<std::string> regkey_blacklist = {
        "SOFTWARE\\Vmware, Inc.\\Vmware Tools", "SOFTWARE\\Oracle\\", "HARDWARE\\ACPI\\DSDT\\VBOX"
    };

    bool mldzplksq() {

        for (auto regkey = 0; regkey < 3; regkey++) {
            HKEY hKey = NULL;
            auto status = RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                regkey_blacklist[regkey].c_str(),
                0,
                KEY_READ,
                &hKey
            );

            if (status == ERROR_SUCCESS) {
                MessageBoxA(NULL, "Yes, I check the registry. Deal with it.", "[!] Virtual Machine or Sandbox Detected: ", MB_OK);
                std::cout << "[!] Yes, I check the registry. Deal with it.";
                RegCloseKey(hKey);
                mlcdskcdazd();
                lkezszpd();
                zadzedze();
                return false;
            }
        }

        return true;
    }

    bool aqxsqskdz() {

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return true;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            return true;
        }

        do {
            for (const auto& tool : tools_blacklist) {
                if (_stricmp(pe.szExeFile, tool.c_str()) == 0) {
                    std::string msg = "Seriously are you using: " + tool;
                    MessageBoxA(
                        NULL,
                        msg.c_str(),
                        "[!] Debugger / Analysis Tool Detected",
                        MB_OK
                    );
                    CloseHandle(hSnapshot);
                    mlcdskcdazd();
                    lkezszpd();
                    zadzedze();
                    return false;
                }
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);
        return true;
    }
};





struct mlqxsqsd{

    bool switch_desktop(){
        MessageBoxA(NULL, "Oops… the screen ran away.", "[!] Debugger Detected:", MB_OK);
        HDESK hNewDesktop = CreateDesktopA("Are you stuck ?", NULL, NULL, 0, DESKTOP_CREATEWINDOW | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP, NULL);

        if (!hNewDesktop){
            return FALSE;
        }
        
        return SwitchDesktop(hNewDesktop);
    }




    bool wcdsfdez(){

        NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (!NtQueryInformationProcess) {
            std::cout << "No NtQueryInformation APi detected";
            return false;
        }

        PROCESS_BASIC_INFORMATION pbi = {0};
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

        if (status != 0){
            std::cout << "NtqueryInformation call error";
            return false;
        }

        BYTE* peb = (BYTE*)pbi.PebBaseAddress;
        bool BeingDebugged = peb[2];

        if (BeingDebugged){
            std::cout << "Yes i checked the PEB structure. Flag triggered. I’m done. Bye!";
            mlcdskcdazd();
            lkezszpd();
            zadzedze();
        }
        else {
            return true;
        }

        if (IsDebuggerPresent()){
            std::cout << "[!] I feel someone watching me…\n";
            switch_desktop();
            mlcdskcdazd();
            lkezszpd();
            zadzedze();
        }
        else {
            return true;
        
        }


        BOOL debugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger);
    
        if (debugger){
            std::cout << "[!] Remote presence detected. Did you think I wouldn’t notice?\n";
            switch_desktop();
            mlcdskcdazd();
            lkezszpd();
            zadzedze();
        }  

        else {
            return true;
        }


        

        return true;
    };

};



bool dezdzzsqd(){

    __try {
        CloseHandle((HANDLE)0xDEADBEEF);
    }

    __except(EXCEPTION_INVALID_HANDLE == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH){
        return true;
    }
    return true;
};



class cdedseq {

    public:
        std::string jdezd = "ADD rcx, 1";
        std::string ezdz = "ag";
        std::string dede = "MOV rsp, 2";
        std::string dedez = "NOP";
        std::string dezd = "Fdez";
        std::string lkffdv = "MOV rsp, byte ptr[rbp]";
        std::string hade = "(ByP@$$_";
        std::string zdez = "XOR rax, rax";
        std::string dedze = "a_)";
        std::string lea_d = "LEA rsp, [rip]";
        std::string qscze = "B0$$)";
        std::string wjnd = "POP rip";
        std::string api_d = "MOV rax, 1";
        std::string dezadz = "l&ée";
        std::string process_d = "MOV rdi, 0";
        std::string exit_d = "call exit";
        

    private:
        std::string password = "password";
        std::string there_is_no_password = "It's a flag not a password!";
        
};



struct Abde29de {

    lkdqdz          bsqjbs;
    mlqxsqsd        mldeqsdz;
    sfmklfr         mlcds;

    cdedseq mlod;
    std::string pmqxe;

    void wmdes(){
        mlcds.aqxsqskdz();
        mldeqsdz.wcdsfdez();
        dezdzzsqd();
        bsqjbs.mlxeokazs();
        bsqjbs.mlcdscedsq();

        pmqxe.clear();

        for(int i = 0; i < 1; i++){
            pmqxe += mlod.dezd[i];
        }

        mlcds.aqxsqskdz();
        mldeqsdz.wcdsfdez();
        dezdzzsqd();
        bsqjbs.mlxeokazs();
        bsqjbs.mlcdscedsq();

        for(int i = 0; i < 1; i++){
            pmqxe += mlod.dezadz[i];
        }
        mlcds.aqxsqskdz();
        mldeqsdz.wcdsfdez();
        dezdzzsqd();
        bsqjbs.mlxeokazs();
        bsqjbs.mlcdscedsq();

        for(int i = 0; i < 2; i++){
            pmqxe += mlod.ezdz[i];
        }

        mlcds.aqxsqskdz();
        mldeqsdz.wcdsfdez();
        dezdzzsqd();
        bsqjbs.mlxeokazs();
        bsqjbs.mlcdscedsq();

        lkezszpd();
        for(int i = 0; i < 8; i++){
            pmqxe += mlod.hade[i];
        }

        mlcds.aqxsqskdz();
        mldeqsdz.wcdsfdez();
        dezdzzsqd();
        bsqjbs.mlxeokazs();
        bsqjbs.mlcdscedsq();

        for(int i = 0; i < 2; i++){
            pmqxe += mlod.dedze[i];
        
        }
        mlcds.aqxsqskdz();
        mldeqsdz.wcdsfdez();
        dezdzzsqd();
        bsqjbs.mlxeokazs();
        bsqjbs.mlcdscedsq();

        lkezszpd();
        for(int i = 0; i < 5; i++){
            pmqxe += mlod.qscze[i];
        };
    }


    void poeszd(){

        lkezszpd();
        mlcds.aqxsqskdz();
        mldeqsdz.wcdsfdez();
        dezdzzsqd();
        bsqjbs.mlxeokazs();
        bsqjbs.mlcdscedsq();

        if (pmqxe == x75de){
            std::cout << "[-] Congrat you won";
        }
        else {
            std::cout << "[!] Wrong flag";
        }
    }

};



int main() {

    lkdqdz          bsqjbs;
    mlqxsqsd        mldeqsdz;
    sfmklfr         mlcds;
    Abde29de        kcqsd;

    mlcds.mldzplksq();
    mlcds.aqxsqskdz();
    bsqjbs.calcul_hash_of_reference();
    bsqjbs.calcul_new_hash();
    

    std::cout << "[-] Welcome, reverser. This binary does not want to be understood.\n";
    std::cout << "Enter the flag. This is the easy part: ";
    std::getline(std::cin, x75de);

    kcqsd.wmdes();
    kcqsd.poeszd();


    return 0;
}