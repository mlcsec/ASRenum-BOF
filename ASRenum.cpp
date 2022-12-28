#define _WIN32_DCOM
#include <comdef.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

static unsigned short int step  = 1;

int main(int iArgCnt, char** argv) {
    
    wchar_t * guidRule[] = {
    L"Block abuse of exploited vulnerable signed drivers",
    L"Block Adobe Reader from creating child processes",  
    L"Block all Office applications from creating child processes",
    L"Block credential stealing from the Windows local security authority subsystem (lsass.exe)", 
    L"Block executable content from email client and webmail",
    L"Block executable files from running unless they meet a prevalence, age, or trusted list criterion", 
    L"Block execution of potentially obfuscated scripts",
    L"Block JavaScript or VBScript from launching downloaded executable content",
    L"Block Office applications from creating executable content",
    L"Block Office applications from injecting code into other processes",
    L"Block Office communication application from creating child processes", 
    L"Block persistence through WMI event subscription", 
    L"Block process creations originating from PSExec and WMI commands",
    L"Block untrusted and unsigned processes that run from USB",
    L"Block Win32 API calls from Office macros", 
    L"Use advanced protection against ransomware"};

    wchar_t * guidID[] = {
    L"56a863a9-875e-4185-98a7-b882c64b5ce5",
    L"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    L"d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    L"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    L"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    L"01443614-cd74-433a-b99e-2ecdc07bfc25",
    L"5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    L"d3e037e1-3eb8-44c8-a917-57927947596d",
    L"3b576869-a4ec-4529-8536-b80a7769e899",
    L"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    L"26190899-1602-49e8-8b27-eb1d0a1ce869",
    L"e6db77e5-3df2-4cf1-b95a-636979351e5b",
    L"d1e49aac-8f56-4280-b9ba-993a6d77406c",
    L"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    L"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    L"c1db55ab-c21a-4637-bb3f-a12568109d35"};

    wchar_t * rules[16];
    int orderNumber[16] = {NULL};
    int len = sizeof(guidID)/sizeof(guidID[0]);

    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        printf("[!] Failed to initialize COM library. Error code = %#x\n", hres);
        return 1;
    }

    // Initialize COM process security
    hres = CoInitializeSecurity(
        NULL,
        -1, 
        NULL,
        NULL, 
        RPC_C_AUTHN_LEVEL_DEFAULT, 
        RPC_C_IMP_LEVEL_IMPERSONATE, 
        NULL,              
        EOAC_NONE,
        NULL 
    );


    if (FAILED(hres)) {
        printf("[!] Failed to initialize security. Error code = %#x\n", hres);
        CoUninitialize();
        return 1;
    }

    // Obtain the initial locator to WMI
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        printf("[!] Failed to create IWbemLocator object. Err code = %#x\n", hres);
        CoUninitialize();
        return 1;
    }

    // Connect to the local root\cimv2 namespace through the IWbemLocator::ConnectServer method and obtain pointer pSvc to make IWbemServices calls.
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        printf("[!] Could not connect. Error code = %#x\n", hres);
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    printf("[*] Connected to ROOT\\Microsoft\\Windows\\Defender\n");

    // Set security levels on the proxy so the WMI service can impersonate the client
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT, 
        RPC_C_AUTHZ_NONE, 
        NULL, 
        RPC_C_AUTHN_LEVEL_CALL, 
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, 
        EOAC_NONE
    );

    if (FAILED(hres)) {
        printf("[!] Could not set proxy blanket. Error code = %#x\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

   // Use the IWbemServices pointer to make requests of WMI

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("Select * from MSFT_MpPreference"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        printf("[-] Query for MpPrefence failed with = 0x%#x\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               
    }

    // Get the data from the query

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    unsigned long ulIndex = 0;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        hr = pclsObj->Get(L"AttackSurfaceReductionRules_Ids", 0, &vtProp, 0, 0);
        printf("\n[*] ASR Rules: \n");
        printf("    ==============================================================================================================\n");
        printf("   | Action   |  Rule\t\t\t\t\t\t\t\t\t\t\t\t  |\n");
        printf("    ==============================================================================================================\n");
        step++;

        if (!FAILED(hr))
        {
            if (!((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY)))
            {
                if ((vtProp.vt & VT_ARRAY))
                {
                    long lower, upper;
                    BSTR Element;

                    SAFEARRAY* pSafeArray = vtProp.parray;

                    step++;

                    hres = SafeArrayGetLBound(pSafeArray, 1, &lower);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }

                    SafeArrayGetUBound(pSafeArray, 1, &upper);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }
                    
                    for (long i = lower; i <= upper; i++)
                    {
                        hres = SafeArrayGetElement(pSafeArray, &i, &Element);

                        if (FAILED(hres))
                        {
                            break;
                        }
                        else
                        {
                            ++ulIndex;
                            unsigned int j;
                            
                            for(j = 0; j < len; ++j) {
                                if (wcscmp(guidID[j], Element) == 0) {
                                    orderNumber[i] = j;
                                    rules[j] = guidRule[j];
                                }
                            }
                        }
                    }
                    pSafeArray = NULL;
                }
            }
        }
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"AttackSurfaceReductionRules_Actions", 0, &vtProp, 0, 0);
        step++;

        if (!FAILED(hr))
        {
            if (!((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY)))
            {
                if ((vtProp.vt & VT_ARRAY))
                {
                    long lower, upper;
                    BSTR Element;

                    SAFEARRAY* pSafeArray = vtProp.parray;

                    step++;

                    hres = SafeArrayGetLBound(pSafeArray, 1, &lower);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }

                    SafeArrayGetUBound(pSafeArray, 1, &upper);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }
                    
                    for (long i = lower; i <= upper; i++)
                    {
                        hres = SafeArrayGetElement(pSafeArray, &i, &Element);

                        if (FAILED(hres))
                        {
                            break;
                        }
                        else
                        {
                            ++ulIndex;

                            for (int j = 0; j < 16; j++){
                                if (orderNumber[j] != NULL) {
                                    if (int(Element) == 1){
                                        printf("     BLOCK    |  %S\n", rules[orderNumber[i]]);
                                        break;
                                        }
                                    if (int(Element) == 2) {
                                        printf("     AUDIT    |  %S\n", rules[orderNumber[i]]);
                                        break;
                                    }
                                    if(int(Element) == 6) {
                                        printf("     WARN     |  %S\n", rules[orderNumber[i]]);
                                        break;
                                    }
                                    if(int(Element) == 0) {
                                        printf("     DISABLED |  %S\n", rules[orderNumber[i]]);
                                        break;
                                    }     
                                }

                            }
                        }
                    }
                    pSafeArray = NULL;
                }
            }
        }
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"AttackSurfaceReductionOnlyExclusions", 0, &vtProp, 0, 0);
        printf("\n[*] ASR Exclusions: \n");
        step++;

        if (!FAILED(hr))
        {
            if (!((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY)))
            {
                if ((vtProp.vt & VT_ARRAY))
                {
                    long lower, upper;
                    BSTR Element;

                    SAFEARRAY* pSafeArray = vtProp.parray;

                    step++;

                    hres = SafeArrayGetLBound(pSafeArray, 1, &lower);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }

                    SafeArrayGetUBound(pSafeArray, 1, &upper);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }
                    
                    for (long i = lower; i <= upper; i++)
                    {
                        hres = SafeArrayGetElement(pSafeArray, &i, &Element);

                        if (FAILED(hres))
                        {
                            break;
                        }
                        else
                        {
                            ++ulIndex;
                            printf("    %S\n", (wchar_t*)Element);
                        }
                    }
                    pSafeArray = NULL;
                }
            }
        }
        VariantClear(&vtProp);
    }

    if (pEnumerator != NULL)
    {
        pEnumerator->Reset();
        pEnumerator = NULL;
        step++;
    }

    if (pSvc != NULL)
    {
        pSvc->Release();
        step++;
    }

    if (pLoc != NULL)
    {
        pLoc->Release();
        step++;
    }
    CoUninitialize();
    step++;

    return 0;
}
