#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include "beacon.h"
#include "win32.h"
#define WQL                     L"WQL"
#define WQLNAMESPACE            L"ROOT\\Microsoft\\Windows\\Defender"
#define DEFENDER_WQL            L"Select * from MSFT_MpPreference"

static unsigned short int step  = 1;

extern "C" void dumpFormatAllocation(formatp* formatAllocationData)
{
    char*   outputString = NULL;
    int     sizeOfObject = 0;

    outputString = BeaconFormatToString(formatAllocationData, &sizeOfObject);
    BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    BeaconFormatFree(formatAllocationData);

    return;
}

extern "C" void go(char* argc, int len) {

    formatp fpObject;
    formatp fpExclusionObject; // leave 
    BeaconFormatAlloc(&fpObject, 64 * 1024);
    
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

    HRESULT hres;

    // Initialize COM
    hres = OLE32$CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to initialize COM library. Error code = %#x\n", hres);
        return;
    }

    // Initialize COM process security
    hres = OLE32$CoInitializeSecurity(
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
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to initialize security. Error code = %#x\n", hres);
        OLE32$CoUninitialize();
        return;
    }

    // Obtain the initial locator to WMI
    IWbemLocator* pLoc = NULL;
    hres = OLE32$CoCreateInstance(g_CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, g_IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to create IWbemLocator object. Err code = %#x\n", hres);
        OLE32$CoUninitialize();
        return;
    }

    // Connect to the local root\cimv2 namespace through the IWbemLocator::ConnectServer method and obtain pointer pSvc to make IWbemServices calls.
    IWbemServices* pSvc = NULL;

    BSTR bstrDefenderRootWMI = OLEAUT32$SysAllocString(WQLNAMESPACE);

    hres = pLoc->ConnectServer(
        bstrDefenderRootWMI,
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Could not connect. Error code = %#x\n", hres);
        pLoc->Release();
        OLE32$CoUninitialize();
        OLEAUT32$SysFreeString(bstrDefenderRootWMI);
        return;
    }

    BeaconFormatPrintf(&fpObject,"[*] Connected to ROOT\\Microsoft\\Windows\\Defender\n");

    // Set security levels on the proxy so the WMI service can impersonate the client
    hres = OLE32$CoSetProxyBlanket(
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
        BeaconPrintf(CALLBACK_ERROR,"[!] Could not set proxy blanket. Error code = %#x\n", hres);
        pSvc->Release();
        pLoc->Release();
        OLE32$CoUninitialize();
        OLEAUT32$SysFreeString(bstrDefenderRootWMI);
        return;
    }

   // Use the IWbemServices pointer to make requests of WMI

    IEnumWbemClassObject* pEnumerator = NULL;

    BSTR bstrWQL = OLEAUT32$SysAllocString(WQL);
    if (bstrWQL == NULL)
    {
        // Free allocated strings
        OLEAUT32$SysFreeString(bstrDefenderRootWMI);

        // Release used memory
        if (pSvc != NULL)
        {
            pSvc->Release();
        }
        if (pLoc != NULL)
        {
            pLoc->Release();
        }
        // Uninitialize OLE environment
        OLE32$CoUninitialize();
    }
    else
    {
        step++;
    }

    BSTR bstrQuery = OLEAUT32$SysAllocString(DEFENDER_WQL);
    if (bstrQuery == NULL)
    {
        // Free allocated strings
        OLEAUT32$SysFreeString(bstrWQL);
        OLEAUT32$SysFreeString(bstrDefenderRootWMI);

        // Release used memory
        if (pSvc != NULL)
        {
            pSvc->Release();
        }
        if (pLoc != NULL)
        {
            pLoc->Release();
        }
        
        OLE32$CoUninitialize();
    }
    else
    {
        step++;
    }

    hres = pSvc->ExecQuery(
        bstrWQL,
        bstrQuery,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        BeaconPrintf(CALLBACK_ERROR,"[-] Query for MpPrefence failed with = 0x%#x\n", hres);
        pSvc->Release();
        pLoc->Release();

        if (pEnumerator != NULL)
        {
            pEnumerator->Release();
        }
        if (pSvc != NULL)
        {
            pSvc->Release();
        }
        if (pLoc != NULL)
        {
            pLoc->Release();
        }
        // Destroy our COM
        OLE32$CoUninitialize();

        // Ensure we free our binary "strings"
        OLEAUT32$SysFreeString(bstrQuery);
        step++;

        OLEAUT32$SysFreeString(bstrWQL);
        step++;

        OLEAUT32$SysFreeString(bstrDefenderRootWMI);
        step++;
        return;               
    } else {
        step++;
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
        BeaconFormatPrintf(&fpObject,"[*] ASR Rules:\n");
        BeaconFormatPrintf(&fpObject,"    ==============================================================================================================\n");
        BeaconFormatPrintf(&fpObject,"   | Action   |  Rule\t\t\t\t\t\t\t\t\t\t      |\n");
        BeaconFormatPrintf(&fpObject,"    ==============================================================================================================\n");
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

                    hres = OLEAUT32$SafeArrayGetLBound(pSafeArray, 1, &lower);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }

                    OLEAUT32$SafeArrayGetUBound(pSafeArray, 1, &upper);
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
                        hres = OLEAUT32$SafeArrayGetElement(pSafeArray, &i, &Element);

                        if (FAILED(hres))
                        {
                            break;
                        }
                        else
                        {
                            ++ulIndex;
                            unsigned int j;
                            
                            for(j = 0; j < 16; ++j) {
                                if (MSVCRT$wcscmp(guidID[j], Element) == 0) {
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
        OLEAUT32$VariantClear(&vtProp);

        hr = pclsObj->Get(L"AttackSurfaceReductionRules_Actions", 0, &vtProp, 0, 0);
        step++;

        if (!FAILED(hr))
        {
            if (!((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY)))
            {
                if ((vtProp.vt & VT_ARRAY))
                {
                    long lower, upper;
                    int Element;

                    SAFEARRAY* pSafeArray = vtProp.parray;

                    step++;

                    hres = OLEAUT32$SafeArrayGetLBound(pSafeArray, 1, &lower);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }

                    OLEAUT32$SafeArrayGetUBound(pSafeArray, 1, &upper);
                    
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
                        hres = OLEAUT32$SafeArrayGetElement(pSafeArray, &i, &Element);

                        if (FAILED(hres))
                        {
                            break;
                        }
                        else
                        {
                            ++ulIndex;

                            for (int j = 0; j < 16; j++){
                                if (orderNumber[j] != NULL) {
                                    if ((Element) == 1){
                                        BeaconFormatPrintf(&fpObject,"     BLOCK    |  %S\n", rules[orderNumber[i]]);
                                        break;
                                    }
                                    if ((Element) == 2){
                                        BeaconFormatPrintf(&fpObject,"     AUDIT    |  %S\n", rules[orderNumber[i]]);
                                        break;
                                    }
                                    if ((Element) == 6){
                                        BeaconFormatPrintf(&fpObject,"     WARN     |  %S\n", rules[orderNumber[i]]);
                                        break;
                                    }
                                    if ((Element) == 0){
                                        BeaconFormatPrintf(&fpObject,"     DISABLED |  %S\n", rules[orderNumber[i]]);
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
        OLEAUT32$VariantClear(&vtProp);

        hr = pclsObj->Get(L"AttackSurfaceReductionOnlyExclusions", 0, &vtProp, 0, 0);
        BeaconFormatPrintf(&fpObject,"\n[*] ASR Exclusions:\n");
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

                    hres = OLEAUT32$SafeArrayGetLBound(pSafeArray, 1, &lower);
                    if (FAILED(hres))
                    {
                        // Cleanup regimen
                    }
                    else
                    {
                        step++;
                    }

                    OLEAUT32$SafeArrayGetUBound(pSafeArray, 1, &upper);
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
                        hres = OLEAUT32$SafeArrayGetElement(pSafeArray, &i, &Element);

                        if (FAILED(hres))
                        {
                            break;
                        }
                        else
                        {
                            ++ulIndex;
                            BeaconFormatPrintf(&fpObject,"    %S\n",(wchar_t*)Element);
                        }
                    }
                    pSafeArray = NULL;
                }
            }
        }
        OLEAUT32$VariantClear(&vtProp);
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

    OLE32$CoUninitialize();
    step++;

    OLEAUT32$SysFreeString(bstrQuery);
    step++;

    OLEAUT32$SysFreeString(bstrWQL);
    step++;

    OLEAUT32$SysFreeString(bstrDefenderRootWMI);
    step++;

    dumpFormatAllocation(&fpObject);
    return;
}