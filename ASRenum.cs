using System;
using System.Linq;
using System.Management;
using System.Collections.Generic;

public class Connect
{
    public static void Main() 
    {
        string[] guidRule= {
        "Block abuse of exploited vulnerable signed drivers",
        "Block Adobe Reader from creating child processes",  
        "Block all Office applications from creating child processes",
        "Block credential stealing from the Windows local security authority subsystem (lsass.exe)", 
        "Block executable content from email client and webmail",
        "Block executable files from running unless they meet a prevalence, age, or trusted list criterion", 
        "Block execution of potentially obfuscated scripts",
        "Block JavaScript or VBScript from launching downloaded executable content",
        "Block Office applications from creating executable content",
        "Block Office applications from injecting code into other processes",
        "Block Office communication application from creating child processes", 
        "Block persistence through WMI event subscription", 
        "Block process creations originating from PSExec and WMI commands",
        "Block untrusted and unsigned processes that run from USB",
        "Block Win32 API calls from Office macros", 
        "Use advanced protection against ransomware"
        };

        string[] guidID = {
        "56a863a9-875e-4185-98a7-b882c64b5ce5",
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
        "01443614-cd74-433a-b99e-2ecdc07bfc25",
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
        "d3e037e1-3eb8-44c8-a917-57927947596d",
        "3b576869-a4ec-4529-8536-b80a7769e899",
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
        "26190899-1602-49e8-8b27-eb1d0a1ce869",
        "e6db77e5-3df2-4cf1-b95a-636979351e5b",
        "d1e49aac-8f56-4280-b9ba-993a6d77406c",
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
        "c1db55ab-c21a-4637-bb3f-a12568109d35"
        };

        ConnectionOptions options = new ConnectionOptions();
        options.Impersonation = System.Management.ImpersonationLevel.Impersonate;
        
        ManagementScope scope = new ManagementScope("\\\\localhost\\ROOT\\Microsoft\\Windows\\Defender", options);
        scope.Connect();
        
        Console.WriteLine("[*] Connected to ROOT\\Microsoft\\Windows\\Defender\n");
        
        ObjectQuery query = new ObjectQuery("Select * from MSFT_MpPreference");
        ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope,query);
        ManagementObjectCollection queryCollection = searcher.Get();
        
        string[] rules = { };
        List<string> listRules = new List<string>(rules.ToList());
        
        string[] actions = { };
        List<string> listActions = new List<string>(actions.ToList());
        
        foreach (ManagementObject mo in queryCollection)
        {
            if (mo["AttackSurfaceReductionRules_Ids"] == null)
                Console.WriteLine("[*] ASR Rules: \n{0}", mo["AttackSurfaceReductionRules_Ids"]);
            else
            {
                string[] arrRule = (string[])(mo["AttackSurfaceReductionRules_Ids"]);
                foreach (string arrValue in arrRule)
                {
                    for (int i=0; i < 16; i++){
                        if (String.Equals(guidID[i], arrValue)){
                            listRules.Add(guidRule[i]);
                            break;
                        }
                    }
                    
                }
            }
        }
        
        foreach ( ManagementObject mo in queryCollection)
        {
            if (mo["AttackSurfaceReductionRules_Actions"] == null)
                Console.WriteLine("\n[*] ASR Actions: \n{0}", mo["AttackSurfaceReductionRules_Actions"]);
            else
            {
                byte[] arrAction = (byte[])(mo["AttackSurfaceReductionRules_Actions"]);
                foreach (byte arrValue in arrAction)
                {
                    if (arrValue == 1) {
                        listActions.Add(" BLOCK    ");
                    } else if (arrValue == 2) {
                        listActions.Add(" AUDIT    ");
                    } else if (arrValue == 6) {
                        listActions.Add(" WARN     ");
                    } else if (arrValue == 0) {
                        listActions.Add(" DISABLED ");
                    }
                }
            }
        }
        
        rules = listRules.ToArray();
        actions = listActions.ToArray();
        
        Console.WriteLine("[*] ASR Rules: ");
        Console.WriteLine("    ==============================================================================================================");
        Console.WriteLine("   | Action  |  Rule\t\t\t\t\t\t\t\t\t\t\t\t  |");
        Console.WriteLine("    ==============================================================================================================");

        for (int i=0; i<rules.Length; i++) {
            Console.WriteLine("    {0}  {1}", actions[i], rules[i]);
        }

        foreach ( ManagementObject mo in queryCollection)
        {
            if (mo["AttackSurfaceReductionOnlyExclusions"] == null)
                Console.WriteLine("\n[*] ASR Exclusions: \n{0}", mo["AttackSurfaceReductionOnlyExclusions"]);
            else
            {
                Console.WriteLine("\n[*] ASR Exclusions: ");
                string[] arrExclusionPath = (string[])(mo["AttackSurfaceReductionOnlyExclusions"]);
                foreach (string arrValue in arrExclusionPath)
                {
                    Console.WriteLine("    {0}", arrValue);
                }
            }
        }
    }
}
