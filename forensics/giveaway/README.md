# Forensics :: Giveaway

*Santa's SOC team is working overtime during December due to Christmas phishing campaigns. A new team of malicious actors is targeting mainly those affected by the holiday spirit. Could you analyse the document and find the command & control server?*

### Challenge Files: [forensics_giveaway.zip](forensics_giveaway.zip)

For this challenge, you are provided with a Word document *christmas_giveaway.docm*. The "m" at the end of the file extension gives away that this will be a VB macro challenge. So we will go straight there in Libre Office on my Kali VM and check the source code.

![macros](img/1.png)

Opening the file, we see an alert that the document contains macros and can go to Tools -> Macros -> Edit Macros to view the code. Scrolling through, you can see there is a lot of noise that doesn't matter, but we're specifically looking for obfuscated strings.

Finally we see this section:

```vba
HPkXUcxLcAoMHOlj = "https://elvesfactory/" & Chr(Asc("H")) & Chr(84) & Chr(Asc("B")) & "" & Chr(123) & "" & Chr(84) & Chr(Asc("h")) & "1" & Chr(125 - 10) & Chr(Asc("_")) & "1s" & Chr(95) & "4"
cxPZSGdIQDAdRVpziKf = "_" & Replace("present", "e", "3") & Chr(85 + 10)
fqtSMHFlkYeyLfs = Replace("everybody", "e", "3")
fqtSMHFlkYeyLfs = Replace(fqtSMHFlkYeyLfs, "o", "0") & "_"
ehPsgfAcWaYrJm = Chr(Asc("w")) & "4" & Chr(110) & "t" & Chr(115) & "_" & Chr(Asc("f")) & "0" & Chr(121 - 7) & Chr(95)
FVpHoEqBKnhPO = Replace("christmas", "i", "1")
FVpHoEqBKnhPO = Replace(FVpHoEqBKnhPO, "a", "4") & Chr(119 + 6)

Open XPFILEDIR For Output As #FileNumber
Print #FileNumber, "strRT = HPkXUcxLcAoMHOlj & cxPZSGdIQDAdRVpziKf & fqtSMHFlkYeyLfs & ehPsgfAcWaYrJm & FVpHoEqBKnhPO"
```

The encoding here is pretty easy to figure out manually just by reading through it and converting character codes, replacing values, etc by hand. This reveals the flag:

```HTB{th1s_1s_4_pr3s3nt_3v3ryb0dy_w4nts_f0r_chr1stm4s}```


