@echo off

set csc=@c:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe
cmd /c %csc% /out:aila2-filter.exe *.cs
