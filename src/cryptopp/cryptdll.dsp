# Microsoft Developer Studio Project File - Name="cryptdll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=cryptdll - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "cryptdll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "cryptdll.mak" CFG="cryptdll - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cryptdll - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "cryptdll - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cryptdll - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "cryptdll___Win32_Release"
# PROP BASE Intermediate_Dir "cryptdll___Win32_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "DLL_Release"
# PROP Intermediate_Dir "DLL_Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CRYPTDLL_EXPORTS" /YX /FD /c
# ADD CPP /nologo /G5 /MT /W3 /GR /GX /Zi /O1 /Ob2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CRYPTOPP_EXPORTS" /D CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2=1 /D "USE_PRECOMPILED_HEADERS" /Yu"pch.h" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 advapi32.lib /nologo /base:"0x42900000" /dll /map /debug /machine:I386 /out:"DLL_Release/cryptopp.dll" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
OutDir=.\DLL_Release
TargetPath=.\DLL_Release\cryptopp.dll
InputPath=.\DLL_Release\cryptopp.dll
SOURCE="$(InputPath)"

"$(OutDir)\cryptopp.mac.done" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	CTRelease\cryptest mac_dll $(TargetPath) 
	echo mac done > $(OutDir)\cryptopp.mac.done 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "cryptdll - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "cryptdll___Win32_Debug"
# PROP BASE In