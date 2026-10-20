Unicode true
!include "MUI2.nsh"
Name "Gulpsuite ${VERSION}"
OutFile "${OUTPUT}"
InstallDir "$LOCALAPPDATA\Programs\Gulpsuite"
RequestExecutionLevel user
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to Gulpsuite ${VERSION} Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will install Gulpsuite and its preconfigured integrated Chromium browser on your computer.$\r$\n$\r$\nNo system-wide proxy settings or personal browser profiles will be modified."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\gulpsuite.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch Gulpsuite now"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Gulpsuite & Integrated Chromium"
  SetOutPath "$INSTDIR"
  File /r "${APPDIR}\*.*"
  CreateDirectory "$SMPROGRAMS\Gulpsuite"
  CreateShortcut "$SMPROGRAMS\Gulpsuite\Gulpsuite.lnk" "$INSTDIR\gulpsuite.exe"
  CreateShortcut "$DESKTOP\Gulpsuite.lnk" "$INSTDIR\gulpsuite.exe"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gulpsuite" "DisplayName" "Gulpsuite"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gulpsuite" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gulpsuite" "Publisher" "Gulpsuite Project"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gulpsuite" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gulpsuite" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
SectionEnd

Section "Uninstall"
  ; This folder contains only installed resources, never browser profiles or projects.
  RMDir /r "$INSTDIR\resources\chromium"
  Delete "$INSTDIR\resources\chromium-manifest.json"
  RMDir "$INSTDIR\resources"
  Delete "$INSTDIR\gulpsuite.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$DESKTOP\Gulpsuite.lnk"
  Delete "$SMPROGRAMS\Gulpsuite\Gulpsuite.lnk"
  RMDir "$SMPROGRAMS\Gulpsuite"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gulpsuite"
SectionEnd
