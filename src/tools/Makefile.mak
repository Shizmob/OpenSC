TOPDIR = ..\..

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-tool.exe opensc-explorer.exe pkcs15-tool.exe pkcs15-crypt.exe \
		pkcs11-tool.exe cardos-tool.exe eidenv.exe openpgp-tool.exe iasecc-tool.exe \
		opensc-notify.exe egk-tool.exe goid-tool.exe paccess-tool.exe opensc-asn1.exe \
		pkcs11-register.exe $(PROGRAMS_OPENSSL)

OBJECTS = util.obj versioninfo-tools.res

LIBS = $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\libopensc\opensc.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib \
	   $(TOPDIR)\src\common\libpkcs11.lib \
	   $(TOPDIR)\src\common\libscdl.lib

all: $(TARGETS)

$(TARGETS): $(OBJECTS) $(LIBS)

opensc-notify.exe: opensc-notify-cmdline.obj versioninfo-opensc-notify.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj opensc-notify-cmdline.obj versioninfo-opensc-notify.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1

npa-tool.exe: npa-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj npa-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1

egk-tool.exe: egk-tool-cmdline.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj egk-tool-cmdline.obj $(OBJECTS) $(LIBS) $(ZLIB_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1

goid-tool.exe: goid-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj goid-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1

opensc-asn1.exe: opensc-asn1-cmdline.obj fread_to_eof.obj versioninfo-tools.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj opensc-asn1-cmdline.obj fread_to_eof.obj versioninfo-tools.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1

pkcs11-register.exe: pkcs11-register-cmdline.obj fread_to_eof.obj $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj pkcs11-register-cmdline.obj fread_to_eof.obj versioninfo-tools.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1

pkcs15-tool.exe: pkcs15-tool.obj $(TOPDIR)\src\pkcs11\pkcs11-display.obj
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(TOPDIR)\src\pkcs11\pkcs11-display.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
	mt -manifest exe.manifest -outputresource:$@;1
