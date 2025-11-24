all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/sauroneye.x64.o SauronEyeBOF/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sauroneye.x64.o) && echo '[+] sauroneye' || echo '[!] sauroneye build failed'



clean:
	@(rm -rf _bin)