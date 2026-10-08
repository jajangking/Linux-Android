# Handoff ronde 5: regresi di Termux setelah shim rootfs-first

## 1. Apa yang berubah sejak ronde 4

- `src/rootshim.c` mencegat `execve` dan `execv` (serta `syscall(SYS_execve, ...)`). Kebijakannya rootfs-first:
  - ELF dinamis di rootfs dijalankan lewat `ld-linux` rootfs (`--library-path`, `--argv0`).
  - Shebang dijalankan ulang lewat interpreter-nya (rekursi maksimal 4).
  - Skrip host di luar rootfs dijalankan oleh shell rootfs, dengan file diberikan sebagai `/proc/self/fd/N`.
  - ELF host di luar rootfs diteruskan ke kernel apa adanya.
- `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid` (beserta versi `_r`), serta enumerasi `setpwent`/`getpwent`/`endpwent` dan padanan `gr`, kini membaca `etc/passwd` dan `etc/group` dari rootfs. Tanpa `ROOTSHIM_ROOT`, semuanya meneruskan ke implementasi berikutnya.
- Constructor shim: program yang dijalankan kernel dari path rootfs tetapi memakai libc host dijalankan ulang **sekali** lewat loader rootfs. Penanda `ROOTSHIM_REEXEC` mencegah loop. Tanpa `ROOTSHIM_ROOT`, jalur ini tidak aktif.
- `make all` bersih dari warning.
- `tests/test-debian-rootfs.sh` di x86: 31 cek PASS, **0 KNOWN-LIMIT**.

Catatan untuk Termux: kode ini belum pernah dikompilasi dengan Bionic. Yang perlu dicek adalah apakah `src/rootshim.c` tetap bersih dengan clang dan `__ANDROID_API__=24`. Perhatikan `<grp.h>`, `<pwd.h>`, `getline`, `SYS_fcntl`, `SYS_pread64`, `SYS_readlinkat`, dan `SYS_openat`.

## 2. Langkah

Jalankan dari checkout repo di `arena/a4c2b8db-linux-android`, commit `HEAD` yang sudah ada:

```
git rev-parse --short HEAD
make -B all 2>&1 | tee build/make-all.log; echo "rc=$?"
grep -c warning build/make-all.log
make -B test 2>&1 | tee build/make-test.log; echo "rc=$?"
sh tools/termux-check.sh
```

Gunakan `make -B` (bukan `make clean`) karena `tools/termux-check.sh` memakai `build/`.

## 3. Yang harus dicek

- `make all`: rc=0 dan 0 warning di `build/make-all.log`. Jika ada error karena Bionic, salin baris error persis.
- `make test`: rc=0, `summary failures=0`.
- Suite Debian: harus `SKIP` (tidak ada glibc/dpkg). Salin baris SKIP persis.
- `termux-check`: harus tetap PASS=6 FAIL=0 SKIP=0 ERROR=0, exit 0 seperti ronde 3. Jika ada FAIL pada hardlink, catat sebagai FAIL dengan bukti dan jangan mengubah klasifikasinya sendiri (lihat batasan).
- Opsional, tanpa izin khusus: `printf 'echo ok\n' > $PREFIX/tmp/t.sh; chmod 755 $PREFIX/tmp/t.sh; sh -c '$PREFIX/tmp/t.sh'` harus mencetak `ok`. Ini memastikan exec biasa tidak rusak dengan shim terpasang.
- Opsional: `id -u` dan `id -un` harus tetap berjalan tanpa error dengan shim terpasang (jalur NSS passthrough).

## 4. Format laporan balik

```
Handoff round 5 — Termux regresi shim rootfs-first
Commit: <git rev-parse --short HEAD>
Perangkat/Android: <uname -a; TERMUX_VERSION; __ANDROID_API__>
Arsitektur: <uname -m>
Compiler: <clang --version | head -1>

make all: <PASS/FAIL; jumlah warning>
make test: <rc; summary failures=…>
suite debian rootfs: <baris SKIP/ok/FAIL persis>
Ringkasan termux-check: PASS=<n> FAIL=<n> SKIP=<n> ERROR=<n>; exit=<n>
note SKIP di termux-check: <ada/tidak; isi>
opsional exec biasa: <ok / tidak dijalankan>
opsional NSS passthrough: <ok / tidak dijalankan>

Hal di luar dugaan:
<tulis apa adanya>

Lampiran: build/termux-report.txt, build/make-all.log, build/make-test.log
```

## 5. Batasan yang harus dipahami

- Suite Debian hanya berjalan di host glibc. Di Termux, `SKIP` adalah hasil yang benar.
- Batas yang tersisa (README, "Hasil uji rootfs Debian"): ELF host di luar rootfs tetap melihat file lewat pemetaan rootfs; `execvp`, `posix_spawn`, dan inline asm belum dicegat; `getgrouplist`, `initgroups`, dan `getspnam` belum diinterposisi.
- Kebijakan hardlink (hasil Android yang tidak bisa diperbaiki dicatat sebagai `SKIP` dengan bukti, bukan `FAIL`) **belum dikonfirmasi user**. Sampai dikonfirmasi, jangan mengubah klasifikasi tes hardlink. Laporkan apa adanya.
- Jangan mengedit `src/`, `tests/`, `tools/`, `docs/`, atau `README.md`. Jangan `commit`, `push`, atau membuat branch. Jangan jalankan `su`, `sudo`, atau `unshare --map-root-user`.
