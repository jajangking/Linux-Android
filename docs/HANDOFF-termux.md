# Handoff ronde 5: regresi di Termux setelah shim execve (B2)

## 1. Apa yang berubah sejak ronde 4

- `src/rootshim.c` kini mencegat `execve` dan `execv` (serta `syscall(SYS_execve, ...)`). Kebijakannya rootfs-first dengan fallback host:
  - ELF dinamis di rootfs dijalankan lewat `ld-linux` rootfs (`--library-path`, `--argv0`).
  - Shebang dijalankan ulang lewat interpreter-nya (rekursi maksimal 4).
  - Path yang tidak ada di rootfs diteruskan ke exec host apa adanya.
  - Jika `ROOTSHIM_ROOT` tidak di-set, jalur baru tidak aktif (passthrough). Di Termux tanpa rootfs, perilaku exec seharusnya sama seperti sebelumnya.
- `make all` bersih dari warning (`-Wformat-truncation` sudah diperbaiki).
- `tests/test-debian-rootfs.sh`: 26 cek PASS, 3 KNOWN-LIMIT di x86. Dua cek execve (shebang rootfs, `id -u` lewat `execve`) dan cek libc rootfs untuk program yang di-exec sekarang PASS.
- Batas yang terukur dan tetap: exec ke path host-only diteruskan, tetapi file yang dibuka program itu tetap dipetakan ke rootfs (KNOWN-LIMIT).

Catatan untuk Termux: ini perubahan pada kode yang belum pernah dikompilasi dengan Bionic. Yang perlu dicek adalah apakah `src/rootshim.c` tetap bersih dengan clang dan `__ANDROID_API__=24`. Perhatikan `<elf.h>`, `SYS_pread64`, `SYS_readlinkat`, dan `SYS_openat`.

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
- Opsional, jika tersedia dan tidak butuh izin khusus: `printf 'echo ok\n' > $PREFIX/tmp/t.sh; chmod 755 $PREFIX/tmp/t.sh; sh -c '$PREFIX/tmp/t.sh'` harus mencetak `ok`. Ini memastikan exec biasa tidak rusak dengan shim terpasang.

## 4. Format laporan balik

```
Handoff round 5 — Termux regresi execve B2
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

Hal di luar dugaan:
<tulis apa adanya>

Lampiran: build/termux-report.txt, build/make-all.log, build/make-test.log
```

## 5. Batasan yang harus dipahami

- Suite Debian hanya berjalan di host glibc. Di Termux, `SKIP` adalah hasil yang benar.
- Di host x86, suite ini masih punya 3 `KNOWN-LIMIT` (belum nol): NSS membaca `/etc/passwd` host, binary yang dimuat kernel memakai libc host, dan exec host-only yang membaca file lewat `open()`. Ketiganya bukan `FAIL`. Target nol KNOWN-LIMIT belum tercapai dan belum dikerjakan di sisi Termux.
- Kebijakan hardlink (hasil Android yang tidak bisa diperbaiki dicatat sebagai `SKIP` dengan bukti, bukan `FAIL`) **belum dikonfirmasi user**. Sampai dikonfirmasi, jangan mengubah klasifikasi tes hardlink. Laporkan apa adanya.
- Jangan mengedit `src/`, `tests/`, `tools/`, `docs/`, atau `README.md`. Jangan `commit`, `push`, atau membuat branch. Jangan jalankan `su`, `sudo`, atau `unshare --map-root-user`.
