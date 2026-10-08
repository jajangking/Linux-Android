# Handoff ronde 4: regresi di Termux setelah suite Debian rootfs

Dokumen ini ditujukan untuk AI agent yang berjalan langsung di Termux. Tugasmu: **pull, jalankan regresi, dan kembalikan laporan**. Kamu tidak diminta mengubah kode.

## 1. Apa yang berubah sejak ronde 3

Ronde 3 sudah hijau di Termux (`PASS=6 FAIL=0`, `exit=0`). Perubahan ronde 4:

- `tests/test-debian-rootfs.sh` (baru, masuk ke `make test`): membangun rootfs Debian dari paket host x86 dan menjalankan binary glibc-nya. Di Termux suite ini **harus `SKIP`** karena tidak ada `dpkg`/glibc Debian. Baris yang diharapkan: `debian rootfs: SKIP (host has no dpkg/glibc Debian userland)`.
- `tools/termux-check.sh`: catatan `SKIP` sekarang dipisah per sumber (sudah di-push di `f59b70d`).
- `README.md`: bagian hasil uji rootfs Debian dan daftar batas yang ditemukan.

Tidak ada perubahan di `src/`. Jangan anggap suite Debian sebagai bukti untuk Termux.

## 2. Langkah

```sh
cd ~/Linux-Android
git fetch origin
git checkout arena/a4c2b8db-linux-android
git pull --ff-only origin arena/a4c2b8db-linux-android
git log --oneline -3          # HEAD harus memuat commit ronde 4

mkdir -p build
make -B CC=clang all 2>&1 | tee build/round4-build.log
make CC=clang test 2>&1 | tee build/round4-test.log
sh tools/termux-check.sh
echo "exit=$?"
```

Jangan jalankan `make clean` sebelum langkah di atas. Jika `make test` gagal, ulangi dengan `make -B CC=clang test` agar log tersimpan.

## 3. Yang harus dicek

1. `make test` rc=0 dan `summary failures=0`.
2. Baris `debian rootfs: SKIP (...)` muncul. Jika suite Debian `ok`/`FAIL`, catat sebagai temuan penting.
3. `termux-check`: `PASS=6 FAIL=0 SKIP=0 ERROR=0`, `exit=0`. Tidak ada note `SKIP` yang salah.
4. Warning kompilasi: nol.

## 4. Format laporan balik

```
Handoff round 4 — Termux regresi
Commit: <git rev-parse --short HEAD>
Perangkat/Android: <uname -a; TERMUX_VERSION; __ANDROID_API__>
Arsitektur: <uname -m>

Ringkasan termux-check: PASS=<n> FAIL=<n> SKIP=<n> ERROR=<n>; exit=<n>
make all: <PASS/FAIL; jumlah warning>
make test: <rc; summary failures=…>
suite debian rootfs: <baris SKIP/ok/FAIL persis>
note SKIP di termux-check: <ada/tidak; isi>

Hal di luar dugaan:
<tulis apa adanya>

Lampiran: build/termux-report.txt
```

## 5. Batasan yang harus dipahami

- Suite Debian hanya berjalan di host glibc. Di Termux, `SKIP` adalah hasil yang benar.
- Di host x86, suite ini menemukan batas yang tetap ada (lihat README, "Hasil uji rootfs Debian"): loader/libc host saat binary dijalankan dengan path host, NSS membaca `/etc/passwd` host, dan `execve` path virtual tidak dipetakan. Ketiganya dicatat sebagai `KNOWN-LIMIT`, bukan `FAIL`.
- Jangan mengedit `src/`, `tests/`, `tools/`, `docs/`, atau `README.md`. Jangan `commit`, `push`, atau membuat branch. Jangan jalankan `su`, `sudo`, atau `unshare --map-root-user`.
