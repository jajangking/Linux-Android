# Handoff: verifikasi di Termux (untuk agent lokal)

Dokumen ini ditujukan untuk AI agent yang berjalan langsung di Termux (perangkat Android). Tugasmu: **menjalankan tes dan repro di Termux, lalu mengembalikan laporan**. Kamu **tidak** diminta mengubah kode.

## 1. Konteks singkat

- Repo: `jajangking/Linux-Android` — eksperimen menjalankan sebagian program Linux user-space di Termux tanpa root/PRoot memakai shim `LD_PRELOAD` (`src/rootshim.c`) dan supervisor seccomp (`src/seccomp_supervisor.c`).
- Ini **bukan** sandbox keamanan dan `uid=0` yang tampil hanyalah nilai tiruan. Jangan menafsirkan hasil tes sebagai bukti keamanan.
- Branch kerja: `arena/a4c2b8db-linux-android`.
- Hasil review kode sebelumnya di Linux (x86_64) menemukan dua bug yang ingin kita konfirmasi di Termux (arm64, Bionic):
  1. **chroot()** tiruan: `chroot()` ke file biasa (bukan direktori) mengubah virtual root sebelum error, sehingga pemetaan path rusak setelahnya. Repro: `tests/repro/chroot_file.c`.
  2. **getgroups()** di bawah `rootbox`: `getegid()` mengembalikan `0`, tetapi `getgroups()` mengembalikan jumlah `0` (daftar kosong). Repro: `tests/repro/getgroups.c`.

## 2. Prasyarat di Termux

```sh
pkg update
pkg install -y git clang make
```

Pastikan repo sudah tersedia dan berada di branch yang benar:

```sh
cd ~/Linux-Android            # atau lokasi clone-mu
git fetch origin
git checkout arena/a4c2b8db-linux-android
git pull --ff-only origin arena/a4c2b8db-linux-android
git log --oneline -3          # HEAD harus memuat tools/termux-check.sh dan docs/HANDOFF-termux.md
```

Jika `git` meminta autentikasi, jangan mencari atau menyimpan token sendiri; laporkan ke user bahwa akses git di Termux perlu diatur.

## 3. Langkah utama (satu perintah)

Dari root repo:

```sh
sh tools/termux-check.sh
echo "exit=$?"
```

Skrip ini:
1. Mencatat lingkungan (arsitektur, `PREFIX`, `TERMUX_VERSION`, compiler, status seccomp shell).
2. Build ulang dengan `clang` (fallback `cc`) via `make -B all`.
3. Menjalankan `make test` (tiga smoke test).
4. Mereproduksi bug chroot() dan menandai `KNOWN-BUG` jika masih terjadi.
5. Mereproduksi bug getgroups() di bawah `rootbox`, menandai `SKIP` jika seccomp user-notification tidak tersedia.
6. Menjalankan `tools/probe-termux.sh` (cek `unshare`, seccomp, dan build probe).

Hasil lengkap ditulis ke **`build/termux-report.txt`**. Log tiap langkah ada di `build/termux-*.log`. Direktori `build/` sudah di-ignore Git.

Arti status:

| Status | Arti |
|---|---|
| `PASS` | Perilaku sesuai harapan |
| `FAIL` | Regresi nyata — prioritas tinggi, sertakan log |
| `KNOWN-BUG` | Bug yang sudah diketahui masih terjadi (bukan regresi baru) |
| `SKIP` | Fitur kernel/Android tidak tersedia (mis. seccomp user-notification) |
| `ERROR` | Skrip tidak bisa menjalankan langkah (mis. `clang`/`make` belum terpasang) |

Catatan: `exit` non-zero bila ada `FAIL` atau `ERROR`. `KNOWN-BUG` dan `SKIP` **tidak** menyebabkan exit non-zero.

## 4. Yang harus dilakukan agent lokal

1. Jalankan `sh tools/termux-check.sh` dan biarkan selesai (bisa 1–3 menit).
2. Jika ada `ERROR` karena paket hilang, pasang paket yang diminta (`pkg install -y clang make`), lalu ulangi langkah 1.
3. Jika ada `FAIL`, jalankan ulang `make test` secara verbose dan simpan outputnya:
   ```sh
   make -B CC=clang test 2>&1 | tee build/termux-test-verbose.log
   ```
4. Jika `probe-termux.sh` mencetak `seccomp supervisor: unavailable`, catat itu apa adanya — jangan dianggap bug.
5. Jangan mengedit file di `src/`, `tests/`, atau `tools/`. Jangan `commit`, `push`, atau membuat branch baru. Jangan jalankan `su`, `sudo`, atau `unshare` dengan `--map-root-user` untuk "memaksa" tes.
6. Kembalikan `build/termux-report.txt` (dan log yang relevan) ke user.

## 5. Format laporan balik

Salin bagian ini dan isi. Lampirkan `build/termux-report.txt` lengkap.

```
Handoff result — Termux verification
Commit: <git rev-parse --short HEAD>
Perangkat/Android: <uname -a, TERMUX_VERSION jika ada>
Arsitektur: <uname -m>
Compiler: <clang --version | head -1>

Ringkasan: PASS=<n> FAIL=<n> KNOWN-BUG=<n> SKIP=<n> ERROR=<n>

Temuan utama:
- make all: <PASS/FAIL>
- make test: <PASS/FAIL, sebutkan tes yang SKIP>
- chroot() bug: <KNOWN-BUG / PASS / ...>
- getgroups() bug: <KNOWN-BUG / PASS / SKIP / ...>
- probe-termux: <ringkasan: unshare, seccomp, NoNewPrivs>

Hal di luar dugaan (jika ada):
<tulis apa adanya>

Lampiran: build/termux-report.txt
```

## 6. Jika ada hal yang tidak jelas

Jangan menebak. Tulis pertanyaanmu di bagian "Hal di luar dugaan" dan sertakan output yang relevan. Pertanyaan yang paling berguna untuk kami:

- Apakah `make test` menampilkan `SKIP` pada tes seccomp? (Jika ya, seccomp user-notification tidak aktif di perangkat ini.)
- Apakah `getgroups()` di bawah `rootbox` mengembalikan daftar yang berisi `0` atau tetap kosong?
- Apakah `rootshim-probe` menghasilkan `cwd=/ uid=0 gid=0 st_uid=0 marker=from-rootfs` di Bionic?
