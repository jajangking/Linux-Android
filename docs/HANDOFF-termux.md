# Handoff ronde 2: verifikasi di Termux (untuk agent lokal)

Dokumen ini ditujukan untuk AI agent yang berjalan langsung di Termux (perangkat Android). Tugasmu: **pull perbaikan terbaru, jalankan tes, dan kembalikan laporan**. Kamu **tidak** diminta mengubah kode.

## 1. Apa yang berubah sejak ronde 1

Balasan ronde 1 (`ARENA-REPLY.md`) menemukan bug dan temuan tambahan. Semuanya sudah diperbaiki di branch ini, dan sudah diverifikasi di x86 (Debian, gcc 12). **Verifikasi di Bionic/Termux belum dilakukan** — itulah tugasmu.

| Temuan | Perbaikan | Yang perlu dicek di Termux |
|---|---|---|
| `chroot()` merusak virtual root saat gagal | Validasi `S_ISDIR`; state diubah hanya setelah `chdir` berhasil | `tests/repro/chroot_file.c` harus `PASS` |
| `getgroups()` kosong di bawah rootbox | Supervisor membalas `{0}` dan menulis GID 0 ke buffer lewat `process_vm_writev`; shim juga meng-hook `getgroups` | **`repro-getgroups` harus `PASS`.** Jika `process_vm_writev` ditolak di perangkat ini, hasilnya `FAIL` exit 4 — laporkan apa adanya |
| `__open_2`/`__openat_2` tidak di-hook (coreutils bocor) | Hook ditambahkan, termasuk varian `64` | `coreutils under shim` harus `PASS`; `rootshim-hooks` harus `PASS` |
| Hook `*at`, `symlink`, `readlink`, `statx`, xattr, dll. belum ada | Ditambahkan (lihat README "Yang ada sekarang") | `rootshim-hooks` harus `PASS` |
| `test-rootbox-combined.sh` gagal karena `id` tidak ditemukan | Tes diubah: memakai probe terkompilasi dan `sh` dengan path absolut | `make test` harus hijau |
| Output `Seccomp`/`NoNewPrivs` di runner tidak tampil di terminal | Diperbaiki | — |

Keputusan yang **sengaja tidak** diubah: `execve` tidak di-hook (lihat README, "Keputusan: execve tidak dipetakan"). Jangan menganggap ini regresi.

## 2. Prasyarat

```sh
pkg update
pkg install -y git clang make
```

## 3. Langkah

```sh
cd ~/Linux-Android            # atau lokasi clone-mu
git fetch origin
git checkout arena/a4c2b8db-linux-android
git pull --ff-only origin arena/a4c2b8db-linux-android
git log --oneline -3          # HEAD harus memuat "round 2" / commit setelah d3bfe3d

mkdir -p build
make -B CC=clang all 2>&1 | tee build/round2-build.log
make CC=clang test 2>&1 | tee build/round2-test.log
sh tools/termux-check.sh
echo "exit=$?"
```

Catatan: jangan jalankan `make clean` sebelum langkah di atas; itu menghapus `build/` beserta log yang baru dibuat. Jika `make test` gagal, jalankan ulang bagian yang gagal saja dengan `make -B CC=clang test` agar log verbose tersimpan di `build/`.

Hasil lengkap ada di `build/termux-report.txt`. Log tiap langkah ada di `build/`.

Arti status:

| Status | Arti |
|---|---|
| `PASS` | Perilaku sesuai harapan |
| `FAIL` | Regresi atau bug yang masih ada — **prioritas tinggi**, sertakan log |
| `SKIP` | Fitur kernel/Android tidak tersedia (mis. seccomp user-notification) |
| `ERROR` | Skrip tidak bisa menjalankan langkah (mis. `clang`/`make` belum terpasang) |

`exit` non-zero bila ada `FAIL` atau `ERROR`.

## 4. Pemeriksaan tambahan (wajib, cepat)

Jalankan ini dan sertakan hasilnya di laporan. Tidak ada yang mengubah repo.

```sh
# a) Simbol yang diekspor shim (harus ada __open_2, statx hanya jika API>=30)
nm -D build/librootshim.so | grep -E '__open(at)?(64)?_2|statx|getgroups|renameat2|faccessat2'

# b) Apakah coreutils Termux mengimpor entry point fortify? (informasi, bukan lulus/gagal)
readelf --dyn-syms "$(command -v cat)" | grep -oE '__open(at)?(64)?_2' | sort -u

# c) Peringatan kompilasi dari build clang (harus nol atau dicatat)
grep -iE 'warning|error' build/round2-build.log build/round2-test.log || echo "no warnings"

# d) Supervisor: getgroups di bawah rootbox
build/rootbox -- build/repro-getgroups; echo "rc=$?"

# e) Cek izin ptrace untuk process_vm_writev (diagnosis jika (d) gagal)
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "yama: not present"
```

Jika `(d)` menghasilkan `rc=4`, jangan mencoba mengubah SELinux atau mencari root. Laporkan saja.

## 5. Yang harus dilakukan agent lokal

1. Pull branch, lalu jalankan langkah di bagian 3 dan 4.
2. Jika ada `FAIL`, simpan output lengkapnya dan jalankan ulang bagian yang gagal dengan `make -B CC=clang test` untuk log verbose.
3. Jika ada `ERROR` karena paket hilang, pasang paketnya (`pkg install -y clang make`), lalu ulangi.
4. Catat `SKIP` apa adanya; jangan dianggap lulus.
5. Jangan mengedit file di `src/`, `tests/`, `tools/`, `docs/`, atau `README.md`. Jangan `commit`, `push`, atau membuat branch baru. Jangan jalankan `su`, `sudo`, atau `unshare --map-root-user` untuk "memaksa" tes.
6. Kembalikan laporan sesuai format di bagian 6, dan lampirkan `build/termux-report.txt`.

## 6. Format laporan balik

Salin template ini dan isi. Lampirkan `build/termux-report.txt` lengkap, serta log yang relevan jika ada `FAIL`.

```
Handoff round 2 — Termux verification
Commit: <git rev-parse --short HEAD>
Perangkat/Android: <uname -a; TERMUX_VERSION>
Arsitektur: <uname -m>
Compiler: <clang --version | head -1>
Make: <make --version | head -1>

Ringkasan termux-check: PASS=<n> FAIL=<n> SKIP=<n> ERROR=<n>

Per langkah:
- make all (clang, -Wall -Wextra): <PASS/FAIL; jumlah warning>
- make test: <PASS/FAIL; sebutkan tes yang FAIL/SKIP>
- chroot() repro: <PASS/FAIL>
- getgroups() repro di rootbox: <PASS/FAIL/SKIP; rc>
- coreutils di bawah shim: <PASS/FAIL; sebutkan tool yang gagal>
- rootshim-hooks: <PASS/FAIL; sebutkan check yang FAIL>
- probe-termux.sh: <ringkasan: unshare, seccomp, NoNewPrivs>

Hasil pemeriksaan tambahan (bagian 4):
a) simbol shim: <tempel>
b) coreutils __open_2: <ya/tidak, sebutkan binary>
c) warning: <jumlah/daftar>
d) rootbox getgroups: <rc dan output>
e) ptrace_scope: <nilai>

Hal di luar dugaan:
<tulis apa adanya, termasuk pertanyaan>

Lampiran: build/termux-report.txt
```

## 7. Pertanyaan yang paling penting untuk dijawab

- Apakah `repro-getgroups` lulus di rootbox pada perangkat ini (bagian 4d)? Ini satu-satunya check yang bergantung pada izin Android untuk `process_vm_writev`.
- Apakah `rootshim-hooks` lulus di Bionic? Tes ini memakai `_FORTIFY_SOURCE=2`, jadi jalur `__open_2` benar-benar diuji.
- Apakah `coreutils under shim` lulus? Sebelum perbaikan, `cat`, `cp`, `mv`, `rm`, `ln`, `ls`, `stat`, `dd`, `head` bocor ke host.
- Apakah ada warning kompilasi dari deklarasi `statx`, `renameat2`, atau `faccessat2` di API level Termux?
