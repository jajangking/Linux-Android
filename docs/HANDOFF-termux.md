# Handoff ronde 3: verifikasi di Termux (untuk agent lokal)

Dokumen ini ditujukan untuk AI agent yang berjalan langsung di Termux (perangkat Android). Tugasmu: **pull perbaikan terbaru, jalankan tes, dan kembalikan laporan**. Kamu **tidak** diminta mengubah kode.

## 1. Apa yang berubah sejak ronde 2

Balasan ronde 2 (`ARENA-REPLY.md` di commit `5fa7c8f`) melaporkan `PASS=4 FAIL=2`. Perubahan ronde 3 menjawab tiga temuan:

| Temuan ronde 2 | Perbaikan ronde 3 | Yang perlu dicek di Termux |
|---|---|---|
| `linkat` ditolak Android (`EACCES`), membuat 6 check hook gagal | Probe hard link di **host** (tanpa shim) dijalankan dulu. Jika host menolak, check `linkat`/`link` dilaporkan `skip`. Check `rename`/`unlink` memakai file sendiri | `make test` hijau; output memuat `host hard links: denied` dan `skip linkat/link` |
| `mv` tidak ter-hook; `rename`/`renameat`/`renameat2` tidak pernah terpicu | Hipotesis: gnulib memanggil `syscall(SYS_renameat2, …)` langsung saat libc tidak mendeklarasikannya (Bionic API 24). Shim sekarang juga **mengintersep `syscall()`** dari libc dan memetakan path-argument. Terverifikasi di x86 dengan program yang memanggil `syscall(SYS_renameat2)` mentah | `coreutils under shim` harus `PASS`, termasuk `mv` dengan path absolut. Jika tetap gagal, lihat bagian 4a |
| `statx` tidak dipetakan di Termux (`__ANDROID_API__ = 24`) | Wrapper `statx()` tetap hanya untuk glibc/API ≥ 30 (karena Bionic API 24 tidak mendeklarasikan `statx`). Panggilan `statx` **mentah** sekarang dipetakan dan pemiliknya disamarkan lewat `syscall()` | `rootshim-hooks` harus `PASS` (termasuk `raw syscall(SYS_statx) synthetic owner`) |

Juga berubah: `syscall(SYS_getuid/SYS_getgid)` mentah mengembalikan 0 saat fake identity aktif, dan `syscall(SYS_newfstatat)` mentah menyamarkan pemilik. Keduanya diuji di `rootshim-hooks`.

Keputusan yang **tetap** tidak berubah: `execve` tidak dipetakan (README, "Keputusan: execve tidak dipetakan").

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
git log --oneline -3          # HEAD harus memuat commit ronde 3 (setelah 5fa7c8f)

mkdir -p build
make -B CC=clang all 2>&1 | tee build/round3-build.log
make CC=clang test 2>&1 | tee build/round3-test.log
sh tools/termux-check.sh
echo "exit=$?"
```

Jangan jalankan `make clean` sebelum langkah di atas, karena itu menghapus `build/` beserta log. Jika `make test` gagal, jalankan ulang hanya bagian yang gagal dengan `make -B CC=clang test` agar log verbose tersimpan.

Arti status: `PASS` = sesuai harapan; `FAIL` = regresi atau bug aktif (prioritas tinggi, sertakan log); `SKIP` = tidak tersedia di perangkat (mis. seccomp, atau hard link ditolak host); `ERROR` = langkah tidak bisa dijalankan. `exit` non-zero bila ada `FAIL` atau `ERROR`.

## 4. Pemeriksaan tambahan (wajib, cepat)

Jalankan dan sertakan hasilnya di laporan. Tidak ada yang mengubah repo.

```sh
# a) Hipotesis mv: apakah mv Termux memanggil syscall() langsung?
readelf -W --dyn-syms "$(command -v mv)" | grep -E ' (syscall|renameat2?)@' ; echo "---"

# b) Simbol yang diekspor shim: syscall harus ada; statx hanya jika API>=30
nm -D build/librootshim.so | grep -E ' (syscall|__open_2|renameat2|faccessat2|getgroups|statx)$'

# c) Probe hard link di host (tanpa shim)
d=$(mktemp -d); : > "$d/a"; ln "$d/a" "$d/b" && echo "host hardlink: OK" || echo "host hardlink: DENIED"; rm -rf "$d"

# d) Peringatan kompilasi (harus nol)
grep -iE 'warning|error' build/round3-build.log build/round3-test.log || echo "no warnings"

# e) Hasil mv secara langsung (path absolut di dalam rootfs)
R=$(mktemp -d); mkdir -p "$R/rf/etc" "$R/rf/rsh-m"; echo from-rootfs > "$R/rf/etc/marker"; : > "$R/rf/rsh-m/copy"
ROOTSHIM_ROOT="$R/rf" ROOTSHIM_FAKE_ID=1 LD_PRELOAD="$PWD/build/librootshim.so" "$(command -v mv)" /rsh-m/copy /rsh-m/moved; echo "mv rc=$?"; ls "$R/rf/rsh-m"; rm -rf "$R"
```

## 5. Yang harus dilakukan agent lokal

1. Pull branch, lalu jalankan bagian 3 dan 4.
2. Jika ada `FAIL`, simpan output lengkap dan jalankan ulang bagian yang gagal dengan `make -B CC=clang test`.
3. Jika ada `ERROR` karena paket hilang, pasang (`pkg install -y clang make`), lalu ulangi.
4. Catat `SKIP` apa adanya; jangan dianggap lulus.
5. Jangan mengedit `src/`, `tests/`, `tools/`, `docs/`, atau `README.md`. Jangan `commit`, `push`, atau membuat branch. Jangan jalankan `su`, `sudo`, atau `unshare --map-root-user`.
6. Kembalikan laporan sesuai bagian 6, dan lampirkan `build/termux-report.txt`.

## 6. Format laporan balik

```
Handoff round 3 — Termux verification
Commit: <git rev-parse --short HEAD>
Perangkat/Android: <uname -a; TERMUX_VERSION; __ANDROID_API__ bila diketahui>
Arsitektur: <uname -m>
Compiler: <clang --version | head -1>
Make: <make --version | head -1>

Ringkasan termux-check: PASS=<n> FAIL=<n> SKIP=<n> ERROR=<n>

Per langkah:
- make all (clang, -Wall -Wextra): <PASS/FAIL; jumlah warning>
- make test: <PASS/FAIL; tes yang FAIL/SKIP>
- chroot() repro: <PASS/FAIL>
- getgroups() repro di rootbox: <PASS/FAIL/SKIP; rc>
- coreutils di bawah shim (termasuk mv absolut): <PASS/FAIL; tool yang gagal>
- rootshim-hooks: <PASS/FAIL; check yang FAIL/skip>
- probe-termux.sh: <ringkasan>

Pemeriksaan tambahan (bagian 4):
a) mv mengimpor syscall/renameat2: <tempel>
b) simbol shim: <tempel>
c) probe hard link host: <supported/denied>
d) warning: <jumlah/daftar>
e) mv langsung: rc=<n>; isi rsh-m: <daftar>

Hal di luar dugaan:
<tulis apa adanya>

Lampiran: build/termux-report.txt
```

## 7. Pertanyaan yang paling penting

- Apakah `mv` dengan path absolut sekarang berhasil di dalam rootfs (bagian 4e)? Dan apakah `readelf` (4a) menunjukkan `mv` memanggil `syscall`? Keduanya menguji hipotesis ronde 3.
- Apakah `make test` hijau dengan hard link ditolak host? Output harus memuat `skip`, bukan `FAIL`.
- Apakah `rootshim-hooks` lulus di Bionic, termasuk check `raw syscall(...)`?
- Apakah ada warning kompilasi dari `syscall` interposer atau `fake_raw_stat` di clang Termux?
