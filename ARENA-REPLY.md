# ARENA-REPLY — balasan untuk arena.ai (ronde 2)

**Kepada:** arena.ai (batch `a4c2b8db-linux-android`)
**Dari:** jajangking (verifikasi di perangkat nyata)
**Tanggal:** 2026-10-08 | Branch: `arena/a4c2b8db-linux-android` (`f6e3801`)

Handoff ronde 2 (`docs/HANDOFF-termux.md`) sudah dijalankan di Termux (arm64, Bionic,
Android 16). Runner, repro, dan seluruh tes baru bekerja apa adanya. Tidak ada file di
`src/`, `tests/`, `tools/`, `docs/`, atau `README.md` yang saya sentuh — sesuai §5 handoff.

> Balasan ronde 1 ada di commit `d3bfe3d`. Isinya: verifikasi `PASS=2 FAIL=1 KNOWN-BUG=2`, akar-cause
> `test-rootbox-combined.sh`, temuan `__open_2`/`__openat_2`,
> dan temuan `getgroups` di lapisan shim. Ketiganya sudah diperbaiki di `f6e3801` dan
> saya konfirmasi closing-nya di bawah.

```
Commit: f6e3801
uname:  Linux localhost 6.12.38-android16-5-gb575a0b6e647-ab14355190-4k #1 SMP PREEMPT
        Wed Oct 29 06:56:12 UTC 2025 aarch64 Android
        TERMUX_VERSION: 0.119.0-beta.3   __ANDROID_API__ = 24
        PREFIX: /data/data/com.termux/files/usr   uid (nyata): 10496
clang version 21.1.8   GNU Make 4.4.1

Ringkasan termux-check: PASS=4 FAIL=2 SKIP=0 ERROR=0
```

| Langkah | Hasil |
|---|---|
| `make all` (clang, `-Wall -Wextra`) | **PASS** — 0 warning |
| `make test` | **FAIL** — `tests/test-rootshim-hooks.sh` |
| chroot() repro | **PASS** — sudah diperbaiki |
| getgroups() repro di rootbox | **PASS** — sudah diperbaiki |
| coreutils di bawah shim | **FAIL** — `mv` |
| rootshim-hooks | **FAIL** — 6 check |
| probe-termux.sh | **PASS** |

Laporan mentah: `build/termux-report.txt`.

---

## 1. Kedua bug ronde 1: tertutup, keduanya terverifikasi di Bionic

**`chroot()`** — `tests/repro/chroot_file.c` sekarang `PASS`:

```
chroot(/afile) rc=-1 errno=Not a directory
open(/etc/marker) after failed chroot: fd=3 errno=ok
[PASS] failed chroot() leaves virtual root intact
```

**`getgroups()`** — `tests/repro/getgroups.c` sekarang `PASS`, **`rc=0`**, bukan `FAIL`
exit 4. Artinya **`process_vm_writev` diizinkan di perangkat ini**:

```
build/rootbox -- build/repro-getgroups
getgroups n=1 0
egid=0
rc=0
```

Ini menjawab pertanyaan §7 Anda yang paling penting: iya, `repro-getgroups` lulus di
rootbox, dan tidak perlu fallback apa pun.

**`test-rootbox-combined.sh`** juga hijau — usulan probe terkompilasi saya diterima:

```
cwd=/ uid=0 gid=0 st_uid=0 marker=from-rootfs
shell-marker=from-rootfs
combined rootbox/shim smoke test: PASS
```

**`rootshim-hooks` lulus di Bionic** untuk jalur fortify yang Anda maksud:

```
ok    open(flags runtime) via __open_2
ok    openat(flags runtime) via __openat_2
ok    getgroups lists synthetic group 0
ok    chroot(file) fails ENOTDIR
ok    virtual root intact after failed chroot
ok    '..' clamped at virtual root
```

Yaitu simbol `__open_2`/`__openat_2` benar-benar diuji dan benar-benar bekerja di
arm64/Bionic. Peningkatan dari "semua GNU coreutils bocor" (ronde 1) ke "hanya `mv` yang bocor"
adalah progres nyata.

---

## 2. `FAIL` #1: `linkat` EACCES — restriksi Android, **bukan** bug shim

6 check `rootshim-hooks` gagal, tapi hanya **1 akar**:

```
FAIL  linkat (errno=Permission denied)                    <-- akar
FAIL  link        (errno=No such file or directory)         \
FAIL  renameat    (errno=No such file or directory)          |
FAIL  rename      (errno=No such file or directory)          > 5 cascade:
FAIL  unlinkat    (errno=No such file or directory)          | hardlink tidak
FAIL  unlink (hard link) (errno=No such file or directory)  /  pernah dibuat
summary failures=6
```

Bukti bahwa ini restriksi platform dan bukan shim — program C polos, **tanpa
`LD_PRELOAD` sama sekali**:

```
$ ./hl $d/f $d/h
linkat(...) = -1 errno=Permission denied
```

Hook `linkat`/`link` sendiri benar. Saya uji terpisah dengan file sumber yang benar:

```
renameat (independent)   rc=0   ok
rename (independent)     rc=0   ok
unlinkat (independent)   rc=0   ok
unlink (independent)     rc=0   ok
linkat  <-- akar         rc=-1  Permission denied
```

Empat operasi pertama benar-benar mendarat di dalam rootfs (dicek langsung dari host).
Jadi 5 kegagalan lain **100% cascade**.

### Masalahnya adalah klasifikasi status

`termux-check.sh` melaporkannya `FAIL` — artinya "regresi, prioritas tinggi". Padahal
handoff Anda sendiri punya kategori `SKIP` untuk tepat kasus ini: *"fitur kernel/Android
tidak tersedia"*. Akibatnya **`make test` tidak akan pernah hijau di Termux**, dan setiap
ronde berikutnya akan melaporkan regresi palsu yang sama.

**Saran fix:** probe kemampuan hardlink sekali di awal `tests/rootshim_hooks.c`. Kalau
`linkat` mengembalikan `EACCES`/`EPERM`, laporkan 6 check itu sebagai `skip` dan jangan
tambah ke `failures`. Pola ini sudah dipakai di file yang sama untuk xattr `ENOTSUP`
(baris 112), jadi cukup konsisten dengan gaya yang sudah ada.

Catatan: ini hasil yang sama seperti temuan "kontrol ilmiah" di proyek `Brainstorming`
— `linkat` dengan `AT_EMPTY_PATH` butuh `CAP_DAC_READ_SEARCH` dan gagal di Android.
Hard link **`flags=0`** pun gagal di sini, jadi restriksinya lebih luas dari yang biasa
ditemukan.

---

## 3. `FAIL` #2: `mv` bocor — dan ini batas innate shim, bukan hook yang hilang

5 check coreutils gagal, 1 akar:

```
FAIL  mv (cannot move '/rsh-coreutils/copy' to '/rsh-coreutils/moved')
FAIL  mv renamed inside rootfs         \
FAIL  chmod (cannot access .../moved)    > 4 cascade: file tidak pernah
FAIL  chmod changed rootfs file        /  dipindahkan
FAIL  rm (cannot remove .../moved)
```

Hook `rename`/`renameat` **bukan** penyebabnya: keduanya `ok` di `rootshim-hooks`, dan
`mv` dengan path host yang sudah berada di dalam rootfs juga berhasil (`rc=0`).

Hasil pengujian yang saya lakukan:

| Skenario | Hasil |
|---|---|
| `mv /c/copy /c/moved` (path absolut virtual) | **gagal** |
| `mv copy moved` setelah `cd /c` (path relatif) | **berhasil**, file mendarat di rootfs |

`mv` aman kalau **kernel** yang me-resolve path — dari cwd yang sudah dipetakan `chdir`
milik shim. Gagal kalau `mv` sendiri harus me-resolve path absolut.

### Simbol yang dipakai `mv`: belum ketemu

Saya pasang interposer untuk `rename`, `renameat`, `renameat2`, `symlinkat`, `statx`,
`stat`, `lstat`, `fstatat`, `openat`, `__open_2`, `__openat_2`, `unlink`, `unlinkat`,
`link`, `linkat`, `faccessat`, `symlink` — **nol** yang terpicu saat `mv` berjalan.

Lalu saya pasang *blocker* yang memaksa `rename`/`renameat`/`renameat2` mengembalikan
`0` tanpa melakukan apa pun. Blocker **tidak pernah** terpicu, dan `mv` tetap gagal di
path virtual. Jadi bisa disimpulkan `mv` tidak pernah menyentuh ketiga simbol itu.

Perbandingan dengan tool lain dari binary `coreutils` yang **sama**:

| tool | jejak interposeable |
|---|---|
| `ls` | 15 |
| `cp` | 3 |
| `rm` | 2 |
| `cat` | 2 |
| **`mv`** | **0** |
| `ln -s` | 0 — tapi **lulus** di tes, karena `ln` lewat `symlinkat` yang sudah di-hook |

`ln -s` nol jejak tapi tetap benar adalah bukti bahwa "nol jejak" tidak otomatis berarti
bocor: yang menentukan adalah apakah path-nya jatuh ke kernel atau tidak. Pada `mv`,
pathnya jatuh ke kernel apa adanya.

`strace` tidak tersedia di Termux, jadi saya tidak bisa melihat syscall mentahnya. Saya
**tidak** mengklaim tahu penyebabnya, dan saya sengaja tidak menebak.

**Saran:** ini yang paling berharga untuk ronde 3. Bukan karena `mv` penting, tapi karena
pola "satu binary coreutils, sebagian operasi lolos PLT dan sebagian tidak" menentukan
seberapa luas batas innate shim ini. README sudah menyatakan `execve` tidak dipetakan;
`mv` memberi contoh nyata bahwa daftar itu belum lengkap.

Kalau memang kesimpulannya "diterima sebagai limitasi innate", saya tetap menyarankan
dokumentasikan eksplisit di README, dengan contoh yang bisa direproduksi, supaya tidak
ditemukan sebagai kejutan di ronde berikutnya.

---

## 4. `statx` hook dikompilasi keluar di Termux — tanpa warning

```
$ nm -D build/librootshim.so | grep -ci statx
0
```

Penyebabnya guard di `src/rootshim.c:431`:

```c
#if defined(__GLIBC__) || (defined(__ANDROID_API__) && __ANDROID_API__ >= 30)
```

Di Termux ini `__ANDROID_API__ = 24` (saya verifikasi lewat preprocessor, bukan tebakan),
jadi cabangnya mati. Ini **sesuai aturan yang Anda tulis sendiri** di handoff §1
("`statx` hanya jika API>=30") dan tidak menghasilkan warning — tapi konsekuensinya tidak
tercatat di mana pun:

- Setiap program yang memanggil `statx()` langsung bocor dari shim.
- Untuk target Debian/glibc ke depan, `statx` justru jalur yang **paling sering** dipakai
  program modern. Jadi kondisi sekarang menunda masalah, bukan menyelesaikannya.

**Saran:** turunkan ambangnya ke `>= 24` untuk Bionic — header-nya sudah menyediakan
`struct statx` — atau minimal catat di README bahwa shim tidak meng-map `statx` di Termux.

Ini menjawab pertanyaan §7 terakhir Anda: **tidak ada warning** dari deklarasi `statx`,
`renameat2`, atau `faccessat2`. Ketiganya bersih. Tapi `statx` justru yang hilang.

---

## 5. Hasil pemeriksaan tambahan (§4)

**a) Simbol yang diekspor shim** — `__open_2`, `__open64_2`, `__openat_2`,
`__openat64_2`, `faccessat2`, `getgroups`, `renameat2` **semua ada**. `statx` tidak ada
(lihat bagian `statx` di atas).

**b) coreutils mengimpor entry point fortify** — ya: `__open_2`, `__openat_2`.

**c) Warning kompilasi** — **0**, baik `build/round2-build.log` maupun
`build/round2-test.log`.

**d) `rootbox -- build/repro-getgroups`** — `getgroups n=1 0`, `egid=0`, **rc=0**.

**e) `ptrace_scope`** — `yama: not present`. Android memang tidak memakai Yama;
`process_vm_writev` tetap berfungsi (lihat (d)).

---

## 6. Yang membaik dari ronde 1

- `Seccomp`/`NoNewPrivs` kini tampil di terminal, bukan hanya di file laporan.
- Shim mengekspor `getgroups` — GID host tidak lagi bocor ke "root" virtual saat shim
  dipakai tanpa rootbox.
- `chroot()` tidak lagi merusak virtual root saat gagal.
- `test-rootbox-combined.sh` tidak lagi bergantung `PATH` host.
- `execve` sengaja tidak dipetakan — sesuai instruksi, saya tidak menghitungnya regresi.

---

## 7. Yang TIDAK bisa diverifikasi (jujur)

- **Tidak ada `strace`** di Termux, jadi mekanisme `mv` (§3) tidak bisa saya buktikan.
  Yang saya punya hanya bukti negatif: tidak ada satu pun interposer saya yang terpicu.
- **`unshare --map-root-user` tetap tidak dicoba**, sesuai §5 handoff. Jadi klaim README
  bahwa user-namespace tidak tersedia belum terverifikasi runner — hanya
  `--map-current-user` (`Invalid argument`) yang dicoba.
- **Tidak ada rootfs Debian nyata.** Semua verifikasi memakai rootfs minimal buatan tes.
  Interaksi dengan rootfs bercabang (symlink melintas, device node, `PT_INTERP`, glibc)
  **tidak** tersentuh sama sekali.
- **Tidak ada CI.** Semua hasil berasal dari satu perangkat arm64; perilaku x86_64 yang
  jadi asal verifikasi Anda belum dikonfirmasi ulang di sini.

---

## 8. Untuk arena.ai kalau dipanggil lagi

Ronde 2 menutup semua item ronde 1. Yang tersisa bukan bug, tapi tiga keputusan sadar
yang memang tidak mudah:

1. **`linkat` → `SKIP`** (paling mendesak). Tanpa ini `make test` tidak akan pernah hijau
   di Termux dan setiap ronde melaporkan regresi palsu.
2. **`statx` di API 24** atau didokumentasikan sebagai tidak dipetakan.
3. **`mv`** — dokumentasikan sebagai limitasi innate yang terbukti, idealnya dengan contoh
   reproduksi yang sudah saya siapkan (§3).

Tidak ada lagi item yang menunggu dari handoff ronde 2. Kalau ada kontribusi lanjutan, yang
bernilai paling tinggi menurut saya adalah **membedah `mv`** — kalau ternyata penyebabnya
mekanisme umum yang juga memengaruhi program lain, itu temuan struktural; kalau ternyata
khusus `mv`, kita setidaknya punya bukti dan batas yang jelas.

Regresi wajib tetap: `make all` (0 warning), `make test`, `tests/repro/chroot_file.c`,
`tests/repro/getgroups.c`, `tests/rootshim_hooks.c`, `tests/test-coreutils-shim.sh`,
`tools/termux-check.sh`, `tools/probe-termux.sh`. `make test` harus hijau di Termux
setelah butir 1 dikerjakan, dan `termux-check.sh` harus keluar `exit=0`.

— jajangking