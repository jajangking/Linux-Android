# ARENA-REPLY — balasan untuk arena.ai

**Kepada:** arena.ai (batch `a4c2b8db-linux-android`)
**Dari:** jajangking (review + verifikasi di perangkat nyata)
**Tanggal:** 2026-10-08 | Branch: `arena/a4c2b8db-linux-android` (`b08452f`)

Handoff `docs/HANDOFF-termux.md` sudah dijalankan di Termux (arm64, Bionic, Android 16).
Runner `tools/termux-check.sh` + kedua repro bekerja apa adanya. Tidak ada file di `src/`,
`tests/`, atau `tools/` yang saya sentuh — sesuai §4 handoff.

```
Commit: b08452f
uname:  Linux localhost 6.12.38-android16-5-gb575a0b6e647-ab14355190-4k #1 SMP PREEMPT
        Wed Oct 29 06:56:12 UTC 2025 aarch64 Android
        TERMUX_VERSION: 0.119.0-beta.3      PREFIX: /data/data/com.termux/files/usr
        uid (nyata): 10496                 context: u:r:untrusted_app_27:s0:c240,c257,c512,c768
clang version 21.1.8   GNU Make 4.4.1

PASS=2 FAIL=1 KNOWN-BUG=2 SKIP=0 ERROR=0
```

Laporan mentah: **`docs/termux-report.txt`** (salinan `build/termux-report.txt`).

| Langkah | Status |
|---|---|
| `make all` (clang, `-Wall -Wextra`) | **PASS** — build bersih, nol warning |
| `make test` | **FAIL** — `tests/test-rootbox-combined.sh` |
| repro `chroot()` | **KNOWN-BUG** — terkonfirmasi |
| repro `getgroups()` | **KNOWN-BUG** — terkonfirmasi |
| `probe-termux.sh` | **PASS** |

---

## 1. Jawaban atas 3 pertanyaan di §6 handoff

**1. Apakah `make test` menampilkan `SKIP` pada tes seccomp?**
Tidak. Seccomp user-notification **aktif** di perangkat ini — `Seccomp: 2`,
`NoNewPrivs: 0`, `rootbox -- id` → `0`, `test-supervisor.sh` **PASS**. Jadi kegagalan
`make test` §2 di bawah **bukan** karena seccomp.

**2. Apakah `getgroups()` mengembalikan daftar berisi `0` atau tetap kosong?**
**Kosong (`n=0`)**, sementara `getegid()==0`. Dan ini lebih berbahaya dari yang terlihat —
lihat §4.

**3. Apakah `rootshim-probe` menghasilkan `cwd=/ uid=0 gid=0 st_uid=0 marker=from-rootfs` di Bionic?**
Ya, persis. `test-rootshim.sh` **PASS** di aarch64/Bionic.

---

## 2. `FAIL`: `test-rootbox-combined.sh` — ini bug di tes, bukan di shim

```
sh: 1: id: not found
cwd=/ uid= marker=from-rootfs
make: *** [Makefile:25: test] Error 1
```

Akar masalahnya terisolasi. Tes membangun rootfs yang hanya berisi `etc/rootshim-marker`,
lalu memanggil `$(id -u)`. Shim mengarahkan ulang **semua** path absolut di luar
`$ROOTSHIM_ROOT`, sehingga entri `PATH` host (`/data/.../usr/bin`) menjadi tidak terlihat:

```
# di dalam rootbox + shim:
stat /data/.../usr/bin/id    -> rc=127 (ENOENT)   # di host file ini ADA
test -x /data/.../usr/bin/id -> rc=1
command -v id                -> rc=127
```

Bukti perbaikan (uji di direktori temp, **tidak** mengubah repo): dengan symlink `bin/id`
di dalam rootfs tes dan `PATH` yang menunjuk ke sana, tes lulus persis:

```
cwd=/ uid=0 marker=from-rootfs
```

**Saran fix:** `tests/test-rootbox-combined.sh` sebaiknya (a) membuat `rootfs/bin` berisi
symlink ke `id`, atau (b) memakai `build/rootshim-probe` yang sudah ada sebagai pengganti
`id` — probe C tidak bergantung `PATH` sama sekali, jadi lebih deterministik.

Catatan desain yang lebih luas: perilaku "path di luar rootfs tidak terlihat" memang
disengaja, tapi berarti **rootfs sungguhan wajib punya `/bin` + `/usr/bin` sendiri
dan `PATH=/bin:/usr/bin`**. README §"Batas keamanan" belum menyebutnya; ini sebaiknya
didokumentasikan supaya tidak mengejutkan pengguna.

---

## 3. `KNOWN-BUG` #1: `chroot()` merusak virtual root — terkonfirmasi

```
chroot(/afile) rc=-1 errno=Not a directory
open(/etc/marker) after failed chroot: fd=-1 errno=Not a directory
```

Lokasi: `src/rootshim.c:539-563`. Urutan penyebabnya persis:

```c
if (!realpath(mapped, resolved)) { ...; return -1; }  /* realpath() pada FILE BIASA -> BERHASIL */
memcpy(root_dir, resolved, n + 1);                   /* root_dir := path ke FILE  <-- rusak di sini */
root_len = n;                                        /* root_len := panjang file   <-- rusak di sini */
return next_chdir(root_dir);                         /* baru DI SINI chdir gagal ENOTDIR */
```

`realpath()` tidak memverifikasi bahwa target adalah direktori, dan `root_dir`/`root_len`
ditulis **sebelum** `chdir` dicoba. Setelah itu `map_path("/etc/marker")` menjadi
`$rootfs/afile/etc/marker` → `ENOTDIR` — persis gejala yang dilaporkan.

**Fix yang disarankan:** `stat()` pada `resolved` lalu tolak kalau bukan `S_ISDIR`,
**dan/atau** tulis `root_dir`/`root_len` ke variabel `static` lokal dan baru commit ke
global setelah `chdir` berhasil. Yang kedua menutup kelas bug yang lebih luas — termasuk
kegagalan `chdir` dengan `ENOMEM`, `EROFS`, atau `ELOOP`, yang semuanya akan meninggalkan
virtual root dalam keadaan setengah tertulis.

---

## 4. `KNOWN-BUG` #2: `getgroups()` — dan `id` menyamarinya

```
getgroups n=0
egid=0
```

Lokasi: `src/seccomp_supervisor.c:174-181`. `respond_to_notification()` membalas
`response.val = 0` untuk semua identity query. Untuk `getuid`/`geteuid`/`getgid`/`getegid`
itu benar — skalar. Tapi `getgroups()` mengembalikan **jumlah** group dan mengisi array,
jadi `val = 0` berarti "nol group".

Saya verifikasi dengan interposer logger (`getgroups`/`getgid`/`getegid`):

```
# tanpa rootbox:
  getegid()=10496  getgid()=10496
  getgroups(0)=4   getgroups(4)=4
uid=10496(u0_a496) gid=10496(u0_a496) groups=10496(u0_a496),3003(inet),9997(everybody),20496(u0_a496_cache),50496(all_a496)

# dengan rootbox:
  getegid()=0  getgid()=0
  getgroups(0)=0   getgroups(0)=0
uid=0(root) gid=0(root) groups=0(root)
```

**Penting:** GNU coreutils `id` jatuh ke fallback "cetak egid sebagai satu-satunya group"
saat daftar supplementary kosong. Jadi `groups=0(root)` **terlihat benar**, padahal
`getgroups()` mengembalikan `n=0`. Artinya `tests/test-supervisor.sh` yang mengecek
`id -u` secara struktural **tidak mungkin** menangkap bug ini — itu sebabnya
`tests/repro/getgroups.c` memang diperlukan, dan ia bekerja dengan benar.

**Fix yang disarankan:** balas `val = 1` dan tulis `gid 0` ke buffer tracee pada
`request.data.args[1]` memakai `process_vm_writev`.

### Temuan tambahan di lapisan shim

`src/rootshim.c` **tidak meng-hook `getgroups` sama sekali**. Shim saja, tanpa rootbox:

```
getgroups n=4 3003 9997 20496 50496    <-- GID host bocor ke dalam "root" virtual
egid=0
```

Jadi ada ketidakkonsistenan di kedua lapisan, dan saling berlawanan arah:

| Konfigurasi | `getegid()` | `getgroups()` |
|---|---|---|
| shim saja | `0` (palsu) | 4 group **host asli** bocor |
| rootbox saja | `0` | kosong |
| shim + rootbox | `0` | kosong |

Praktikalnya: program yang memanggil `getgroups()` tanpa lewat PLT (langsung via syscall,
atau lewat `setgroups`/`initgroups`) akan melihat angka yang bertentangan dengan `egid`.
Kedua lapisan perlu diselaraskan — entah konsisten "root virtual" (`[0]`), atau
konsisten "jangan apa-apakan" (biarkan real). Yang sekarang adalah yang terburuk dari
keduanya.

---

## 5. `probe-termux.sh`

```
user.max_user_namespaces: not readable/available
NoNewPrivs:  0
Seccomp:     2
unshare: unavailable (exit 1): unshare: unshare failed: Invalid argument
uid=0(root) gid=0(root) groups=0(root) context=u:r:untrusted_app_27:s0:...
seccomp-child-ran
seccomp supervisor child exit: 0
```

- `unshare --user --map-current-user` → `Invalid argument`. Sesuai README §"Probe di
  Termux" — jalur user-namespace memang tidak tersedia di proses Termux ini. **Bukan bug.**
- `Seccomp: 2` (filter mode) + `NoNewPrivs: 0`; supervisor user-notification tetap berfungsi.
- Catatan kecil: `tools/termux-check.sh:45` —
  `grep … | tee -a "$report" >/dev/null` menulis baris `Seccomp`/`NoNewPrivs` hanya ke file
  laporan, tidak ke stdout. Ringkasan di terminal terlihat kosong dan mudah disalahbaca
  sebagai "tidak terbaca". Boleh diubah ke `log "$(grep …)"`.

---

## 6. Temuan di luar 2 bug yang diminta — paling berdampak dari semua

**`src/rootshim.c` tidak meng-hook `__open_2` / `__openat_2`.** Semua binary GNU coreutils
di Termux mengimpor dua simbol fortify itu — bukan `open`/`openat` biasa:

```
$ readelf --dyn-syms $PREFIX/bin/coreutils | grep __open
 0: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __open_2@LIBC
 0: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __openat_2@LIBC
```

Verifikasi di arm64:

```
# shim sekarang:
$ ROOTSHIM_ROOT=$R LD_PRELOAD=build/librootshim.so $PREFIX/bin/cat /etc/rootshim-marker
cat: /etc/rootshim-marker: No such file or directory     # shim bocor

# + shim supplements yang meng-map __open_2/__openat_2 (dibuat di temp, tidak di repo):
marker-ok                                                  # berhasil
```

Terverifikasi terpengaruh: `cat cp mv rm ln tar ls stat dd head`. Hook `*at` yang lain
juga belum ada — terverifikasi gagal di dalam virtual root:

```
mv /d/a /d/b     -> No such file or directory   (renameat)
rm /d/b          -> No such file or directory   (unlinkat)
ln -s b /d/l     -> No such file or directory   (symlink)
readlink /d/link -> (kosong)                     (readlink bocor)
mkdir /d/e       -> OK                          (hook mkdir ada)
```

Sedang belum ter-hook: `__open_2`, `__openat_2`, `mkdirat`, `unlinkat`, `renameat`,
`renameat2`, `link`, `linkat`, `symlink`, `symlinkat`, `readlink`, `readlinkat`, `statx`,
`faccessat2`, `execve`/`execv`, `fopenat`, `utimensat`, `chmod`/`fchmodat`, `truncate`,
`getxattr`/`lgetxattr`/`lsetxattr` (perlu untuk `tar` dan `cp -a`).

Dua simbol fortify itu adalah penghalang terbesar untuk target "sebagian program Linux
user-space" — tanpa keduanya, shim praktis tidak berguna untuk program GNU mana pun.

---

## 7. Prioritas perbaikan yang saya sarankan

1. **`__open_2` + `__openat_2`** — membuka jalan semua program GNU. Dampak terbesar per baris.
2. **`chroot()`** — guard `S_ISDIR` + commit `root_dir`/`root_len` setelah `chdir` sukses.
3. **`getgroups()`** — balas `val=1` + `process_vm_writev`; plus hook `getgroups` di shim agar dua lapisan konsisten.
4. **`test-rootbox-combined.sh`** — hentikan ketergantungan pada `PATH` host, supaya `make test` hijau.
5. **Sisa `*at`/`symlink`/`statx`/`getxattr`** — dikerjakan bertahap.
6. **Dokumentasikan batas `PATH`** di README §"Batas keamanan".

Poin 1 dan 3 bisa digabung jadi satu commit karena keduanya menyangkut hooking yang
hilang, dan bisa diverifikasi dengan runner yang sudah ada — `tests/repro/` tinggal
nambah dua file baru, `termux-check.sh` tinggal nambah dua langkah. Kalau keempatnya
kerjakan, `make test` jadi hijau dan `KNOWN-BUG=2` turun jadi `PASS`, terukur lewat
runner yang sama.

---

## 8. Yang TIDAK bisa diverifikasi (jujur, bukan ditutup-tutupi)

- **`unshare --user --map-root-user` tidak bisa diuji** di perangkat ini —
  `Invalid argument`, dan `/proc/sys/user/max_user_namespaces` tidak terbaca. Jadi klaim
  README bahwa user-namespace tidak tersedia **belum terverifikasi oleh runner**; hanya
  satu probe `unshare --map-current-user` yang dicoba, dan `--map-root-user` **tidak
  pernah** dicoba (mengikuti aturan §4 handoff: jangan paksa dengan `su`).
- **Tidak ada target Debian rootfs nyata** di repo, jadi semua verifikasi di atas memakai
  rootfs minimal buatan tes. Interaksi dengan rootfs bercabang (symlink, hardlink,
  device node, `PT_INTERP`, modul glibc) **tidak** tersentuh.
- **Tidak ada CI.** Semua hasil di atas berasal dari satu perangkat arm64. Perilaku x86_64
  yang jadi asal review awal **belum** dikonfirmasi ulang di sini, dan tidak ada yang
  salah di sana, tapi juga belum ada bukti positif.

---

## 9. Untuk arena.ai kalau dipanggil lagi

Tidak ada item yang tertinggal dari `docs/HANDOFF-termux.md` — kedua bug yang diminta
sudah terkonfirmasi, dan `FAIL` di `make test` sudah terisolasi ke akar penyebabnya. Kalau
mau kontribusi lanjutan, prioritas yang jujur bernilai:

(a) implementasikan `__open_2`/`__openat_2` beserta rangkaian `*at`/`symlink` dari §6;
(b) tambah `tests/repro/` untuk `__open_2` dan `getgroups` di shim supaya runner punya
    regresi terukur;
(c) **uji perilaku `PATH` pada rootfs bercabang** — ini yang paling mungkin memunculkan
    bug yang belum kita lihat;
(d) tambahkan `README` §batas keamanan untuk `PATH` host yang menghilang.

Regresi wajib tetap: `make all`, `make test`, `tests/repro/chroot_file.c`,
`tests/repro/getgroups.c`, `tools/probe-termux.sh` — semuanya harus tetap hijau setelah
perubahan di atas.

— jajangking