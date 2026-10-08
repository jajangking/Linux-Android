# Linux-Android (Rootless Debian experiment)

Eksperimen untuk menjalankan **sebagian program Linux user-space** dari Termux tanpa root dan tanpa PRoot, memakai shim `LD_PRELOAD` dan supervisor seccomp. Ini masih proof of concept—belum menjadi wadah Debian lengkap dan belum mengintegrasikan OpenCode.

> **Penting:** “uid 0” yang dilihat proses di sini hanya nilai tiruan. Proses tetap berjalan sebagai UID aplikasi Termux (mis. `10496` di perangkat uji; `/proc/self/status` tetap menampilkan UID asli). Ini bukan eskalasi privilege, bukan `chroot` kernel, dan bukan batas keamanan untuk menjalankan program tak tepercaya.

## Yang ada sekarang

- `build/librootshim.so`: shim eksperimental yang memetakan path absolut ke `ROOTSHIM_ROOT`, memvirtualkan UID/GID/groups, menjadikan `chown` no-op, dan menyediakan `chroot()` tiruan berbasis prefix.
  - **Path-taking calls** (plain dan `*at`): `open`/`open64`/`openat`/`openat64`, entry point fortify `__open_2`/`__openat_2` (dan varian `64`), `fopen`/`fopen64`, `opendir`, `stat`/`lstat`/`fstatat`/`stat64`/`lstat64`/`fstatat64`/`statx`, `access`/`faccessat`/`faccessat2`, `chdir`, `mkdir`/`mkdirat`, `unlink`/`unlinkat`/`rmdir`, `rename`/`renameat`/`renameat2`, `link`/`linkat`, `symlink`/`symlinkat` (hanya lokasi link yang dipetakan; target disimpan apa adanya), `readlink`/`readlinkat`, `chmod`/`fchmodat`, `truncate`, `utimensat` (path `NULL` diteruskan), `getxattr`/`lgetxattr`/`setxattr`/`lsetxattr`/`listxattr`/`llistxattr`/`removexattr`/`lremovexattr`, `chown`/`lchown`/`fchownat` (no-op saat fake ID aktif).
  - **Identitas tiruan** (`ROOTSHIM_FAKE_ID=1`): `getuid`/`geteuid`/`getgid`/`getegid`/`getresuid`/`getresgid` mengembalikan 0; `getgroups` mengembalikan daftar `{0}`; `stat`/`fstat`/`statx` melaporkan pemilik 0.
  - **`syscall()` (libc)** juga diintersep: panggilan `syscall(SYS_renameat2, …)` dan sejenisnya dipetakan dengan aturan yang sama seperti wrapper di atas. Ini menutup kebocoran `mv` di Termux: gnulib memanggil `renameat2` lewat `syscall()` saat libc tidak mendeklarasikannya (Bionic API 24). Intersepsi hanya berlaku untuk pemanggil yang lewat PLT; inline asm dan binary statis tidak tercakup.
  - **`statx`**: wrapper `statx()` hanya dikompilasi jika header menyediakan `struct statx` (glibc, atau Bionic API ≥ 30). Termux dengan `__ANDROID_API__ = 24` tidak punya wrapper `statx` sama sekali, jadi program di Termux tidak dapat memanggilnya langsung; panggilan `statx` mentah tetap dipetakan lewat `syscall()`.
- `build/rootbox`: supervisor proof-of-concept berbasis seccomp user notification. Ia **hanya** mengubah hasil query `getuid`/`geteuid`/`getgid`/`getegid` menjadi `0`, dan `getgroups` menjadi `{0}`. Ia **tidak** memberi kapabilitas root atau melakukan operasi kernel `mount`/`chroot`.
- `build/rootshim-hooks`: probe regresi untuk seluruh hook di atas, dibangun dengan `_FORTIFY_SOURCE=2`.
- `tests/`: smoke test dan regresi (lihat bagian "Build dan tes"). Pemanggilan `syscall()` mentah diuji di `tests/rootshim_hooks.c`.
- `tools/probe-termux.sh`: membangun dan menjalankan probe di Termux serta mencatat batasan kernel/aplikasi.
- `tools/termux-check.sh`: menjalankan seluruh tes dan repro di Termux, lalu menulis `build/termux-report.txt`.
- `docs/HANDOFF-termux.md`: instruksi verifikasi untuk agent lokal di Termux.

## Syarat PATH dan isi rootfs

Path di luar `ROOTSHIM_ROOT` **tidak terlihat** bagi proses yang dipetakan. Karena itu:

- Rootfs sungguhan wajib memiliki `/bin` dan `/usr/bin` sendiri, serta `PATH=/bin:/usr/bin` (atau sesuai isi rootfs).
- `PATH` host (mis. `/data/data/com.termux/files/usr/bin`) tidak bisa dipakai untuk mencari program di dalam rootfs. Shell di dalam shim akan gagal menemukan `id` dsb. kecuali tersedia di rootfs.
- Tes di repo sengaja tidak bergantung pada PATH: program yang diuji dikompilasi, dan pemeriksaan shell hanya memakai builtin serta path absolut ke `sh`.

## Hard link di Android

Beberapa perangkat Android menolak `link(2)`/`linkat(2)` untuk proses aplikasi, bahkan tanpa shim (terukur di Termux arm64). Itu batas platform, bukan kesalahan shim. Karena itu `tests/test-rootshim-hooks.sh` memeriksa dulu dukungan hard link di host (tanpa shim). Jika host menolak, pemeriksaan `linkat`/`link` dilaporkan sebagai `skip`; pemeriksaan lain tetap wajib lulus. Pemeriksaan `rename`/`unlink` memakai file sendiri, sehingga tidak bergantung pada hard link.

## Keputusan: `execve` rootfs-first (B2)

`execve` dan `execv` (serta `syscall(SYS_execve, ...)`) dicegat. Kebijakannya rootfs-first dengan fallback host, bukan pemetaan buta:

- **ELF dinamis** (ada `PT_INTERP`) di rootfs dijalankan sebagai `ld-linux` rootfs dengan `--library-path` rootfs, `--argv0` sama dengan argv[0] asli, lalu program yang sudah dipetakan. Dengan begitu libc dimuat dari rootfs.
- **Shebang** dijalankan ulang sebagai interpreter-nya (rekursi maksimal 4 tingkat), dengan argv yang sama seperti yang dibangun kernel.
- **ELF statis** dan binary yang arsitekturnya tidak cocok diserahkan ke kernel dengan path yang sudah dipetakan.
- **Skrip host di luar rootfs** dijalankan oleh shell rootfs. Shim membuka file skrip sekali, lalu menyerahkannya sebagai `/proc/self/fd/N`. `/proc` tidak dipetakan, jadi interpreter membaca file itu lewat descriptor yang diwariskan. Akibatnya `$0` di skrip itu berisi `/proc/self/fd/N`.
- **ELF host di luar rootfs** diteruskan ke kernel apa adanya. Batas: file yang dibuka ELF itu tetap dipetakan ke rootfs (`open()` tidak punya fallback host), jadi ELF host yang membaca data dari path host tidak akan melihatnya.
- **Symlink akhir** di-resolve di dalam rootfs (maksimal 16 hop); target absolut dibasiskan ulang ke root. Symlink direktori perantara diserahkan ke kernel.
- **Tidak tercakup:** `execvp`/`execl*` yang tidak melewati `execve` PLT, `posix_spawn` (glibc memanggil `__execve` internal), inline asm, dan binary statis yang melakukan syscall sendiri.
- Override jalur library loader: env `ROOTSHIM_LOADER_LIBPATH`.

### Libc dari rootfs untuk program yang dijalankan kernel

Program di dalam rootfs yang dijalankan dengan path host (mis. `rootbox-run.sh` atau tes) dimuat kernel dengan ELF interpreter host, sehingga libc awalnya dari host. Constructor shim mendeteksi ini dari `/proc/self/maps`, lalu menjalankan ulang program **sekali** lewat loader rootfs dengan argv dari `/proc/self/cmdline`. Penanda `ROOTSHIM_REEXEC` mencegah loop dan dihapus di proses kedua, sehingga anak-anaknya tidak terpengaruh. Jika exec ulang gagal, proses tetap jalan dengan libc host.

### NSS: `getpw*` dan `getgr*` dari rootfs

`libnss_files` membaca `/etc/passwd` dan `/etc/group` lewat open internal glibc yang tidak bisa dicegat `LD_PRELOAD`. Karena itu shim menginterposisi API publik: `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid` (beserta versi `_r`), dan enumerasi `setpwent`/`getpwent`/`endpwent` serta padanan `gr`. Semuanya membaca `<rootfs>/etc/passwd` dan `<rootfs>/etc/group`. Tanpa `ROOTSHIM_ROOT`, fungsi-fungsi ini meneruskan ke implementasi berikutnya.

Batas: `getgrouplist`, `initgroups`, dan `getspnam` tidak diinterposisi.

## Identitas dan `getgroups`

Dua lapisan menyamarkan identitas dan keduanya dibuat konsisten:

- **Shim (in-process):** `getgroups` di-hook dan mengembalikan `{0}`. Ini mencakup pemanggil yang lewat PLT.
- **Supervisor (seccomp):** pemanggil yang memakai syscall langsung juga dijawab `{0}`. Supervisor menulis GID 0 ke buffer tracee lewat `process_vm_writev`. Jika kernel/SELinux menolak penulisan itu, supervisor membalas `EPERM` (bukan daftar kosong). Izin ini perlu diuji di tiap perangkat.

Sebelum perbaikan, `getgroups()` di bawah `rootbox` mengembalikan `0` grup sementara `getegid()` mengembalikan `0`. GNU `id` menutupinya dengan fallback, sehingga tes `id -u` saja tidak cukup untuk menangkap bug ini.

## chroot()

`chroot(path)` tiruan hanya menerima **direktori** yang ada. Virtual root diganti setelah semua pemeriksaan dan `chdir` berhasil; kegagalan (mis. `ENOTDIR`) meninggalkan root sebelumnya utuh. `chroot` tetap tidak pernah memanggil syscall kernel `chroot`.

## Build dan tes di host Linux

```sh
make
make test
```

`make test` menjalankan:

| Tes | Isi |
|---|---|
| `test-rootshim.sh` | Pemetaan path dasar dan identitas tiruan |
| `test-supervisor.sh` | `rootbox -- id -u` mencetak `0` |
| `test-rootbox-combined.sh` | Probe dan shell di bawah rootbox + shim, tanpa bergantung PATH host |
| `test-rootshim-hooks.sh` | Seluruh hook path-taking dan identitas, dibangun dengan fortify; semua hasil harus berada di rootfs |
| `test-supervisor-groups.sh` | `getgroups()` di bawah rootbox mencakup grup 0 |
| `test-coreutils-shim.sh` | `cat cp mv rm ln readlink ls stat dd head chmod truncate touch mkdir` di bawah shim; tidak ada kebocoran ke host |
| `test-debian-rootfs.sh` | Rootfs Debian bookworm dibangun dari daftar file `dpkg` paket yang terpasang di host (tanpa jaringan); binary glibc-nya dijalankan di bawah shim. `SKIP` di host non-Debian. Saat ini tidak ada `KNOWN-LIMIT`; batas baru dicatat sebagai `KNOWN-LIMIT`, bukan `FAIL` |

Tes rootbox akan menandai dirinya `SKIP` jika seccomp user notification tidak tersedia di lingkungan tempat tes dijalankan.

## Probe dan verifikasi di Termux

```sh
pkg install clang make git
sh tools/termux-check.sh
```

Runner menulis `build/termux-report.txt`. Probe `tools/probe-termux.sh` tidak membutuhkan `su`. Karena percobaan `unshare --user --map-root-user` dan `--map-current-user` sebelumnya menghasilkan `Invalid argument`, pendekatan user-namespace/chroot tidak tersedia di proses Termux tersebut. Supervisor seccomp adalah mekanisme terpisah; probe akan menguji apakah Android mengizinkannya.

## Smoke test shim manual

```sh
make
mkdir -p "$HOME/rootfs-demo/etc"
echo demo > "$HOME/rootfs-demo/etc/rootshim-marker"
ROOTSHIM_ROOT="$HOME/rootfs-demo" \
ROOTSHIM_FAKE_ID=1 \
LD_PRELOAD="$PWD/build/librootshim.so" \
  "$PWD/build/rootshim-probe"
```

Output yang diharapkan memuat `cwd=/`, `uid=0`, `gid=0`, dan `marker=demo`. File tersebut tetap dimiliki UID Termux di kernel.

Uji supervisor secara terpisah:

```sh
build/rootbox -- id -u
build/rootbox -- id -G
```

Jika didukung, proses anak mencetak `0` untuk keduanya. Jika tidak, supervisor melaporkan alasan syscall seccomp ditolak.

Keduanya bisa dicoba bersama pada program yang ABI-nya cocok dengan shim:

```sh
ROOTSHIM_ROOT="$HOME/rootfs-demo" ROOTSHIM_FAKE_ID=1 \
ROOTSHIM_LIB="$PWD/build/librootshim.so" \
  tools/rootbox-run.sh -- /bin/sh -c 'cd /; pwd; id -u; cat /etc/rootshim-marker'
```

Supervisor memasang `LD_PRELOAD` hanya pada proses anak. Untuk program Debian/glibc, shim juga harus dibangun dengan ABI glibc yang sesuai; jangan preload library Bionic Termux ke proses glibc.

## Status target Debian dan OpenCode

### Hasil uji rootfs Debian (`test-debian-rootfs.sh`)

Tes ini memakai coreutils, bash, dash, dan libc6 Debian 12 yang sebenarnya, di host x86_64 Debian 12. Sumber paketnya adalah paket host Debian 12 (glibc 2.36-9+deb12u14, coreutils 9.1-1, bash 5.2.15, dash 0.5.12), **bukan** mirror. Yang sudah terbukti: `cp`, `mv` (termasuk jalur `renameat2` wrapper glibc), `ln`, `readlink`, `ls`, `rm`, `stat -c %u` (jalur statx glibc, pemilik tiruan), `id -u`, builtin dash, shebang rootfs lewat `execve`, `id -u` lewat `execve` (uid 0), NSS dari `etc/passwd` dan `etc/group` rootfs (termasuk akun khusus rootfs), libc rootfs untuk program yang dijalankan kernel, dan skrip host di luar rootfs, semuanya di bawah shim dan terbatas pada rootfs.

Ketiga batas yang sebelumnya terukur sudah ditutup dan dicek sebagai PASS:

- **Libc dari host untuk program yang dijalankan kernel:** diperbaiki dengan exec ulang lewat loader rootfs (lihat di atas).
- **NSS membaca `/etc/passwd` host:** diperbaiki dengan interposisi `getpw*`/`getgr*` (lihat di atas). Akun khusus rootfs terlihat oleh `getent` dan `id`.
- **Skrip host di luar rootfs:** dijalankan oleh shell rootfs dengan `/proc/self/fd/N` (lihat keputusan `execve`).

Batas yang tersisa:

- **ELF host di luar rootfs** tetap melihat file-file lewat pemetaan rootfs (lihat keputusan `execve`).
- **`execve` lewat `execvp`, `posix_spawn`, atau inline asm** belum dicegat.
- **`getgrouplist`/`initgroups`/`getspnam`** belum diinterposisi.

Target akhir berupa rootfs Debian ARM64 yang sudah diekstrak di penyimpanan privat Termux. Untuk menjalankannya dibutuhkan pekerjaan tambahan: pemanggilan glibc loader dari rootfs, kompatibilitas `PT_INTERP`/shebang, perluasan cakupan `execve` ke `execvp`/`posix_spawn` (B2 sudah mencakup `execve`/`execv`, lihat keputusan di atas), ownership virtual yang konsisten, serta uji tiap paket. Shim Bionic Termux **tidak** bisa langsung di-preload ke program glibc; shim harus dibangun untuk ABI glibc yang sama dengan program Debian.

OpenCode dan CLI yang tersedia sebagai paket Termux sebaiknya dijalankan native lewat Termux terlebih dahulu. Menjalankan build Linux/glibc-nya di rootfs adalah target lanjutan, bukan kemampuan yang dijamin oleh proof of concept ini.

## Batas keamanan dan kompatibilitas

- Jangan gunakan ini sebagai sandbox keamanan. Path translation berbasis `LD_PRELOAD` dapat dilewati oleh syscall langsung, executable statis/setuid, `execvp`/`posix_spawn` dan inline asm, proses yang membersihkan environment, dan symlink/path traversal yang belum ditangani. Symlink dengan target absolut tetap diselesaikan oleh kernel terhadap root host.
- Pemetaan lexical: path virtual yang diawali persis dengan path host rootfs (mis. `/data/.../rootfs/etc/x`) dibiarkan apa adanya dan **tidak** dipetakan ulang.
- Program tetap hanya memiliki izin Android/Termux biasa. `chown` yang tampak sukses tidak mengubah owner kernel; `uid=0` tiruan tidak dapat memasang filesystem atau mengakses perangkat yang dilarang Android. `/proc/self/status` dan `stat` lewat syscall yang tidak di-hook masih menampilkan UID/GID asli.
- Syscall yang tidak di-hook (mis. `getdents` langsung, `realpath` internal glibc, `execvp`/`posix_spawn`, `getgrouplist`/`initgroups`) tidak tercakup pemetaan. Syscall mentah yang dipanggil lewat `syscall()` dari libc dipetakan untuk daftar path-argument yang dikenal; inline asm (`svc`) dan binary statis tidak.
- Seccomp user notification bergantung pada dukungan kernel **dan** kebijakan seccomp/SELinux aplikasi. ADB biasa tidak dapat menambahkan dukungan yang tidak ada. Pengisian daftar grup di jalur seccomp juga bergantung pada `process_vm_writev`, yang bisa ditolak kebijakan ptrace.
- “Debian lengkap” dalam arti boot init/systemd atau mendapatkan hak kernel root tidak dapat dijanjikan pada batasan ini. Fokus eksperimen adalah CLI yang kooperatif dan dapat berjalan sebagai user-space process.
