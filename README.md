# Linux-Android (Rootless Debian experiment)

Eksperimen untuk menjalankan **sebagian program Linux user-space** dari Termux tanpa root dan tanpa PRoot, memakai shim `LD_PRELOAD` dan supervisor seccomp. Ini masih proof of concept—belum menjadi wadah Debian lengkap dan belum mengintegrasikan OpenCode.

> **Penting:** “uid 0” yang dilihat proses di sini hanya nilai tiruan. Proses tetap berjalan sebagai UID aplikasi Termux (mis. `10496` di perangkat uji; `/proc/self/status` tetap menampilkan UID asli). Ini bukan eskalasi privilege, bukan `chroot` kernel, dan bukan batas keamanan untuk menjalankan program tak tepercaya.

## Yang ada sekarang

- `build/librootshim.so`: shim eksperimental yang memetakan path absolut ke `ROOTSHIM_ROOT`, memvirtualkan UID/GID/groups, menjadikan `chown` no-op, dan menyediakan `chroot()` tiruan berbasis prefix.
  - **Path-taking calls** (plain dan `*at`): `open`/`open64`/`openat`/`openat64`, entry point fortify `__open_2`/`__openat_2` (dan varian `64`), `fopen`/`fopen64`, `opendir`, `stat`/`lstat`/`fstatat`/`stat64`/`lstat64`/`fstatat64`/`statx`, `access`/`faccessat`/`faccessat2`, `chdir`, `mkdir`/`mkdirat`, `unlink`/`unlinkat`/`rmdir`, `rename`/`renameat`/`renameat2`, `link`/`linkat`, `symlink`/`symlinkat` (hanya lokasi link yang dipetakan; target disimpan apa adanya), `readlink`/`readlinkat`, `chmod`/`fchmodat`, `truncate`, `utimensat` (path `NULL` diteruskan), `getxattr`/`lgetxattr`/`setxattr`/`lsetxattr`/`listxattr`/`llistxattr`/`removexattr`/`lremovexattr`, `chown`/`lchown`/`fchownat` (no-op saat fake ID aktif).
  - **Identitas tiruan** (`ROOTSHIM_FAKE_ID=1`): `getuid`/`geteuid`/`getgid`/`getegid`/`getresuid`/`getresgid` mengembalikan 0; `getgroups` mengembalikan daftar `{0}`; `stat`/`fstat`/`statx` melaporkan pemilik 0.
  - **`statx`** hanya dikompilasi jika header menyediakan `struct statx` (glibc, atau Bionic API ≥ 30). Termux pada API level lebih rendah tidak memakai hook ini.
- `build/rootbox`: supervisor proof-of-concept berbasis seccomp user notification. Ia **hanya** mengubah hasil query `getuid`/`geteuid`/`getgid`/`getegid` menjadi `0`, dan `getgroups` menjadi `{0}`. Ia **tidak** memberi kapabilitas root atau melakukan operasi kernel `mount`/`chroot`.
- `build/rootshim-hooks`: probe regresi untuk seluruh hook di atas, dibangun dengan `_FORTIFY_SOURCE=2`.
- `tests/`: smoke test dan regresi (lihat bagian "Build dan tes").
- `tools/probe-termux.sh`: membangun dan menjalankan probe di Termux serta mencatat batasan kernel/aplikasi.
- `tools/termux-check.sh`: menjalankan seluruh tes dan repro di Termux, lalu menulis `build/termux-report.txt`.
- `docs/HANDOFF-termux.md`: instruksi verifikasi untuk agent lokal di Termux.

## Syarat PATH dan isi rootfs

Path di luar `ROOTSHIM_ROOT` **tidak terlihat** bagi proses yang dipetakan. Karena itu:

- Rootfs sungguhan wajib memiliki `/bin` dan `/usr/bin` sendiri, serta `PATH=/bin:/usr/bin` (atau sesuai isi rootfs).
- `PATH` host (mis. `/data/data/com.termux/files/usr/bin`) tidak bisa dipakai untuk mencari program di dalam rootfs. Shell di dalam shim akan gagal menemukan `id` dsb. kecuali tersedia di rootfs.
- Tes di repo sengaja tidak bergantung pada PATH: program yang diuji dikompilasi, dan pemeriksaan shell hanya memakai builtin serta path absolut ke `sh`.

## Keputusan: `execve` tidak dipetakan

`execve`/`execv`/`execvp` dan turunannya **tidak** di-hook. Alasannya: shell dan program lain mencari binary lewat `PATH` host dengan `execve`; jika `execve` dipetakan, binary host yang valid akan hilang dari pandangan. Akibatnya:

- Program yang meng-exec path absolut di dalam rootfs (mis. `/usr/bin/foo` milik Debian) akan menjalankan binary host di path yang sama, bukan milik rootfs.
- Mengubah perilaku ini memerlukan kebijakan lookup terpisah (rootfs-first dengan fallback host); belum dikerjakan.

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

Target akhir berupa rootfs Debian ARM64 yang sudah diekstrak di penyimpanan privat Termux. Untuk menjalankannya dibutuhkan pekerjaan tambahan: pemanggilan glibc loader dari rootfs, kompatibilitas `PT_INTERP`/shebang, lookup `execve` yang rootfs-aware (lihat keputusan di atas), ownership virtual yang konsisten, serta uji tiap paket. Shim Bionic Termux **tidak** bisa langsung di-preload ke program glibc; shim harus dibangun untuk ABI glibc yang sama dengan program Debian.

OpenCode dan CLI yang tersedia sebagai paket Termux sebaiknya dijalankan native lewat Termux terlebih dahulu. Menjalankan build Linux/glibc-nya di rootfs adalah target lanjutan, bukan kemampuan yang dijamin oleh proof of concept ini.

## Batas keamanan dan kompatibilitas

- Jangan gunakan ini sebagai sandbox keamanan. Path translation berbasis `LD_PRELOAD` dapat dilewati oleh syscall langsung, executable statis/setuid, `execve` (tidak di-hook), proses yang membersihkan environment, dan symlink/path traversal yang belum ditangani. Symlink dengan target absolut tetap diselesaikan oleh kernel terhadap root host.
- Pemetaan lexical: path virtual yang diawali persis dengan path host rootfs (mis. `/data/.../rootfs/etc/x`) dibiarkan apa adanya dan **tidak** dipetakan ulang.
- Program tetap hanya memiliki izin Android/Termux biasa. `chown` yang tampak sukses tidak mengubah owner kernel; `uid=0` tiruan tidak dapat memasang filesystem atau mengakses perangkat yang dilarang Android. `/proc/self/status` dan `stat` lewat syscall yang tidak di-hook masih menampilkan UID/GID asli.
- Syscall yang tidak di-hook (mis. `execve`, `readdir` berbasis `getdents` langsung, `realpath` internal glibc) tidak tercakup pemetaan.
- Seccomp user notification bergantung pada dukungan kernel **dan** kebijakan seccomp/SELinux aplikasi. ADB biasa tidak dapat menambahkan dukungan yang tidak ada. Pengisian daftar grup di jalur seccomp juga bergantung pada `process_vm_writev`, yang bisa ditolak kebijakan ptrace.
- “Debian lengkap” dalam arti boot init/systemd atau mendapatkan hak kernel root tidak dapat dijanjikan pada batasan ini. Fokus eksperimen adalah CLI yang kooperatif dan dapat berjalan sebagai user-space process.
