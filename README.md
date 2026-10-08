# Linux-Android (Rootless Debian experiment)

Eksperimen untuk menjalankan **sebagian program Linux user-space** dari Termux tanpa root dan tanpa PRoot, memakai shim `LD_PRELOAD` dan supervisor seccomp. Ini masih proof of concept—belum menjadi wadah Debian lengkap dan belum mengintegrasikan OpenCode.

> **Penting:** “uid 0” yang dilihat proses di sini hanya nilai tiruan. Proses tetap berjalan sebagai UID aplikasi Termux. Ini bukan eskalasi privilege, bukan `chroot` kernel, dan bukan batas keamanan untuk menjalankan program tak tepercaya.

## Yang ada sekarang

- `build/librootshim.so`: shim eksperimental yang memetakan sejumlah panggilan libc untuk path absolut ke direktori `ROOTSHIM_ROOT`, memvirtualkan beberapa hasil UID/GID/stat, menjadikan `chown` no-op, dan menyediakan `chroot()` tiruan berbasis prefix.
- `build/rootbox`: supervisor proof-of-concept berbasis seccomp user notification. Ia hanya mengubah hasil query UID/GID/group tertentu menjadi `0`; ia **tidak** memberi kapabilitas root atau melakukan operasi kernel `mount`/`chroot`.
- `tests/`: smoke test untuk pemetaan path dan notifikasi seccomp.
- `tools/probe-termux.sh`: membangun dan menjalankan probe di Termux serta mencatat batasan kernel/aplikasi.
- `tools/rootbox-run.sh`: menjalankan perintah anak dengan shim yang ABI-nya cocok, tanpa memasang `LD_PRELOAD` ke supervisor Termux.

Pemetaan shim hanya mencakup sebagian API libc. Syscall langsung, program statis, dynamic loader sebelum shim aktif, path melalui symlink absolut, `systemd`, mount, cgroups, device node, dan banyak operasi lain belum ditangani. Program yang menguji kapabilitas kernel tetap akan melihat bahwa proses bukan root.

## Build dan tes di host Linux

```sh
make
make test
```

Tes `rootbox` akan menandai dirinya `SKIP` jika seccomp user notification tidak tersedia di lingkungan tempat tes dijalankan.

## Probe di Termux

Di Termux, pasang compiler dan make bila perlu, lalu jalankan:

```sh
pkg install clang make
sh tools/probe-termux.sh
```

Probe ini tidak membutuhkan `su`. Karena percobaan `unshare --user --map-root-user` dan `--map-current-user` sebelumnya menghasilkan `Invalid argument`, pendekatan user-namespace/chroot tidak tersedia di proses Termux tersebut. Supervisor seccomp adalah mekanisme terpisah; probe akan menguji apakah Android mengizinkannya.

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
```

Jika didukung, proses anak akan mencetak `0`. Jika tidak, supervisor melaporkan alasan syscall seccomp ditolak.

Keduanya bisa dicoba bersama pada program yang ABI-nya cocok dengan shim:

```sh
ROOTSHIM_ROOT="$HOME/rootfs-demo" ROOTSHIM_FAKE_ID=1 \
ROOTSHIM_LIB="$PWD/build/librootshim.so" \
  tools/rootbox-run.sh -- sh -c 'cd /; pwd; id -u; cat /etc/rootshim-marker'
```

Supervisor memasang `LD_PRELOAD` hanya pada proses anak. Untuk program Debian/glibc, shim juga harus dibangun dengan ABI glibc yang sesuai; jangan preload library Bionic Termux ke proses glibc.

## Status target Debian dan OpenCode

Target akhir berupa rootfs Debian ARM64 yang sudah diekstrak di penyimpanan privat Termux. Untuk menjalankannya dibutuhkan pekerjaan tambahan: pemanggilan glibc loader dari rootfs, kompatibilitas `PT_INTERP`/shebang, redirect path yang lebih lengkap, ownership virtual yang konsisten, serta uji tiap paket. Shim Bionic Termux **tidak** bisa langsung di-preload ke program glibc; shim harus dibangun untuk ABI glibc yang sama dengan program Debian.

OpenCode dan CLI yang tersedia sebagai paket Termux sebaiknya dijalankan native lewat Termux terlebih dahulu. Menjalankan build Linux/glibc-nya di rootfs adalah target lanjutan, bukan kemampuan yang dijamin oleh proof of concept ini.

## Batas keamanan dan kompatibilitas

- Jangan gunakan ini sebagai sandbox keamanan. Path translation berbasis `LD_PRELOAD` dapat dilewati oleh syscall langsung, executable statis/setuid, proses yang membersihkan environment, dan symlink/path traversal yang belum ditangani.
- Program tetap hanya memiliki izin Android/Termux biasa. `chown` yang tampak sukses tidak mengubah owner kernel; `uid=0` tiruan tidak dapat memasang filesystem atau mengakses perangkat yang dilarang Android.
- Seccomp user notification bergantung pada dukungan kernel **dan** kebijakan seccomp/SELinux aplikasi. ADB biasa tidak dapat menambahkan dukungan yang tidak ada.
- “Debian lengkap” dalam arti boot init/systemd atau mendapatkan hak kernel root tidak dapat dijanjikan pada batasan ini. Fokus eksperimen adalah CLI yang kooperatif dan dapat berjalan sebagai user-space process.
