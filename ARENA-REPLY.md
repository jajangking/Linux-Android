# ARENA-REPLY — balasan untuk arena.ai (ronde 3)

**Kepada:** arena.ai (batch `a4c2b8db-linux-android`)
**Dari:** jajangking (verifikasi di perangkat nyata)
**Tanggal:** 2026-10-08 | Branch: `arena/a4c2b8db-linux-android` (`0f14479`)

Handoff ronde 3 (`docs/HANDOFF-termux.md`) sudah dijalankan di Termux (arm64, Bionic,
Android 16, `__ANDROID_API__ = 24`). Tidak ada file di `src/`, `tests/`, `tools/`,
`docs/`, atau `README.md` yang saya sentuh — sesuai §5 handoff.

> Riwayat balasan: ronde 1 = `d3bfe3d`, ronde 2 = `5fa7c8f` (keduanya sudah tersimpan di
> branch ini).

```
Commit: 0f14479
uname:  Linux localhost 6.12.38-android16-5-gb575a0b6e647-ab14355190-4k #1 SMP PREEMPT
        Wed Oct 29 06:56:12 UTC 2025 aarch64 Android
        TERMUX_VERSION: 0.119.0-beta.3   __ANDROID_API__ = 24
        PREFIX: /data/data/com.termux/files/usr   uid (nyata): 10496
clang version 21.1.8   GNU Make 4.4.1

Ringkasan termux-check: PASS=6 FAIL=0 SKIP=0 ERROR=0     exit=0
```

**Hijau penuh.** `make test` untuk pertama kalinya keluar `rc=0` dengan `summary failures=0`.

| Langkah | Hasil |
|---|---|
| `make all` (clang, `-Wall -Wextra`) | **PASS** — 0 warning |
| `make test` | **PASS** — `failures=0`, 2 check `skip` |
| chroot() repro | **PASS** |
| getgroups() repro di rootbox | **PASS** — `getgroups n=1 0`, rc=0 |
| coreutils di bawah shim | **PASS** — termasuk `mv` path absolut |
| rootshim-hooks | **PASS** — 0 `FAIL`, 2 `skip` |
| probe-termux.sh | **PASS** |

Laporan mentah: `build/termux-report.txt`.

---

## 1. Ketiga temuan ronde 2 tertutup — dan hipotesis `mv`-nya benar

### 1.1 `mv`: hipotesis `syscall()` **terkonfirmasi**

Inilah jawaban untuk pertanyaan §7 Anda yang paling penting. `readelf -W` (§4a):

```
152: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND renameat@LIBC
377: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND syscall@LIBC
```

`mv` memang mengimpor `syscall@LIBC`. Itu sebabnya **seluruh** interposer yang saya pasang
di ronde 2 tidak pernah terpicu — `mv` masuk lewat `syscall()`, bukan lewat PLT
`renameat`. Bukti negatif yang saya laporkan di ronde 2 justru mengarah tepat ke titik ini.

Hasil langsung (§4e):

```
mv rc=0
isi rsh-m: moved
```

Dan di `make test`:

```
ok    mv
ok    mv renamed inside rootfs
coreutils under shim test: PASS
```

### 1.2 Hard link: `SKIP`, bukan `FAIL`

```
host hard links: denied by host (checks will be SKIP)
skip  linkat/link (host denies hard links; not a shim failure)
```

Persis yang saya minta di ronde 2 §2: penolakan platform dilaporkan `SKIP`, bukan
`FAIL`. Probe dijalankan di host tanpa shim, jadi benar-benar mengukur kemampuan
platform dan bukan kemampuan shim. `rename`/`unlink` juga dipisah ke file sendiri
sehingga tidak ikut jadi cascade — dan keduanya hijau:

```
ok    create file for rename checks
ok    renameat
ok    rename
ok    unlinkat
```

### 1.3 `statx`: keputusan API 24 sudah tertutup

Wrapper `statx()` memang tetap tidak ada di Termux (`nm -D` tidak mengacaknya), tapi
jalur mentahnya sekarang dipetakan. Check baru hijau:

```
ok    raw syscall(SYS_renameat2) absolute path
ok    raw syscall(SYS_unlinkat) absolute path
ok    raw syscall(SYS_openat) absolute path
ok    raw syscall(SYS_getuid/SYS_getgid) synthetic 0
ok    raw syscall(SYS_newfstatat) synthetic owner
ok    raw syscall(SYS_statx) synthetic owner
```

`raw syscall(SYS_statx) synthetic owner` **ok** justru tanpa wrapper `statx` — itu
konsekuensi keputusan API 24 yang tertutup dengan rapi, dan saya setuju dengan
keputusan itu.

---

## 2. Pemeriksaan tambahan (bagian 4)

**(a) `mv` mengimpor syscall/renameat2** — ya:

```
152: UND renameat@LIBC
377: UND syscall@LIBC
```

**(b) Simbol shim** — ada semua yang diharapkan:

```
T __open_2    T faccessat2    T getgroups    T renameat2    T syscall
```

`statx` tidak ada, sesuai yang Anda nyatakan (hanya bila API ≥ 30; Termux di sini 24).

**(c) Probe hard link host** — `DENIED` (`Permission denied`).

**(d) Warning** — **0**, di `build/round3-build.log` maupun `build/round3-test.log`,
termasuk dari interposer `syscall` maupun `fake_raw_stat`. Ini menjawab pertanyaan §7
terakhir: interposer `syscall` bersih di clang Termux.

**(e) `mv` langsung** — `rc=0`; isi `rsh-m/`: `moved`.

---

## 3. Sanity sweep tambahan (di luar handoff)

Meng-intersep `syscall()` itu berisiko tinggi: `syscall()` adalah satu-satunya syscall
entry point universal di libc, dan salah handling-nya bisa merusak `futex`, `gettid`, atau
propagasi exit code. Karena itu saya uji sendiri, bukan hanya menerima `make test`:

| Yang diuji | Hasil |
|---|---|
| `grep sed wc sort find tee` di bawah shim (path absolut) | rc=0 semua |
| `/proc/self/status`, `/dev/urandom` | passthrough ok |
| pipe dan subshell `$(...)` | ok |
| propagasi exit code (`exit 42`) | `rc=42`, benar |
| 5 skrip `make test` | hijau |

Tidak ada regresi. Syscall non-path diteruskan dengan benar.

---

## 4. Satu temuan: catatan runner yang salah attribut

```
[PASS] make test
note: at least one test reported SKIP (seccomp user notification unavailable here).
```

**Note itu salah.** Sumbernya `tools/termux-check.sh:65` — `grep -q 'SKIP'` pada test log.
Satu-satunya `SKIP` di log tersebut adalah hard link yang ditolak host:

```
12: host hard links: denied by host (checks will be SKIP)
25: skip  linkat/link (host denies hard links; not a shim failure)
```

Laporan ini **kontradiksi sendiri**: 12 baris di bawahnya, Step 4 `rootbox` **PASS**
dengan `getgroups n=1 0`, dan `probe-termux.sh` mencetak `uid=0(root)` +
`seccomp supervisor child exit: 0`. Seccomp user-notification jelas **aktif**.

Dampaknya nyata, bukan teoritis: operator yang membaca laporan ini bisa menyimpulkan
`rootbox` tidak berfungsi di perangkat ini — padahal justru sebaliknya. Dan karena note
itu muncul pada setiap ronde ke depan selama `SKIP` masih ada, ia akan terus menyesatkan.

Ini kelas kesalahan yang sama dengan temuan ronde 2 §2, hanya arahnya terbalik. Waktu itu
platform ditolak dilaporkan `FAIL` (terlalu yakin); sekarang platform ditolak disalahkan
ke seccomp (terlalu ragu). Keduanya berasal dari satu keputusan yang sama: `SKIP` tidak
pernah dipisahkan menurut asalnya.

**Saran:** pisahkan `SKIP` menurut sumber sebelum mencetak note — mis. hanya cetak note
seccomp kalau yang `SKIP` memang berasal dari `rootbox`/seccomp, dan cetak note hard-link
kalau yang `SKIP` berasal dari `skip linkat/link`. Kalau tidak mau diubah, lebih aman
**menghapus note itu** sekarang: isinya tidak membawa informasi baru lagi.

Prioritas rendah, karena tidak memengaruhi exit code maupun status check mana pun.

---

## 5. Yang tidak bisa diverifikasi (jujur)

- **Tidak ada `strace`.** Jadi interposer `syscall()` hanya saya uji lewat program yang
  memanggil `syscall(SYS_*)` langsung (milik `rootshim-hooks`), bukan lewat observasi
  syscall mentah program nyata seperti `mv`. Mekanisme `mv` saya buktikan lewat `readelf`
  dan hasil fungsional, bukan lewat syscall trace.
- **Tidak ada rootfs Debian nyata.** Semua verifikasi tetap memakai rootfs minimal buatan
  tes. Interaksi dengan glibc, `PT_INTERP`, device node, dan rootfs bercabang **belum
  tersentuh sama sekali** — dan justru ini yang paling dekat dengan target akhir proyek.
- **`unshare --map-root-user` tidak dicoba**, sesuai §5 handoff. Klaim README bahwa
  user-namespace tidak tersedia belum terverifikasi runner; hanya `--map-current-user`
  (`Invalid argument`) yang diuji.
- **Tidak ada CI.** Semua hasil berasal dari satu perangkat arm64. Perilaku x86_64 yang
  jadi asal verifikasi Anda belum dikonfirmasi ulang di sini.

---

## 6. Untuk arena.ai kalau dipanggil lagi

Tidak ada lagi item terbuka dari handoff ronde 3. Ketiga temuan ronde 2 tertutup, dan
`make test` hijau untuk pertama kalinya dengan `FAIL=0` di perangkat saya.

Kalau ada kontribusi lanjutan, yang menurut saya paling bernilai:

1. **Rootfs Debian nyata.** Semua yang kita kerjakan selama tiga ronde berhenti di rootfs
   minimal. Batas paling besar dari proyek ini bukan hooking, melainkan fakta bahwa belum
   ada satu pun program Debian asli yang pernah diuji. Hook `statx` dan `syscall()` yang
   baru dibuat justru paling relevan justru di sana — dan belum pernah diuji di sana.
2. **Pisahkan asal `SKIP` di `termux-check.sh`** (§4 di atas) sebelum ronde berikutnya,
   supaya catatan tidak ikut menyesatkan lagi.
3. **CI.** Satu job `clang` di x86_64 + satu di arm64 akan menghemat waktu yang paling
   murah untuk semua ronde berikutnya, karena sekarang verifikasi hanya bisa dilakukan di
   satu perangkat.

Regresi wajib tetap: `make all` (0 warning), `make test`, `tests/repro/chroot_file.c`,
`tests/repro/getgroups.c`, `tests/rootshim_hooks.c`,
`tests/test-coreutils-shim.sh`, `tests/test-supervisor-groups.sh`,
`tools/termux-check.sh`, `tools/probe-termux.sh`. Di Termux, kondisi sekarang adalah
`make test` rc=0 dan `termux-check.sh` exit=0 — jadikan itu titik regresi.

— jajangking