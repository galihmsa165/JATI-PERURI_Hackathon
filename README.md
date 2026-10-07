# JATI: Secure Element e-Paspor Berbasis PUF

JATI adalah rancangan chip keamanan (*secure element*) untuk e-Paspor yang **tidak menyimpan kunci di memori**. Setiap kali chip menyala, kunci dibentuk ulang dari "sidik jari" fisik silikon (*Physically Unclonable Function*, PUF), sehingga chip hasil salinan tidak dapat membuktikan keasliannya. Rancangan ini dibuat untuk **PERURI Chip Hackathon 2026, Track 01: Secure Identity & Security Element Chip**, dan diimplementasikan sebagai prototipe pada FPGA Cyclone V (papan Terasic DE10-Nano).

## Fitur utama

- **Kunci dari PUF:** 1.024 *ring oscillator*, fuzzy extractor (pemilihan pasangan 1-dari-8 dan voting mayoritas), serta tag integritas HMAC atas helper data (*robust fuzzy extractor*).
- **Rantai kunci di perangkat keras:** R_PUF → K_DEV → K_CA / K_DG, diturunkan dengan HMAC-SHA256 KDF. Kunci hanya mengalir lewat jalur khusus dan tidak pernah melewati bus data.
- **Protokol terinspirasi ICAO Doc 9303 dalam versi simetris:**
  - EXTERNAL AUTH (kunci pintu dari MRZ)
  - Secure Messaging (AES-CBC + HMAC, penghitung SSC)
  - TERMINAL AUTH (membuka DG3 biometrik)
  - INTERNAL AUTH (bukti chip asli)
- **Anti-tamper:**
  - Sensor lebar pulsa clock, sensor tegangan berbasis *canary timing*, dan watchdog clock independen.
  - State FSM dan lifecycle dikodekan Hamming agar fault terdeteksi.
  - Zeroize redundan yang menghapus seluruh rahasia dalam satu siklus, bahkan tanpa clock.
- **Tanpa prosesor dan firmware:** 16 perintah APDU ISO/IEC 7816-4 diterjemahkan langsung oleh `ctrl_fsm`.

## Hasil implementasi

| Parameter | Hasil |
|---|---|
| Perangkat | Cyclone V 5CSEBA6U23I7 (DE10-Nano) |
| Toolchain | Quartus Prime Lite 23.1 |
| Logika | 17.512 ALM (42%) |
| Fmax terburuk (Slow, 1,1 V, 100 °C) | 65,03 MHz (kebutuhan 50 MHz) |
| Memori blok | 10.240 bit (< 1%) |
| DSP | 0 |
| Pin | 10 |
| Verifikasi | 192/192 pengujian otomatis lulus (Icarus Verilog dan ModelSim) |

## Struktur repositori

```
RTL/      Kode Verilog-2001 seluruh modul (top-level: jati_top.v)
SIM/      Testbench self-checking (tb_*.v), skrip ModelSim (*_run.do.txt), model simulasi
IP/       PLL Intel (pll_sys) dari Quartus IP Catalog
QUARTUS/  Proyek Quartus (zeroize.qpf/.qsf, top-level jati_top), diagram RTL dan FSM
```

## Modul RTL

| Kelompok | Modul |
|---|---|
| Komunikasi dan kendali | `uart`, `apdu_parser`, `ctrl_fsm`, `bus_mux` |
| Kriptografi | `sha256_core`, `hmac_kdf`, `aes128_sm` |
| Identitas dan kunci | `ro_puf`, `ro_puf_array`, `fuzzy_ext`, `key_manager`, `trng`, `trng_ro` |
| Penyimpanan data | `dg_memory`, `lifecycle` |
| Keamanan fisik | `tamper_sensor`, `clk_watchdog`, `wd_ro`, `zeroize` |
| Clock dan reset | `clk_rst`, `glitch_inj` (khusus demo; `GLITCH_EN = 0` untuk chip final) |

Satu-satunya IP pihak ketiga adalah PLL Intel. Seluruh modul lain, termasuk inti kriptografi, ditulis oleh tim.

## Menjalankan simulasi (ModelSim)

```
cd SIM
vsim -do jati_top_run.do.txt      # uji sistem lewat pin UART
vsim -do key_manager_run.do.txt   # contoh uji unit
```

Setiap testbench mencetak LULUS/GAGAL secara otomatis.

## Sintesis (Quartus)

Buka `QUARTUS/zeroize.qpf` di Quartus Prime Lite 23.1 lalu jalankan *Compile Design*. Top-level entity adalah `jati_top`, untuk perangkat 5CSEBA6U23I7.

## Pin DE10-Nano

| Pin | Arah | Fungsi | Lokasi |
|---|---|---|---|
| `clk_50` | Masuk | Clock 50 MHz | PIN_V11 |
| `rst_n` | Masuk | Reset, aktif rendah | PIN_AH17 (KEY0) |
| `uart_rx` | Masuk | APDU dari reader | PIN_V12 (GPIO_0[0]) |
| `glitch_test_en` | Masuk | Pemicu glitch (demo) | PIN_Y24 (SW0) |
| `uart_tx` | Keluar | Jawaban ke reader | PIN_E8 (GPIO_0[1]) |
| `led_status[3:0]` | Keluar | Status lifecycle | LED0–LED3 |
| `pll_locked` | Keluar | PLL terkunci | LED4 |

UART 8N1 pada 921.600 baud, dengan frame CRC-16 CCITT.

## Keterbatasan prototipe

- **Verifikasi keaslian chip online.** Verifikasi membutuhkan layanan penerbit karena memakai kunci simetris. Verifikasi offline dengan tanda tangan kunci publik (ECC) direncanakan sebagai tahap berikutnya.
- **Lifecycle volatil di FPGA.** Status lifecycle hilang saat daya mati karena FPGA tidak memiliki OTP. Pada ASIC, status ini disimpan di OTP/eFuse.
- **Proteksi analisis daya terbatas.** Proteksi saat ini berupa pengacakan waktu. *Masking* direncanakan untuk versi ASIC.
- **Penempatan RO belum dikunci.** Quartus Prime Lite tidak mendukung LogicLock.
- **Uniqueness antar-chip baru tervalidasi di simulasi.** Tim baru memiliki satu papan.

## Tim

- Raka Daffa Iftikhaar (ketua)
- Galih Muhammad Syah Athaya
- Bevinda Vivian
- Ayman Rafsanjani Natawijaya

## Lisensi

Dirilis di bawah [Apache License 2.0](LICENSE).
