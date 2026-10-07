// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : zeroize
// Fungsi  : Membangkitkan sinyal global "zeroize" yang menghapus semua rahasia
//           (kunci, round key, ipad/opad, respons PUF, dsb.) saat ada serangan.
//
// Prinsip desain (security-by-design):
//   1. Jalur langsung (kombinasional): zeroize aktif dalam hitungan nanodetik
//      begitu tamper_alarm naik, TANPA menunggu clock. Penting karena serangan
//      glitch justru menyerang clock.
//   2. Dua register "armed" independen (redundansi): setelah alarm, zeroize
//      tetap aktif walaupun tamper_alarm turun lagi. Kalau satu register
//      terbalik akibat fault injection, register satunya tetap menahan zeroize.
//   3. Fail-safe saat menyala: sebelum reset pertama, zeroize AKTIF.
//   4. Self-healing: jika kedua register armed berbeda (tanda fault), keduanya
//      dipaksa ke kondisi aman pada tepi clock berikutnya. Fault tunggal tidak
//      bisa "bersembunyi" lalu digabung dengan fault kedua.
//   5. Zeroize hanya bisa dilepas lewat reset, dan pelepasannya sinkron
//      terhadap clk_sys (aman untuk register penerima).
//
// Antarmuka:
//   clk_sys      : clock sistem (net global)
//   rst_sync_n   : reset aktif rendah, sudah tersinkron (net global)
//   tamper_alarm : dari tamper_sensor, HARUS keluaran register (bebas glitch)
//   zeroize      : aktif tinggi, ke semua blok penyimpan rahasia
//
// Catatan kontrak untuk blok penerima:
//   Gunakan zeroize sebagai clear ASINKRON pada register rahasia, misalnya:
//     always @(posedge clk_sys or posedge zeroize)
//       if (zeroize) key_reg <= 128'd0;
//       else ...
// =============================================================================

module zeroize (
    input  wire clk_sys,
    input  wire rst_sync_n,
    input  wire tamper_alarm,
    output wire zeroize
);

    // -------------------------------------------------------------------------
    // Dua register armed yang identik tetapi WAJIB tetap terpisah.
    // (* preserve *) mencegah Quartus menggabungkan keduanya menjadi satu
    // register (optimasi yang akan menghilangkan redundansi).
    // Nilai awal 0 = "belum aman" -> zeroize aktif sampai reset pertama.
    // -------------------------------------------------------------------------
    (* preserve *) reg armed_a = 1'b0;
    (* preserve *) reg armed_b = 1'b0;

    // Clear asinkron oleh tamper_alarm, di-arm ulang secara sinkron saat reset,
    // dan saling memeriksa (self-healing) di setiap tepi clock.
    always @(posedge clk_sys or posedge tamper_alarm) begin
        if (tamper_alarm)
            armed_a <= 1'b0;            // alarm: langsung tidak aman
        else if (!rst_sync_n)
            armed_a <= 1'b1;            // reset: arm ulang
        else if (armed_a != armed_b)
            armed_a <= 1'b0;            // ketidakcocokan = fault: kembali aman
    end

    always @(posedge clk_sys or posedge tamper_alarm) begin
        if (tamper_alarm)
            armed_b <= 1'b0;            // alarm: langsung tidak aman
        else if (!rst_sync_n)
            armed_b <= 1'b1;            // reset: arm ulang
        else if (armed_a != armed_b)
            armed_b <= 1'b0;            // ketidakcocokan = fault: kembali aman
    end

    // -------------------------------------------------------------------------
    // Keluaran: aktif jika SALAH SATU kondisi terpenuhi.
    //   - tamper_alarm        : jalur langsung, tanpa clock
    //   - ~armed_a / ~armed_b : jalur sticky, cukup salah satu
    // Akibatnya: satu fault yang membalik satu register tidak bisa
    // mematikan zeroize.
    // -------------------------------------------------------------------------
    (* keep *) wire path_direct = tamper_alarm;
    (* keep *) wire path_a      = ~armed_a;
    (* keep *) wire path_b      = ~armed_b;

    assign zeroize = path_direct | path_a | path_b;

endmodule