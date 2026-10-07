// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : clk_watchdog   (revisi keamanan A11)
// Fungsi  : Mendeteksi clock sistem yang DIHENTIKAN atau diperlambat drastis.
//
// Detektor lain di tamper_sensor butuh tepi clock untuk bekerja, sehingga
// clock yang dihentikan total tidak terdeteksi. Watchdog ini memakai ring
// oscillator independen (wd_ro) sebagai clock pembanding:
//   - Domain clk_sys: register tog berbalik setiap siklus.
//   - Domain RO: tog disinkronkan; setiap kali tidak berubah, penghitung naik.
//     Penghitung mencapai LIMIT (tidak ada tepi clk_sys selama LIMIT periode
//     RO) -> stop = 1 dan terkunci sampai reset.
// stop adalah keluaran register di domain RO, sehingga bisa langsung memicu
// zeroize secara asinkron walaupun clk_sys mati.
// Watchdog hanya aktif setelah reset dilepas (PLL sudah terkunci).
// =============================================================================
module clk_watchdog #(
    parameter integer LIMIT = 128    // periode RO tanpa tepi clk_sys
)(
    input  wire clk_sys,
    input  wire rst_sync_n,
    output reg  stop = 1'b0      // nilai power-up (FPGA) agar tidak pernah X
);
    // Domain clk_sys
    reg tog = 1'b0;
    always @(posedge clk_sys or negedge rst_sync_n)
        if (!rst_sync_n) tog <= 1'b0;
        else             tog <= ~tog;

    // Ring oscillator independen
    wire ro;
    wd_ro u_ro (.en(rst_sync_n), .ro(ro));

    // Domain RO
    reg       s1 = 1'b0, s2 = 1'b0, s3 = 1'b0;
    reg [7:0] cnt = 8'd0;
    always @(posedge ro or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            s1 <= 1'b0; s2 <= 1'b0; s3 <= 1'b0; cnt <= 8'd0; stop <= 1'b0;
        end else begin
            s1 <= tog; s2 <= s1; s3 <= s2;
            if (s2 != s3)              cnt <= 8'd0;
            else if (cnt != 8'hFF)     cnt <= cnt + 1'b1;
            if (cnt == LIMIT[7:0])     stop <= 1'b1;
        end
    end
endmodule