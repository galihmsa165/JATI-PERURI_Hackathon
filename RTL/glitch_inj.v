// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : glitch_inj  (KHUSUS DEMO, dimatikan di chip final)
// Fungsi  : Menyuntikkan satu pulsa clock palsu (glitch) ke clk_sys untuk
//           menguji apakah tamper_sensor mendeteksi serangan clock glitch.
//
// Bentuk glitch:
//   clk_pll  : ‾‾‾‾‾‾‾‾‾‾|__________|‾‾‾‾‾‾‾‾‾‾
//   clk_sys  : ‾‾‾‾‾‾‾‾‾‾|__|‾‾|____|‾‾‾‾‾‾‾‾‾‾
//                           ^^^^ pulsa sempit di tengah fase rendah
//   Register penerima melihat dua tepi naik dalam satu periode: siklus
//   menjadi jauh lebih pendek dari 20 ns, persis seperti serangan glitch.
//
// Cara kerja:
//   1. glitch_test_en (saklar/pin, asinkron) disinkronkan, lalu dideteksi
//      tepi naiknya: SATU tekan = SATU glitch (one-shot).
//   2. Pada tepi turun clk_pll, sinyal trig berbalik (toggle).
//   3. trig dilewatkan rantai inverter. Pulsa = XOR dua titik di rantai:
//      mulai setelah N_START tahap, lebar N_WIDTH tahap.
//   4. clk_sys = clk_pll OR pulsa.
//
// Parameter:
//   ENABLE   : 1 = mode demo, 0 = bypass total (clk_sys = clk_pll),
//              dipakai untuk chip final.
//   N_START  : jumlah tahap delay sebelum pulsa dimulai
//   N_WIDTH  : jumlah tahap delay = lebar pulsa (HARUS GENAP)
//   STAGE_PS : delay per tahap, HANYA untuk simulasi. Quartus mengabaikan
//              delay "#" dan memakai delay LUT asli (sekitar 0,5-1 ns/tahap).
//
// Catatan hardware:
//   - Lebar pulsa sebenarnya di FPGA bergantung pada delay LUT dan routing.
//     Ukur dengan tamper_sensor (TDC) lalu atur N_START/N_WIDTH agar pulsa
//     selesai sebelum tepi naik berikutnya (10 ns setelah tepi turun).
//   - Quartus akan memberi peringatan "gated clock" / "ignored delay".
//     Untuk modul ini, peringatan tersebut memang disengaja.
// =============================================================================
`timescale 1ns/1ps

module glitch_inj #(
    parameter integer ENABLE   = 1,
    parameter integer N_START  = 4,
    parameter integer N_WIDTH  = 4,
    parameter integer STAGE_PS = 600
)(
    input  wire clk_pll,
    input  wire glitch_test_en,
    output wire clk_sys
);

    localparam integer N_TOTAL = N_START + N_WIDTH;

    genvar i;

    generate
    if (ENABLE == 0) begin : g_bypass
        // ---------------------------------------------------------------------
        // Chip final: tidak ada logika sama sekali di jalur clock
        // ---------------------------------------------------------------------
        assign clk_sys = clk_pll;

    end else begin : g_inj
        // ---------------------------------------------------------------------
        // 1. Sinkronizer + deteksi tepi naik (domain tepi turun clk_pll)
        // ---------------------------------------------------------------------
        reg en_s1 = 1'b0;
        reg en_s2 = 1'b0;
        reg en_s3 = 1'b0;
        reg trig  = 1'b0;

        always @(negedge clk_pll) begin
            en_s1 <= glitch_test_en;
            en_s2 <= en_s1;
            en_s3 <= en_s2;
            if (en_s2 && !en_s3)
                trig <= ~trig;          // satu toggle = satu glitch
        end

        // ---------------------------------------------------------------------
        // 2. Rantai inverter (delay line). (* keep *) mencegah Quartus
        //    menghapus pasangan inverter yang secara logika saling meniadakan.
        // ---------------------------------------------------------------------
        (* keep *) wire [N_TOTAL:0] dly;
        assign dly[0] = trig;

        for (i = 0; i < N_TOTAL; i = i + 1) begin : g_chain
            assign #(STAGE_PS / 1000.0) dly[i+1] = ~dly[i];
        end

        // ---------------------------------------------------------------------
        // 3. Pulsa sempit: aktif selama transisi merambat dari titik N_START
        //    ke titik N_TOTAL. N_WIDTH genap -> kedua titik berpolaritas sama.
        // ---------------------------------------------------------------------
        (* keep *) wire pulse = dly[N_START] ^ dly[N_TOTAL];

        assign clk_sys = clk_pll | pulse;
    end
    endgenerate

endmodule