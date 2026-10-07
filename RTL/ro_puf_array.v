// =============================================================================
// JATI - Bank ring oscillator RO-PUF (UNTUK QUARTUS / FPGA)
// Modul   : ro_puf_array
//
// 1024 RO identik, masing-masing N_STAGE tahap (1 NAND enable + inverter).
// Hanya RO yang indeksnya sama dengan sel_a atau sel_b yang menyala.
//
// PENTING:
//   - TIDAK BISA disimulasikan (loop kombinasional). Untuk ModelSim pakai
//     SIM/ro_puf_array_sim.v.
//   - Masukkan file ini ke proyek Quartus, JANGAN versi _sim.
//   - Quartus akan memberi 1024 peringatan "combinational loop": disengaja.
//   - (* keep *) mencegah Quartus menghapus inverter.
//
// CATATAN PENEMPATAN (penting untuk kualitas PUF):
//   Agar perbedaan frekuensi berasal dari variasi proses silikon (unik per
//   chip), bukan dari perbedaan jalur routing (sama di semua chip), setiap
//   RO idealnya ditempatkan dengan pola identik. Quartus Lite tidak punya
//   LogicLock, jadi penempatan perlu diatur dengan location assignment per
//   sel (skrip Tcl). Tanpa itu, PUF tetap berfungsi, tetapi uniqueness
//   antar-chip bisa turun.
// =============================================================================

module ro_puf_array #(
    parameter integer N_RO    = 1024,
    parameter integer N_STAGE = 3          // ganjil
)(
    input  wire [9:0] sel_a,
    input  wire [9:0] sel_b,
    input  wire       en,
    output wire       ro_a,
    output wire       ro_b
);

    // OPTIMASI B1: dekoder one-hot bersama + multiplekser dua tingkat
    // (32 grup x 32 RO), menggantikan 2 x 1.024 pembanding indeks terpisah.
    wire [N_RO-1:0] ro;
    wire [N_RO-1:0] oh_a = {{(N_RO-1){1'b0}}, 1'b1} << sel_a;
    wire [N_RO-1:0] oh_b = {{(N_RO-1){1'b0}}, 1'b1} << sel_b;

    genvar i, j;
    generate
        for (i = 0; i < N_RO; i = i + 1) begin : g_ro
            wire en_i = en & (oh_a[i] | oh_b[i]);

            (* keep *) wire [N_STAGE-1:0] s;

            assign s[0] = ~(en_i & s[N_STAGE-1]);      // NAND enable
            for (j = 1; j < N_STAGE; j = j + 1) begin : g_inv
                assign s[j] = ~s[j-1];
            end

            assign ro[i] = s[N_STAGE-1];
        end
    endgenerate

    wire [31:0] grp_a = ro[{sel_a[9:5], 5'd0} +: 32];
    wire [31:0] grp_b = ro[{sel_b[9:5], 5'd0} +: 32];
    assign ro_a = grp_a[sel_a[4:0]];
    assign ro_b = grp_b[sel_b[4:0]];

endmodule