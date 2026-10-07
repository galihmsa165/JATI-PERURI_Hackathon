// =============================================================================
// JATI - Sumber entropi TRNG (UNTUK QUARTUS / FPGA)
// Modul   : trng_ro
//
// N_RO ring oscillator berjalan bebas, keluarannya di-XOR. Panjang RO dibuat
// berbeda-beda (3, 5, 7 tahap) agar frekuensinya tidak saling mengunci
// (injection locking), yang akan menurunkan entropi.
//
// PENTING:
//   - File ini TIDAK BISA disimulasikan: loop kombinasional tanpa delay akan
//     membuat simulator berhenti. Untuk ModelSim pakai trng_ro_sim.v.
//   - Masukkan file ini ke proyek Quartus, JANGAN trng_ro_sim.v.
//   - Quartus akan memberi peringatan "combinational loop". Itu disengaja.
//   - (* keep *) mencegah Quartus menghapus inverter-inverter RO.
// =============================================================================

module trng_ro #(
    parameter integer N_RO = 8
)(
    input  wire en,
    output wire raw
);

    wire [N_RO-1:0] ro_out;

    genvar i, j;
    generate
        for (i = 0; i < N_RO; i = i + 1) begin : g_ro
            localparam integer L = 3 + 2 * (i % 3);   // 3, 5, atau 7 tahap

            (* keep *) wire [L-1:0] s;

            // Tahap 0: NAND sebagai enable (RO berhenti saat en = 0)
            assign s[0] = ~(en & s[L-1]);
            for (j = 1; j < L; j = j + 1) begin : g_inv
                assign s[j] = ~s[j-1];
            end

            assign ro_out[i] = s[L-1];
        end
    endgenerate

    assign raw = ^ro_out;

endmodule