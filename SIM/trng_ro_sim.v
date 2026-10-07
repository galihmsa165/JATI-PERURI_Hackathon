// =============================================================================
// JATI - Model sumber entropi TRNG untuk SIMULASI SAJA
// Modul   : trng_ro (nama sama dengan versi FPGA)
//
// PENTING: Hanya untuk ModelSim/Icarus. JANGAN dimasukkan ke proyek Quartus.
//
// Meniru ring oscillator dengan jitter: keluaran berbalik pada interval acak
// 0,5 - 4,5 ns selama en = 1, dan diam di 0 saat en = 0.
// =============================================================================
`timescale 1ns/1ps

module trng_ro #(
    parameter integer N_RO = 8,      // tidak dipakai, agar port/parameter sama
    parameter integer SEED = 20261003
)(
    input  wire en,
    output reg  raw
);

    integer seed;
    real    d;

    initial begin
        raw  = 1'b0;
        seed = SEED;
    end

    always begin
        if (en) begin
            d = 0.5 + ($random(seed) & 1023) / 256.0;
            #(d) raw = ~raw;
        end else begin
            raw = 1'b0;
            @(en);
        end
    end

endmodule