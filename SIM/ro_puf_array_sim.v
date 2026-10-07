// =============================================================================
// JATI - Model bank RO-PUF untuk SIMULASI SAJA
// Modul   : ro_puf_array (nama sama dengan versi FPGA)
//
// PENTING: Hanya untuk ModelSim/Icarus. JANGAN dimasukkan ke proyek Quartus.
//
// Model:
//   - Setiap RO punya setengah-periode dasar 5,0 ns +/- 5% yang ditentukan
//     oleh hash(CHIP_SEED, indeks). CHIP_SEED berbeda = "chip" berbeda,
//     meniru variasi proses silikon.
//   - Setiap setengah-periode ditambah jitter acak +/- JIT_PS pikodetik.
//   - Saat en = 0, keluaran diam di 0.
// =============================================================================
`timescale 1ns/1ps

module ro_puf_array #(
    parameter integer N_RO      = 1024,
    parameter integer N_STAGE   = 3,
    parameter integer CHIP_SEED = 1,
    parameter integer JIT_PS    = 5
)(
    input  wire [9:0] sel_a,
    input  wire [9:0] sel_b,
    input  wire       en,
    output reg        ro_a,
    output reg        ro_b
);

    // Hash 32 bit (lowbias32) agar frekuensi antar-RO tidak berkorelasi
    function real half_period(input [9:0] idx);
        reg [31:0] x;
        begin
            x = {22'd0, idx} * 32'h9E3779B1 + CHIP_SEED * 32'h85EBCA6B;
            x = x ^ (x >> 16);
            x = x * 32'h7FEB352D;
            x = x ^ (x >> 15);
            x = x * 32'h846CA68B;
            x = x ^ (x >> 16);
            half_period = 4.75 + (x % 501) / 1000.0;   // 4,75 .. 5,25 ns
        end
    endfunction

    integer js_a = 101;
    integer js_b = 202;

    initial begin
        ro_a = 1'b0;
        ro_b = 1'b0;
    end

    always begin
        if (en === 1'b1) begin
            #(half_period(sel_a) + ($random(js_a) % (JIT_PS + 1)) / 1000.0);
            ro_a = ~ro_a;
        end else begin
            ro_a = 1'b0;
            @(en);
        end
    end

    always begin
        if (en === 1'b1) begin
            #(half_period(sel_b) + ($random(js_b) % (JIT_PS + 1)) / 1000.0);
            ro_b = ~ro_b;
        end else begin
            ro_b = 1'b0;
            @(en);
        end
    end

endmodule