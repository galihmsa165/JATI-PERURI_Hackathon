// =============================================================================
// JATI - Model perilaku PLL untuk SIMULASI SAJA
// Modul   : pll_sys (nama sama dengan IP PLL yang dibuat di Quartus)
//
// PENTING: File ini hanya untuk ModelSim/Icarus. JANGAN dimasukkan ke proyek
// Quartus, karena Quartus memakai pll_sys hasil IP Catalog. Kalau keduanya
// masuk, akan terjadi error "module pll_sys sudah didefinisikan".
//
// Perilaku yang dimodelkan:
//   - Selama rst = 1          : locked = 0, outclk_0 diam di 0
//   - Setelah rst dilepas     : locked = 1 setelah LOCK_CYCLES siklus refclk
//   - Setelah locked          : outclk_0 = refclk (50 MHz -> 50 MHz)
// =============================================================================
`timescale 1ns/1ps

module pll_sys #(
    parameter integer LOCK_CYCLES = 20
)(
    input  wire refclk,
    input  wire rst,
    output wire outclk_0,
    output reg  locked
);

    integer cnt;

    initial begin
        locked = 1'b0;
        cnt    = 0;
    end

    // Diperbarui di tepi turun agar outclk_0 mulai bersih di tepi naik berikutnya
    always @(negedge refclk or posedge rst) begin
        if (rst) begin
            cnt    <= 0;
            locked <= 1'b0;
        end else if (cnt < LOCK_CYCLES) begin
            cnt    <= cnt + 1;
        end else begin
            locked <= 1'b1;
        end
    end

    assign outclk_0 = locked ? refclk : 1'b0;

endmodule