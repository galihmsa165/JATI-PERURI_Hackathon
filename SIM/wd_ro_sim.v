// =============================================================================
// JATI - Model ring oscillator watchdog, KHUSUS SIMULASI (jangan ke Quartus)
// Periode ~3 ns (setengah periode 1,5 ns) saat en = 1; diam di 0 saat en = 0.
// =============================================================================
`timescale 1ns/1ps
module wd_ro (
    input  wire en,
    output reg  ro
);
    initial ro = 1'b0;
    always begin
        if (en === 1'b1) begin #1.5 ro = ~ro; end
        else begin ro = 1'b0; @(en); end
    end
endmodule