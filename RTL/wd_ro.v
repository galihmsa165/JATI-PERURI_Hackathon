// =============================================================================
// JATI - Ring oscillator untuk watchdog clock (UNTUK QUARTUS / FPGA)
// Modul   : wd_ro
// 5 tahap (1 NAND enable + 4 inverter). TIDAK bisa disimulasikan (loop
// kombinasional); untuk ModelSim pakai SIM/wd_ro_sim.v.
// =============================================================================
module wd_ro (
    input  wire en,
    output wire ro
);
    (* keep *) wire [4:0] s;
    assign s[0] = ~(en & s[4]);
    assign s[1] = ~s[0];
    assign s[2] = ~s[1];
    assign s[3] = ~s[2];
    assign s[4] = ~s[3];
    assign ro = s[4];
endmodule