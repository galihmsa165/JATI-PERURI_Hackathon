// =============================================================================
// Testbench self-checking untuk modul clk_rst
// Kompilasi bersama model PLL simulasi:
//   iverilog -o tb pll_sys_sim.v clk_rst.v tb_clk_rst.v && vvp tb
// =============================================================================
`timescale 1ns/1ps

module tb_clk_rst;

    localparam integer HOLD     = 16;
    localparam integer MIN_RST  = HOLD + 3;   // sinkronizer 3 FF + penahan

    reg  clk_50 = 1'b0;
    reg  rst_n  = 1'b0;          // tombol ditekan saat menyala
    wire clk_pll;
    wire rst_sync_n;
    wire pll_locked;

    integer errors = 0;
    integer n_cyc;
    real    t1, t2;
    reg     watch_stable = 1'b0;
    integer spurious     = 0;

    clk_rst #(.HOLD_CYCLES(HOLD)) dut (
        .clk_50     (clk_50),
        .rst_n      (rst_n),
        .clk_pll    (clk_pll),
        .rst_sync_n (rst_sync_n),
        .pll_locked (pll_locked)
    );

    // Clock papan 50 MHz
    always #10 clk_50 = ~clk_50;

    initial begin
        $dumpfile("tb_clk_rst.vcd");
        $dumpvars(0, tb_clk_rst);
    end

    // -------------------------------------------------------------------------
    // Monitor 1: setiap kali reset dilepas, harus tepat setelah tepi naik clock
    // -------------------------------------------------------------------------
    always @(posedge rst_sync_n) begin
        if (clk_pll !== 1'b1) begin
            $display("[GAGAL] Reset dilepas TIDAK sinkron dengan clk_pll (t=%0t)", $time);
            errors = errors + 1;
        end
    end

    // Monitor 2: selama periode stabil, reset tidak boleh aktif sendiri
    always @(negedge rst_sync_n) if (watch_stable) spurious = spurious + 1;

    // -------------------------------------------------------------------------
    task check(input ok, input [8*64-1:0] msg);
        begin
            if (ok) $display("[LULUS] %0s", msg);
            else begin
                $display("[GAGAL] %0s (t=%0t)", msg, $time);
                errors = errors + 1;
            end
        end
    endtask

    // Hitung tepi clk_pll sampai reset dilepas (dengan batas waktu)
    task count_until_release(output integer cycles);
        begin
            cycles = 0;
            while (rst_sync_n !== 1'b1 && cycles < 1000) begin
                @(posedge clk_pll); #1;
                cycles = cycles + 1;
            end
        end
    endtask

    // -------------------------------------------------------------------------
    initial begin
        // 1. Saat menyala dengan tombol reset ditekan
        #100;
        check(rst_sync_n === 1'b0, "1a. Reset aktif saat tombol ditekan");
        check(pll_locked === 1'b0, "1b. PLL belum terkunci saat direset");

        // 2. Tombol dilepas: PLL mengunci, reset masih ditahan
        rst_n = 1'b1;
        @(posedge pll_locked); #1;
        check(rst_sync_n === 1'b0, "2. Reset masih aktif tepat saat PLL baru terkunci");

        // 3. Reset dilepas setelah sinkronizer + penahan
        count_until_release(n_cyc);
        $display("        (reset dilepas setelah %0d siklus clk_pll)", n_cyc);
        check(rst_sync_n === 1'b1 && n_cyc >= MIN_RST, "3. Reset dilepas setelah minimal HOLD+3 siklus");

        // 4. Frekuensi clk_pll = 50 MHz (periode 20 ns)
        @(posedge clk_pll); t1 = $realtime;
        @(posedge clk_pll); t2 = $realtime;
        check((t2 - t1) > 19.99 && (t2 - t1) < 20.01, "4. Periode clk_pll = 20 ns (50 MHz)");

        // 5. Stabil: tidak ada reset palsu selama 200 siklus
        watch_stable = 1'b1;
        repeat (200) @(posedge clk_pll);
        watch_stable = 1'b0;
        check(spurious == 0 && rst_sync_n === 1'b1, "5. Stabil 200 siklus tanpa reset palsu");

        // 6. Assert asinkron: tombol ditekan di tengah siklus
        @(posedge clk_pll); #5;
        rst_n = 1'b0; #1;
        check(rst_sync_n === 1'b0, "6a. Reset aktif seketika tanpa menunggu clock");
        #200 rst_n = 1'b1;
        @(posedge pll_locked); #1;
        count_until_release(n_cyc);
        check(rst_sync_n === 1'b1 && n_cyc >= MIN_RST, "6b. Pulih normal setelah tombol dilepas");

        // 7. Glitch reset sangat pendek (2 ns) tetap menghasilkan reset penuh
        @(posedge clk_pll); #3;
        rst_n = 1'b0; #2 rst_n = 1'b1; #1;
        check(rst_sync_n === 1'b0, "7a. Glitch 2 ns tetap memicu reset");
        @(posedge pll_locked); #1;
        count_until_release(n_cyc);
        check(rst_sync_n === 1'b1 && n_cyc >= MIN_RST, "7b. Glitch diperpanjang menjadi reset penuh");

        // 8. PLL kehilangan kunci (misalnya clock masukan diganggu)
        @(posedge clk_pll); #4;
        force dut.u_pll.locked = 1'b0; #1;
        check(rst_sync_n === 1'b0, "8a. Kehilangan kunci PLL langsung memicu reset");
        #100 release dut.u_pll.locked;
        @(posedge pll_locked); #1;
        count_until_release(n_cyc);
        check(rst_sync_n === 1'b1 && n_cyc >= MIN_RST, "8b. Reset dilepas lagi setelah PLL terkunci");

        // Ringkasan
        #100;
        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule