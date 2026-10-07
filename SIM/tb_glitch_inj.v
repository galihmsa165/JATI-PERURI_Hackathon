// =============================================================================
// Testbench self-checking untuk modul glitch_inj
// Jalankan:  iverilog -o tb glitch_inj.v tb_glitch_inj.v && vvp tb
// =============================================================================
`timescale 1ns/1ps

module tb_glitch_inj;

    localparam integer N_START  = 4;
    localparam integer N_WIDTH  = 4;
    localparam integer STAGE_PS = 600;
    localparam real    EXP_START = N_START * STAGE_PS / 1000.0;   // 2,4 ns
    localparam real    EXP_WIDTH = N_WIDTH * STAGE_PS / 1000.0;   // 2,4 ns

    reg  clk_pll        = 1'b0;
    reg  glitch_test_en = 1'b0;
    wire clk_sys;       // DUT mode demo
    wire clk_sys_bp;    // DUT mode chip final (bypass)

    integer errors = 0;

    glitch_inj #(.ENABLE(1), .N_START(N_START), .N_WIDTH(N_WIDTH), .STAGE_PS(STAGE_PS)) dut (
        .clk_pll        (clk_pll),
        .glitch_test_en (glitch_test_en),
        .clk_sys        (clk_sys)
    );

    glitch_inj #(.ENABLE(0)) dut_bp (
        .clk_pll        (clk_pll),
        .glitch_test_en (glitch_test_en),
        .clk_sys        (clk_sys_bp)
    );

    // clk_pll 50 MHz (periode 20 ns)
    always #10 clk_pll = ~clk_pll;

    initial begin
        $dumpfile("tb_glitch_inj.vcd");
        $dumpvars(0, tb_glitch_inj);
    end

    // -------------------------------------------------------------------------
    // Monitor: pulsa tambahan = tepi naik clk_sys saat clk_pll sedang rendah
    // -------------------------------------------------------------------------
    real    t_negpll = 0.0;
    real    rise_off = 0.0;     // waktu mulai pulsa, diukur dari tepi turun clk_pll
    real    fall_off = 0.0;     // waktu akhir pulsa, diukur dari tepi turun clk_pll
    integer extra    = 0;
    integer extra_bp = 0;
    integer mism_bp  = 0;
    reg     mon_on   = 1'b0;
    reg     in_glitch = 1'b0;   // 1 = sedang di dalam pulsa glitch

    always @(negedge clk_pll) t_negpll = $realtime;

    always @(posedge clk_sys)
        if (mon_on && clk_pll === 1'b0) begin
            extra     = extra + 1;
            rise_off  = $realtime - t_negpll;
            in_glitch = 1'b1;
        end

    // Hanya tepi turun milik pulsa glitch yang diukur (bebas race dengan
    // tepi turun normal clk_pll)
    always @(negedge clk_sys)
        if (in_glitch) begin
            fall_off  = $realtime - t_negpll;
            in_glitch = 1'b0;
        end

    always @(posedge clk_sys_bp)
        if (mon_on && clk_pll === 1'b0) extra_bp = extra_bp + 1;

    // Mode bypass harus identik dengan clk_pll setiap saat.
    // Sampel digeser 0,125 ns agar tidak pernah jatuh tepat di tepi clock
    // (menghindari race urutan event antar-simulator).
    initial begin
        #0.125;
        forever begin
            if (mon_on && clk_sys_bp !== clk_pll) mism_bp = mism_bp + 1;
            #0.25;
        end
    end

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

    // -------------------------------------------------------------------------
    initial begin
        #100 mon_on = 1'b1;

        // 1. Tanpa perintah: tidak ada glitch
        repeat (50) @(posedge clk_pll);
        check(extra == 0, "1. Tanpa perintah: clk_sys bersih, tanpa glitch");

        // 2. Saklar dinyalakan di waktu acak (asinkron): tepat satu glitch
        #7.3 glitch_test_en = 1'b1;
        repeat (10) @(posedge clk_pll);
        check(extra == 1, "2. Satu tekan saklar = tepat satu glitch");

        // 3. Lebar pulsa sesuai N_WIDTH x STAGE_PS
        $display("        (pulsa mulai %0.2f ns, berakhir %0.2f ns setelah tepi turun clk_pll)",
                 rise_off, fall_off);
        check((fall_off - rise_off) > EXP_WIDTH - 0.05 && (fall_off - rise_off) < EXP_WIDTH + 0.05,
              "3. Lebar pulsa = N_WIDTH x STAGE_PS");

        // 4. Posisi pulsa: mulai setelah N_START tahap, selesai sebelum tepi naik
        check(rise_off > EXP_START - 0.05 && rise_off < EXP_START + 0.05,
              "4a. Pulsa mulai setelah N_START x STAGE_PS");
        check(fall_off < 10.0, "4b. Pulsa selesai di dalam fase rendah clk_pll");

        // 5. Saklar ditahan: tidak boleh ada glitch tambahan (one-shot)
        repeat (50) @(posedge clk_pll);
        check(extra == 1, "5. Saklar ditahan: tetap hanya satu glitch");

        // 6. Saklar dilepas lalu ditekan lagi: satu glitch baru
        glitch_test_en = 1'b0;
        repeat (10) @(posedge clk_pll);
        #3.1 glitch_test_en = 1'b1;
        repeat (10) @(posedge clk_pll);
        check(extra == 2, "6. Tekan ulang = satu glitch baru");

        // 7. Mode chip final (ENABLE=0): clk_sys selalu identik dengan clk_pll
        check(extra_bp == 0 && mism_bp == 0, "7. Mode bypass: clk_sys identik dengan clk_pll");

        // Ringkasan
        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule