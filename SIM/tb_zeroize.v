// =============================================================================
// Testbench self-checking untuk modul zeroize
// Jalankan:  iverilog -o tb tb_zeroize.v zeroize.v && vvp tb
// =============================================================================
`timescale 1ns/1ps

module tb_zeroize;

    reg  clk_sys      = 1'b0;
    reg  rst_sync_n   = 1'b1;
    reg  tamper_alarm = 1'b0;
    reg  clk_en       = 1'b1;
    wire zeroize;

    integer errors = 0;

    zeroize dut (
        .clk_sys      (clk_sys),
        .rst_sync_n   (rst_sync_n),
        .tamper_alarm (tamper_alarm),
        .zeroize      (zeroize)
    );

    // Clock 50 MHz (periode 20 ns), bisa dimatikan untuk uji "clock mati"
    always #10 if (clk_en) clk_sys = ~clk_sys;

    initial begin
        $dumpfile("tb_zeroize.vcd");
        $dumpvars(0, tb_zeroize);
    end

    task check(input expected, input [8*48-1:0] msg);
        begin
            if (zeroize !== expected) begin
                $display("[GAGAL] %0s : zeroize=%b, harapan=%b (t=%0t)", msg, zeroize, expected, $time);
                errors = errors + 1;
            end else
                $display("[LULUS] %0s", msg);
        end
    endtask

    task do_reset;
        begin
            rst_sync_n = 1'b0;
            repeat (3) @(posedge clk_sys);
            #1 rst_sync_n = 1'b1;
            @(posedge clk_sys); #1;
        end
    endtask

    initial begin
        // 1. Fail-safe saat menyala: sebelum reset, zeroize harus aktif
        #5;
        check(1'b1, "1. Aktif saat menyala sebelum reset");

        // 2. Setelah reset, zeroize harus lepas
        do_reset();
        check(1'b0, "2. Lepas setelah reset");

        // 3. Pulsa alarm sangat singkat (3 ns) di antara dua tepi clock:
        //    harus langsung aktif dan tetap aktif setelah pulsa hilang
        @(posedge clk_sys); #4;
        tamper_alarm = 1'b1; #1;
        check(1'b1, "3a. Aktif seketika tanpa menunggu clock");
        #2 tamper_alarm = 1'b0; #1;
        check(1'b1, "3b. Tetap aktif setelah pulsa alarm hilang");
        repeat (5) @(posedge clk_sys); #1;
        check(1'b1, "3c. Tetap aktif beberapa siklus kemudian");

        // 4. Simulasi fault injection: satu register armed dibalik ke 1
        force dut.armed_a = 1'b1; #1;
        check(1'b1, "4a. Satu register dibalik: tetap aktif");
        release dut.armed_a;                 // nilai 1 tertinggal di register
        @(posedge clk_sys); #1;              // self-healing di tepi berikutnya
        if (dut.armed_a !== 1'b0) begin
            $display("[GAGAL] 4b. Register terbalik tidak dipulihkan");
            errors = errors + 1;
        end else
            $display("[LULUS] 4b. Register terbalik dipulihkan ke aman dalam 1 siklus");
        force dut.armed_b = 1'b1; #1;        // fault kedua di register lain
        check(1'b1, "4c. Fault kedua (setelah pulih): tetap aktif");
        release dut.armed_b;
        @(posedge clk_sys); #1;

        // 5. Reset meng-arm ulang
        do_reset();
        check(1'b0, "5. Lepas lagi setelah reset");

        // 6. Clock dimatikan (serangan menghentikan clock), lalu alarm
        clk_en = 1'b0; #50;
        tamper_alarm = 1'b1; #1;
        check(1'b1, "6a. Aktif walaupun clock mati");
        #5 tamper_alarm = 1'b0; #50;
        check(1'b1, "6b. Tetap aktif walaupun clock mati");
        clk_en = 1'b1;

        // 7. Reset tidak bisa melepas zeroize selama alarm masih aktif
        tamper_alarm = 1'b1;
        rst_sync_n = 1'b0; repeat (3) @(posedge clk_sys);
        rst_sync_n = 1'b1; repeat (2) @(posedge clk_sys); #1;
        check(1'b1, "7. Alarm masih aktif: reset tidak melepas");
        tamper_alarm = 1'b0;

        // Ringkasan
        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule