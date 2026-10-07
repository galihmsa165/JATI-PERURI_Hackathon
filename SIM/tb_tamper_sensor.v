// =============================================================================
// Testbench self-checking untuk modul tamper_sensor
// Jalankan:  iverilog -o tb tamper_sensor.v tb_tamper_sensor.v && vvp tb
//
// Testbench membangkitkan clock sendiri, termasuk:
//   - glitch (pulsa sempit 2,4 ns di tengah fase rendah, seperti glitch_inj)
//   - fase rendah yang dipendekkan
//   - perubahan frekuensi (overclock / underclock)
//
// Aturan anti-race:
//   1. Masukan diubah 1 ns setelah tepi clock, pengecekan saat kondisi tenang.
//   2. Monitor memakai penanda keadaan (mon_on) dan baru aktif setelah reset.
//   3. Pengecekan sinyal yang mungkin X memakai ===.
// =============================================================================
`timescale 1ns/1ps

module tb_tamper_sensor;

    reg        rst_sync_n = 1'b0;
    reg        fsm_fault  = 1'b0;
    wire       tamper_alarm;
    wire [2:0] tamper_cause;

    integer errors  = 0;
    integer bad_reg = 0;
    reg     mon_on  = 1'b0;

    // -------------------------------------------------------------------------
    // Pembangkit clock yang bisa diatur
    // -------------------------------------------------------------------------
    real hp_hi = 10.0;      // lama fase tinggi (ns)
    real hp_lo = 10.0;      // lama fase rendah (ns)
    reg  clk_base = 1'b0;
    reg  gp       = 1'b0;   // pulsa glitch tambahan
    reg  clk_stop = 1'b0;   // A11: menghentikan clock
    wire clk_sys  = (clk_base | gp) & ~clk_stop;

    initial begin
        #5;
        forever begin
            clk_base = 1'b1; #(hp_hi);
            clk_base = 1'b0; #(hp_lo);
        end
    end

    tamper_sensor dut (
        .clk_sys      (clk_sys),
        .rst_sync_n   (rst_sync_n),
        .fsm_fault    (fsm_fault),
        .tamper_alarm (tamper_alarm),
        .tamper_cause (tamper_cause)
    );

    initial begin
        $dumpfile("tb_tamper_sensor.vcd");
        $dumpvars(0, tb_tamper_sensor);
    end

    // Monitor: tamper_alarm hanya boleh naik tepat setelah tepi naik clock
    // (bukti bahwa ia keluaran register, syarat dari modul zeroize)
    always @(posedge tamper_alarm)
        if (mon_on && clk_sys !== 1'b1) bad_reg = bad_reg + 1;

    // -------------------------------------------------------------------------
    task check(input ok, input [8*64-1:0] msg);
        begin
            if (ok) $display("[LULUS] %0s", msg);
            else begin
                $display("[GAGAL] %0s (alarm=%b cause=%b, t=%0t)", msg,
                         tamper_alarm, tamper_cause, $time);
                errors = errors + 1;
            end
        end
    endtask

    task set_mhz(input real mhz);
        begin
            hp_hi = 500.0 / mhz;
            hp_lo = 500.0 / mhz;
        end
    endtask

    task do_reset;
        begin
            set_mhz(50.0);
            rst_sync_n = 1'b0;
            repeat (3) @(posedge clk_base);
            #1 rst_sync_n = 1'b1;
            repeat (20) @(posedge clk_base);   // lewati jendela aktivasi
            #1;
        end
    endtask

    // Glitch: pulsa 2,4 ns, mulai 2,4 ns setelah tepi turun
    task inject_glitch;
        begin
            @(negedge clk_base);
            #2.4 gp = 1'b1;
            #2.4 gp = 1'b0;
        end
    endtask

    // Satu siklus dengan fase rendah hanya 2 ns
    task short_low;
        begin
            @(posedge clk_base); #1;
            hp_lo = 2.0;
            @(posedge clk_base); #1;
            hp_lo = 10.0;
        end
    endtask

    // -------------------------------------------------------------------------
    initial begin
        do_reset();
        mon_on = 1'b1;

        // 1. Operasi normal 50 MHz: tidak boleh ada alarm palsu
        repeat (300) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b0 && tamper_cause === 3'b000, "1. 50 MHz normal: tanpa alarm palsu");

        // 2. Toleransi: sedikit lebih cepat dan jauh lebih lambat tetap aman
        set_mhz(55.0);
        repeat (300) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b0, "2a. 55 MHz (+10%): tanpa alarm");
        set_mhz(25.0);
        repeat (100) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b0, "2b. 25 MHz (lebih lambat): tanpa alarm");
        set_mhz(50.0);
        repeat (20) @(posedge clk_base); #1;

        // 3. Serangan clock glitch
        inject_glitch();
        repeat (3) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b1 && tamper_cause[0] === 1'b1, "3. Glitch 2,4 ns terdeteksi (cause[0])");

        // 4. Alarm terkunci walau clock kembali normal
        repeat (200) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b1, "4. Alarm tetap menyala setelah serangan berhenti");

        // 5. Reset menghapus alarm
        do_reset();
        check(tamper_alarm === 1'b0 && tamper_cause === 3'b000, "5. Reset menghapus alarm");

        // 6. Fase rendah dipendekkan (distorsi duty cycle)
        short_low();
        repeat (3) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b1 && tamper_cause[0] === 1'b1, "6. Fase rendah 2 ns terdeteksi (cause[0])");

        // 7. Overclock 70 MHz: hanya canary yang terpicu
        do_reset();
        set_mhz(70.0);
        repeat (10) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b1 && tamper_cause === 3'b010, "7. Overclock 70 MHz terdeteksi canary (cause=010)");

        // 8. Fault di FSM (pulsa 1 siklus)
        do_reset();
        @(posedge clk_base); #1 fsm_fault = 1'b1;
        @(posedge clk_base); #1 fsm_fault = 1'b0;
        repeat (2) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b1 && tamper_cause === 3'b100, "8. FSM fault terdeteksi (cause=100)");

        // 9. Alarm selalu keluar dari register
        check(bad_reg == 0, "9. tamper_alarm selalu naik tepat di tepi clock (register)");

        // 10. Clock dihentikan total (A11): alarm tanpa tepi clock
        do_reset();
        @(negedge clk_base); #1 clk_stop = 1'b1;
        #2000;
        check(tamper_alarm === 1'b1, "10a. Clock berhenti 2 us: alarm menyala tanpa clock");
        clk_stop = 1'b0;
        repeat (5) @(posedge clk_base); #1;
        check(tamper_cause[0] === 1'b1, "10b. Saat clock kembali, penyebab tercatat");

        // 11. Clock normal lama: watchdog tidak alarm palsu
        do_reset();
        repeat (2000) @(posedge clk_base); #1;
        check(tamper_alarm === 1'b0, "11. Clock normal: watchdog tanpa alarm palsu");

        // Ringkasan
        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule