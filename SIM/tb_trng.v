// =============================================================================
// Testbench self-checking untuk modul trng
// Kompilasi bersama model sumber entropi simulasi:
//   iverilog -o tb trng_ro_sim.v trng.v tb_trng.v && vvp tb
//
// Aturan anti-race: masukan diubah 1 ns setelah tepi naik clock, keluaran
// dibaca sebelum tepi berikutnya.
// =============================================================================
`timescale 1ns/1ps

module tb_trng;

    localparam [3:0]   ID        = 4'h2;
    localparam [3:0]   WRONG_ID  = 4'h4;
    localparam [7:0]   R_CTRL    = 8'h00, R_STATUS = 8'h01, R_DATA = 8'h02;
    localparam integer DIV       = 4;       // dipercepat untuk simulasi
    localparam integer APT_W     = 1024;
    localparam integer N_WORDS   = 64;

    reg         clk_sys    = 1'b0;
    reg         rst_sync_n = 1'b0;
    reg         zeroize    = 1'b0;
    reg  [45:0] req        = 46'd0;
    wire [31:0] rdata;

    integer errors = 0;
    integer i, k, ones, dup, guard;
    reg [31:0] v, st;
    reg [31:0] words [0:N_WORDS-1];

    // Pola bias untuk uji APT
    reg     pat      = 1'b0;
    reg     pat_on   = 1'b0;
    integer pat_pos  = 0;
    integer pat_tick = 0;

    trng #(.SLAVE_ID(ID), .SAMPLE_DIV(DIV), .APT_W(APT_W)) dut (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .req (req), .rdata (rdata)
    );

    always #10 clk_sys = ~clk_sys;

    initial begin
        $dumpfile("tb_trng.vcd");
        $dumpvars(0, tb_trng);
    end

    // Pembangkit pola 9x "1" lalu 1x "0" (90% satu, tanpa deret panjang),
    // berganti setiap DIV siklus sehingga setiap elemen tercuplik sekali.
    always @(posedge clk_sys) if (pat_on) begin
        #1;
        pat_tick = pat_tick + 1;
        if (pat_tick == DIV) begin
            pat_tick = 0;
            pat_pos  = (pat_pos + 1) % 10;
            pat      = (pat_pos != 9);
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

    task bus_wr(input [3:0] id, input [7:0] ra, input [31:0] d);
        begin
            @(posedge clk_sys); #1;
            req = {id, ra, d, 1'b1, 1'b0};
            @(posedge clk_sys); #1;
            req = 46'd0;
        end
    endtask

    task bus_rd(input [3:0] id, input [7:0] ra, output [31:0] d);
        begin
            @(posedge clk_sys); #1;
            req = {id, ra, 32'd0, 1'b0, 1'b1};
            @(posedge clk_sys); #1;          // rdata ter-register di tepi ini (pop juga)
            req = 46'd0;
            d = rdata;
        end
    endtask

    task do_reset;
        begin
            rst_sync_n = 1'b0;
            repeat (3) @(posedge clk_sys);
            #1 rst_sync_n = 1'b1;
        end
    endtask

    // Tunggu bit STATUS tertentu menjadi 1 (dengan batas waktu)
    task wait_status(input integer bitn, input integer max_cyc);
        begin
            guard = 0;
            bus_rd(ID, R_STATUS, st);
            while (st[bitn] !== 1'b1 && guard < max_cyc) begin
                repeat (50) @(posedge clk_sys);
                guard = guard + 50;
                bus_rd(ID, R_STATUS, st);
            end
        end
    endtask

    // -------------------------------------------------------------------------
    initial begin
        do_reset();

        // 1. Kondisi awal
        bus_rd(ID, R_STATUS, st);
        check(st == 32'd0, "1a. Setelah reset: mati, belum siap, kosong");
        bus_rd(ID, R_DATA, v);
        check(v == 32'd0, "1b. DATA = 0 saat belum ada angka acak");

        // 2. Perintah ke ID slave lain diabaikan
        bus_wr(WRONG_ID, R_CTRL, 32'd1);
        bus_rd(ID, R_STATUS, st);
        check(st[0] == 1'b0, "2. Tulis ke ID slave lain tidak menyalakan TRNG");

        // 3. Nyalakan: startup test harus lulus satu jendela penuh dulu
        bus_wr(ID, R_CTRL, 32'd1);
        repeat (100) @(posedge clk_sys);
        bus_rd(ID, R_STATUS, st);
        check(st[1] == 1'b0, "3a. Belum siap sebelum jendela startup selesai");
        wait_status(1, (APT_W + 50) * DIV);
        check(st[1] == 1'b1 && st[3] == 1'b0, "3b. Siap setelah startup test lulus");

        // 4. Data tersedia dan pembacaan bersifat pop
        wait_status(2, 4000);
        k = st[10:8];
        bus_rd(ID, R_DATA, v);
        bus_rd(ID, R_STATUS, st);
        check(v != 32'd0 && st[10:8] == k - 1, "4. Data acak terbaca dan FIFO berkurang (pop)");

        // 5. Baca dengan ID lain: rdata 0 dan tidak mengambil data
        wait_status(2, 4000);
        k = st[10:8];
        bus_rd(WRONG_ID, R_DATA, v);
        bus_rd(ID, R_STATUS, st);
        check(st[10:8] >= k, "5. Baca dengan ID lain: data tidak diambil (tidak di-pop)");

        // 6. Kumpulkan 64 kata: cek keseimbangan bit dan tidak ada duplikat
        for (i = 0; i < N_WORDS; i = i + 1) begin
            wait_status(2, 4000);
            bus_rd(ID, R_DATA, words[i]);
        end
        ones = 0;
        for (i = 0; i < N_WORDS; i = i + 1)
            for (k = 0; k < 32; k = k + 1)
                ones = ones + words[i][k];
        $display("        (proporsi bit 1 = %0d dari %0d bit)", ones, N_WORDS * 32);
        check(ones > N_WORDS * 32 * 45 / 100 && ones < N_WORDS * 32 * 55 / 100,
              "6a. Proporsi bit 1 antara 45% dan 55%");
        dup = 0;
        for (i = 0; i < N_WORDS; i = i + 1)
            for (k = i + 1; k < N_WORDS; k = k + 1)
                if (words[i] == words[k]) dup = dup + 1;
        check(dup == 0, "6b. Tidak ada kata acak yang berulang");

        // 7. FIFO kosong: DATA = 0
        wait_status(2, 4000);
        k = st[10:8];
        for (i = 0; i < k; i = i + 1) bus_rd(ID, R_DATA, v);
        bus_rd(ID, R_DATA, v);
        check(v == 32'd0, "7. FIFO kosong: DATA bernilai 0");

        // 8. Sumber macet (stuck-at-1): RCT harus mendeteksi
        wait_status(2, 4000);
        force dut.u_src.raw = 1'b1;
        repeat (60 * DIV) @(posedge clk_sys);
        bus_rd(ID, R_STATUS, st);
        check(st[4] == 1'b1 && st[3] == 1'b1, "8a. RCT mendeteksi sumber macet");
        check(st[2] == 1'b0 && st[10:8] == 3'd0, "8b. FIFO dikosongkan saat gagal");
        bus_rd(ID, R_DATA, v);
        check(v == 32'd0, "8c. DATA = 0 saat gagal");

        // 9. Status gagal terkunci, tidak bisa dihapus lewat bus
        release dut.u_src.raw;
        bus_wr(ID, R_CTRL, 32'd0);
        bus_wr(ID, R_CTRL, 32'd1);
        repeat ((APT_W + 50) * DIV) @(posedge clk_sys);
        bus_rd(ID, R_STATUS, st);
        check(st[3] == 1'b1 && st[2] == 1'b0, "9. Status gagal terkunci sampai reset");

        // 10. Sumber bias (90% satu, tanpa deret panjang): APT harus mendeteksi
        do_reset();
        pat_on = 1'b1;
        force dut.u_src.raw = pat;
        bus_wr(ID, R_CTRL, 32'd1);
        repeat ((3 * APT_W + 50) * DIV) @(posedge clk_sys);
        bus_rd(ID, R_STATUS, st);
        check(st[5] == 1'b1 && st[4] == 1'b0, "10a. APT mendeteksi bias (RCT tidak)");
        check(st[2] == 1'b0, "10b. Tidak ada data keluar dari sumber bias");
        release dut.u_src.raw;
        pat_on = 1'b0;

        // 11. Zeroize di tengah siklus menghapus semua angka acak
        do_reset();
        bus_wr(ID, R_CTRL, 32'd1);
        wait_status(1, (APT_W + 50) * DIV);
        wait_status(2, 4000);
        @(posedge clk_sys); #5;
        zeroize = 1'b1; #1;
        check(dut.f_cnt == 3'd0 && dut.fifo0 == 32'd0 && dut.fifo1 == 32'd0 &&
              dut.fifo2 == 32'd0 && dut.fifo3 == 32'd0 && dut.enable == 1'b0,
              "11. Zeroize menghapus FIFO dan mematikan TRNG seketika");
        zeroize = 1'b0;

        // Ringkasan
        // 19. Hemat daya: FIFO penuh -> ring oscillator berhenti (B3)
        do_reset();
        bus_wr(ID, R_CTRL, 32'd1);
        k = 0;
        while (dut.f_cnt != 3'd4 && k < 400000) begin @(posedge clk_sys); k = k + 1; end
        repeat (3) @(posedge clk_sys); #1;
        check(dut.pause === 1'b1 && dut.u_src.en === 1'b0, "19a. FIFO penuh: RO dimatikan");
        bus_rd(ID, R_DATA, v);
        k = 0;
        while (dut.f_cnt != 3'd4 && k < 400000) begin @(posedge clk_sys); k = k + 1; end
        check(dut.f_cnt == 3'd4 && dut.fail === 1'b0, "19b. RO hidup lagi, FIFO terisi, health test tetap lulus");

        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule