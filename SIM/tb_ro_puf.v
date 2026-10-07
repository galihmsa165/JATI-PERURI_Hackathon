// =============================================================================
// Testbench self-checking untuk modul ro_puf
//   Bagian A: uji unit ro_puf
//   Bagian B: uji integrasi ro_puf + fuzzy_ext pada dua "chip" berbeda
//
// Kompilasi (urutan penting: model RO simulasi, bukan versi FPGA):
//   iverilog -o tb ro_puf_array_sim.v ro_puf.v fuzzy_ext.v tb_ro_puf.v && vvp tb
//
// Aturan anti-race:
//   1. Masukan diubah 1 ns setelah tepi naik, pengecekan saat kondisi tenang.
//   2. Monitor memakai penanda keadaan dan baru aktif setelah reset.
//   3. Pengecekan sinyal yang mungkin X memakai ===.
// =============================================================================
`timescale 1ns/1ps

module tb_ro_puf;

    localparam integer WIN_U  = 256;   // jendela uji unit
    localparam integer WIN_I  = 128;   // jendela uji integrasi (lebih cepat)
    localparam [3:0]   FE_ID  = 4'h5;
    localparam [7:0]   R_CTRL = 8'h00, R_STATUS = 8'h01;

    reg clk_sys    = 1'b0;
    reg rst_sync_n = 1'b0;
    reg zeroize    = 1'b0;
    always #10 clk_sys = ~clk_sys;

    integer errors = 0;

    task check(input ok, input [8*64-1:0] msg);
        begin
            if (ok) $display("[LULUS] %0s", msg);
            else begin
                $display("[GAGAL] %0s (t=%0t)", msg, $time);
                errors = errors + 1;
            end
        end
    endtask

    // Salinan fungsi hash model, untuk menghitung "jawaban benar"
    function real hp(input integer seed, input [9:0] idx);
        reg [31:0] x;
        begin
            x = {22'd0, idx} * 32'h9E3779B1 + seed * 32'h85EBCA6B;
            x = x ^ (x >> 16);
            x = x * 32'h7FEB352D;
            x = x ^ (x >> 15);
            x = x * 32'h846CA68B;
            x = x ^ (x >> 16);
            hp = 4.75 + (x % 501) / 1000.0;
        end
    endfunction

    // Perkiraan hitungan: jumlah tepi naik selama WIN siklus (20 ns)
    function integer expect_cnt(input integer seed, input [9:0] idx, input integer win);
        begin
            expect_cnt = (win * 20.0) / (2.0 * hp(seed, idx));
        end
    endfunction

    task do_reset;
        begin
            rst_sync_n = 1'b0;
            repeat (3) @(posedge clk_sys);
            #1 rst_sync_n = 1'b1;
            repeat (2) @(posedge clk_sys);
            #1;
        end
    endtask

    // =========================================================================
    // BAGIAN A: DUT unit (chip seed 1)
    // =========================================================================
    reg  [20:0] puf_ctl = 21'd0;
    wire [31:0] cnt;
    wire        cnt_done;

    ro_puf #(.WIN(WIN_U)) dut (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n),
        .puf_ctl (puf_ctl), .cnt (cnt), .cnt_done (cnt_done)
    );

    // Monitor (di tepi turun): jumlah pulsa, hasil, kebocoran cnt, RO diam
    reg     mon_on   = 1'b0;
    integer n_done   = 0;
    integer leak     = 0;
    integer idle_tgl = 0;
    reg     watch_idle = 1'b0;
    reg [31:0] last_cnt;

    always @(negedge clk_sys) if (mon_on) begin
        if (cnt_done === 1'b1) begin
            n_done   = n_done + 1;
            last_cnt = cnt;
        end else if (cnt !== 32'd0)
            leak = leak + 1;
    end
    always @(dut.ro_a or dut.ro_b) if (watch_idle) idle_tgl = idle_tgl + 1;

    task measure(input [9:0] a, input [9:0] b, output [15:0] ca, output [15:0] cb);
        integer guard, n0;
        begin
            n0 = n_done;
            @(posedge clk_sys); #1 puf_ctl = {1'b1, b, a};
            @(posedge clk_sys); #1 puf_ctl = 21'd0;
            guard = 0;
            while (n_done == n0 && guard < WIN_U + 100) begin
                @(posedge clk_sys); guard = guard + 1;
            end
            @(posedge clk_sys); #1;
            ca = last_cnt[15:0];
            cb = last_cnt[31:16];
        end
    endtask

    // =========================================================================
    // BAGIAN B: dua chip lengkap (ro_puf + fuzzy_ext), seed 1 dan seed 2
    // =========================================================================
    reg  [45:0] req_a = 46'd0, req_b = 46'd0;
    wire [31:0] rd_a, rd_b;
    wire [20:0] ctl_a, ctl_b;
    wire [31:0] c_a, c_b;
    wire        d_a, d_b;
    wire [127:0] rp_a, rp_b;
    wire        rv_a, rv_b;

    ro_puf    #(.WIN(WIN_I)) puf_a (.clk_sys(clk_sys), .rst_sync_n(rst_sync_n),
                                    .puf_ctl(ctl_a), .cnt(c_a), .cnt_done(d_a));
    fuzzy_ext #(.SLAVE_ID(FE_ID)) fe_a (.clk_sys(clk_sys), .rst_sync_n(rst_sync_n),
                                    .zeroize(zeroize), .req(req_a), .rdata(rd_a),
                                    .puf_ctl(ctl_a), .cnt(c_a), .cnt_done(d_a),
                                    .r_puf(rp_a), .r_valid(rv_a));

    ro_puf    #(.WIN(WIN_I)) puf_b (.clk_sys(clk_sys), .rst_sync_n(rst_sync_n),
                                    .puf_ctl(ctl_b), .cnt(c_b), .cnt_done(d_b));
    fuzzy_ext #(.SLAVE_ID(FE_ID)) fe_b (.clk_sys(clk_sys), .rst_sync_n(rst_sync_n),
                                    .zeroize(zeroize), .req(req_b), .rdata(rd_b),
                                    .puf_ctl(ctl_b), .cnt(c_b), .cnt_done(d_b),
                                    .r_puf(rp_b), .r_valid(rv_b));

    defparam puf_b.u_arr.CHIP_SEED = 2;    // chip B: silikon berbeda

    reg [127:0] R_A = 128'd0, R_B = 128'd0;
    always @(negedge clk_sys) begin
        if (rv_a === 1'b1) R_A = rp_a;
        if (rv_b === 1'b1) R_B = rp_b;
    end

    task fe_cmd(input integer which, input [31:0] d);
        begin
            @(posedge clk_sys); #1;
            if (which == 0) req_a = {FE_ID, R_CTRL, d, 1'b1, 1'b0};
            else            req_b = {FE_ID, R_CTRL, d, 1'b1, 1'b0};
            @(posedge clk_sys); #1;
            req_a = 46'd0; req_b = 46'd0;
        end
    endtask

    task fe_wait(input integer which, output [31:0] st);
        integer guard;
        begin
            guard = 0;
            st = 32'd1;
            while (st[0] == 1'b1 && guard < 400000) begin
                repeat (200) @(posedge clk_sys);
                guard = guard + 200;
                #1;
                if (which == 0) req_a = {FE_ID, R_STATUS, 32'd0, 1'b0, 1'b1};
                else            req_b = {FE_ID, R_STATUS, 32'd0, 1'b0, 1'b1};
                @(posedge clk_sys); #1;
                req_a = 46'd0; req_b = 46'd0;
                st = (which == 0) ? rd_a : rd_b;
            end
        end
    endtask

    function integer hamming(input [127:0] x, input [127:0] y);
        integer n;
        begin
            hamming = 0;
            for (n = 0; n < 128; n = n + 1) hamming = hamming + (x[n] ^ y[n]);
        end
    endfunction

    // =========================================================================
    integer    i, ok_order, n_pairs, spread, ea, eb, g;
    reg [15:0] ca, cb, cmin, cmax;
    reg [9:0]  ra, rb;
    reg [31:0] st;
    reg [127:0] gold;
    reg [5:0]  h;

    initial begin
        $dumpfile("tb_ro_puf.vcd");
        $dumpvars(0, tb_ro_puf.dut);
    end

    initial begin
        do_reset();
        mon_on = 1'b1;

        // ---------------- BAGIAN A ----------------
        // A1. Kondisi diam
        check(cnt === 32'd0 && cnt_done === 1'b0 && dut.ro_en === 1'b0,
              "A1. Setelah reset: diam, RO mati, cnt = 0");

        // A2. Satu pengukuran: RO 3 dan RO 17
        measure(10'd3, 10'd17, ca, cb);
        ea = expect_cnt(1, 10'd3, WIN_U);
        eb = expect_cnt(1, 10'd17, WIN_U);
        $display("        (RO 3: %0d, perkiraan %0d | RO 17: %0d, perkiraan %0d)", ca, ea, cb, eb);
        check(n_done == 1, "A2a. Tepat satu pulsa cnt_done");
        check(ca >= ea - 3 && ca <= ea + 3 && cb >= eb - 3 && cb <= eb + 3,
              "A2b. Hitungan sesuai frekuensi model (+/-3)");

        // A3. cnt tidak terlihat di luar pulsa
        check(leak == 0, "A3. cnt = 0 di luar pulsa cnt_done");

        // A4. Pengulangan: pasangan yang sama diukur 5 kali
        cmin = 16'hFFFF; cmax = 16'd0;
        for (i = 0; i < 5; i = i + 1) begin
            measure(10'd3, 10'd17, ca, cb);
            if (ca < cmin) cmin = ca;
            if (ca > cmax) cmax = ca;
        end
        $display("        (RO 3 diukur 5x: %0d .. %0d)", cmin, cmax);
        check(cmax - cmin <= 4, "A4. Hasil ukur berulang stabil (selisih <= 4)");

        // A5. Urutan kecepatan 20 pasangan acak sesuai model
        ok_order = 0; n_pairs = 0;
        for (i = 0; i < 20; i = i + 1) begin
            ra = (i * 97 + 13) % 1024;
            rb = (i * 389 + 501) % 1024;
            measure(ra, rb, ca, cb);
            ea = expect_cnt(1, ra, WIN_U);
            eb = expect_cnt(1, rb, WIN_U);
            if (ea - eb > 6 || eb - ea > 6) begin      // abaikan pasangan nyaris seri
                n_pairs = n_pairs + 1;
                if ((ca > cb) == (ea > eb)) ok_order = ok_order + 1;
            end
        end
        check(n_pairs > 0 && ok_order == n_pairs, "A5. RO lebih cepat selalu menghasilkan hitungan lebih besar");

        // A6. RO benar-benar mati saat diam
        watch_idle = 1'b1;
        repeat (300) @(posedge clk_sys);
        watch_idle = 1'b0;
        check(idle_tgl == 0, "A6. Tidak ada RO berosilasi saat diam");

        // A7. Start kedua saat sibuk diabaikan
        i = n_done;
        @(posedge clk_sys); #1 puf_ctl = {1'b1, 10'd17, 10'd3};
        @(posedge clk_sys); #1 puf_ctl = 21'd0;
        repeat (50) @(posedge clk_sys); #1 puf_ctl = {1'b1, 10'd900, 10'd800};
        @(posedge clk_sys); #1 puf_ctl = 21'd0;
        repeat (WIN_U + 100) @(posedge clk_sys);
        ea = expect_cnt(1, 10'd3, WIN_U);
        check(n_done == i + 1 && last_cnt[15:0] >= ea - 3 && last_cnt[15:0] <= ea + 3,
              "A7. Start saat sibuk diabaikan, hasil tetap pasangan pertama");

        // ---------------- BAGIAN B ----------------
        // Dua chip: enrollment lalu rekonstruksi, berjalan bersamaan
        fe_cmd(0, 32'd1);
        fe_cmd(1, 32'd1);
        fe_wait(0, st);
        check(st[1] == 1'b1 && st[3] == 1'b0, "B1a. Chip A: enrollment dengan ro_puf berhasil");
        fe_wait(1, st);
        check(st[1] == 1'b1 && st[3] == 1'b0, "B1b. Chip B: enrollment dengan ro_puf berhasil");

        // Jawaban benar chip A dari model + helper yang dipilih fuzzy_ext
        for (g = 0; g < 128; g = g + 1) begin
            h = fe_a.helper[g];
            gold[g] = hp(1, g*8 + h[2:0]) < hp(1, g*8 + h[5:3]);   // a lebih cepat
        end

        fe_cmd(0, 32'd2);
        fe_cmd(1, 32'd2);
        fe_wait(0, st);
        $display("        (chip A: grup tidak stabil = %0d)", st[15:8]);
        check(st[2] == 1'b1 && R_A == gold, "B2. Chip A: kunci hasil rekonstruksi sesuai model");
        fe_wait(1, st);
        check(st[2] == 1'b1 && R_B != 128'd0, "B3. Chip B: rekonstruksi berhasil");

        $display("        (jarak Hamming chip A vs chip B = %0d dari 128, ideal 64)", hamming(R_A, R_B));
        check(hamming(R_A, R_B) > 40 && hamming(R_A, R_B) < 88,
              "B4. Dua chip menghasilkan kunci berbeda (uniqueness)");

        // Ringkasan
        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule