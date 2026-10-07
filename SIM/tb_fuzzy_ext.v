// =============================================================================
// Testbench self-checking untuk modul fuzzy_ext
// Jalankan:  iverilog -o tb fuzzy_ext.v tb_fuzzy_ext.v && vvp tb
//
// Testbench ini berisi MODEL RO-PUF sederhana: 1024 RO dengan frekuensi dasar
// acak (berbeda per "chip") ditambah derau setiap kali diukur.
//
// Aturan anti-race: masukan bus diubah 1 ns setelah tepi naik, pulsa r_valid
// ditangkap di tepi TURUN clock.
// =============================================================================
`timescale 1ns/1ps

module tb_fuzzy_ext;

    localparam [3:0]   ID       = 4'h5;
    localparam [3:0]   WRONG_ID = 4'h3;
    localparam [7:0]   R_CTRL = 8'h00, R_STATUS = 8'h01, R_MSEL = 8'h02,
                       R_MCNT = 8'h03, R_MDIFF  = 8'h04;
    localparam integer LAT     = 20;      // latensi model PUF (siklus)
    localparam integer TMO     = 2000;
    localparam integer SEED_A  = 1111;
    localparam integer SEED_B  = 2222;

    reg          clk_sys    = 1'b0;
    reg          rst_sync_n = 1'b0;
    reg          zeroize    = 1'b0;
    reg  [45:0]  req        = 46'd0;
    wire [31:0]  rdata;
    wire [20:0]  puf_ctl;
    reg  [31:0]  cnt        = 32'd0;
    reg          cnt_done   = 1'b0;
    wire [127:0] r_puf;
    wire         r_valid;

    integer errors = 0;
    integer i, j, guard, hd, match, pulses;
    reg [31:0]  v, st;
    reg [127:0] r_cap, R_A, R_A2, R_B, gold;
    reg [5:0]   helper_save [0:127];
    reg         rpuf_leak;
    reg         mon_on = 1'b0;     // monitor aktif setelah reset pertama selesai

    fuzzy_ext #(.SLAVE_ID(ID), .N_VOTE(5), .TIMEOUT(TMO), .CHAR_MODE(1)) dut (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .req (req), .rdata (rdata),
        .puf_ctl (puf_ctl), .cnt (cnt), .cnt_done (cnt_done),
        .r_puf (r_puf), .r_valid (r_valid)
    );

    always #10 clk_sys = ~clk_sys;

    initial begin
        $dumpfile("tb_fuzzy_ext.vcd");
        $dumpvars(0, tb_fuzzy_ext);
    end

    // =========================================================================
    // MODEL RO-PUF
    // =========================================================================
    integer fbase [0:1023];   // frekuensi dasar per RO (ciri unik chip)
    integer noise_amp = 3;    // derau pengukuran (+/-)
    integer nseed     = 77;
    integer lat_cnt   = -1;
    reg     respond   = 1'b1;
    reg [9:0] la, lb;

    task gen_chip(input integer seed);
        integer s, n;
        begin
            s = seed;
            for (n = 0; n < 1024; n = n + 1)
                fbase[n] = 5000 + ($random(s) % 201);   // 4800..5200
        end
    endtask

    function [15:0] meas(input [9:0] idx);
        begin
            meas = fbase[idx] + ($random(nseed) % (noise_amp + 1));
        end
    endfunction

    always @(posedge clk_sys) begin
        cnt_done <= 1'b0;
        if (puf_ctl[20]) begin
            la      <= puf_ctl[9:0];
            lb      <= puf_ctl[19:10];
            lat_cnt <= LAT;
        end else if (lat_cnt > 0)
            lat_cnt <= lat_cnt - 1;
        else if (lat_cnt == 0) begin
            if (respond) begin
                cnt      <= {meas(lb), meas(la)};
                cnt_done <= 1'b1;
            end
            lat_cnt <= -1;
        end
    end

    // Penangkap pulsa r_valid (di tepi turun, bebas race).
    // Hanya aktif setelah reset pertama: sebelum itu semua sinyal masih X,
    // dan sebagian simulator memicu "negedge" palsu saat clock diinisialisasi
    // di waktu 0.
    always @(negedge clk_sys) if (mon_on) begin
        if (r_valid === 1'b1) begin
            r_cap  = r_puf;
            pulses = pulses + 1;
        end else if (r_valid === 1'b0 && r_puf !== 128'd0)
            rpuf_leak = 1'b1;          // r_puf tidak boleh terlihat di luar pulsa
    end

    // =========================================================================
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
            @(posedge clk_sys); #1;          // rdata ter-register di tepi ini
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

    task wait_idle;
        begin
            guard = 0;
            bus_rd(ID, R_STATUS, st);
            while (st[0] == 1'b1 && guard < 200000) begin
                repeat (100) @(posedge clk_sys);
                guard = guard + 100;
                bus_rd(ID, R_STATUS, st);
            end
        end
    endtask

    // Bit "benar" menurut model, dari helper yang tersimpan di DUT
    task golden_from_helper(output [127:0] gr);
        integer gg;
        reg [5:0] h;
        begin
            for (gg = 0; gg < 128; gg = gg + 1) begin
                h = dut.helper[gg];
                gr[gg] = (fbase[gg*8 + h[2:0]] > fbase[gg*8 + h[5:3]]);
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
    initial begin
        pulses = 0;  rpuf_leak = 1'b0;
        gen_chip(SEED_A);
        do_reset();
        mon_on = 1'b1;

        // 1. Kondisi awal
        bus_rd(ID, R_STATUS, st);
        check(st == 32'd0, "1a. Setelah reset: diam, belum enroll");
        bus_rd(ID, R_STATUS, v);
        bus_rd(WRONG_ID, R_STATUS, v);
        check(v == 32'd0, "1b. Baca dengan ID lain: rdata tidak berubah");

        // 2. Rekonstruksi dengan helper kosong harus ditolak
        bus_wr(ID, R_CTRL, 32'd2);
        wait_idle();
        check(st[3] == 1'b1 && pulses == 0, "2. Helper kosong (a==b) ditolak, tidak ada r_valid");

        // 3. Enrollment chip A
        do_reset();
        bus_wr(ID, R_CTRL, 32'd1);
        wait_idle();
        check(st[1] == 1'b1 && st[3] == 1'b0, "3a. Enrollment selesai tanpa error");
        match = 0;
        for (i = 0; i < 128; i = i + 1) begin
            bus_rd(ID, 8'h80 + i, v);
            helper_save[i] = v[5:0];
            if (v[2:0] < v[5:3]) match = match + 1;
        end
        check(match == 128, "3b. Semua helper sah (a < b, a != b)");
        bus_rd(ID, R_MDIFF, v);
        $display("        (selisih frekuensi terkecil pasangan terpilih = %0d)", v);
        check(v > 0, "3c. MIN_DIFF terisi");

        // 4. Rekonstruksi chip A
        golden_from_helper(gold);
        bus_wr(ID, R_CTRL, 32'd2);
        wait_idle();
        R_A = r_cap;
        check(pulses == 1 && st[2] == 1'b1, "4a. Tepat satu pulsa r_valid");
        check(R_A == gold, "4b. R_PUF sama dengan bit benar dari model");
        check(dut.R == 128'd0, "4c. R terhapus setelah diserahkan");
        check(rpuf_leak == 1'b0, "4d. r_puf tidak pernah terlihat di luar pulsa");
        $display("        (grup tidak stabil = %0d)", st[15:8]);

        // 5. Setelah rekonstruksi: helper terkunci dan tidak bisa diulang
        bus_wr(ID, 8'h80, 32'h0000_003F);
        bus_rd(ID, 8'h80, v);
        check(v[5:0] == helper_save[0], "5a. Helper tidak bisa diubah setelah terkunci");
        // A9: rekonstruksi ulang (derau) boleh sampai 3 kali, lalu ditolak
        bus_wr(ID, R_CTRL, 32'd2);  wait_idle;
        bus_wr(ID, R_CTRL, 32'd2);  wait_idle;
        check(pulses == 3 && r_cap == R_A, "5b. Rekonstruksi ulang (maks 3x) memberi kunci sama");
        bus_wr(ID, R_CTRL, 32'd2);
        repeat (200) @(posedge clk_sys);
        check(pulses == 3, "5c. Rekonstruksi keempat ditolak");
        bus_wr(ID, R_CTRL, 32'd4);
        bus_rd(ID, R_STATUS, st);
        check(st[0] == 1'b0, "5d. Mode ukur mentah mati setelah helper terkunci");

        // 6. Keandalan: boot ulang dengan derau 13x lebih besar
        do_reset();
        for (i = 0; i < 128; i = i + 1) bus_wr(ID, 8'h80 + i, {26'd0, helper_save[i]});
        noise_amp = 40;
        bus_wr(ID, R_CTRL, 32'd2);
        wait_idle();
        R_A2 = r_cap;
        $display("        (derau +/-40: grup tidak stabil = %0d, bit berbeda = %0d)",
                 st[15:8], hamming(R_A, R_A2));
        check(R_A2 == R_A, "6. Kunci tetap sama walau derau jauh lebih besar");
        noise_amp = 3;

        // 7. Keunikan: chip B dengan RO berbeda menghasilkan kunci berbeda
        gen_chip(SEED_B);
        do_reset();
        bus_wr(ID, R_CTRL, 32'd1);  wait_idle();
        bus_wr(ID, R_CTRL, 32'd2);  wait_idle();
        R_B = r_cap;
        hd = hamming(R_A, R_B);
        $display("        (jarak Hamming chip A vs chip B = %0d dari 128, ideal 64)", hd);
        check(hd > 40 && hd < 88, "7. Chip berbeda menghasilkan kunci berbeda");

        // 8. Serangan helper: satu grup diubah menjadi a == b
        do_reset();
        for (i = 0; i < 128; i = i + 1) bus_wr(ID, 8'h80 + i, {26'd0, helper_save[i]});
        bus_wr(ID, 8'h80 + 5, {26'd0, 3'd2, 3'd2});
        j = pulses;
        bus_wr(ID, R_CTRL, 32'd2);
        wait_idle();
        check(st[3] == 1'b1 && pulses == j, "8. Helper dimanipulasi (a==b) -> error, tanpa kunci");

        // 9. ro_puf tidak menjawab -> batas waktu, tidak menggantung
        do_reset();
        respond = 1'b0;
        bus_wr(ID, R_CTRL, 32'd1);
        wait_idle();
        check(st[3] == 1'b1 && st[0] == 1'b0, "9. Batas waktu: error, modul kembali diam");
        respond = 1'b1;

        // 10. Zeroize di tengah rekonstruksi
        gen_chip(SEED_A);
        do_reset();
        for (i = 0; i < 128; i = i + 1) bus_wr(ID, 8'h80 + i, {26'd0, helper_save[i]});
        j = pulses;
        bus_wr(ID, R_CTRL, 32'd2);
        repeat (5000) @(posedge clk_sys);
        #5 zeroize = 1'b1; #1;
        check(dut.R == 128'd0 && dut.state == 4'd0 && r_valid == 1'b0,
              "10. Zeroize menghapus respons sementara seketika");
        zeroize = 1'b0;
        repeat (5) @(posedge clk_sys);
        check(pulses == j, "10b. Tidak ada r_valid setelah zeroize");

        // 11. Mode karakterisasi: ukur satu pasangan RO
        do_reset();
        bus_wr(ID, R_MSEL, {6'd0, 10'd17, 6'd0, 10'd3});
        bus_wr(ID, R_CTRL, 32'd4);
        wait_idle();
        bus_rd(ID, R_MCNT, v);
        check((v[15:0]  >= fbase[3]  - 3) && (v[15:0]  <= fbase[3]  + 3) &&
              (v[31:16] >= fbase[17] - 3) && (v[31:16] <= fbase[17] + 3),
              "11. Mode ukur: hitungan sesuai frekuensi RO 3 dan 17");

        // Ringkasan
        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule