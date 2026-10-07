// =============================================================================
// Testbench self-checking untuk modul key_manager
// Jalankan:  iverilog -o tb key_manager.v tb_key_manager.v && vvp tb
//
// Aturan anti-race (lihat pengalaman glitch_inj):
//   - Masukan diubah 1 ns SETELAH tepi naik clock.
//   - Keluaran dicek 1 ns setelah tepi naik / setelah masukan berubah.
// =============================================================================
`timescale 1ns/1ps

module tb_key_manager;

    // Pengkodean key_sel (sama dengan key_manager.v)
    localparam [3:0] SEL_NONE = 4'h0, SEL_RPUF = 4'h1, SEL_DEV = 4'h2, SEL_CA = 4'h3,
                     SEL_DG = 4'h4, SEL_T = 4'h5, SEL_TA = 4'h6, SEL_ACC_ENC = 4'h7,
                     SEL_ACC_MAC = 4'h8, SEL_S_ENC = 4'h9, SEL_S_MAC = 4'hA,
                     SEL_WRAP = 4'hB, CMD_KILL_RPUF = 4'hC, CMD_RETRY_RPUF = 4'hF, CMD_CLR_SESS = 4'hD, CMD_ERASE_T = 4'hE;

    // Nilai uji
    localparam [127:0] V_RPUF  = 128'h0123456789ABCDEF_FEDCBA9876543210;
    localparam [127:0] V_RPUF2 = 128'hDEADBEEFDEADBEEF_DEADBEEFDEADBEEF;
    localparam [127:0] V_DEV   = 128'h11111111222222223333333344444444;
    localparam [127:0] V_DEV2  = 128'h99999999999999999999999999999999;
    localparam [127:0] V_CA    = 128'hCACACACACACACACA_0000000000000001;
    localparam [127:0] V_DG    = 128'hD6D6D6D6D6D6D6D6_0000000000000002;
    localparam [127:0] V_T     = 128'h7777777777777777_0000000000000003;
    localparam [127:0] V_T2    = 128'h7777777777777777_FFFFFFFFFFFFFFFF;
    localparam [127:0] V_TA    = 128'hA5A5A5A5A5A5A5A5_0000000000000004;
    localparam [127:0] V_S1    = 128'h5E55105E55105E55_0000000000000005;
    localparam [127:0] V_S2    = 128'h5E55105E55105E55_0000000000000006;

    reg          clk_sys    = 1'b0;
    reg          rst_sync_n = 1'b0;
    reg          zeroize    = 1'b0;
    reg  [3:0]   key_sel    = SEL_NONE;
    reg  [127:0] r_puf      = 128'd0;
    reg          r_valid    = 1'b0;
    reg  [127:0] kdf_key    = 128'd0;
    reg          kdf_wr     = 1'b0;
    wire [127:0] key_out;
    wire [127:0] wrap_key;
    wire         key_ok;

    integer errors = 0;
    integer s;
    integer bad;

    reg  scan_mode = 1'b0;
    wire key_kdf_only;

    key_manager dut (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .key_sel (key_sel), .r_puf (r_puf), .r_valid (r_valid),
        .kdf_key (kdf_key), .kdf_wr (kdf_wr), .scan_mode (scan_mode),
        .key_out (key_out), .wrap_key (wrap_key), .key_ok (key_ok),
        .key_kdf_only (key_kdf_only)
    );

    always #10 clk_sys = ~clk_sys;   // 50 MHz

    initial begin
        $dumpfile("tb_key_manager.vcd");
        $dumpvars(0, tb_key_manager);
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

    // Tulis satu slot lewat jalur KDF (satu siklus kdf_wr)
    task wr(input [3:0] sel, input [127:0] val);
        begin
            @(posedge clk_sys); #1;
            key_sel = sel; kdf_key = val; kdf_wr = 1'b1;
            @(posedge clk_sys); #1;
            kdf_wr = 1'b0; kdf_key = 128'd0; key_sel = SEL_NONE;
        end
    endtask

    // Kirim R_PUF dari fuzzy extractor
    task load_rpuf(input [127:0] val);
        begin
            @(posedge clk_sys); #1;
            r_puf = val; r_valid = 1'b1;
            @(posedge clk_sys); #1;
            r_valid = 1'b0; r_puf = 128'd0;
        end
    endtask

    // Pilih slot lalu baca (kombinasional)
    task rd(input [3:0] sel);
        begin
            key_sel = sel; #1;
        end
    endtask

    task do_reset;
        begin
            rst_sync_n = 1'b0;
            repeat (3) @(posedge clk_sys);
            #1 rst_sync_n = 1'b1;
        end
    endtask

    // -------------------------------------------------------------------------
    initial begin
        do_reset();

        // 1. Setelah reset: semua slot kosong
        bad = 0;
        for (s = 0; s < 16; s = s + 1) begin
            rd(s[3:0]);
            if (key_ok !== 1'b0 || key_out !== 128'd0 || wrap_key !== 128'd0) bad = bad + 1;
        end
        check(bad == 0, "1. Setelah reset semua slot kosong");

        // 2. K_DEV tidak bisa disuntikkan tanpa R_PUF
        wr(SEL_DEV, V_DEV);
        rd(SEL_DEV);
        check(key_ok === 1'b0, "2. K_DEV ditolak sebelum ada R_PUF");

        // 3. R_PUF masuk dari fuzzy extractor
        load_rpuf(V_RPUF);
        rd(SEL_RPUF);
        check(key_ok === 1'b1 && key_out === V_RPUF, "3. R_PUF tersimpan dan terbaca");

        // 4. K_DEV terbentuk -> R_PUF otomatis terhapus
        wr(SEL_DEV, V_DEV);
        rd(SEL_DEV);
        check(key_ok === 1'b1 && key_out === V_DEV, "4a. K_DEV tersimpan");
        rd(SEL_RPUF);
        check(key_ok === 1'b0 && key_out === 128'd0, "4b. R_PUF otomatis terhapus");

        // 5. R_PUF tidak bisa diisi ulang setelah dipakai
        load_rpuf(V_RPUF2);
        rd(SEL_RPUF);
        check(key_ok === 1'b0, "5. R_PUF tidak bisa diisi ulang sampai reset");

        // 6. Slot identitas hanya bisa ditulis sekali
        wr(SEL_DEV, V_DEV2);
        rd(SEL_DEV);
        check(key_out === V_DEV, "6. K_DEV tidak bisa ditimpa");

        // 7. K_CA dan K_DG diturunkan dari K_DEV
        wr(SEL_CA, V_CA);
        wr(SEL_DG, V_DG);
        rd(SEL_CA);
        check(key_ok === 1'b1 && key_out === V_CA, "7a. K_CA tersimpan");
        rd(SEL_DG);
        check(key_ok === 1'b1 && key_out === V_DG, "7b. K_DG tersimpan");

        // 8. Kunci sesi boleh ditulis ulang
        wr(SEL_S_ENC, V_S1);
        wr(SEL_S_ENC, V_S2);
        rd(SEL_S_ENC);
        check(key_ok === 1'b1 && key_out === V_S2, "8. Kunci sesi bisa diperbarui");

        // 9. CMD_CLR_SESS menghapus kunci sesi saja
        wr(SEL_ACC_MAC, V_S1);
        wr(CMD_CLR_SESS, 128'd0);
        rd(SEL_S_ENC);
        check(key_ok === 1'b0 && key_out === 128'd0, "9a. Kunci sesi terhapus");
        rd(SEL_ACC_MAC);
        check(key_ok === 1'b0, "9b. Kunci pintu terhapus");
        rd(SEL_CA);
        check(key_ok === 1'b1 && key_out === V_CA, "9c. K_CA tetap aman");

        // 10. Fitur wrap: key_out = K_T, wrap_key = K_CA
        wr(SEL_T, V_T);
        wr(SEL_TA, V_TA);
        rd(SEL_WRAP);
        check(key_ok === 1'b1 && key_out === V_T && wrap_key === V_CA, "10a. SEL_WRAP: K_T ke AES, K_CA sebagai data");
        bad = 0;
        for (s = 0; s < 16; s = s + 1) begin
            rd(s[3:0]);
            if (s[3:0] != SEL_WRAP && wrap_key !== 128'd0) bad = bad + 1;
        end
        check(bad == 0, "10b. wrap_key selalu 0 di luar SEL_WRAP");

        // 11. Hapus K_T permanen: wrap mati dan K_T tidak bisa diisi ulang
        wr(CMD_ERASE_T, 128'd0);
        rd(SEL_WRAP);
        check(key_ok === 1'b0 && wrap_key === 128'd0, "11a. Setelah ERASE_T, wrap mati");
        wr(SEL_T, V_T2);
        rd(SEL_T);
        check(key_ok === 1'b0 && key_out === 128'd0, "11b. K_T tidak bisa diisi ulang");

        // 12. Kode cadangan / perintah tidak mengeluarkan kunci apa pun
        bad = 0;
        rd(SEL_NONE);     if (key_ok || key_out !== 128'd0) bad = bad + 1;
        rd(4'hC);         if (key_ok || key_out !== 128'd0) bad = bad + 1;
        rd(CMD_CLR_SESS); if (key_ok || key_out !== 128'd0) bad = bad + 1;
        rd(CMD_ERASE_T);  if (key_ok || key_out !== 128'd0) bad = bad + 1;
        rd(4'hF);         if (key_ok || key_out !== 128'd0) bad = bad + 1;
        check(bad == 0, "12. Kode cadangan/perintah tidak mengeluarkan kunci");

        // 13. Zeroize di tengah siklus: semua kunci hilang seketika
        rd(SEL_CA);
        @(posedge clk_sys); #4;
        zeroize = 1'b1; #1;
        check(key_out === 128'd0 && key_ok === 1'b0, "13a. Zeroize menghapus seketika tanpa clock");
        bad = 0;
        for (s = 0; s < 16; s = s + 1) begin
            rd(s[3:0]);
            if (key_ok !== 1'b0 || key_out !== 128'd0 || wrap_key !== 128'd0) bad = bad + 1;
        end
        check(bad == 0, "13b. Semua slot kosong setelah zeroize");

        // 14. Selama zeroize aktif, penulisan apa pun ditolak
        load_rpuf(V_RPUF);
        wr(SEL_TA, V_TA);
        rd(SEL_RPUF);
        check(key_ok === 1'b0, "14a. R_PUF ditolak selama zeroize");
        rd(SEL_TA);
        check(key_ok === 1'b0, "14b. Kunci ditolak selama zeroize");

        // 15. Reset memulihkan chip: rantai PUF bisa berjalan lagi
        zeroize = 1'b0;
        do_reset();
        load_rpuf(V_RPUF);
        wr(SEL_DEV, V_DEV);
        rd(SEL_DEV);
        check(key_ok === 1'b1 && key_out === V_DEV, "15. Setelah reset, rantai PUF berjalan normal");

        // 16. CMD_KILL_RPUF: helper data ditolak -> R_PUF dibuang, K_DEV mustahil
        do_reset();
        load_rpuf(V_RPUF);
        wr(CMD_KILL_RPUF, 128'd0);
        rd(SEL_RPUF);
        check(key_ok === 1'b0 && key_out === 128'd0, "16a. CMD_KILL_RPUF menghapus R_PUF");
        wr(SEL_DEV, V_DEV);
        rd(SEL_DEV);
        check(key_ok === 1'b0, "16b. Setelah KILL_RPUF, K_DEV tidak bisa dibentuk");
        load_rpuf(V_RPUF2);
        rd(SEL_RPUF);
        check(key_ok === 1'b0, "16c. R_PUF baru ditolak sampai reset");

        // 17. CMD_RETRY_RPUF: dua kali coba ulang boleh, ketiga = blokir
        do_reset();
        load_rpuf(V_RPUF);  wr(CMD_RETRY_RPUF, 128'd0);
        load_rpuf(V_RPUF2); rd(SEL_RPUF);
        check(key_ok === 1'b1 && key_out === V_RPUF2, "17a. Setelah RETRY, R_PUF baru diterima");
        wr(CMD_RETRY_RPUF, 128'd0);
        load_rpuf(V_RPUF);  rd(SEL_RPUF);
        check(key_ok === 1'b1, "17b. RETRY kedua masih diizinkan");
        wr(CMD_RETRY_RPUF, 128'd0);
        load_rpuf(V_RPUF2); rd(SEL_RPUF);
        check(key_ok === 1'b0, "17c. RETRY ketiga: jatah habis, R_PUF diblokir");

        // 18. Penanda KDF-only untuk kebijakan HMAC (A1)
        bad = 0;
        rd(SEL_RPUF); if (key_kdf_only !== 1'b1) bad = bad + 1;
        rd(SEL_DEV);  if (key_kdf_only !== 1'b1) bad = bad + 1;
        rd(SEL_CA);   if (key_kdf_only !== 1'b0) bad = bad + 1;
        rd(SEL_S_MAC);if (key_kdf_only !== 1'b0) bad = bad + 1;
        check(bad == 0, "18. key_kdf_only hanya untuk R_PUF dan K_DEV");

        // 19. Mode scan (DFT) menghapus semua kunci seketika (A10)
        do_reset();
        load_rpuf(V_RPUF); wr(SEL_DEV, V_DEV); wr(SEL_CA, V_CA);
        #3 scan_mode = 1'b1; #1;
        rd(SEL_CA);
        check(key_ok === 1'b0 && key_out === 128'd0, "19. scan_mode menghapus kunci tanpa clock");
        scan_mode = 1'b0;

        // Ringkasan
        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

endmodule