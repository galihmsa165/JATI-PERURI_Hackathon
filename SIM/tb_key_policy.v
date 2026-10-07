// =============================================================================
// Testbench kebijakan pemakaian kunci (A1): key_manager + hmac_kdf + sha256_core
// Membuktikan K_CA tidak bisa dibaca lewat HMAC(K_DEV, "JATI-CA") mode biasa.
// =============================================================================
`timescale 1ns/1ps
module tb_key_policy;
    reg clk = 0, rst = 0;
    always #10 clk = ~clk;
    reg  [3:0]   key_sel = 0;
    reg  [127:0] r_puf = 128'h0123456789ABCDEF0123456789ABCDEF;
    reg          r_valid = 0;
    reg  [45:0]  req = 0;
    wire [31:0]  rd;
    wire [127:0] key_out, wrap_key, kdf_key;
    wire         key_ok, kdf_only, kdf_wr, sha_ready;
    wire [34:0]  sha_ctl;
    wire [255:0] digest;
    integer errors = 0, i;
    reg [31:0] v;

    key_manager km (.clk_sys(clk), .rst_sync_n(rst), .zeroize(1'b0), .key_sel(key_sel),
        .r_puf(r_puf), .r_valid(r_valid), .kdf_key(kdf_key), .kdf_wr(kdf_wr), .scan_mode(1'b0),
        .key_out(key_out), .wrap_key(wrap_key), .key_ok(key_ok), .key_kdf_only(kdf_only));
    hmac_kdf hm (.clk_sys(clk), .rst_sync_n(rst), .zeroize(1'b0), .req(req), .rdata(rd),
        .key_in(key_out), .key_kdf_only(kdf_only), .kdf_key(kdf_key), .kdf_wr(kdf_wr),
        .sha_ctl(sha_ctl), .digest(digest), .sha_ready(sha_ready));
    sha256_core sh (.clk_sys(clk), .rst_sync_n(rst), .zeroize(1'b0), .sha_ctl(sha_ctl),
        .digest(digest), .sha_ready(sha_ready));

    task wr(input [7:0] a, input [31:0] d);
        begin @(posedge clk); #1 req = {4'h0, a, d, 1'b1, 1'b0}; @(posedge clk); #1 req = 0; end
    endtask
    task rdd(input [7:0] a, output [31:0] d);
        begin @(posedge clk); #1 req = {4'h0, a, 32'd0, 1'b0, 1'b1}; @(posedge clk); #1 req = 0; d = rd; end
    endtask
    task check(input ok, input [8*64-1:0] m);
        begin if (ok) $display("[LULUS] %0s", m); else begin $display("[GAGAL] %0s", m); errors = errors + 1; end end
    endtask
    // pesan: label 7-8 byte, atau 40 byte
    task msg(input [63:0] lbl, input integer len);
        begin
            wr(8'h28, len);
            wr(8'h2C, lbl[63:32]); wr(8'h30, lbl[31:0]);
            for (i = 2; i < 10; i = i + 1) wr(8'h2C + 4*i, 32'h11111111);
        end
    endtask
    task run(input [31:0] ctrl, input [3:0] src, input [3:0] dst);
        begin
            key_sel = src;
            wr(8'h00, ctrl);
            #1 key_sel = dst;
            repeat (450) @(posedge clk);
            key_sel = 4'h0;
        end
    endtask

    initial begin
        #50 rst = 1;
        @(posedge clk); #1 r_valid = 1; @(posedge clk); #1 r_valid = 0;
        msg("JATI-DEV", 8);  run(32'd2, 4'h1, 4'h2);
        check(km.v_dev === 1'b1, "1. KDF R_PUF -> K_DEV berjalan normal");

        msg("JATI-CA ", 7); run(32'd1, 4'h2, 4'h0);
        rdd(8'h04, v);
        check(v[2] === 1'b1 && v[1] === 1'b0, "2. HMAC biasa (K_DEV, \"JATI-CA\") DITOLAK (pol_err)");
        rdd(8'h08, v);
        check(v == 32'd0, "3. Digest tetap 0: K_CA tidak bocor ke bus");

        msg("JATI-CA ", 40); run(32'd1, 4'h2, 4'h0);
        rdd(8'h04, v);
        check(v[2] === 1'b0 && v[1] === 1'b1, "4. HMAC biasa K_DEV dengan pesan >= 40 byte diizinkan");

        msg("JATI-CA ", 7); run(32'd2, 4'h2, 4'h3);
        check(km.v_ca === 1'b1, "5. KDF K_DEV -> K_CA (jalur resmi) tetap berjalan");

        msg("CA-TEST ", 7); run(32'd1, 4'h3, 4'h0);
        rdd(8'h04, v);
        check(v[1] === 1'b1 && v[2] === 1'b0, "6. HMAC biasa dengan K_CA (bukan KDF-only) diizinkan");

        if (errors == 0) $display("\n=== SEMUA TES LULUS ==="); else $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end
endmodule