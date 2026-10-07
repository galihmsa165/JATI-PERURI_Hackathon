// =============================================================================
// Testbench SISTEM PENUH untuk jati_top
//
// Host (laptop) disimulasikan lengkap:
//   - mengirim APDU lewat pin uart_rx (frame SYNC + header + data + Le + CRC16)
//   - menerima jawaban dari pin uart_tx dan memeriksa CRC16
//   - menghitung kriptografi sisi host (HMAC-SHA256, AES) dengan instans
//     hmac_kdf/sha256_core/aes128_sm terpisah yang kuncinya diberi oleh host
//
// Skenario mengikuti siklus hidup e-paspor:
//   BLANK -> personalisasi -> LOCK -> kunci pintu -> secure messaging ->
//   autentikasi terminal -> bukti chip asli -> integritas helper data ->
//   serangan glitch
//
// Aturan anti-race: masukan diubah 1 ns setelah tepi naik, monitor aktif
// setelah reset, sinyal yang mungkin X dicek dengan ===.
// =============================================================================
`timescale 1ns/1ps

module tb_jati_top;

    localparam integer BIT_CLK = 8;                    // clock per bit UART
    localparam integer BAUD    = 50_000_000 / BIT_CLK; // 6,25 Mbaud (simulasi)

    reg  clk_50 = 1'b0;
    reg  rst_n  = 1'b0;
    reg  uart_rx_line = 1'b1;
    reg  glitch_test_en = 1'b0;
    wire uart_tx_line;
    wire [3:0] led_status;
    wire pll_locked;

    always #10 clk_50 = ~clk_50;
    localparam integer DLYB = 2000;     // A5: jeda dasar (dipercepat untuk simulasi)

    jati_top #(.BAUD_RATE(BAUD), .TRNG_DIV(4), .PUF_WIN(64), .DLY_BASE(DLYB)) dut (
        .clk_50 (clk_50), .rst_n (rst_n), .uart_rx (uart_rx_line),
        .glitch_test_en (glitch_test_en), .uart_tx (uart_tx_line),
        .led_status (led_status), .pll_locked (pll_locked)
    );

    integer errors = 0;
    reg [15:0] r_sw;
    integer    r_len;
    reg        r_ok;           // jawaban diterima dan CRC benar
    integer    kbus_leak = 0;
    task check(input ok, input [8*72-1:0] msg);
        begin
            if (ok) $display("[LULUS] %0s", msg);
            else begin
                $display("[GAGAL] %0s (SW=%h len=%0d, t=%0t)", msg, r_sw, r_len, $time);
                errors = errors + 1;
            end
        end
    endtask

    // =========================================================================
    // CRC-16 CCITT (sama dengan apdu_parser)
    // =========================================================================
    function [15:0] crc16(input [15:0] c, input [7:0] d);
        integer b;
        reg [15:0] x;
        begin
            x = c ^ {d, 8'h00};
            for (b = 0; b < 8; b = b + 1) x = x[15] ? ((x << 1) ^ 16'h1021) : (x << 1);
            crc16 = x;
        end
    endfunction

    // =========================================================================
    // UART host: kirim dan terima
    // =========================================================================
    task uart_send(input [7:0] b);
        integer i;
        begin
            uart_rx_line = 1'b0; repeat (BIT_CLK) @(posedge clk_50);
            for (i = 0; i < 8; i = i + 1) begin
                uart_rx_line = b[i]; repeat (BIT_CLK) @(posedge clk_50);
            end
            uart_rx_line = 1'b1; repeat (BIT_CLK + 2) @(posedge clk_50);
        end
    endtask

    reg [7:0] rxq [0:8191];   // log semua byte jawaban
    integer   rxn = 0;
    reg       rx_on = 1'b0;

    always begin
        @(negedge uart_tx_line);
        if (rx_on) begin : rx_byte
            integer i;
            reg [7:0] b;
            repeat (BIT_CLK / 2) @(posedge clk_50);           // tengah bit start
            for (i = 0; i < 8; i = i + 1) begin
                repeat (BIT_CLK) @(posedge clk_50);
                b[i] = uart_tx_line;
            end
            repeat (BIT_CLK) @(posedge clk_50);               // bit stop
            rxq[rxn] = b;
            rxn = rxn + 1;
        end
    end

    // =========================================================================
    // Kirim APDU, terima jawaban
    // =========================================================================
    reg [7:0]  cd   [0:255];   // data perintah
    reg [7:0]  rd   [0:255];   // data jawaban

    task apdu(input [7:0] cla, input [7:0] ins, input [7:0] p1, input [7:0] p2,
              input integer lc, input integer le, input integer max_cyc,
              input bad_crc);
        integer i, g, n0, tot;
        reg [15:0] c;
        reg [7:0]  sync;
        begin
            n0   = rxn;
            sync = (le >= 0) ? 8'h5A : 8'h5B;
            c = crc16(16'hFFFF, sync); uart_send(sync);
            c = crc16(c, cla); uart_send(cla);
            c = crc16(c, ins); uart_send(ins);
            c = crc16(c, p1);  uart_send(p1);
            c = crc16(c, p2);  uart_send(p2);
            c = crc16(c, lc[7:0]); uart_send(lc[7:0]);
            for (i = 0; i < lc; i = i + 1) begin c = crc16(c, cd[i]); uart_send(cd[i]); end
            if (le >= 0) begin c = crc16(c, le[7:0]); uart_send(le[7:0]); end
            if (bad_crc) c = c ^ 16'h0001;
            uart_send(c[15:8]);
            uart_send(c[7:0]);

            // Tunggu SW1 SW2 LEN, lalu data + CRC
            r_ok = 1'b0; r_sw = 16'hFFFF; r_len = -1;
            g = 0;
            while (rxn < n0 + 3 && g < max_cyc) begin @(posedge clk_50); g = g + 1; end
            if (rxn >= n0 + 3) begin
                tot = 3 + rxq[n0 + 2] + 2;
                while (rxn < n0 + tot && g < max_cyc) begin @(posedge clk_50); g = g + 1; end
                if (rxn >= n0 + tot) begin
                    r_sw  = {rxq[n0], rxq[n0 + 1]};
                    r_len = rxq[n0 + 2];
                    c = 16'hFFFF;
                    for (i = 0; i < 3 + r_len; i = i + 1) c = crc16(c, rxq[n0 + i]);
                    for (i = 0; i < r_len; i = i + 1) rd[i] = rxq[n0 + 3 + i];
                    r_ok = (c == {rxq[n0 + 3 + r_len], rxq[n0 + 4 + r_len]});
                end
            end
            repeat (20) @(posedge clk_50);
        end
    endtask

    // =========================================================================
    // Mesin kripto sisi host
    // =========================================================================
    reg  [45:0]  hreq = 46'd0, areq = 46'd0;
    reg  [127:0] hkey = 128'd0, akey = 128'd0;
    wire [31:0]  hrd, ard;
    wire [127:0] h_kk;  wire h_kw;
    wire [34:0]  h_sc;  wire [255:0] h_dg;  wire h_sr;

    hmac_kdf    host_hmac (.clk_sys(clk_50), .rst_sync_n(rst_n), .zeroize(1'b0),
                           .req(hreq), .rdata(hrd), .key_in(hkey),
                           .kdf_key(h_kk), .kdf_wr(h_kw),
                           .sha_ctl(h_sc), .digest(h_dg), .sha_ready(h_sr));
    sha256_core host_sha  (.clk_sys(clk_50), .rst_sync_n(rst_n), .zeroize(1'b0),
                           .sha_ctl(h_sc), .digest(h_dg), .sha_ready(h_sr));
    aes128_sm   host_aes  (.clk_sys(clk_50), .rst_sync_n(rst_n), .zeroize(1'b0),
                           .req(areq), .rdata(ard), .key_in(akey), .wrap_key(128'd0));

    task hb_wr(input [11:0] a, input [31:0] d);
        begin @(posedge clk_50); #1 hreq = {a, d, 1'b1, 1'b0}; @(posedge clk_50); #1 hreq = 46'd0; end
    endtask
    task hb_rd(input [11:0] a, output [31:0] d);
        begin @(posedge clk_50); #1 hreq = {a, 32'd0, 1'b0, 1'b1}; @(posedge clk_50); #1 hreq = 46'd0; d = hrd; end
    endtask
    task ab_wr(input [11:0] a, input [31:0] d);
        begin @(posedge clk_50); #1 areq = {a, d, 1'b1, 1'b0}; @(posedge clk_50); #1 areq = 46'd0; end
    endtask
    task ab_rd(input [11:0] a, output [31:0] d);
        begin @(posedge clk_50); #1 areq = {a, 32'd0, 1'b0, 1'b1}; @(posedge clk_50); #1 areq = 46'd0; d = ard; end
    endtask

    reg [7:0]   hm_in [0:63];    // pesan HMAC host
    reg [255:0] hdig;

    task host_hmac_run(input [127:0] key, input integer len);
        integer i;
        reg [31:0] w;
        begin
            hkey = key;
            hb_wr(12'h028, len);
            for (i = 0; i < (len + 3) / 4; i = i + 1)
                hb_wr(12'h02C + 4*i, {hm_in[4*i], hm_in[4*i+1], hm_in[4*i+2], hm_in[4*i+3]});
            hb_wr(12'h000, 32'd1);
            repeat (450) @(posedge clk_50);
            for (i = 0; i < 8; i = i + 1) begin hb_rd(12'h008 + 4*i, w); hdig = {hdig[223:0], w}; end
        end
    endtask

    function [127:0] kdf_hi(input [255:0] d); kdf_hi = d[255:128]; endfunction

    task host_aes_ecb(input [127:0] key, input [127:0] din, input dec, output [127:0] dout);
        reg [31:0] w0, w1, w2, w3;
        begin
            akey = key;
            ab_wr(12'h110, din[127:96]); ab_wr(12'h114, din[95:64]);
            ab_wr(12'h118, din[63:32]);  ab_wr(12'h11C, din[31:0]);
            ab_wr(12'h100, dec ? 32'd3 : 32'd1);
            repeat (90) @(posedge clk_50);   // AES 32 bit: ~52-62 siklus
            ab_rd(12'h130, w0); ab_rd(12'h134, w1); ab_rd(12'h138, w2); ab_rd(12'h13C, w3);
            dout = {w0, w1, w2, w3};
        end
    endtask

    // =========================================================================
    // Data skenario
    // =========================================================================
    reg [191:0] MRZ      = "L898902C<369080619406236";   // 24 byte (gaya ICAO)
    reg [191:0] MRZ_SALAH= "X00000000000000000000000";
    reg [127:0] S_KT     = 128'h0F1E2D3C4B5A69788796A5B4C3D2E1F0;
    reg [127:0] S_KTA    = 128'h00112233445566778899AABBCCDDEEFF;
    reg [127:0] DATA_UM  = 128'h4A4154492D44415441554D554D2D3031;   // "JATI-DATAUMUM-01"
    reg [127:0] DATA_DG3 = 128'hB10B10B10B10B10B10B10B10B10B10B1;

    reg [127:0] K_T_h, K_TA_h, K_CA_h, K_ACCE_h, K_ACCM_h, K_SENC_h, K_SMAC_h;
    reg [127:0] wrapped, blk, c1, c2, p1, p2;
    reg [63:0]  rnd_ic, rnd_ifd, ssc_h;
    reg [127:0] k_ifd, k_ic;
    reg [7:0]   helper [0:127];
    reg [7:0]   tag    [0:15];
    integer     i, okc;

    task set_cd128(input integer o, input [127:0] v);
        integer j; begin for (j = 0; j < 16; j = j + 1) cd[o + j] = v[127 - 8*j -: 8]; end
    endtask
    function [127:0] rd128(input integer o);
        integer j; begin for (j = 0; j < 16; j = j + 1) rd128[127 - 8*j -: 8] = rd[o + j]; end
    endfunction

    // KDF host: label + data
    task host_kdf_label(input [127:0] key, input [31:0] label4, input [191:0] data24,
                        input integer dlen, output [127:0] out);
        integer j;
        begin
            for (j = 0; j < 4; j = j + 1) hm_in[j] = label4[31 - 8*j -: 8];
            for (j = 0; j < dlen; j = j + 1) hm_in[4 + j] = data24[191 - 8*j -: 8];
            host_hmac_run(key, 4 + dlen);
            out = kdf_hi(hdig);
        end
    endtask

    // MAC SM perintah: HMAC(K_SMAC, SSC || CLA INS P1 P2 || Le || payload)[0..7]
    task sm_cmd_mac(input [7:0] cla, input [7:0] ins, input [7:0] p1, input [7:0] p2,
                    input [7:0] le, input integer plen, output [63:0] mac);
        integer j;
        begin
            ssc_h = ssc_h + 1;
            for (j = 0; j < 8; j = j + 1) hm_in[j] = ssc_h[63 - 8*j -: 8];
            hm_in[8] = cla; hm_in[9] = ins; hm_in[10] = p1; hm_in[11] = p2; hm_in[12] = le;
            for (j = 0; j < plen; j = j + 1) hm_in[13 + j] = cd[j];
            host_hmac_run(K_SMAC_h, 13 + plen);
            mac = hdig[255:192];
        end
    endtask

    // MAC SM jawaban: HMAC(K_SMAC, SSC || 90 00 || data)[0..7]
    task sm_resp_mac_ok(input integer dlen, output ok);
        begin sm_resp_mac_sw(dlen, 16'h9000, ok); end
    endtask

    // A13: MAC jawaban SM juga melindungi status word (termasuk error)
    task sm_resp_mac_sw(input integer dlen, input [15:0] swx, output ok);
        integer j;
        reg [63:0] m;
        begin
            ssc_h = ssc_h + 1;
            for (j = 0; j < 8; j = j + 1) hm_in[j] = ssc_h[63 - 8*j -: 8];
            hm_in[8] = swx[15:8]; hm_in[9] = swx[7:0];
            for (j = 0; j < dlen; j = j + 1) hm_in[10 + j] = rd[j];
            host_hmac_run(K_SMAC_h, 10 + dlen);
            m = hdig[255:192];
            ok = 1'b1;
            for (j = 0; j < 8; j = j + 1) if (rd[dlen + j] != m[63 - 8*j -: 8]) ok = 1'b0;
        end
    endtask

    // A6: dekripsi blok pertama jawaban SM dengan IV = AES(K_S_ENC, 0^64 || SSC jawaban)
    task sm_dec_first(output [127:0] p);
        reg [127:0] ivx, d0;
        begin
            host_aes_ecb(K_SENC_h, {64'd0, ssc_h}, 1'b0, ivx);
            host_aes_ecb(K_SENC_h, rd128(0), 1'b1, d0);
            p = d0 ^ ivx;
        end
    endtask

    // EXTERNAL AUTH lengkap dengan MRZ tertentu
    task ext_auth(input [191:0] mrz, output ok_out);
        reg [63:0] m;
        integer j;
        reg okm;
        begin
            // Tantangan dari chip
            apdu(8'h00, 8'h84, 8'h00, 8'h00, 0, 8, 400000, 1'b0);
            for (j = 0; j < 8; j = j + 1) rnd_ic[63 - 8*j -: 8] = rd[j];
            // Kunci pintu sisi host
            host_kdf_label(128'd0, "ACCE", mrz, 24, K_ACCE_h);
            host_kdf_label(128'd0, "ACCM", mrz, 24, K_ACCM_h);
            rnd_ifd = 64'h1122334455667788;
            k_ifd   = 128'hA1A2A3A4A5A6A7A8A9AAABACADAEAFB0;
            // E_IFD = AES-CBC(K_ACC_ENC, IV 0, RND.IFD || RND.IC || K.IFD)
            host_aes_ecb(K_ACCE_h, {rnd_ifd, rnd_ic}, 1'b0, c1);
            host_aes_ecb(K_ACCE_h, k_ifd ^ c1, 1'b0, c2);
            set_cd128(0, c1); set_cd128(16, c2);
            for (j = 0; j < 32; j = j + 1) hm_in[j] = cd[j];
            host_hmac_run(K_ACCM_h, 32);
            m = hdig[255:192];
            for (j = 0; j < 8; j = j + 1) cd[32 + j] = m[63 - 8*j -: 8];
            apdu(8'h00, 8'h82, 8'h00, 8'h00, 40, 40, 600000, 1'b0);
            ok_out = 1'b0;
            if (r_sw == 16'h9000 && r_len == 40) begin
                // Periksa M_IC lalu dekripsi E_IC
                for (j = 0; j < 32; j = j + 1) hm_in[j] = rd[j];
                host_hmac_run(K_ACCM_h, 32);
                m = hdig[255:192];
                okm = 1'b1;
                for (j = 0; j < 8; j = j + 1) if (rd[32 + j] != m[63 - 8*j -: 8]) okm = 1'b0;
                host_aes_ecb(K_ACCE_h, rd128(0), 1'b1, p1);
                host_aes_ecb(K_ACCE_h, rd128(16), 1'b1, p2);
                p2 = p2 ^ rd128(0);
                k_ic = p2;
                // Kunci sesi + SSC
                for (j = 0; j < 4; j = j + 1) hm_in[j] = "SENC" >> (8 * (3 - j));
                for (j = 0; j < 16; j = j + 1) begin
                    hm_in[4 + j]  = k_ifd[127 - 8*j -: 8];
                    hm_in[20 + j] = k_ic[127 - 8*j -: 8];
                end
                host_hmac_run(K_ACCE_h, 36);  K_SENC_h = kdf_hi(hdig);
                hm_in[1] = "M"; hm_in[2] = "A"; hm_in[3] = "C";
                host_hmac_run(K_ACCM_h, 36);  K_SMAC_h = kdf_hi(hdig);
                ssc_h = {rnd_ic[31:0], rnd_ifd[31:0]};
                ok_out = okm && (p1 == {rnd_ic, rnd_ifd});
            end
        end
    endtask

    task reboot;
        begin
            @(posedge clk_50); #1 rst_n = 1'b0;
            repeat (20) @(posedge clk_50);
            #1 rst_n = 1'b1;
            wait (dut.rst_sync_n === 1'b1);
            repeat (50) @(posedge clk_50);
        end
    endtask

    // =========================================================================
    reg        ok1;
    time       t_a, t_b;
    reg [63:0] mac;
    reg [127:0] chal;

    initial begin
        repeat (10) @(posedge clk_50);
        rst_n = 1'b1;
        wait (dut.rst_sync_n === 1'b1);
        repeat (50) @(posedge clk_50);
        rx_on = 1'b1;

        // ---------------- BLANK ----------------
        apdu(8'h80, 8'hCA, 8'h00, 8'h00, 0, 5, 50000, 1'b0);
        check(r_ok && r_sw == 16'h9000 && rd[0] == 8'h00, "01. Lewat UART: GET STATUS di BLANK (CRC jawaban benar)");

        apdu(8'h80, 8'hCA, 8'h00, 8'h00, 0, 5, 50000, 1'b1);
        check(r_ok && r_sw == 16'h6A80, "02. Frame dengan CRC rusak ditolak (6A80)");

        set_cd128(0, S_KT);
        apdu(8'h80, 8'h30, 8'h00, 8'h00, 16, -1, 200000, 1'b0);
        check(r_sw == 16'h9000, "03. LOAD K_T di BLANK");
        okc = 0;
        for (i = 0; i < 16; i = i + 1) if (dut.u_apdu.packet_ram[i] == 8'd0) okc = okc + 1;
        check(okc == 16, "03b. Rahasia K_T dihapus dari buffer APDU");

        // ---------------- PERSO ----------------
        apdu(8'h80, 8'h20, 8'h00, 8'h00, 0, -1, 50000, 1'b0);
        check(r_sw == 16'h9000, "04. START PERSO");

        set_cd128(0, S_KTA);
        apdu(8'h80, 8'h32, 8'h00, 8'h00, 16, -1, 200000, 1'b0);
        check(r_sw == 16'h9000, "05a. LOAD K_TA");
        apdu(8'h80, 8'h32, 8'h00, 8'h00, 16, -1, 200000, 1'b0);
        check(r_sw == 16'h6985, "05b. K_TA tidak bisa diisi ulang (6985)");

        for (i = 0; i < 24; i = i + 1) cd[i] = MRZ[191 - 8*i -: 8];
        apdu(8'h80, 8'hD6, 8'h00, 8'h00, 24, -1, 100000, 1'b0);
        set_cd128(0, DATA_UM);
        apdu(8'h80, 8'hD6, 8'h01, 8'h00, 16, -1, 100000, 1'b0);
        check(r_sw == 16'h9000, "06a. UPDATE: MRZ dan data umum tertulis");
        set_cd128(0, DATA_DG3);
        apdu(8'h80, 8'hD6, 8'h03, 8'h00, 16, -1, 100000, 1'b0);
        check(r_sw == 16'h6985, "06b. DG3 ditolak sebelum K_DG ada (A7)");

        apdu(8'h00, 8'hB0, 8'h01, 8'h00, 0, 16, 100000, 1'b0);
        check(r_sw == 16'h9000 && r_len == 16 && rd128(0) == DATA_UM, "07. READ polos saat PERSO");

        apdu(8'h80, 8'h10, 8'h00, 8'h00, 0, 0, 3000000, 1'b0);
        okc = 0;
        for (i = 0; i < 128; i = i + 1) begin
            helper[i] = rd[i];
            if (rd[i][2:0] != rd[i][5:3]) okc = okc + 1;
        end
        check(r_sw == 16'h9000 && r_len == 128 && okc == 128, "08. ENROLL PUF: 128 byte helper");

        apdu(8'h80, 8'h16, 8'h00, 8'h00, 0, -1, 3000000, 1'b0);
        for (i = 0; i < 16; i = i + 1) tag[i] = rd[i];
        check(r_sw == 16'h9000 && r_len == 16 && dut.u_km.v_ca === 1'b1 && dut.u_km.v_dg === 1'b1,
              "09. RECONSTRUCT: tag helper dibuat, K_DEV, K_CA, K_DG terbentuk");

        set_cd128(0, DATA_DG3);
        apdu(8'h80, 8'hD6, 8'h03, 8'h00, 16, -1, 200000, 1'b0);
        check(r_sw == 16'h9000 && dut.u_mem.mem[8'hC0] != DATA_DG3[127:96],
              "09b. DG3 tertulis TERENKRIPSI K_DG di memori (A7)");
        apdu(8'h00, 8'hB0, 8'h03, 8'h00, 0, 16, 200000, 1'b0);
        check(r_sw == 16'h9000 && rd128(0) == DATA_DG3, "09c. READ PERSO: DG3 didekripsi benar");

        apdu(8'h80, 8'h18, 8'h00, 8'h00, 0, 16, 200000, 1'b0);
        wrapped = rd128(0);
        for (i = 0; i < 7; i = i + 1) hm_in[i] = "JATI-KT" >> (8 * (6 - i));
        for (i = 0; i < 16; i = i + 1) hm_in[7 + i] = S_KT[127 - 8*i -: 8];
        host_hmac_run(128'd0, 23);  K_T_h = kdf_hi(hdig);
        host_aes_ecb(K_T_h, wrapped, 1'b1, K_CA_h);
        check(r_sw == 16'h9000 && K_CA_h == dut.u_km.k_ca, "10. EXPORT K_CA: penerbit membuka bungkus dengan K_T");

        apdu(8'h80, 8'h44, 8'h00, 8'h00, 0, -1, 200000, 1'b0);
        apdu(8'h80, 8'hCA, 8'h00, 8'h00, 0, 5, 50000, 1'b0);
        check(r_sw == 16'h9000 && rd[0] == 8'h02 && dut.u_km.v_t === 1'b0,
              "11. LOCK: lifecycle 02 dan K_T terhapus");

        // ---------------- LOCKED: tanpa autentikasi ----------------
        apdu(8'h80, 8'h18, 8'h00, 8'h00, 0, 16, 50000, 1'b0);
        check(r_sw == 16'h6985, "12a. EXPORT K_CA setelah LOCK ditolak");
        apdu(8'h00, 8'hB0, 8'h01, 8'h00, 0, 16, 50000, 1'b0);
        check(r_sw == 16'h6982, "12b. READ tanpa kunci pintu ditolak (6982)");
        for (i = 0; i < 8; i = i + 1) cd[i] = 8'h00;
        apdu(8'h0C, 8'hB0, 8'h01, 8'h00, 8, 16, 50000, 1'b0);
        check(r_sw == 16'h6982, "12c. Perintah SM tanpa sesi ditolak (6982)");

        for (i = 0; i < 128; i = i + 1) cd[i] = helper[i];
        apdu(8'h80, 8'h14, 8'h00, 8'h00, 128, -1, 100000, 1'b0);
        check(r_sw == 16'h6700, "12d. LOCKED: LOAD HELPER tanpa tag ditolak (6700)");

        // ---------------- Kunci pintu ----------------
        ext_auth(MRZ_SALAH, ok1);
        check(r_sw == 16'h6300 && dut.u_fsm.fail_cnt == 4'd1, "13a. EXTERNAL AUTH dengan MRZ salah ditolak (6300)");
        apdu(8'h00, 8'h82, 8'h00, 8'h00, 40, 40, 400000, 1'b0);
        check(r_sw == 16'h6985, "13b. Tantangan yang sama tidak bisa dicoba ulang (A4)");
        t_a = $time;
        ext_auth(MRZ_SALAH, ok1);
        t_b = $time;
        check(r_sw == 16'h6300 && dut.u_fsm.fail_cnt == 4'd2, "13c. Kegagalan kedua: jeda 2x lebih lama (A5)");

        ext_auth(MRZ, ok1);
        check(r_sw == 16'h9000 && ok1, "14. EXTERNAL AUTH benar: M_IC sah, RND.IC/RND.IFD cocok");

        // ---------------- Secure messaging ----------------
        sm_cmd_mac(8'h0C, 8'hB0, 8'h01, 8'h00, 8'd16, 0, mac);
        for (i = 0; i < 8; i = i + 1) cd[i] = mac[63 - 8*i -: 8];
        apdu(8'h0C, 8'hB0, 8'h01, 8'h00, 8, 16, 300000, 1'b0);
        sm_resp_mac_ok(16, ok1);
        sm_dec_first(blk);
        check(r_sw == 16'h9000 && r_len == 24 && ok1 && blk == DATA_UM,
              "15. READ (SM): terenkripsi, MAC sah, isi benar");

        sm_cmd_mac(8'h0C, 8'hB0, 8'h03, 8'h00, 8'd16, 0, mac);
        for (i = 0; i < 8; i = i + 1) cd[i] = mac[63 - 8*i -: 8];
        apdu(8'h0C, 8'hB0, 8'h03, 8'h00, 8, 16, 300000, 1'b0);
        sm_resp_mac_sw(0, 16'h6982, ok1);
        check(r_sw == 16'h6982 && r_len == 8 && ok1, "16. DG3 ditolak sebelum TA, error ber-MAC (A13)");

        // ---------------- Terminal auth ----------------
        begin : tk
            reg [255:0] d;
            // K_TA sisi terminal, lalu bukti HMAC(K_TA, "TA" || RND.IC)
            for (i = 0; i < 7; i = i + 1) hm_in[i] = "JATI-TA" >> (8 * (6 - i));
            for (i = 0; i < 16; i = i + 1) hm_in[7 + i] = S_KTA[127 - 8*i -: 8];
            host_hmac_run(128'd0, 23);  K_TA_h = kdf_hi(hdig);
            hm_in[0] = "T"; hm_in[1] = "A";
            for (i = 0; i < 8; i = i + 1) hm_in[2 + i] = rnd_ic[63 - 8*i -: 8];
            host_hmac_run(K_TA_h, 10);  d = hdig;
            for (i = 0; i < 16; i = i + 1) cd[i] = d[255 - 8*i -: 8];
        end
        sm_cmd_mac(8'h0C, 8'h82, 8'h01, 8'h00, 8'd0, 16, mac);
        for (i = 0; i < 8; i = i + 1) cd[16 + i] = mac[63 - 8*i -: 8];
        apdu(8'h0C, 8'h82, 8'h01, 8'h00, 24, 0, 300000, 1'b0);
        sm_resp_mac_ok(0, ok1);
        check(r_sw == 16'h9000 && ok1, "17. TERMINAL AUTH berhasil");

        sm_cmd_mac(8'h0C, 8'hB0, 8'h03, 8'h00, 8'd16, 0, mac);
        for (i = 0; i < 8; i = i + 1) cd[i] = mac[63 - 8*i -: 8];
        apdu(8'h0C, 8'hB0, 8'h03, 8'h00, 8, 16, 300000, 1'b0);
        sm_resp_mac_ok(16, ok1);
        sm_dec_first(blk);
        check(r_sw == 16'h9000 && ok1 && blk == DATA_DG3, "18. DG3 terbaca setelah TERMINAL AUTH");

        // ---------------- Bukti chip asli ----------------
        chal = 128'hC4A11E46EC4A11E46EC4A11E46EC4A11;
        set_cd128(0, chal);
        sm_cmd_mac(8'h0C, 8'h88, 8'h00, 8'h00, 8'd32, 16, mac);
        for (i = 0; i < 8; i = i + 1) cd[16 + i] = mac[63 - 8*i -: 8];
        apdu(8'h0C, 8'h88, 8'h00, 8'h00, 24, 32, 300000, 1'b0);
        sm_resp_mac_ok(32, ok1);
        hm_in[0] = "C"; hm_in[1] = "A";
        for (i = 0; i < 9; i = i + 1)  hm_in[2 + i]  = MRZ[191 - 8*i -: 8];     // A14: nomor dokumen
        for (i = 0; i < 16; i = i + 1) hm_in[11 + i] = chal[127 - 8*i -: 8];
        host_hmac_run(K_CA_h, 27);
        okc = 0;
        for (i = 0; i < 32; i = i + 1) if (rd[i] == hdig[255 - 8*i -: 8]) okc = okc + 1;
        check(r_sw == 16'h9000 && ok1 && okc == 32, "19. INTERNAL AUTH: jawaban cocok dengan K_CA penerbit");

        // ---------------- MAC dipalsukan ----------------
        sm_cmd_mac(8'h0C, 8'hB0, 8'h01, 8'h00, 8'd16, 0, mac);
        for (i = 0; i < 8; i = i + 1) cd[i] = mac[63 - 8*i -: 8] ^ 8'h01;
        apdu(8'h0C, 8'hB0, 8'h01, 8'h00, 8, 16, 300000, 1'b0);
        check(r_sw == 16'h6988, "20a. MAC perintah dipalsukan ditolak (6988)");
        apdu(8'h0C, 8'hB0, 8'h01, 8'h00, 8, 16, 300000, 1'b0);
        check(r_sw == 16'h6982, "20b. Sesi otomatis diputus setelah MAC salah");

        // ---------------- Kunci tidak pernah lewat bus ----------------
        check(kbus_leak == 0, "21. Tidak ada nilai kunci yang muncul di bus selama simulasi");

        // ---------------- Integritas helper data (boot ulang) ----------------
        // 23. Helper dimanipulasi: satu grup ditukar (a <-> b), tag asli
        reboot();
        apdu(8'h80, 8'h20, 8'h00, 8'h00, 0, -1, 50000, 1'b0);
        for (i = 0; i < 128; i = i + 1) cd[i] = helper[i];
        cd[5] = {2'b00, helper[5][2:0], helper[5][5:3]};
        for (i = 0; i < 16; i = i + 1) cd[128 + i] = tag[i];
        apdu(8'h80, 8'h14, 8'h00, 8'h00, 144, -1, 100000, 1'b0);
        apdu(8'h80, 8'h16, 8'h00, 8'h00, 0, -1, 3000000, 1'b0);
        check(r_sw == 16'h6300 && dut.u_km.v_rpuf === 1'b0 && dut.u_km.v_dev === 1'b0 && dut.u_km.v_ca === 1'b0,
              "23. Helper dimanipulasi: ditolak (6300), R_PUF dibuang, tanpa kunci");
        check(dut.u_fe.rc_cnt == 2'd3, "23b. Sebelum ditolak, rekonstruksi diulang 3x (A9)");

        // 24. Tag dipalsukan: helper asli, 1 bit tag dibalik
        reboot();
        apdu(8'h80, 8'h20, 8'h00, 8'h00, 0, -1, 50000, 1'b0);
        for (i = 0; i < 128; i = i + 1) cd[i] = helper[i];
        for (i = 0; i < 16; i = i + 1) cd[128 + i] = tag[i];
        cd[128] = cd[128] ^ 8'h01;
        apdu(8'h80, 8'h14, 8'h00, 8'h00, 144, -1, 100000, 1'b0);
        apdu(8'h80, 8'h16, 8'h00, 8'h00, 0, -1, 3000000, 1'b0);
        check(r_sw == 16'h6300 && dut.u_km.v_dev === 1'b0, "24. Tag dipalsukan: ditolak (6300), tanpa kunci");

        // 25. Helper + tag asli: kunci identik dengan personalisasi
        reboot();
        apdu(8'h80, 8'h20, 8'h00, 8'h00, 0, -1, 50000, 1'b0);
        for (i = 0; i < 128; i = i + 1) cd[i] = helper[i];
        for (i = 0; i < 16; i = i + 1) cd[128 + i] = tag[i];
        apdu(8'h80, 8'h14, 8'h00, 8'h00, 144, -1, 100000, 1'b0);
        apdu(8'h80, 8'h16, 8'h00, 8'h00, 0, -1, 3000000, 1'b0);
        check(r_sw == 16'h9000 && r_len == 0 && dut.u_km.k_ca == K_CA_h,
              "25. Helper + tag asli: lolos, K_CA identik dengan saat personalisasi");

        // ---------------- Serangan fault pada lifecycle (A2) ----------------
        reboot();
        apdu(8'h80, 8'h20, 8'h00, 8'h00, 0, -1, 50000, 1'b0);
        @(posedge clk_50); #1 force dut.u_lc.st = 8'h2C;      // PERSO (0x2D) dengan 1 bit terbalik
        @(posedge clk_50); #1 release dut.u_lc.st;
        repeat (10) @(posedge clk_50); #1;
        check(dut.u_lc.lc_fault === 1'b1 && dut.zeroize === 1'b1 && led_status === 4'b1111,
              "27. Bit lifecycle dibalik: lc_fault -> zeroize (A2)");

        // ---------------- Serangan fault pada flag otorisasi (A3) ----------------
        reboot();
        @(posedge clk_50); #1 force dut.u_fsm.ac_q = 8'hA4;   // 1 bit dari pola "ya"/"tidak"
        @(posedge clk_50); #1 release dut.u_fsm.ac_q;
        repeat (10) @(posedge clk_50); #1;
        check(dut.fsm_fault === 1'b1 && dut.zeroize === 1'b1, "28. Bit flag sesi dibalik: fsm_fault -> zeroize (A3)");

        // ---------------- Clock sistem dihentikan (A11) ----------------
        reboot();
        apdu(8'h80, 8'h20, 8'h00, 8'h00, 0, -1, 50000, 1'b0);
        for (i = 0; i < 16; i = i + 1) cd[i] = 8'h11;
        apdu(8'h80, 8'h30, 8'h00, 8'h00, 16, -1, 200000, 1'b0);
        force dut.clk_sys = 1'b0;
        #3000;
        check(dut.zeroize === 1'b1 && dut.u_km.v_t === 1'b0, "29. Clock dihentikan 3 us: zeroize tanpa clock, K_T terhapus (A11)");
        release dut.clk_sys;

        // ---------------- Serangan glitch ----------------
        reboot();
        apdu(8'h80, 8'h20, 8'h00, 8'h00, 0, -1, 50000, 1'b0);
        @(posedge clk_50); #1 glitch_test_en = 1'b1;
        repeat (40) @(posedge clk_50);
        check(dut.zeroize === 1'b1 && dut.u_km.v_ca === 1'b0 && led_status === 4'b1111,
              "30a. Glitch clock: tamper -> zeroize, kunci terhapus, LED 1111");
        apdu(8'h80, 8'hCA, 8'h00, 8'h00, 0, 5, 30000, 1'b0);
        check(r_sw == 16'hFFFF, "30b. Chip tidak menjawab lagi setelah serangan");

        if (errors == 0) $display("\n=== SEMUA TES LULUS ===");
        else             $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end

    // =========================================================================
    // Pengawas: nilai kunci di key_manager tidak boleh muncul di bus data
    // =========================================================================
    always @(negedge clk_50) if (rx_on) begin : watch
        reg [127:0] ks [0:4];
        integer q, w;
        ks[0] = dut.u_km.k_ca;  ks[1] = dut.u_km.k_dev; ks[2] = dut.u_km.k_dg;
        ks[3] = dut.u_km.k_s_enc; ks[4] = dut.u_km.k_s_mac;
        for (q = 0; q < 5; q = q + 1)
            if (ks[q] != 128'd0)
                for (w = 0; w < 4; w = w + 1)
                    if (dut.m_rdata == ks[q][127 - 32*w -: 32] || dut.m_req[33:2] == ks[q][127 - 32*w -: 32])
                        kbus_leak = kbus_leak + 1;
    end

endmodule