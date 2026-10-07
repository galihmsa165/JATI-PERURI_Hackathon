// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : fuzzy_ext
// Fungsi  : Mengubah frekuensi ring oscillator (RO-PUF) yang berisik menjadi
//           respons 128 bit yang stabil (R_PUF), lalu menyerahkannya ke
//           key_manager.
//
// Metode "1-dari-8" + voting mayoritas:
//   ENROLLMENT (sekali, di pabrik):
//     Untuk setiap grup g (0..127) berisi 8 RO, ukur frekuensi ke-8 RO,
//     pilih RO tercepat dan terlambat (selisih frekuensi terbesar = paling
//     stabil terhadap suhu/tegangan). Indeks keduanya disimpan sebagai
//     HELPER DATA 6 bit per grup: {b[2:0], a[2:0]} dengan a < b.
//     Helper data TIDAK RAHASIA: ia hanya memberi tahu pasangan mana yang
//     dibandingkan, bukan mana yang lebih cepat.
//   REKONSTRUKSI (setiap boot):
//     Untuk setiap grup, ukur pasangan (a, b) sebanyak N_VOTE kali.
//     Bit kunci = mayoritas dari (f_a > f_b). Hasil 128 bit dikirim ke
//     key_manager dengan pulsa r_valid, lalu langsung dihapus dari modul ini.
//
// Aturan keamanan:
//   1. Rekonstruksi hanya sekali per boot. Begitu dimulai, helper data
//      TERKUNCI (tidak bisa diubah) sampai reset. Mencegah penyerang mengubah
//      helper sedikit demi sedikit untuk menebak bit kunci.
//   2. Helper dengan a == b (pasangan RO dengan dirinya sendiri, yang akan
//      selalu menghasilkan bit 0 yang mudah ditebak) DITOLAK -> error.
//      Helper kosong setelah reset juga otomatis ditolak.
//   3. r_puf bernilai 0 kecuali selama satu siklus r_valid.
//   4. Mode karakterisasi (CHAR_MODE) membaca frekuensi mentah RO. Mode ini
//      MEMBOCORKAN bit kunci, jadi hanya untuk prototipe/riset, otomatis mati
//      setelah helper terkunci, dan WAJIB CHAR_MODE = 0 di chip final.
//   5. Batas waktu: jika ro_puf tidak menjawab, proses dihentikan (error),
//      tidak menggantung selamanya.
//   6. zeroize/reset menghapus respons dan semua data sementara seketika.
//
// Kontrak dengan ro_puf:
//   puf_ctl[9:0]   = indeks RO A (0..1023)
//   puf_ctl[19:10] = indeks RO B (0..1023)
//   puf_ctl[20]    = start (pulsa 1 siklus)
//   cnt[15:0]      = hitungan frekuensi RO A,  cnt[31:16] = RO B
//   cnt_done       = pulsa 1 siklus saat cnt sah
//   Indeks RO = {grup[6:0], posisi[2:0]}.
//
// Format bus (standar JATI final): req[45:34] alamat ([11:8] ID slave, FE = 5,
//   [7:0] register), req[33:2] data, req[1] we, req[0] re.
//   rdata TER-REGISTER: sah satu siklus setelah permintaan baca.
//
// Peta register:
//   0x00 CTRL     (W) bit0 enroll, bit1 rekonstruksi, bit2 ukur satu pasangan
//   0x01 STATUS   (R) bit0 sibuk, bit1 enrolled, bit2 rekonstruksi selesai,
//                     bit3 error, bit4 helper terkunci,
//                     bit[15:8] jumlah grup tidak stabil (voting tidak bulat)
//   0x02 MEAS_SEL (R/W) [9:0] RO A, [25:16] RO B   (khusus CHAR_MODE)
//   0x03 MEAS_CNT (R) {cnt_b, cnt_a} hasil ukur     (khusus CHAR_MODE)
//   0x04 MIN_DIFF (R) selisih frekuensi terkecil di antara pasangan terpilih
//   0x80..0xFF HELPER[g] (R/W) [5:0] = {b, a} untuk grup g = addr[6:0]
// =============================================================================

module fuzzy_ext #(
    parameter [3:0]   SLAVE_ID  = 4'h5,
    parameter integer RC_MAX    = 3,      // A9: batas rekonstruksi per boot
    parameter integer N_VOTE    = 5,       // ganjil, maksimal 7
    parameter integer TIMEOUT   = 65535,   // siklus menunggu cnt_done
    parameter integer CHAR_MODE = 1        // 1 = prototipe, 0 = chip final
)(
    input  wire         clk_sys,
    input  wire         rst_sync_n,
    input  wire         zeroize,

    input  wire [45:0]  req,
    output reg  [31:0]  rdata,

    output reg  [20:0]  puf_ctl,
    input  wire [31:0]  cnt,
    input  wire         cnt_done,

    output wire [127:0] r_puf,
    output reg          r_valid
);

    // -------------------------------------------------------------------------
    // Dekode bus
    // -------------------------------------------------------------------------
    localparam [7:0] REG_CTRL = 8'h00, REG_STATUS = 8'h01, REG_MSEL = 8'h02,
                     REG_MCNT = 8'h03, REG_MDIFF  = 8'h04;

    wire [11:0] addr  = req[45:34];
    wire [31:0] wdata = req[33:2];
    wire        we    = req[1];
    wire        re    = req[0];
    wire        sel   = (addr[11:8] == SLAVE_ID);
    wire [7:0]  ra    = addr[7:0];

    wire clr = zeroize | ~rst_sync_n;

    // -------------------------------------------------------------------------
    // State machine
    // -------------------------------------------------------------------------
    localparam [3:0] S_IDLE    = 4'd0,
                     S_EN_MEAS = 4'd1,  S_EN_WAIT = 4'd2,
                     S_EN_EVAL = 4'd3,  S_EN_STORE = 4'd4,
                     S_RC_MEAS = 4'd5,  S_RC_WAIT = 4'd6,  S_RC_BIT = 4'd7,
                     S_RC_OUT  = 4'd8,  S_RC_CLR  = 4'd9,
                     S_MS_MEAS = 4'd10, S_MS_WAIT = 4'd11;

    reg [3:0]   state;
    reg [6:0]   g;            // grup aktif
    reg [1:0]   p;            // pasangan saat enrollment (0..3)
    reg [2:0]   k;            // indeks pencarian max/min
    reg [2:0]   v;            // jumlah pengukuran voting
    reg [2:0]   votes;        // jumlah (f_a > f_b)
    reg [15:0]  f [0:7];      // frekuensi 8 RO dalam satu grup
    reg [15:0]  fmax, fmin;
    reg [2:0]   imax, imin;
    reg [127:0] R;            // respons hasil rekonstruksi
    reg [15:0]  tmo;          // penghitung batas waktu

    reg [5:0]   helper [0:127];
    reg         enrolled, recon_done, err, helper_locked;
    reg  [1:0]  rc_cnt;     // jumlah rekonstruksi di boot ini
    reg [7:0]   unstable;
    reg [15:0]  min_diff;
    reg [25:0]  meas_sel;     // {sel_b, 6'b0, sel_a} disimpan ringkas
    reg [31:0]  meas_cnt;

    wire busy = (state != S_IDLE);

    // Pasangan dari helper data grup aktif
    wire [2:0] h_a = helper[g][2:0];
    wire [2:0] h_b = helper[g][5:3];

    // Perintah dari bus (hanya diterima saat diam)
    wire cmd_wr    = sel && we && (ra == REG_CTRL) && !busy;
    wire cmd_en    = cmd_wr && wdata[0] && !helper_locked;
    // A9: rekonstruksi boleh diulang (derau suhu) maksimal RC_MAX kali per boot.
    //     Helper tetap terkunci sejak rekonstruksi pertama, sehingga pengulangan
    //     tidak bisa dipakai untuk mencoba helper lain.
    wire cmd_rc    = cmd_wr && wdata[1] && !err && (rc_cnt < RC_MAX);
    wire cmd_ms    = cmd_wr && wdata[2] && !helper_locked && (CHAR_MODE != 0);
    wire helper_wr = sel && we && ra[7] && !busy && !helper_locked;

    integer i;

    always @(posedge clk_sys or posedge clr) begin
        if (clr) begin
            state <= S_IDLE;
            g <= 7'd0;  p <= 2'd0;  k <= 3'd0;  v <= 3'd0;  votes <= 3'd0;
            for (i = 0; i < 8; i = i + 1) f[i] <= 16'd0;
            fmax <= 16'd0;  fmin <= 16'd0;  imax <= 3'd0;  imin <= 3'd0;
            R <= 128'd0;  tmo <= 16'd0;
            for (i = 0; i < 128; i = i + 1) helper[i] <= 6'd0;
            enrolled <= 1'b0;  recon_done <= 1'b0;  err <= 1'b0;
            helper_locked <= 1'b0;
            rc_cnt        <= 2'd0;
            unstable <= 8'd0;  min_diff <= 16'd0;
            meas_sel <= 26'd0; meas_cnt <= 32'd0;
            puf_ctl  <= 21'd0;
            r_valid  <= 1'b0;
        end else begin
            puf_ctl[20] <= 1'b0;       // start hanya satu siklus
            r_valid     <= 1'b0;

            // ---- Akses register dari bus ----
            if (helper_wr) helper[ra[6:0]] <= wdata[5:0];
            if (sel && we && (ra == REG_MSEL) && (CHAR_MODE != 0))
                meas_sel <= {wdata[25:16], 6'd0, wdata[9:0]};

            case (state)
                // ==============================================================
                S_IDLE: begin
                    if (cmd_en) begin
                        g <= 7'd0;  p <= 2'd0;
                        enrolled <= 1'b0;
                        state <= S_EN_MEAS;
                    end else if (cmd_rc) begin
                        helper_locked <= 1'b1;      // kunci helper selamanya
                        rc_cnt        <= rc_cnt + 1'b1;
                        recon_done    <= 1'b0;
                        g <= 7'd0;  v <= 3'd0;  votes <= 3'd0;
                        unstable <= 8'd0;
                        R <= 128'd0;
                        state <= S_RC_MEAS;
                    end else if (cmd_ms) begin
                        state <= S_MS_MEAS;
                    end
                end

                // ================= ENROLLMENT =================================
                S_EN_MEAS: begin
                    // Ukur pasangan (2p, 2p+1) di grup g
                    puf_ctl <= {1'b1, g, p, 1'b1, g, p, 1'b0};
                    tmo   <= 16'd0;
                    state <= S_EN_WAIT;
                end

                S_EN_WAIT: begin
                    if (cnt_done) begin
                        f[{p, 1'b0}] <= cnt[15:0];
                        f[{p, 1'b1}] <= cnt[31:16];
                        if (p == 2'd3) begin
                            k     <= 3'd1;
                            state <= S_EN_EVAL;
                        end else begin
                            p     <= p + 1'b1;
                            state <= S_EN_MEAS;
                        end
                    end else if (tmo == TIMEOUT) begin
                        err   <= 1'b1;
                        state <= S_IDLE;
                    end else
                        tmo <= tmo + 1'b1;
                end

                S_EN_EVAL: begin
                    // Cari indeks RO tercepat (imax) dan terlambat (imin)
                    if (k == 3'd1) begin
                        // Bandingkan f[1] dengan f[0] sebagai nilai awal
                        fmax <= (f[1] > f[0]) ? f[1] : f[0];
                        imax <= (f[1] > f[0]) ? 3'd1 : 3'd0;
                        fmin <= (f[1] < f[0]) ? f[1] : f[0];
                        imin <= (f[1] < f[0]) ? 3'd1 : 3'd0;
                    end else begin
                        if (f[k] > fmax) begin fmax <= f[k]; imax <= k; end
                        if (f[k] < fmin) begin fmin <= f[k]; imin <= k; end
                    end
                    if (k == 3'd7) state <= S_EN_STORE;
                    else           k     <= k + 1'b1;
                end

                S_EN_STORE: begin
                    if (imax == imin) begin
                        // Semua frekuensi sama: grup tidak bisa dipakai
                        err   <= 1'b1;
                        state <= S_IDLE;
                    end else begin
                        helper[g] <= (imax < imin) ? {imin, imax} : {imax, imin};
                        if (g == 7'd0 || (fmax - fmin) < min_diff)
                            min_diff <= fmax - fmin;
                        if (g == 7'd127) begin
                            enrolled <= 1'b1;
                            state    <= S_IDLE;
                        end else begin
                            g     <= g + 1'b1;
                            p     <= 2'd0;
                            state <= S_EN_MEAS;
                        end
                    end
                end

                // ================= REKONSTRUKSI ===============================
                S_RC_MEAS: begin
                    if (h_a == h_b) begin
                        // Helper tidak sah (termasuk helper kosong)
                        err   <= 1'b1;
                        R     <= 128'd0;
                        state <= S_IDLE;
                    end else begin
                        puf_ctl <= {1'b1, g, h_b, g, h_a};
                        tmo     <= 16'd0;
                        state   <= S_RC_WAIT;
                    end
                end

                S_RC_WAIT: begin
                    if (cnt_done) begin
                        if (cnt[15:0] > cnt[31:16]) votes <= votes + 1'b1;
                        if (v == N_VOTE - 1) begin
                            v     <= 3'd0;
                            state <= S_RC_BIT;
                        end else begin
                            v     <= v + 1'b1;
                            state <= S_RC_MEAS;
                        end
                    end else if (tmo == TIMEOUT) begin
                        err   <= 1'b1;
                        R     <= 128'd0;
                        state <= S_IDLE;
                    end else
                        tmo <= tmo + 1'b1;
                end

                S_RC_BIT: begin
                    R[g] <= (votes >= (N_VOTE + 1) / 2);
                    if (votes != 3'd0 && votes != N_VOTE)
                        unstable <= unstable + 1'b1;
                    votes <= 3'd0;
                    if (g == 7'd127) state <= S_RC_OUT;
                    else begin
                        g     <= g + 1'b1;
                        state <= S_RC_MEAS;
                    end
                end

                S_RC_OUT: begin
                    r_valid <= 1'b1;            // satu siklus
                    state   <= S_RC_CLR;
                end

                S_RC_CLR: begin
                    R          <= 128'd0;       // hapus segera setelah diserahkan
                    recon_done <= 1'b1;
                    state      <= S_IDLE;
                end

                // ================= UKUR SATU PASANGAN (CHAR_MODE) =============
                S_MS_MEAS: begin
                    puf_ctl <= {1'b1, meas_sel[25:16], meas_sel[9:0]};
                    tmo     <= 16'd0;
                    state   <= S_MS_WAIT;
                end

                S_MS_WAIT: begin
                    if (cnt_done) begin
                        meas_cnt <= cnt;
                        state    <= S_IDLE;
                    end else if (tmo == TIMEOUT) begin
                        err   <= 1'b1;
                        state <= S_IDLE;
                    end else
                        tmo <= tmo + 1'b1;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    // r_puf hanya terlihat selama pulsa r_valid
    assign r_puf = r_valid ? R : 128'd0;

    // -------------------------------------------------------------------------
    // Pembacaan bus (TER-REGISTER: sah satu siklus setelah permintaan)
    // -------------------------------------------------------------------------
    reg [31:0] rdata_c;
    always @(*) begin
        rdata_c = 32'd0;
        if (ra[7])
            rdata_c = {26'd0, helper[ra[6:0]]};
        else case (ra)
            REG_CTRL:   rdata_c = 32'd0;
            REG_STATUS: rdata_c = {16'd0, unstable, 3'd0, helper_locked, err,
                                   recon_done, enrolled, busy};
            REG_MSEL:   rdata_c = (CHAR_MODE != 0) ? {6'd0, meas_sel[25:16], 6'd0, meas_sel[9:0]} : 32'd0;
            REG_MCNT:   rdata_c = (CHAR_MODE != 0) ? meas_cnt : 32'd0;
            REG_MDIFF:  rdata_c = {16'd0, min_diff};
            default:    rdata_c = 32'd0;
        endcase
    end

    always @(posedge clk_sys or posedge clr) begin
        if (clr)              rdata <= 32'd0;
        else if (sel && re)   rdata <= rdata_c;
    end

endmodule