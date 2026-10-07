// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : ctrl_fsm   (FASE 2 + revisi keamanan v3)
//
// REVISI v3 (analisis celah A1-A15):
//   A2  Lifecycle: bit "pernah LOCKED" dibaca tiap perintah; READ polos,
//       personalisasi, LOAD K, ENROLL, EXPORT ditolak setelah pernah LOCKED.
//   A3  Flag sesi (ac_q) dan akses DG3 (ta_q) berupa pola 8 bit; pola rusak
//       -> fsm_fault. Akses DG3 diperiksa dua kali (saat izin dan saat baca).
//   A4  Setiap EXTERNAL AUTH menghabiskan tantangan (1 tantangan = 1 percobaan).
//   A5  Kegagalan EXTERNAL AUTH berturut-turut: jawaban ditunda
//       DLY_BASE << n siklus (maks DLY_MAX_SH).
//   A6  Secure messaging: IV = AES(K_S_ENC, 0^64 || SSC jawaban).
//   A7  DG3 disimpan terenkripsi: AES-CTR dengan K_DG,
//       keystream = AES(K_DG, "JATI-DG3" || 0^7 || nomor blok).
//   A8  Jeda acak 0-15 siklus sebelum setiap operasi AES/HMAC (LFSR yang
//       di-reseed dari TRNG) untuk mempersulit penyelarasan jejak daya.
//   A9  Tag helper tidak cocok -> rekonstruksi diulang maks 2x (derau) sebelum
//       R_PUF dibuang.
//   A12 Bilangan acak dikondisikan: 12 kata TRNG mentah -> HMAC-SHA256 -> 8 kata.
//   A13 Kesalahan setelah MAC perintah SM sah dijawab dengan MAC (SW ikut di-MAC).
//   A14 INTERNAL AUTH terikat nomor dokumen:
//       HMAC(K_CA, "CA" || MRZ[0..8] || tantangan[16]).
//   Kebersihan: rahasia K_T/K_TA dihapus dari buffer APDU setelah dibaca.
// =============================================================================
// (Deskripsi fase 2 di bawah tetap berlaku kecuali yang diubah di atas.)
// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : ctrl_fsm   (FASE 2 - lengkap)
// Fungsi  : "Otak" chip. Menerima APDU dari apdu_parser, menegakkan aturan akses
//           berdasarkan lifecycle, menjalankan perintah lewat bus internal, dan
//           mengendalikan key_manager (key_sel) untuk HMAC/KDF dan AES.
//
// DAFTAR PERINTAH
//   Personalisasi / umum
//     80 CA  GET STATUS         semua status        -> 5 byte status
//     00 84  GET CHALLENGE      PERSO, LOCKED       -> RND.IC 8 byte (Le = 8)
//     80 20  START PERSO        BLANK -> PERSO
//     80 30  LOAD K_T           BLANK, PERSO        Lc = 16 (rahasia transport)
//     80 32  LOAD K_TA          PERSO               Lc = 16 (rahasia terminal)
//     80 D6  UPDATE BINARY      PERSO               offset & panjang kelipatan 4
//     00 B0  READ BINARY        PERSO (polos)       LOCKED wajib secure messaging
//     80 10  ENROLL PUF         PERSO               -> 128 byte helper
//     80 14  LOAD HELPER        sebelum rekonstruksi; Lc = 128 (helper) atau
//                               144 (helper + tag 16 byte); LOCKED wajib 144
//     80 16  RECONSTRUCT        PERSO, LOCKED       R_PUF -> cek tag -> K_DEV -> K_CA, K_DG
//                               (PERSO tanpa tag: tag dibuat dan dikirim, 16 byte)
//     80 18  EXPORT K_CA        PERSO               -> AES_KT(K_CA) 16 byte
//     80 44  LOCK               PERSO -> LOCKED     menghapus K_T permanen
//   Autentikasi (LOCKED)
//     00 82  EXTERNAL AUTH      kunci pintu (meniru BAC), Lc = 40 -> 40 byte
//     0C B0  READ BINARY (SM)   Le 16 / 32, terenkripsi + MAC
//     0C 88  INTERNAL AUTH (SM) bukti chip asli: HMAC(K_CA, "CA" || no_dok || tantangan)
//     0C 82  TERMINAL AUTH (SM) P1 = 01, membuka akses DG3 (biometrik)
//
// KRIPTOGRAFI (terinspirasi ICAO 9303, versi simetris)
//   K_DEV  = KDF(R_PUF, "JATI-DEV");  K_CA = KDF(K_DEV, "JATI-CA");
//   K_DG   = KDF(K_DEV, "JATI-DG");   KDF(K, m) = HMAC-SHA256(K, m)[255:128]
//   K_T    = KDF(0, "JATI-KT" || s);  K_TA = KDF(0, "JATI-TA" || s)
//   Kunci pintu: K_ACC_ENC = KDF(0, "ACCE" || MRZ), K_ACC_MAC = KDF(0, "ACCM" || MRZ)
//               MRZ = 24 byte pertama memori paspor (word 0..5)
//   EXTERNAL AUTH:
//     masuk : E_IFD = AES-CBC(K_ACC_ENC, IV 0, RND.IFD || RND.IC || K.IFD)  (32 B)
//             M_IFD = HMAC(K_ACC_MAC, E_IFD)[0..7]                           (8 B)
//     keluar: E_IC  = AES-CBC(K_ACC_ENC, IV 0, RND.IC || RND.IFD || K.IC)
//             M_IC  = HMAC(K_ACC_MAC, E_IC)[0..7]
//     sesi  : K_S_ENC = KDF(K_ACC_ENC, "SENC" || K.IFD || K.IC)
//             K_S_MAC = KDF(K_ACC_MAC, "SMAC" || K.IFD || K.IC)
//             SSC = RND.IC[4..7] || RND.IFD[4..7]
//   SECURE MESSAGING (CLA 0C):
//     data perintah = payload || MAC8,
//       MAC8 = HMAC(K_S_MAC, SSC+1 || CLA INS P1 P2 || Le[7:0] || payload)[0..7]
//     data jawaban  = data || MAC8,
//       MAC8 = HMAC(K_S_MAC, SSC+2 || SW1 SW2 || data)[0..7]   (v3: SW error juga)
//     READ (SM): data dienkripsi AES-CBC(K_S_ENC, IV = AES(K_S_ENC, 0^64||SSC+2)).
//     MAC salah -> 6988 dan
//     sesi diputus.
//
// INTEGRITAS HELPER DATA (robust fuzzy extractor)
//   tag = c3[0..15], dengan rantai HMAC berkunci R_PUF atas 128 byte helper:
//     c0 = HMAC(R_PUF, "JATI-HDT" || helper[0..31])
//     ci = HMAC(R_PUF, c(i-1)[0..15] || helper[32i..32i+31]),  i = 1..3
//   Dihitung SETELAH rekonstruksi dan SEBELUM K_DEV dibentuk. Tag tidak cocok
//   -> R_PUF dibuang (CMD_KILL_RPUF), tidak ada kunci sampai reboot, SW 6300.
//   Helper yang diubah sedikit pun selalu gagal, sehingga chip tidak lagi
//   menjadi "oracle" bagi serangan manipulasi helper data.
//
// PETA MEMORI (dg_memory 1 KB): 0x000-0x017 MRZ, 0x018-0x2FF data umum,
//   0x300-0x3FF DG3 biometrik (READ hanya setelah TERMINAL AUTH).
//
// ATURAN KEAMANAN
//   1. State dikodekan Hamming (16,11) diperluas, jarak minimal 4 bit.
//      State tidak sah -> fsm_fault -> tamper_sensor -> zeroize.
//   2. zeroize: keluaran dimatikan seketika, semua data sementara dihapus,
//      FSM masuk S_DEAD dan tidak menjawab lagi.
//   3. Kunci tidak pernah melewati FSM; FSM hanya memilih slot (key_sel).
//      key_sel kembali ke NONE segera setelah HMAC/AES mengunci kuncinya.
//   4. Semua buffer sementara (pesan, data, digest) dihapus setiap selesai
//      satu perintah.
//   5. Lifecycle dibaca ulang setiap perintah; semua penantian ber-timeout.
//
// ANTARMUKA (mengikuti kode partner)
//   cmd      = {CLA, INS, P1, P2, Lc[7:0], Le[8:0]},  cmd_crc_err
//   rsp      = {SW1, SW2, len[7:0], kirim}
//   buf_req  = {wr, rd, addr[7:0], wdata[7:0]}  (satu buffer 256 byte bersama;
//              baca sinkron, buf_rdata sah 1 siklus setelah permintaan)
//   m_req    = {alamat[11:0], wdata[31:0], we, re}; rdata ter-register
//   ID slave : 0 HMAC, 1 AES, 2 TRNG, 3 MEM, 4 LC, 5 FE
// =============================================================================

module ctrl_fsm #(
    parameter integer TMO        = 200000,
    parameter integer DLY_BASE   = 65536,   // A5: jeda dasar setelah gagal (siklus)
    parameter integer DLY_MAX_SH = 8        // A5: jeda maks = DLY_BASE << 8
)(
    input  wire        clk_sys,
    input  wire        rst_sync_n,
    input  wire        zeroize,

    input  wire [48:0] cmd,
    input  wire        cmd_valid,
    input  wire        cmd_crc_err,
    output wire [24:0] rsp,
    output wire        rsp_valid,

    output wire [17:0] buf_req,
    input  wire [7:0]  buf_rdata,

    output wire [45:0] m_req,
    input  wire [31:0] m_rdata,

    output wire [3:0]  key_sel,
    input  wire        key_ok,

    output reg         fsm_fault
);

    // =========================================================================
    // Konstanta
    // =========================================================================
    localparam [3:0] ID_HMAC = 4'h0, ID_AES = 4'h1, ID_TRNG = 4'h2,
                     ID_MEM  = 4'h3, ID_LC  = 4'h4, ID_FE   = 4'h5;

    localparam [1:0] LC_BLANK = 2'd0, LC_PERSO = 2'd1, LC_LOCKED = 2'd2, LC_TERM = 2'd3;

    localparam [3:0] K_NONE = 4'h0, K_RPUF = 4'h1, K_DEV = 4'h2, K_CA  = 4'h3,
                     K_DG   = 4'h4, K_T    = 4'h5, K_TA  = 4'h6, K_ACCE = 4'h7,
                     K_ACCM = 4'h8, K_SENC = 4'h9, K_SMAC = 4'hA, K_WRAP = 4'hB,
                     K_KILL = 4'hC, K_CLR  = 4'hD, K_ERASE = 4'hE, K_RETRY = 4'hF;
    // A3: flag otorisasi multi-bit (nilai lain = fault)
    localparam [7:0] AC_YES = 8'hA5, AC_NO = 8'h5A, TA_YES = 8'h3C, TA_NO = 8'hC3;

    localparam [15:0] SW_OK = 16'h9000, SW_LEN = 16'h6700, SW_AUTH = 16'h6982,
                      SW_COND = 16'h6985, SW_SMERR = 16'h6988, SW_DATA = 16'h6A80,
                      SW_P1P2 = 16'h6A86, SW_OFF = 16'h6B00, SW_INS = 16'h6D00,
                      SW_CLA = 16'h6E00, SW_FAIL = 16'h6F00, SW_VERIFY = 16'h6300;

    // AES CTRL: bit1 dekripsi, bit2 wrap, bit3 CBC
    localparam [3:0] A_ENC_CBC = 4'b1000, A_DEC_CBC = 4'b1010, A_WRAP = 4'b0100;

    // State: kode Hamming (16,11) diperluas, jarak minimal 4
    localparam [15:0] S_BOOT    = 16'h000F, S_IDLE    = 16'h0033, S_GETLC   = 16'h003C,
                      S_CHECK   = 16'h0055, S_RESP    = 16'h005A, S_DEAD    = 16'h0066,
                      S_STATUS  = 16'h0069, S_CHAL    = 16'h0096, S_UPD     = 16'h0099,
                      S_READ    = 16'h00A5, S_LCTX    = 16'h00AA, S_ENROLL  = 16'h00C3,
                      S_LOADH   = 16'h00CC, S_RECON   = 16'h00F0, S_LOADK   = 16'h00FF,
                      S_EXPCA   = 16'h0303, S_EXTAUTH = 16'h030C, S_SMCMD   = 16'h0330,
                      S_INTAUTH = 16'h033F, S_TAUTH   = 16'h0356, S_SMREAD  = 16'h0359,
                      S_HMAC    = 16'h0365, S_AES     = 16'h036A, S_RNDW    = 16'h0395,
                      S_SMRESP  = 16'h039A, S_DGKS    = 16'h03A6;

    // String label
    localparam [63:0] STR_DEV = "JATI-DEV";
    localparam [55:0] STR_CA  = "JATI-CA";
    localparam [55:0] STR_DG  = "JATI-DG";
    localparam [55:0] STR_KT  = "JATI-KT";
    localparam [55:0] STR_KTA = "JATI-TA";
    localparam [63:0] STR_HDT = "JATI-HDT";
    localparam [63:0] STR_DG3 = "JATI-DG3";

    // =========================================================================
    // Register
    // =========================================================================
    reg [15:0] state, ret_state;
    reg [4:0]  step, ret_step;
    reg [8:0]  idx;
    reg [3:0]  widx;
    reg [1:0]  bcnt;
    reg [19:0] tmo;
    reg [48:0] cmd_q;
    reg [1:0]  lc_st;
    reg [2:0]  t_cause;
    reg        lc_op;
    reg [31:0] fe_st, tr_st, word, rword;
    reg [15:0] sw;
    reg [7:0]  rlen;
    reg [24:0] rsp_q;
    reg        rsp_v;
    reg [3:0]  key_sel_r;

    reg        rnd_valid, keys_ok;
    reg [7:0]  ac_q, ta_q;            // A3: flag sesi / akses DG3 (multi-bit)
    wire       ac_ok = (ac_q == AC_YES);
    wire       ta_ok = (ta_q == TA_YES);
    wire       flags_bad = !((ac_q == AC_YES) || (ac_q == AC_NO)) ||
                           !((ta_q == TA_YES) || (ta_q == TA_NO));
    reg        ever_lk;               // A2: chip pernah LOCKED (dari lifecycle)
    reg [3:0]  fail_cnt;              // A5: kegagalan EXTERNAL AUTH berturut-turut
    reg [31:0] dly;                   // A5: penghitung jeda
    reg [1:0]  r_try;                 // A9: rekonstruksi ulang yang sudah dipakai
    reg [15:0] lfsr;                  // A8: jitter waktu operasi kripto
    reg [4:0]  jw;                    // A8: sisa siklus jeda acak
    reg        jw_go;
    reg [31:0] pool [0:7];            // A12: bilangan acak terkondisi (HMAC)
    reg [3:0]  pool_n;
    reg [3:0]  rcnt;
    reg [15:0] rw_rs;  reg [4:0] rw_rp;   // A12: alamat kembali RNDW
    reg [15:0] dk_rs;  reg [4:0] dk_rp;   // A7: alamat kembali DGKS
    reg [7:0]  dg_wa;                 // A7: alamat kata DG3
    reg        ks_ok;  reg [5:0] ks_blk;  // A7: keystream DG3 tersimpan
    reg [15:0] sm_sw;                 // A13: status word jawaban SM
    reg [63:0] ssc;
    reg [7:0]  rnd_ic [0:7];
    reg [7:0]  rifd   [0:7];
    reg [7:0]  kifd   [0:15];
    reg [7:0]  kic    [0:15];
    reg [7:0]  mb     [0:55];    // pesan untuk HMAC
    reg [5:0]  mlen;
    reg [7:0]  db     [0:63];    // data kerja / AES (48..63 = keystream DG3)
    reg [7:0]  hm     [0:31];    // hasil HMAC
    reg [5:0]  sm_n;             // panjang data jawaban SM
    reg [7:0]  tag_ref [0:15];   // tag integritas helper data
    reg        tag_valid;        // tag sudah dimuat / dibuat
    reg        tag_new;          // RECONSTRUCT ini membuat tag baru (PERSO)
    reg [1:0]  ck;               // nomor potongan helper (0..3)

    // Parameter subrutin
    reg        h_kdf;
    reg [3:0]  h_src, h_dst;
    reg [3:0]  a_mode, a_ks;
    reg        a_ivz;
    reg [5:0]  a_off;

    integer k;

    // Kolom perintah
    wire [7:0] q_cla = cmd_q[48:41];
    wire [7:0] q_ins = cmd_q[40:33];
    wire [7:0] q_p1  = cmd_q[32:25];
    wire [7:0] q_p2  = cmd_q[24:17];
    wire [7:0] q_lc  = cmd_q[16:9];
    wire [8:0] q_le  = cmd_q[8:0];
    wire [9:0] q_off = {q_p1[1:0], q_p2};
    wire       off_bad = (q_p1[7:2] != 6'd0) || (q_p2[1:0] != 2'b00);
    wire [10:0] end_upd = {1'b0, q_off} + {3'd0, q_lc};
    wire [10:0] end_rd  = {1'b0, q_off} + {2'd0, q_le};
    wire [5:0]  pl      = q_lc[5:0] - 6'd8;          // panjang payload SM
    wire [63:0] ssc_n1  = ssc + 64'd1;                   // SSC untuk jawaban SM
    wire [10:0] q_off11 = {1'b0, q_off};
    wire        upd_dg3 = (end_upd > 11'd768);           // UPDATE menyentuh DG3
    wire        rd_dg3  = (end_rd  > 11'd768);           // READ menyentuh DG3
    wire [7:0]  cur_wa  = q_off[9:2] + idx[7:2];         // alamat kata yang sedang diakses
    wire [31:0] ks_word = {db[48 + 4*dg_wa[1:0]], db[49 + 4*dg_wa[1:0]],
                           db[50 + 4*dg_wa[1:0]], db[51 + 4*dg_wa[1:0]]};

    // =========================================================================
    // Mesin transaksi bus (rdata ter-register: tangkap 2 siklus setelah req)
    // =========================================================================
    reg        b_go, b_we, b_done;
    reg [1:0]  b_ph;
    reg [11:0] b_addr;
    reg [31:0] b_wdata, b_rd;
    reg [45:0] m_req_r;

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            b_ph <= 2'd0;  b_done <= 1'b0;  b_rd <= 32'd0;  m_req_r <= 46'd0;
        end else begin
            b_done <= 1'b0;
            case (b_ph)
                2'd0: if (b_go) begin
                          m_req_r <= {b_addr, b_wdata, b_we, ~b_we};
                          b_ph    <= 2'd1;
                      end
                2'd1: begin m_req_r <= 46'd0; b_ph <= 2'd2; end   // slave & bus_mux mencuplik
                default: begin b_rd <= m_rdata; b_done <= 1'b1; b_ph <= 2'd0; end
            endcase
        end
    end

    // =========================================================================
    // Mesin akses buffer APDU (baca sinkron)
    // =========================================================================
    reg        f_go, f_we, f_done;
    reg [1:0]  f_ph;
    reg [7:0]  f_addr, f_wdata, f_rd;
    reg [17:0] buf_req_r;

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            f_ph <= 2'd0;  f_done <= 1'b0;  f_rd <= 8'd0;  buf_req_r <= 18'd0;
        end else begin
            f_done <= 1'b0;
            case (f_ph)
                2'd0: if (f_go) begin
                          buf_req_r <= {f_we, ~f_we, f_addr, f_wdata};
                          f_ph      <= 2'd1;
                      end
                2'd1: begin buf_req_r <= 18'd0; f_ph <= 2'd2; end
                default: begin f_rd <= buf_rdata; f_done <= 1'b1; f_ph <= 2'd0; end
            endcase
        end
    end

    // =========================================================================
    // Tugas bantu
    // =========================================================================
    task bus_rd(input [3:0] id, input [7:0] r);
        begin b_go <= 1'b1; b_we <= 1'b0; b_addr <= {id, r}; b_wdata <= 32'd0; end
    endtask

    task bus_wr(input [3:0] id, input [7:0] r, input [31:0] d);
        begin b_go <= 1'b1; b_we <= 1'b1; b_addr <= {id, r}; b_wdata <= d; end
    endtask

    task bufrd(input [7:0] a);
        begin f_go <= 1'b1; f_we <= 1'b0; f_addr <= a; f_wdata <= 8'd0; end
    endtask

    task bufwr(input [7:0] a, input [7:0] d);
        begin f_go <= 1'b1; f_we <= 1'b1; f_addr <= a; f_wdata <= d; end
    endtask

    task finish(input [15:0] s, input [7:0] len);
        begin sw <= s; rlen <= len; step <= 5'd0; key_sel_r <= K_NONE; state <= S_RESP; end
    endtask

    task call_hmac(input kdf, input [3:0] src, input [3:0] dst, input [15:0] rs, input [4:0] rstp);
        begin
            h_kdf <= kdf; h_src <= src; h_dst <= dst;
            ret_state <= rs; ret_step <= rstp;
            tmo <= 20'd0; step <= 5'd0; state <= S_HMAC;
        end
    endtask

    task call_aes(input [3:0] mode, input ivz, input [5:0] off, input [3:0] ks,
                  input [15:0] rs, input [4:0] rstp);
        begin
            a_mode <= mode; a_ivz <= ivz; a_off <= off; a_ks <= ks;
            ret_state <= rs; ret_step <= rstp;
            tmo <= 20'd0; step <= 5'd0; state <= S_AES;
        end
    endtask

    task call_rndw(input [15:0] rs, input [4:0] rstp);
        begin
            ret_state <= rs; ret_step <= rstp;
            tmo <= 20'd0; step <= 5'd0; state <= S_RNDW;
        end
    endtask

    task ret;
        begin state <= ret_state; step <= ret_step; end
    endtask

    // Pembanding MAC/hasil (kombinasional)
    //   eq_mac32 : hm[0..7]  == db[32..39]   (M_IFD pada EXTERNAL AUTH)
    //   eq_macpl : hm[0..7]  == db[pl..pl+7] (MAC perintah SM)
    //   eq_ta16  : hm[0..15] == db[0..15]    (TERMINAL AUTH)
    //   eq_tag   : hm[0..15] == tag_ref      (integritas helper data)
    reg     eq_mac32, eq_macpl, eq_ta16, eq_tag;
    integer k2;
    always @(*) begin
        eq_mac32 = 1'b1;  eq_macpl = 1'b1;  eq_ta16 = 1'b1;  eq_tag = 1'b1;
        for (k2 = 0; k2 < 8; k2 = k2 + 1) begin
            if (hm[k2] != db[32 + k2]) eq_mac32 = 1'b0;
            if (hm[k2] != db[pl + k2]) eq_macpl = 1'b0;
        end
        for (k2 = 0; k2 < 16; k2 = k2 + 1) begin
            if (hm[k2] != db[k2])      eq_ta16 = 1'b0;
            if (hm[k2] != tag_ref[k2]) eq_tag  = 1'b0;
        end
    end

    // =========================================================================
    // State machine utama
    // =========================================================================
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            state <= S_BOOT;  step <= 5'd0;  ret_state <= S_IDLE;  ret_step <= 5'd0;
            idx <= 9'd0;  widx <= 4'd0;  bcnt <= 2'd0;  tmo <= 20'd0;
            cmd_q <= 49'd0;  lc_st <= LC_BLANK;  t_cause <= 3'd0;  lc_op <= 1'b0;
            fe_st <= 32'd0;  tr_st <= 32'd0;  word <= 32'd0;  rword <= 32'd0;
            sw <= 16'd0;  rlen <= 8'd0;  rsp_q <= 25'd0;  rsp_v <= 1'b0;
            key_sel_r <= K_NONE;  fsm_fault <= 1'b0;
            rnd_valid <= 1'b0;  ac_q <= AC_NO;  ta_q <= TA_NO;  keys_ok <= 1'b0;
            ssc <= 64'd0;  mlen <= 6'd0;  sm_n <= 6'd0;
            ever_lk <= 1'b0;  fail_cnt <= 4'd0;  dly <= 32'd0;  r_try <= 2'd0;
            lfsr <= 16'hACE1;  jw <= 5'd0;  jw_go <= 1'b0;  pool_n <= 4'd0;  rcnt <= 4'd0;
            rw_rs <= S_IDLE;  rw_rp <= 5'd0;  dk_rs <= S_IDLE;  dk_rp <= 5'd0;
            dg_wa <= 8'd0;  ks_ok <= 1'b0;  ks_blk <= 6'd0;  sm_sw <= SW_OK;
            for (k = 0; k < 8; k = k + 1) pool[k] <= 32'd0;
            h_kdf <= 1'b0;  h_src <= K_NONE;  h_dst <= K_NONE;
            a_mode <= 4'd0;  a_ks <= K_NONE;  a_ivz <= 1'b0;  a_off <= 6'd0;
            b_go <= 1'b0;  b_we <= 1'b0;  b_addr <= 12'd0;  b_wdata <= 32'd0;
            f_go <= 1'b0;  f_we <= 1'b0;  f_addr <= 8'd0;   f_wdata <= 8'd0;
            for (k = 0; k < 8;  k = k + 1) begin rnd_ic[k] <= 8'd0; rifd[k] <= 8'd0; end
            for (k = 0; k < 16; k = k + 1) begin kifd[k] <= 8'd0; kic[k] <= 8'd0; end
            for (k = 0; k < 56; k = k + 1) mb[k] <= 8'd0;
            for (k = 0; k < 64; k = k + 1) db[k] <= 8'd0;
            for (k = 0; k < 32; k = k + 1) hm[k] <= 8'd0;
            for (k = 0; k < 16; k = k + 1) tag_ref[k] <= 8'd0;
            tag_valid <= 1'b0;  tag_new <= 1'b0;  ck <= 2'd0;
        end else begin
            b_go  <= 1'b0;
            f_go  <= 1'b0;
            rsp_v <= 1'b0;
            // A8: LFSR berjalan setiap siklus (x^16 + x^14 + x^13 + x^11 + 1)
            lfsr  <= (lfsr == 16'd0) ? 16'hACE1
                     : {lfsr[14:0], lfsr[15] ^ lfsr[13] ^ lfsr[12] ^ lfsr[10]};

            if (zeroize) begin
                // Hapus semua data sementara dan sesi, lalu mati
                state <= S_DEAD;  key_sel_r <= K_NONE;
                rnd_valid <= 1'b0;  ac_q <= AC_NO;  ta_q <= TA_NO;  keys_ok <= 1'b0;
                ssc <= 64'd0;  rword <= 32'd0;  word <= 32'd0;  ks_ok <= 1'b0;  pool_n <= 4'd0;
                for (k = 0; k < 8; k = k + 1) pool[k] <= 32'd0;
                for (k = 0; k < 8;  k = k + 1) begin rnd_ic[k] <= 8'd0; rifd[k] <= 8'd0; end
                for (k = 0; k < 16; k = k + 1) begin kifd[k] <= 8'd0; kic[k] <= 8'd0; end
                for (k = 0; k < 56; k = k + 1) mb[k] <= 8'd0;
                for (k = 0; k < 64; k = k + 1) db[k] <= 8'd0;
                for (k = 0; k < 32; k = k + 1) hm[k] <= 8'd0;
                for (k = 0; k < 16; k = k + 1) tag_ref[k] <= 8'd0;
                tag_valid <= 1'b0;  tag_new <= 1'b0;
            end else if (flags_bad) begin
                // A3: pola flag otorisasi rusak = fault injection
                fsm_fault <= 1'b1;
                key_sel_r <= K_NONE;
                state     <= S_DEAD;
            end else case (state)

            // ================= BOOT: nyalakan TRNG =================
            S_BOOT: case (step)
                5'd0: begin bus_wr(ID_TRNG, 8'h00, 32'd1); step <= 5'd1; end
                default: if (b_done) begin step <= 5'd0; state <= S_IDLE; end
            endcase

            // ================= Menunggu perintah =================
            S_IDLE: if (cmd_valid) begin
                cmd_q <= cmd;
                step  <= 5'd0;
                if (cmd_crc_err) finish(SW_DATA, 8'd0);     // frame rusak
                else             state <= S_GETLC;
            end

            // ================= Baca lifecycle =================
            S_GETLC: case (step)
                5'd0: begin bus_rd(ID_LC, 8'h00); step <= 5'd1; end
                default: if (b_done) begin
                    lc_st   <= b_rd[1:0];
                    t_cause <= b_rd[4:2];
                    ever_lk <= b_rd[5];                 // A2
                    step    <= 5'd0;
                    state   <= S_CHECK;
                end
            endcase

            // ================= Dekode + aturan akses =================
            S_CHECK: begin
                step <= 5'd0;  idx <= 9'd0;  widx <= 4'd0;  bcnt <= 2'd0;  tmo <= 20'd0;
                if (q_cla == 8'h80 && q_ins == 8'hCA)
                    state <= S_STATUS;
                else if (lc_st == LC_TERM)
                    finish(SW_COND, 8'd0);

                else if (q_cla == 8'h00 && q_ins == 8'h84) begin                 // GET CHALLENGE
                    if (lc_st == LC_BLANK)      finish(SW_COND, 8'd0);
                    else if (q_le != 9'd8)      finish(SW_LEN, 8'd0);
                    else                        state <= S_CHAL;
                end else if (q_cla == 8'h80 && q_ins == 8'h20) begin             // START PERSO
                    if (lc_st != LC_BLANK || ever_lk) finish(SW_COND, 8'd0);
                    else begin lc_op <= 1'b0; state <= S_LCTX; end
                end else if (q_cla == 8'h80 && (q_ins == 8'h30 || q_ins == 8'h32)) begin  // LOAD K_T / K_TA
                    if (ever_lk || (q_ins == 8'h30 && lc_st == LC_LOCKED)) finish(SW_COND, 8'd0);
                    else if (q_ins == 8'h32 && lc_st != LC_PERSO) finish(SW_COND, 8'd0);
                    else if (q_lc != 8'd16)     finish(SW_LEN, 8'd0);
                    else                        state <= S_LOADK;
                end else if (q_cla == 8'h80 && q_ins == 8'hD6) begin             // UPDATE BINARY
                    if (lc_st != LC_PERSO || ever_lk)               finish(SW_COND, 8'd0);
                    else if (q_lc == 8'd0 || q_lc[1:0] != 2'b00)    finish(SW_LEN, 8'd0);
                    else if (off_bad || end_upd > 11'd1024)         finish(SW_OFF, 8'd0);
                    else if (upd_dg3 && !keys_ok)                   finish(SW_COND, 8'd0);  // A7: K_DG wajib
                    else begin ks_ok <= 1'b0; state <= S_UPD; end
                end else if (q_cla == 8'h00 && q_ins == 8'hB0) begin             // READ BINARY polos
                    if (lc_st == LC_LOCKED || ever_lk)              finish(SW_AUTH, 8'd0);  // A2
                    else if (lc_st != LC_PERSO)                     finish(SW_COND, 8'd0);
                    else if (q_le == 9'd0 || q_le[1:0] != 2'b00 || q_le > 9'd252) finish(SW_LEN, 8'd0);
                    else if (off_bad || end_rd > 11'd1024)          finish(SW_OFF, 8'd0);
                    else if (rd_dg3 && !keys_ok)                    finish(SW_COND, 8'd0);
                    else begin ks_ok <= 1'b0; state <= S_READ; end
                end else if (q_cla == 8'h80 && q_ins == 8'h10) begin             // ENROLL
                    if (lc_st != LC_PERSO || ever_lk) finish(SW_COND, 8'd0);
                    else                        state <= S_ENROLL;
                end else if (q_cla == 8'h80 && q_ins == 8'h14) begin             // LOAD HELPER
                    if (q_lc != 8'd128 && q_lc != 8'd144)        finish(SW_LEN, 8'd0);
                    else if (lc_st == LC_LOCKED && q_lc != 8'd144) finish(SW_LEN, 8'd0);  // tag wajib
                    else                        state <= S_LOADH;
                end else if (q_cla == 8'h80 && q_ins == 8'h16) begin             // RECONSTRUCT
                    if (lc_st == LC_BLANK)      finish(SW_COND, 8'd0);
                    else                        state <= S_RECON;
                end else if (q_cla == 8'h80 && q_ins == 8'h18) begin             // EXPORT K_CA
                    if (lc_st != LC_PERSO || !keys_ok || ever_lk) finish(SW_COND, 8'd0);
                    else                        state <= S_EXPCA;
                end else if (q_cla == 8'h80 && q_ins == 8'h44) begin             // LOCK
                    if (lc_st != LC_PERSO)      finish(SW_COND, 8'd0);
                    else begin lc_op <= 1'b1; state <= S_LCTX; end
                end else if (q_cla == 8'h00 && q_ins == 8'h82) begin             // EXTERNAL AUTH
                    if (lc_st != LC_LOCKED || !rnd_valid) finish(SW_COND, 8'd0);
                    else if (q_lc != 8'd40)     finish(SW_LEN, 8'd0);
                    else begin
                        rnd_valid <= 1'b0;      // A4: satu tantangan = satu percobaan
                        state     <= S_EXTAUTH;
                    end
                end else if (q_cla == 8'h0C) begin                               // SECURE MESSAGING
                    if (lc_st != LC_LOCKED || !ac_ok)        finish(SW_AUTH, 8'd0);
                    else if (q_ins != 8'hB0 && q_ins != 8'h88 && q_ins != 8'h82) finish(SW_INS, 8'd0);
                    else if (q_lc < 8'd8 || q_lc > 8'd48)    finish(SW_LEN, 8'd0);
                    else                                     state <= S_SMCMD;
                end else if (q_cla != 8'h00 && q_cla != 8'h80)
                    finish(SW_CLA, 8'd0);
                else
                    finish(SW_INS, 8'd0);
            end

            // ================= GET STATUS (5 byte) =================
            S_STATUS: case (step)
                5'd0: begin bus_rd(ID_FE, 8'h01); step <= 5'd1; end
                5'd1: if (b_done) begin fe_st <= b_rd; bus_rd(ID_TRNG, 8'h01); step <= 5'd2; end
                5'd2: if (b_done) begin tr_st <= b_rd; idx <= 9'd0; step <= 5'd3; end
                5'd3: begin
                    case (idx[2:0])
                        3'd0: bufwr(8'd0, {6'd0, lc_st});
                        3'd1: bufwr(8'd1, {5'd0, t_cause});
                        3'd2: bufwr(8'd2, fe_st[7:0]);
                        3'd3: bufwr(8'd3, tr_st[7:0]);
                        default: bufwr(8'd4, {2'd0, ever_lk, tag_valid, keys_ok, ta_ok, ac_ok, rnd_valid});
                    endcase
                    step <= 5'd4;
                end
                default: if (f_done) begin
                    if (idx == 9'd4) finish(SW_OK, 8'd5);
                    else begin idx <= idx + 1'b1; step <= 5'd3; end
                end
            endcase

            // ================= GET CHALLENGE =================
            S_CHAL: case (step)
                5'd0: begin                         // putus sesi lama
                    ac_q <= AC_NO;  ta_q <= TA_NO;  rnd_valid <= 1'b0;
                    mlen  <= 6'd0;
                    call_hmac(1'b1, K_NONE, K_CLR, S_CHAL, 5'd1);
                end
                5'd1: call_rndw(S_CHAL, 5'd2);
                5'd2: begin
                    rnd_ic[0] <= rword[31:24]; rnd_ic[1] <= rword[23:16];
                    rnd_ic[2] <= rword[15:8];  rnd_ic[3] <= rword[7:0];
                    call_rndw(S_CHAL, 5'd3);
                end
                5'd3: begin
                    rnd_ic[4] <= rword[31:24]; rnd_ic[5] <= rword[23:16];
                    rnd_ic[6] <= rword[15:8];  rnd_ic[7] <= rword[7:0];
                    idx  <= 9'd0;
                    step <= 5'd4;
                end
                5'd4: begin bufwr(idx[7:0], rnd_ic[idx[2:0]]); step <= 5'd5; end
                default: if (f_done) begin
                    if (idx == 9'd7) begin rnd_valid <= 1'b1; finish(SW_OK, 8'd8); end
                    else begin idx <= idx + 1'b1; step <= 5'd4; end
                end
            endcase

            // ================= START PERSO / LOCK =================
            S_LCTX: case (step)
                5'd0: begin
                    if (!lc_op) begin bus_wr(ID_LC, 8'h00, {30'd0, LC_PERSO}); step <= 5'd4; end
                    else begin bus_rd(ID_FE, 8'h01); step <= 5'd1; end
                end
                5'd1: if (b_done) begin
                    // LOCK: PUF sudah enroll + rekonstruksi, kunci sudah diturunkan
                    if (!(b_rd[1] && b_rd[2] && keys_ok && tag_valid)) finish(SW_COND, 8'd0);
                    else begin mlen <= 6'd0; call_hmac(1'b1, K_NONE, K_ERASE, S_LCTX, 5'd2); end
                end
                5'd2: begin bus_wr(ID_LC, 8'h00, {30'd0, LC_LOCKED}); step <= 5'd4; end
                default: if (b_done) finish(SW_OK, 8'd0);
            endcase

            // ================= LOAD K_T / K_TA =================
            S_LOADK: case (step)
                5'd0: begin key_sel_r <= (q_ins == 8'h30) ? K_T : K_TA; step <= 5'd1; end
                5'd1: begin
                    if (key_ok) finish(SW_COND, 8'd0);       // sudah terisi (tulis sekali)
                    else begin key_sel_r <= K_NONE; idx <= 9'd0; step <= 5'd2; end
                end
                5'd2: begin bufrd(idx[7:0]); step <= 5'd3; end
                5'd3: if (f_done) begin
                    mb[7 + idx[3:0]] <= f_rd;
                    if (idx == 9'd15) begin idx <= 9'd0; step <= 5'd7; end
                    else begin idx <= idx + 1'b1; step <= 5'd2; end
                end
                // Rahasia K_T/K_TA dihapus dari buffer APDU (tidak bisa di-zeroize)
                5'd7: begin bufwr(idx[7:0], 8'd0); step <= 5'd8; end
                5'd8: if (f_done) begin
                    if (idx == 9'd15) step <= 5'd4;
                    else begin idx <= idx + 1'b1; step <= 5'd7; end
                end
                5'd4: begin
                    for (k = 0; k < 7; k = k + 1)
                        mb[k] <= (q_ins == 8'h30) ? STR_KT[55 - 8*k -: 8] : STR_KTA[55 - 8*k -: 8];
                    mlen <= 6'd23;
                    call_hmac(1'b1, K_NONE, (q_ins == 8'h30) ? K_T : K_TA, S_LOADK, 5'd5);
                end
                5'd5: begin key_sel_r <= (q_ins == 8'h30) ? K_T : K_TA; step <= 5'd6; end
                5'd6: begin
                    if (key_ok) finish(SW_OK, 8'd0);
                    else        finish(SW_FAIL, 8'd0);
                end
                default: state <= S_DEAD;
            endcase

            // ================= UPDATE BINARY (per kata 32 bit) =================
            S_UPD: case (step)
                5'd0: begin bufrd(idx[7:0]); step <= 5'd1; end
                5'd1: if (f_done) begin
                    word <= {word[23:0], f_rd};
                    if (idx[1:0] == 2'd3) begin
                        if (cur_wa >= 8'hC0) begin              // A7: DG3 dienkripsi K_DG
                            dg_wa <= cur_wa;
                            dk_rs <= S_UPD;  dk_rp <= 5'd3;
                            step  <= 5'd0;  state <= S_DGKS;
                        end else begin
                            bus_wr(ID_MEM, cur_wa, {word[23:0], f_rd});
                            step <= 5'd2;
                        end
                    end else begin idx <= idx + 1'b1; step <= 5'd0; end
                end
                5'd3: begin bus_wr(ID_MEM, dg_wa, word ^ ks_word); step <= 5'd2; end
                5'd2: if (b_done) begin
                    if (idx == {1'b0, q_lc} - 1'b1) finish(SW_OK, 8'd0);
                    else begin idx <= idx + 1'b1; step <= 5'd0; end
                end
                default: state <= S_DEAD;
            endcase

            // ================= READ BINARY polos =================
            S_READ: case (step)
                5'd0: begin bus_rd(ID_MEM, cur_wa); step <= 5'd1; end
                5'd1: if (b_done) begin
                    word <= b_rd; bcnt <= 2'd0;
                    if (cur_wa >= 8'hC0) begin                  // A7: dekripsi DG3
                        dg_wa <= cur_wa;  dk_rs <= S_READ;  dk_rp <= 5'd4;
                        step  <= 5'd0;    state <= S_DGKS;
                    end else step <= 5'd2;
                end
                5'd4: begin word <= word ^ ks_word; step <= 5'd2; end
                5'd2: begin bufwr(idx[7:0], word[31:24]); word <= {word[23:0], 8'd0}; step <= 5'd3; end
                5'd3: if (f_done) begin
                    if (idx == q_le - 1'b1) finish(SW_OK, q_le[7:0]);
                    else begin
                        idx <= idx + 1'b1;
                        if (bcnt == 2'd3) step <= 5'd0;
                        else begin bcnt <= bcnt + 1'b1; step <= 5'd2; end
                    end
                end
                default: state <= S_DEAD;
            endcase

            // ================= ENROLL =================
            S_ENROLL: case (step)
                5'd0: begin tag_valid <= 1'b0; bus_rd(ID_FE, 8'h01); step <= 5'd1; end   // helper baru -> tag lama batal
                5'd1: if (b_done) begin
                    if (b_rd[4]) finish(SW_COND, 8'd0);
                    else begin bus_wr(ID_FE, 8'h00, 32'd1); step <= 5'd2; end
                end
                5'd2: if (b_done) step <= 5'd3;
                5'd3: begin bus_rd(ID_FE, 8'h01); step <= 5'd4; end
                5'd4: if (b_done) begin
                    if (b_rd[0]) begin
                        if (tmo == TMO) finish(SW_FAIL, 8'd0);
                        else begin tmo <= tmo + 1'b1; step <= 5'd3; end
                    end
                    else if (b_rd[3] || !b_rd[1]) finish(SW_FAIL, 8'd0);
                    else begin idx <= 9'd0; step <= 5'd5; end
                end
                5'd5: begin bus_rd(ID_FE, {1'b1, idx[6:0]}); step <= 5'd6; end
                5'd6: if (b_done) begin bufwr(idx[7:0], {2'b00, b_rd[5:0]}); step <= 5'd7; end
                default: if (f_done) begin
                    if (idx == 9'd127) finish(SW_OK, 8'd128);
                    else begin idx <= idx + 1'b1; step <= 5'd5; end
                end
            endcase

            // ================= LOAD HELPER =================
            S_LOADH: case (step)
                5'd0: begin bus_rd(ID_FE, 8'h01); step <= 5'd1; end
                5'd1: if (b_done) begin
                    if (b_rd[4]) finish(SW_COND, 8'd0);
                    else begin idx <= 9'd0; step <= 5'd2; end
                end
                5'd2: begin bufrd(idx[7:0]); step <= 5'd3; end
                5'd3: if (f_done) begin
                    bus_wr(ID_FE, {1'b1, idx[6:0]}, {26'd0, f_rd[5:0]});
                    step <= 5'd4;
                end
                5'd4: if (b_done) begin
                    if (idx != 9'd127) begin idx <= idx + 1'b1; step <= 5'd2; end
                    else if (q_lc == 8'd144) begin idx <= 9'd128; step <= 5'd5; end
                    else begin tag_valid <= 1'b0; finish(SW_OK, 8'd0); end   // tanpa tag (PERSO)
                end
                // Tag 16 byte setelah helper
                5'd5: begin bufrd(idx[7:0]); step <= 5'd6; end
                default: if (f_done) begin
                    tag_ref[idx[3:0]] <= f_rd;
                    if (idx == 9'd143) begin tag_valid <= 1'b1; finish(SW_OK, 8'd0); end
                    else begin idx <= idx + 1'b1; step <= 5'd5; end
                end
            endcase

            // ================= RECONSTRUCT + turunkan kunci =================
            S_RECON: case (step)
                5'd0: begin tag_new <= 1'b0; r_try <= 2'd0; bus_rd(ID_FE, 8'h01); step <= 5'd1; end
                5'd1: if (b_done) begin
                    if (b_rd[4]) finish(SW_COND, 8'd0);
                    else if (!tag_valid && (lc_st != LC_PERSO || ever_lk)) finish(SW_COND, 8'd0);  // LOCKED wajib tag
                    else begin bus_wr(ID_FE, 8'h00, 32'd2); step <= 5'd2; end
                end
                5'd2: if (b_done) step <= 5'd3;
                5'd3: begin bus_rd(ID_FE, 8'h01); step <= 5'd4; end
                5'd4: if (b_done) begin
                    if (b_rd[0]) begin
                        if (tmo == TMO) finish(SW_FAIL, 8'd0);
                        else begin tmo <= tmo + 1'b1; step <= 5'd3; end
                    end
                    else if (b_rd[3] || !b_rd[2]) finish(SW_FAIL, 8'd0);
                    else begin ck <= 2'd0; idx <= 9'd0; step <= 5'd10; end
                end

                // ---- Tag integritas: rantai HMAC(R_PUF) atas 128 byte helper ----
                5'd10: begin bus_rd(ID_FE, {1'b1, ck, idx[4:0]}); step <= 5'd11; end
                5'd11: if (b_done) begin
                    mb[(ck == 2'd0 ? 6'd8 : 6'd16) + idx[4:0]] <= {2'b00, b_rd[5:0]};
                    if (idx[4:0] == 5'd31) step <= 5'd12;
                    else begin idx <= idx + 1'b1; step <= 5'd10; end
                end
                5'd12: begin
                    if (ck == 2'd0) begin
                        for (k = 0; k < 8; k = k + 1) mb[k] <= STR_HDT[63 - 8*k -: 8];
                        mlen <= 6'd40;
                    end else begin
                        for (k = 0; k < 16; k = k + 1) mb[k] <= hm[k];
                        mlen <= 6'd48;
                    end
                    call_hmac(1'b0, K_RPUF, K_NONE, S_RECON, 5'd13);
                end
                5'd13: begin
                    if (ck != 2'd3) begin ck <= ck + 1'b1; idx <= 9'd0; step <= 5'd10; end
                    else if (!tag_valid) begin                 // PERSO: buat tag baru
                        for (k = 0; k < 16; k = k + 1) tag_ref[k] <= hm[k];
                        tag_valid <= 1'b1;  tag_new <= 1'b1;
                        step <= 5'd15;
                    end
                    else if (eq_tag) step <= 5'd15;            // tag cocok
                    else if (r_try != 2'd2) begin              // A9: mungkin derau, coba lagi
                        r_try <= r_try + 1'b1;
                        mlen  <= 6'd0;
                        call_hmac(1'b1, K_NONE, K_RETRY, S_RECON, 5'd22);
                    end
                    else begin                                 // tetap salah: helper dimanipulasi
                        mlen <= 6'd0;
                        call_hmac(1'b1, K_NONE, K_KILL, S_RECON, 5'd14);
                    end
                end
                5'd14: finish(SW_VERIFY, 8'd0);                // R_PUF sudah dibuang
                5'd22: begin bus_wr(ID_FE, 8'h00, 32'd2); tmo <= 20'd0; step <= 5'd2; end

                // ---- Turunkan kunci ----
                5'd15: begin
                    for (k = 0; k < 8; k = k + 1) mb[k] <= STR_DEV[63 - 8*k -: 8];
                    mlen <= 6'd8;
                    call_hmac(1'b1, K_RPUF, K_DEV, S_RECON, 5'd16);
                end
                5'd16: begin
                    for (k = 0; k < 7; k = k + 1) mb[k] <= STR_CA[55 - 8*k -: 8];
                    mlen <= 6'd7;
                    call_hmac(1'b1, K_DEV, K_CA, S_RECON, 5'd17);
                end
                5'd17: begin
                    for (k = 0; k < 7; k = k + 1) mb[k] <= STR_DG[55 - 8*k -: 8];
                    mlen <= 6'd7;
                    call_hmac(1'b1, K_DEV, K_DG, S_RECON, 5'd18);
                end
                5'd18: begin key_sel_r <= K_CA; step <= 5'd19; end
                5'd19: begin
                    if (!key_ok)      finish(SW_FAIL, 8'd0);
                    else if (tag_new) begin keys_ok <= 1'b1; idx <= 9'd0; step <= 5'd20; end
                    else begin keys_ok <= 1'b1; finish(SW_OK, 8'd0); end
                end
                // Kirim tag baru (16 byte) ke penerbit
                5'd20: begin bufwr(idx[7:0], tag_ref[idx[3:0]]); step <= 5'd21; end
                default: if (f_done) begin
                    if (idx == 9'd15) finish(SW_OK, 8'd16);
                    else begin idx <= idx + 1'b1; step <= 5'd20; end
                end
            endcase

            // ================= EXPORT K_CA terbungkus K_T =================
            S_EXPCA: case (step)
                5'd0: begin key_sel_r <= K_WRAP; step <= 5'd1; end
                5'd1: begin
                    if (!key_ok) finish(SW_COND, 8'd0);       // K_T sudah tidak ada
                    else call_aes(A_WRAP, 1'b0, 6'd0, K_WRAP, S_EXPCA, 5'd2);
                end
                5'd2: begin idx <= 9'd0; step <= 5'd3; end
                5'd3: begin bufwr(idx[7:0], db[idx[3:0]]); step <= 5'd4; end
                default: if (f_done) begin
                    if (idx == 9'd15) finish(SW_OK, 8'd16);
                    else begin idx <= idx + 1'b1; step <= 5'd3; end
                end
            endcase

            // ================= EXTERNAL AUTH (kunci pintu) =================
            S_EXTAUTH: case (step)
                // Ambil E_IFD || M_IFD (40 byte)
                5'd0: begin bufrd(idx[7:0]); step <= 5'd1; end
                5'd1: if (f_done) begin
                    db[idx[5:0]] <= f_rd;
                    if (idx == 9'd39) begin widx <= 4'd0; step <= 5'd2; end
                    else begin idx <= idx + 1'b1; step <= 5'd0; end
                end
                // Baca MRZ (word 0..5) -> mb[4..27]
                5'd2: begin bus_rd(ID_MEM, {4'd0, widx}); step <= 5'd3; end
                5'd3: if (b_done) begin
                    mb[4 + 4*widx]     <= b_rd[31:24];
                    mb[4 + 4*widx + 1] <= b_rd[23:16];
                    mb[4 + 4*widx + 2] <= b_rd[15:8];
                    mb[4 + 4*widx + 3] <= b_rd[7:0];
                    if (widx == 4'd5) step <= 5'd4;
                    else begin widx <= widx + 1'b1; step <= 5'd2; end
                end
                // Turunkan K_ACC_ENC dan K_ACC_MAC
                5'd4: begin
                    mb[0] <= "A"; mb[1] <= "C"; mb[2] <= "C"; mb[3] <= "E";
                    mlen <= 6'd28;
                    call_hmac(1'b1, K_NONE, K_ACCE, S_EXTAUTH, 5'd5);
                end
                5'd5: begin
                    mb[3] <= "M";
                    call_hmac(1'b1, K_NONE, K_ACCM, S_EXTAUTH, 5'd6);
                end
                // Periksa M_IFD
                5'd6: begin
                    for (k = 0; k < 32; k = k + 1) mb[k] <= db[k];
                    mlen <= 6'd32;
                    call_hmac(1'b0, K_ACCM, K_NONE, S_EXTAUTH, 5'd7);
                end
                5'd7: begin
                    if (!eq_mac32) begin ac_q <= AC_NO; step <= 5'd25; end
                    else call_aes(A_DEC_CBC, 1'b1, 6'd0, K_ACCE, S_EXTAUTH, 5'd8);
                end
                5'd8: call_aes(A_DEC_CBC, 1'b0, 6'd16, K_ACCE, S_EXTAUTH, 5'd9);
                // Plaintext = RND.IFD || RND.IC || K.IFD ; periksa RND.IC
                5'd9: begin
                    if (db[8]  != rnd_ic[0] || db[9]  != rnd_ic[1] || db[10] != rnd_ic[2] ||
                        db[11] != rnd_ic[3] || db[12] != rnd_ic[4] || db[13] != rnd_ic[5] ||
                        db[14] != rnd_ic[6] || db[15] != rnd_ic[7]) begin
                        ac_q <= AC_NO; step <= 5'd25;
                    end else begin
                        for (k = 0; k < 8;  k = k + 1) rifd[k] <= db[k];
                        for (k = 0; k < 16; k = k + 1) kifd[k] <= db[16 + k];
                        call_rndw(S_EXTAUTH, 5'd10);
                    end
                end
                // K.IC dari TRNG (16 byte)
                5'd10, 5'd11, 5'd12, 5'd13: begin
                    kic[4*(step - 10)]     <= rword[31:24];
                    kic[4*(step - 10) + 1] <= rword[23:16];
                    kic[4*(step - 10) + 2] <= rword[15:8];
                    kic[4*(step - 10) + 3] <= rword[7:0];
                    if (step == 5'd13) step <= 5'd14;
                    else call_rndw(S_EXTAUTH, step + 1'b1);
                end
                // E_IC = AES-CBC(RND.IC || RND.IFD || K.IC)
                5'd14: begin
                    for (k = 0; k < 8;  k = k + 1) begin db[k] <= rnd_ic[k]; db[8 + k] <= rifd[k]; end
                    for (k = 0; k < 16; k = k + 1) db[16 + k] <= kic[k];
                    call_aes(A_ENC_CBC, 1'b1, 6'd0, K_ACCE, S_EXTAUTH, 5'd15);
                end
                5'd15: call_aes(A_ENC_CBC, 1'b0, 6'd16, K_ACCE, S_EXTAUTH, 5'd16);
                // M_IC
                5'd16: begin
                    for (k = 0; k < 32; k = k + 1) mb[k] <= db[k];
                    mlen <= 6'd32;
                    call_hmac(1'b0, K_ACCM, K_NONE, S_EXTAUTH, 5'd17);
                end
                // Kunci sesi
                5'd17: begin
                    for (k = 0; k < 8; k = k + 1) db[32 + k] <= hm[k];
                    mb[0] <= "S"; mb[1] <= "E"; mb[2] <= "N"; mb[3] <= "C";
                    for (k = 0; k < 16; k = k + 1) begin mb[4 + k] <= kifd[k]; mb[20 + k] <= kic[k]; end
                    mlen <= 6'd36;
                    call_hmac(1'b1, K_ACCE, K_SENC, S_EXTAUTH, 5'd18);
                end
                5'd18: begin
                    mb[1] <= "M"; mb[2] <= "A"; mb[3] <= "C";
                    call_hmac(1'b1, K_ACCM, K_SMAC, S_EXTAUTH, 5'd19);
                end
                5'd19: begin
                    ssc <= {rnd_ic[4], rnd_ic[5], rnd_ic[6], rnd_ic[7],
                            rifd[4], rifd[5], rifd[6], rifd[7]};
                    ac_q <= AC_YES;  ta_q <= TA_NO;  rnd_valid <= 1'b0;  fail_cnt <= 4'd0;
                    for (k = 0; k < 16; k = k + 1) begin kifd[k] <= 8'd0; kic[k] <= 8'd0; end
                    idx  <= 9'd0;
                    step <= 5'd20;
                end
                5'd20: begin bufwr(idx[7:0], db[idx[5:0]]); step <= 5'd21; end
                5'd21: if (f_done) begin
                    if (idx == 9'd39) finish(SW_OK, 8'd40);
                    else begin idx <= idx + 1'b1; step <= 5'd20; end
                end
                // A5: jeda bertambah dua kali lipat setiap kegagalan berturut-turut
                5'd25: begin
                    dly <= DLY_BASE << ((fail_cnt > DLY_MAX_SH) ? DLY_MAX_SH : fail_cnt);
                    if (fail_cnt != 4'hF) fail_cnt <= fail_cnt + 1'b1;
                    step <= 5'd26;
                end
                5'd26: begin
                    if (dly == 32'd0) finish(SW_VERIFY, 8'd0);
                    else dly <= dly - 1'b1;
                end
                default: state <= S_DEAD;
            endcase

            // ================= SECURE MESSAGING: verifikasi MAC perintah =================
            S_SMCMD: case (step)
                5'd0: begin bufrd(idx[7:0]); step <= 5'd1; end
                5'd1: if (f_done) begin
                    db[idx[5:0]] <= f_rd;
                    if (idx == {1'b0, q_lc} - 1'b1) step <= 5'd2;
                    else begin idx <= idx + 1'b1; step <= 5'd0; end
                end
                5'd2: begin ssc <= ssc + 1'b1; step <= 5'd3; end
                5'd3: begin
                    for (k = 0; k < 8; k = k + 1) mb[k] <= ssc[63 - 8*k -: 8];
                    mb[8] <= q_cla; mb[9] <= q_ins; mb[10] <= q_p1; mb[11] <= q_p2;
                    mb[12] <= q_le[7:0];
                    for (k = 0; k < 40; k = k + 1) if (k < pl) mb[13 + k] <= db[k];
                    mlen <= 6'd13 + pl;
                    call_hmac(1'b0, K_SMAC, K_NONE, S_SMCMD, 5'd4);
                end
                default: begin
                    if (!eq_macpl) begin
                        ac_q <= AC_NO;  ta_q <= TA_NO;           // sesi diputus
                        finish(SW_SMERR, 8'd0);
                    end else begin
                        step <= 5'd0;  sm_sw <= SW_OK;  ks_ok <= 1'b0;
                        case (q_ins)
                            8'hB0:   state <= S_SMREAD;
                            8'h88:   state <= S_INTAUTH;
                            default: state <= S_TAUTH;
                        endcase
                    end
                end
            endcase

            // ================= READ BINARY (SM) =================
            S_SMREAD: case (step)
                // A13: kesalahan setelah MAC perintah sah dijawab dengan MAC
                5'd0: begin
                    if (pl != 6'd0 || (q_le != 9'd16 && q_le != 9'd32)) begin
                        sm_sw <= SW_LEN;  sm_n <= 6'd0;  state <= S_SMRESP;
                    end else if (off_bad || end_rd > 11'd1024) begin
                        sm_sw <= SW_OFF;  sm_n <= 6'd0;  state <= S_SMRESP;
                    end else if (rd_dg3 && !ta_ok) begin                     // DG3 butuh TA
                        sm_sw <= SW_AUTH; sm_n <= 6'd0;  state <= S_SMRESP;
                    end else if (rd_dg3 && !keys_ok) begin
                        sm_sw <= SW_COND; sm_n <= 6'd0;  state <= S_SMRESP;
                    end else begin idx <= 9'd0; step <= 5'd1; end
                end
                5'd1: begin bus_rd(ID_MEM, cur_wa); step <= 5'd2; end
                5'd2: if (b_done) begin
                    if (cur_wa >= 8'hC0) begin
                        if (!ta_ok) begin                        // A3: pemeriksaan kedua
                            fsm_fault <= 1'b1;  state <= S_DEAD;
                        end else begin
                            word  <= b_rd;  dg_wa <= cur_wa;    // A7: dekripsi DG3
                            dk_rs <= S_SMREAD;  dk_rp <= 5'd7;
                            step  <= 5'd0;  state <= S_DGKS;
                        end
                    end else begin
                        db[idx[5:0]]     <= b_rd[31:24];
                        db[idx[5:0] + 1] <= b_rd[23:16];
                        db[idx[5:0] + 2] <= b_rd[15:8];
                        db[idx[5:0] + 3] <= b_rd[7:0];
                        step <= 5'd8;
                    end
                end
                5'd7: begin
                    db[idx[5:0]]     <= word[31:24] ^ ks_word[31:24];
                    db[idx[5:0] + 1] <= word[23:16] ^ ks_word[23:16];
                    db[idx[5:0] + 2] <= word[15:8]  ^ ks_word[15:8];
                    db[idx[5:0] + 3] <= word[7:0]   ^ ks_word[7:0];
                    step <= 5'd8;
                end
                5'd8: begin
                    if (idx + 9'd4 == q_le) step <= 5'd3;
                    else begin idx <= idx + 9'd4; step <= 5'd1; end
                end
                // A6: IV = AES(K_S_ENC, 0^64 || SSC jawaban)
                5'd3: begin
                    for (k = 0; k < 8; k = k + 1) begin
                        db[32 + k] <= 8'd0;
                        db[40 + k] <= ssc_n1[63 - 8*k -: 8];
                    end
                    call_aes(4'b0000, 1'b0, 6'd32, K_SENC, S_SMREAD, 5'd4);
                end
                5'd4: call_aes(4'b1001, 1'b0, 6'd0, K_SENC, S_SMREAD, 5'd5);   // CBC, IV dari db[32..47]
                5'd5: begin
                    if (q_le == 9'd32) call_aes(A_ENC_CBC, 1'b0, 6'd16, K_SENC, S_SMREAD, 5'd6);
                    else step <= 5'd6;
                end
                5'd6: begin sm_n <= q_le[5:0]; sm_sw <= SW_OK; step <= 5'd0; state <= S_SMRESP; end
                default: state <= S_DEAD;
            endcase

            // ================= INTERNAL AUTH (bukti chip asli) =================
            S_INTAUTH: case (step)
                // A14: jawaban terikat nomor dokumen (9 karakter pertama MRZ)
                //      HMAC(K_CA, "CA" || no_dokumen[9] || tantangan[16])
                5'd0: begin
                    if (pl != 6'd16) begin sm_sw <= SW_LEN; sm_n <= 6'd0; state <= S_SMRESP; end
                    else begin widx <= 4'd0; step <= 5'd1; end
                end
                5'd1: begin bus_rd(ID_MEM, {4'd0, widx}); step <= 5'd2; end
                5'd2: if (b_done) begin
                    mb[2 + 4*widx]     <= b_rd[31:24];
                    mb[2 + 4*widx + 1] <= b_rd[23:16];
                    mb[2 + 4*widx + 2] <= b_rd[15:8];
                    mb[2 + 4*widx + 3] <= b_rd[7:0];
                    if (widx == 4'd2) step <= 5'd3;
                    else begin widx <= widx + 1'b1; step <= 5'd1; end
                end
                5'd3: begin
                    mb[0] <= "C"; mb[1] <= "A";
                    for (k = 0; k < 16; k = k + 1) mb[11 + k] <= db[k];
                    mlen <= 6'd27;
                    call_hmac(1'b0, K_CA, K_NONE, S_INTAUTH, 5'd4);
                end
                5'd4: begin
                    for (k = 0; k < 32; k = k + 1) db[k] <= hm[k];
                    sm_n <= 6'd32; sm_sw <= SW_OK; step <= 5'd0; state <= S_SMRESP;
                end
                default: state <= S_DEAD;
            endcase

            // ================= TERMINAL AUTH (membuka DG3) =================
            S_TAUTH: case (step)
                5'd0: begin
                    if (q_p1 != 8'h01)    begin sm_sw <= SW_P1P2; sm_n <= 6'd0; state <= S_SMRESP; end
                    else if (pl != 6'd16) begin sm_sw <= SW_LEN;  sm_n <= 6'd0; state <= S_SMRESP; end
                    else begin
                        mb[0] <= "T"; mb[1] <= "A";
                        for (k = 0; k < 8; k = k + 1) mb[2 + k] <= rnd_ic[k];
                        mlen <= 6'd10;
                        call_hmac(1'b0, K_TA, K_NONE, S_TAUTH, 5'd1);
                    end
                end
                default: begin
                    if (!eq_ta16) begin ta_q <= TA_NO;  sm_sw <= SW_VERIFY; end
                    else          begin ta_q <= TA_YES; sm_sw <= SW_OK;     end
                    sm_n <= 6'd0; step <= 5'd0; state <= S_SMRESP;
                end
            endcase

            // ================= Jawaban SM: data || MAC8 =================
            S_SMRESP: case (step)
                5'd0: begin ssc <= ssc + 1'b1; step <= 5'd1; end
                5'd1: begin
                    for (k = 0; k < 8; k = k + 1) mb[k] <= ssc[63 - 8*k -: 8];
                    mb[8] <= sm_sw[15:8]; mb[9] <= sm_sw[7:0];
                    for (k = 0; k < 32; k = k + 1) if (k < sm_n) mb[10 + k] <= db[k];
                    mlen <= 6'd10 + sm_n;
                    call_hmac(1'b0, K_SMAC, K_NONE, S_SMRESP, 5'd2);
                end
                5'd2: begin
                    for (k = 0; k < 8; k = k + 1) db[sm_n + k] <= hm[k];
                    idx <= 9'd0; step <= 5'd3;
                end
                5'd3: begin bufwr(idx[7:0], db[idx[5:0]]); step <= 5'd4; end
                default: if (f_done) begin
                    if (idx == {3'd0, sm_n} + 9'd7) finish(sm_sw, {2'b00, sm_n} + 8'd8);
                    else begin idx <= idx + 1'b1; step <= 5'd3; end
                end
            endcase

            // ================= SUBRUTIN: HMAC / KDF =================
            S_HMAC: case (step)
                5'd0: begin key_sel_r <= h_src; bus_wr(ID_HMAC, 8'h28, {26'd0, mlen}); step <= 5'd1; end
                5'd1: if (b_done) begin widx <= 4'd0; step <= 5'd2; end
                5'd2: begin
                    if ({widx, 2'b00} >= mlen) step <= 5'd4;
                    else begin
                        bus_wr(ID_HMAC, 8'h2C + {2'b00, widx, 2'b00},
                               {mb[4*widx], mb[4*widx + 1], mb[4*widx + 2], mb[4*widx + 3]});
                        step <= 5'd3;
                    end
                end
                5'd3: if (b_done) begin widx <= widx + 1'b1; step <= 5'd2; end
                5'd4: begin                                  // A8: jeda acak 0..15 siklus
                    if (!jw_go) begin jw <= {1'b0, lfsr[3:0]}; jw_go <= 1'b1; end
                    else if (jw != 5'd0) jw <= jw - 1'b1;
                    else begin jw_go <= 1'b0; bus_wr(ID_HMAC, 8'h00, h_kdf ? 32'd2 : 32'd1); step <= 5'd5; end
                end
                5'd5: if (b_done) begin
                    // Kunci sudah dikunci HMAC. KDF: arahkan ke slot tujuan.
                    key_sel_r <= h_kdf ? h_dst : K_NONE;
                    tmo <= 20'd0; step <= 5'd6;
                end
                5'd6: begin bus_rd(ID_HMAC, 8'h04); step <= 5'd7; end
                5'd7: if (b_done) begin
                    if (b_rd[2]) finish(SW_FAIL, 8'd0);       // A1: ditolak kebijakan kunci
                    else if (b_rd[1] && !b_rd[0]) begin
                        if (h_kdf) begin key_sel_r <= K_NONE; ret; end
                        else begin widx <= 4'd0; step <= 5'd8; end
                    end
                    else if (tmo == TMO) finish(SW_FAIL, 8'd0);
                    else begin tmo <= tmo + 1'b1; step <= 5'd6; end
                end
                5'd8: begin bus_rd(ID_HMAC, 8'h08 + {2'b00, widx, 2'b00}); step <= 5'd9; end
                default: if (b_done) begin
                    hm[4*widx]     <= b_rd[31:24];
                    hm[4*widx + 1] <= b_rd[23:16];
                    hm[4*widx + 2] <= b_rd[15:8];
                    hm[4*widx + 3] <= b_rd[7:0];
                    if (widx == 4'd7) ret;
                    else begin widx <= widx + 1'b1; step <= 5'd8; end
                end
            endcase

            // ================= SUBRUTIN: AES satu blok =================
            S_AES: case (step)
                5'd0: begin
                    key_sel_r <= a_ks;  widx <= 4'd0;
                    step <= (a_ivz || a_mode[0]) ? 5'd1 : 5'd3;
                end
                // IV = 0 (a_ivz) atau IV = db[32..47] (a_mode[0], A6)
                5'd1: begin
                    bus_wr(ID_AES, 8'h20 + {2'b00, widx, 2'b00},
                           a_mode[0] ? {db[32 + 4*widx], db[33 + 4*widx], db[34 + 4*widx], db[35 + 4*widx]}
                                     : 32'd0);
                    step <= 5'd2;
                end
                5'd2: if (b_done) begin
                    if (widx == 4'd3) begin widx <= 4'd0; step <= 5'd3; end
                    else begin widx <= widx + 1'b1; step <= 5'd1; end
                end
                5'd3: begin
                    if (a_mode[2]) step <= 5'd5;                 // WRAP: DIN dari key_manager
                    else begin
                        bus_wr(ID_AES, 8'h10 + {2'b00, widx, 2'b00},
                               {db[a_off + 4*widx], db[a_off + 4*widx + 1],
                                db[a_off + 4*widx + 2], db[a_off + 4*widx + 3]});
                        step <= 5'd4;
                    end
                end
                5'd4: if (b_done) begin
                    if (widx == 4'd3) step <= 5'd5;
                    else begin widx <= widx + 1'b1; step <= 5'd3; end
                end
                5'd5: begin                                  // A8: jeda acak 0..15 siklus
                    if (!jw_go) begin jw <= {1'b0, lfsr[3:0]}; jw_go <= 1'b1; end
                    else if (jw != 5'd0) jw <= jw - 1'b1;
                    else begin jw_go <= 1'b0; bus_wr(ID_AES, 8'h00, {28'd0, a_mode[3:1], 1'b1}); step <= 5'd6; end
                end
                5'd6: if (b_done) begin key_sel_r <= K_NONE; tmo <= 20'd0; step <= 5'd7; end
                5'd7: begin bus_rd(ID_AES, 8'h04); step <= 5'd8; end
                5'd8: if (b_done) begin
                    if (b_rd[1] && !b_rd[0]) begin widx <= 4'd0; step <= 5'd9; end
                    else if (tmo == TMO) finish(SW_FAIL, 8'd0);
                    else begin tmo <= tmo + 1'b1; step <= 5'd7; end
                end
                5'd9: begin bus_rd(ID_AES, 8'h30 + {2'b00, widx, 2'b00}); step <= 5'd10; end
                default: if (b_done) begin
                    db[a_off + 4*widx]     <= b_rd[31:24];
                    db[a_off + 4*widx + 1] <= b_rd[23:16];
                    db[a_off + 4*widx + 2] <= b_rd[15:8];
                    db[a_off + 4*widx + 3] <= b_rd[7:0];
                    if (widx == 4'd3) ret;
                    else begin widx <= widx + 1'b1; step <= 5'd9; end
                end
            endcase

            // ================= SUBRUTIN: satu kata acak dari TRNG =================
            S_RNDW: case (step)
                // A12: keluaran TRNG dikondisikan: 12 kata mentah (384 bit)
                //      -> HMAC-SHA256 -> 8 kata (256 bit) disimpan di pool
                5'd0: begin
                    if (pool_n != 4'd0) begin
                        rword <= pool[pool_n - 1'b1];
                        pool[pool_n - 1'b1] <= 32'd0;
                        pool_n <= pool_n - 1'b1;
                        lfsr <= lfsr ^ pool[pool_n - 1'b1][15:0];     // A8: reseed jitter
                        ret;
                    end else begin rcnt <= 4'd0; tmo <= 20'd0; step <= 5'd1; end
                end
                5'd1: begin bus_rd(ID_TRNG, 8'h01); step <= 5'd2; end
                5'd2: if (b_done) begin
                    if (b_rd[3])           finish(SW_FAIL, 8'd0);       // health test gagal
                    else if (b_rd[2]) begin bus_rd(ID_TRNG, 8'h02); step <= 5'd3; end
                    else if (tmo == TMO)   finish(SW_FAIL, 8'd0);
                    else begin tmo <= tmo + 1'b1; bus_rd(ID_TRNG, 8'h01); end
                end
                5'd3: if (b_done) begin
                    mb[4*rcnt]     <= b_rd[31:24];
                    mb[4*rcnt + 1] <= b_rd[23:16];
                    mb[4*rcnt + 2] <= b_rd[15:8];
                    mb[4*rcnt + 3] <= b_rd[7:0];
                    if (rcnt == 4'd11) step <= 5'd4;
                    else begin rcnt <= rcnt + 1'b1; tmo <= 20'd0; step <= 5'd1; end
                end
                5'd4: begin
                    rw_rs <= ret_state;  rw_rp <= ret_step;          // simpan alamat kembali
                    mlen  <= 6'd48;
                    call_hmac(1'b0, K_NONE, K_NONE, S_RNDW, 5'd5);
                end
                5'd5: begin
                    for (k = 0; k < 8; k = k + 1)
                        pool[k] <= {hm[4*k], hm[4*k + 1], hm[4*k + 2], hm[4*k + 3]};
                    pool_n    <= 4'd8;
                    ret_state <= rw_rs;  ret_step <= rw_rp;
                    for (k = 0; k < 48; k = k + 1) mb[k] <= 8'd0;     // data mentah dihapus
                    step <= 5'd0;
                end
                default: state <= S_DEAD;
            endcase

            // ================= SUBRUTIN: keystream DG3 (A7) =================
            // ks = AES(K_DG, "JATI-DG3" || 0^7 || nomor_blok), disimpan di db[48..63]
            S_DGKS: case (step)
                5'd0: begin
                    if (ks_ok && ks_blk == dg_wa[7:2]) begin state <= dk_rs; step <= dk_rp; end
                    else begin
                        for (k = 0; k < 8; k = k + 1) db[48 + k] <= STR_DG3[63 - 8*k -: 8];
                        for (k = 56; k < 63; k = k + 1) db[k] <= 8'd0;
                        db[63] <= {2'b00, dg_wa[7:2]};
                        call_aes(4'b0000, 1'b0, 6'd48, K_DG, S_DGKS, 5'd1);
                    end
                end
                5'd1: begin
                    ks_ok <= 1'b1;  ks_blk <= dg_wa[7:2];
                    state <= dk_rs; step <= dk_rp;
                end
                default: state <= S_DEAD;
            endcase

            // ================= Kirim jawaban + bersihkan data sementara =================
            S_RESP: begin
                rsp_q     <= {sw[15:8], sw[7:0], rlen, 1'b1};
                rsp_v     <= 1'b1;
                key_sel_r <= K_NONE;
                for (k = 0; k < 56; k = k + 1) mb[k] <= 8'd0;
                for (k = 0; k < 64; k = k + 1) db[k] <= 8'd0;
                for (k = 0; k < 32; k = k + 1) hm[k] <= 8'd0;
                mlen  <= 6'd0;  word <= 32'd0;  rword <= 32'd0;  ks_ok <= 1'b0;
                step  <= 5'd0;
                state <= S_IDLE;
            end

            S_DEAD: key_sel_r <= K_NONE;

            // ================= State tidak sah = fault injection =================
            default: begin
                fsm_fault <= 1'b1;
                key_sel_r <= K_NONE;
                state     <= S_DEAD;
            end
            endcase
        end
    end

    // =========================================================================
    // Keluaran: dimatikan seketika saat zeroize
    // =========================================================================
    assign m_req     = zeroize ? 46'd0 : m_req_r;
    assign buf_req   = zeroize ? 18'd0 : buf_req_r;
    assign rsp       = rsp_q;
    assign rsp_valid = rsp_v & ~zeroize;
    assign key_sel   = zeroize ? 4'd0 : key_sel_r;

endmodule