// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : key_manager
// Fungsi  : Brankas semua kunci 128 bit. Kunci hanya bisa MASUK (dari fuzzy
//           extractor atau hasil KDF) dan hanya bisa KELUAR ke mesin kripto
//           (HMAC & AES) lewat key_out / wrap_key. Tidak ada port ke bus.
//
// Aturan keamanan yang ditegakkan oleh HARDWARE (bukan oleh FSM):
//   1. Tidak ada jalur baca ke bus. key_out/wrap_key hanya tersambung ke
//      hmac_kdf dan aes128_sm di top-level.
//   2. Rantai asal-usul kunci:
//        R_PUF (dari fuzzy_ext) -> K_DEV -> K_CA, K_DG
//      K_DEV hanya diterima jika R_PUF ada; K_CA/K_DG hanya jika K_DEV ada.
//      Kunci identitas chip tidak bisa disuntikkan tanpa melewati PUF.
//   3. R_PUF otomatis dihapus begitu K_DEV terbentuk, dan tidak bisa diisi
//      ulang sampai reset (mengurangi waktu paparan respons PUF mentah).
//   4. Slot identitas (K_DEV, K_CA, K_DG, K_T, K_TA) hanya bisa ditulis
//      SEKALI per boot. Slot sesi bisa ditulis ulang.
//   5. K_T (kunci transport pabrik) bisa dihapus permanen (sampai reset)
//      dengan CMD_ERASE_T. Setelah itu fitur wrap mati.
//   6. Disimpan di flip-flop, BUKAN RAM, agar bisa dihapus seketika:
//      zeroize / reset menghapus semua kunci secara asinkron.
//
// Pengkodean key_sel[3:0]:
//   0x0 SEL_NONE      key_out = 0
//   0x1 SEL_RPUF      R_PUF  (hanya untuk menurunkan K_DEV)
//   0x2 SEL_DEV       K_DEV
//   0x3 SEL_CA        K_CA   (bukti chip asli)
//   0x4 SEL_DG        K_DG   (enkripsi DG3 di memori)
//   0x5 SEL_T         K_T    (transport, pabrik)
//   0x6 SEL_TA        K_TA   (verifikasi terminal resmi)
//   0x7 SEL_ACC_ENC   kunci pintu, enkripsi
//   0x8 SEL_ACC_MAC   kunci pintu, MAC
//   0x9 SEL_S_ENC     kunci sesi, enkripsi
//   0xA SEL_S_MAC     kunci sesi, MAC
//   0xB SEL_WRAP      key_out = K_T, wrap_key = K_CA (enrollment)
//   0xC               cadangan
//   0xC CMD_KILL_RPUF (bersama kdf_wr) hapus R_PUF tanpa membentuk K_DEV,
//                     dipakai FSM bila tag integritas helper data tidak cocok
//   0xD CMD_CLR_SESS  (bersama kdf_wr) hapus 4 kunci pintu & sesi
//   0xE CMD_ERASE_T   (bersama kdf_wr) hapus K_T dan kunci fitur wrap
//   0xF CMD_RETRY_RPUF(bersama kdf_wr) buang R_PUF TANPA memblokir R_PUF
//                     berikutnya; maksimal 2 kali per boot, setelah itu sama
//                     dengan CMD_KILL_RPUF (A9: rekonstruksi ulang saat derau)
//
// KEBIJAKAN PEMAKAIAN KUNCI (A1)
//   key_kdf_only = 1 saat slot terpilih R_PUF atau K_DEV. hmac_kdf menolak
//   mode HMAC biasa (hasil terbaca bus) untuk kunci ini kecuali pesan >= 40
//   byte, sehingga HMAC(K_DEV, "JATI-CA") = K_CA tidak pernah bisa dibaca.
//
// MODE UJI (A10)
//   scan_mode = 1 (DFT/scan chain pada ASIC) menghapus semua kunci seketika,
//   sehingga scan chain tidak pernah bisa menggeser keluar isi slot kunci.
//
// Penulisan: kdf_wr = 1 selama satu siklus, kdf_key berisi nilai, key_sel
//            menunjuk slot tujuan. Penulisan yang melanggar aturan diabaikan.
// Pembacaan: kombinasional. key_ok = 1 jika slot yang dipilih berisi kunci sah.
// =============================================================================

module key_manager (
    input  wire         clk_sys,
    input  wire         rst_sync_n,
    input  wire         zeroize,

    input  wire [3:0]   key_sel,
    input  wire [127:0] r_puf,
    input  wire         r_valid,
    input  wire [127:0] kdf_key,
    input  wire         kdf_wr,

    input  wire         scan_mode,      // ASIC: mode uji DFT (FPGA: 0)

    output reg  [127:0] key_out,
    output reg  [127:0] wrap_key,
    output reg          key_ok,
    output wire         key_kdf_only    // A1: slot terpilih hanya untuk KDF
);

    // -------------------------------------------------------------------------
    // Pengkodean key_sel
    // -------------------------------------------------------------------------
    localparam [3:0] SEL_NONE     = 4'h0;
    localparam [3:0] SEL_RPUF     = 4'h1;
    localparam [3:0] SEL_DEV      = 4'h2;
    localparam [3:0] SEL_CA       = 4'h3;
    localparam [3:0] SEL_DG       = 4'h4;
    localparam [3:0] SEL_T        = 4'h5;
    localparam [3:0] SEL_TA       = 4'h6;
    localparam [3:0] SEL_ACC_ENC  = 4'h7;
    localparam [3:0] SEL_ACC_MAC  = 4'h8;
    localparam [3:0] SEL_S_ENC    = 4'h9;
    localparam [3:0] SEL_S_MAC    = 4'hA;
    localparam [3:0] SEL_WRAP     = 4'hB;
    localparam [3:0] CMD_KILL_RPUF = 4'hC;
    localparam [3:0] CMD_CLR_SESS = 4'hD;
    localparam [3:0] CMD_ERASE_T  = 4'hE;
    localparam [3:0] CMD_RETRY_RPUF = 4'hF;

    assign key_kdf_only = (key_sel == SEL_RPUF) || (key_sel == SEL_DEV);

    // -------------------------------------------------------------------------
    // Register kunci (flip-flop) dan penanda sah
    // -------------------------------------------------------------------------
    reg [127:0] k_rpuf, k_dev, k_ca, k_dg, k_t, k_ta;
    reg [127:0] k_acc_enc, k_acc_mac, k_s_enc, k_s_mac;

    reg v_rpuf, v_dev, v_ca, v_dg, v_t, v_ta;
    reg v_acc_enc, v_acc_mac, v_s_enc, v_s_mac;

    reg rpuf_spent;   // R_PUF sudah dipakai, tidak boleh diisi ulang
    reg t_locked;     // K_T sudah dihapus permanen
    reg [1:0] retry_cnt;  // jumlah CMD_RETRY_RPUF yang sudah dipakai

    // Hapus asinkron: zeroize ATAU reset. Glitch pada sinyal ini hanya bisa
    // menyebabkan penghapusan ekstra (arah aman / fail-safe).
    wire clr = zeroize | ~rst_sync_n | scan_mode;

    // -------------------------------------------------------------------------
    // Penulisan
    // -------------------------------------------------------------------------
    always @(posedge clk_sys or posedge clr) begin
        if (clr) begin
            k_rpuf <= 128'd0;  k_dev <= 128'd0;  k_ca <= 128'd0;
            k_dg   <= 128'd0;  k_t   <= 128'd0;  k_ta <= 128'd0;
            k_acc_enc <= 128'd0;  k_acc_mac <= 128'd0;
            k_s_enc   <= 128'd0;  k_s_mac   <= 128'd0;
            v_rpuf <= 1'b0;  v_dev <= 1'b0;  v_ca <= 1'b0;
            v_dg   <= 1'b0;  v_t   <= 1'b0;  v_ta <= 1'b0;
            v_acc_enc <= 1'b0;  v_acc_mac <= 1'b0;
            v_s_enc   <= 1'b0;  v_s_mac   <= 1'b0;
            rpuf_spent <= 1'b0;
            t_locked   <= 1'b0;
            retry_cnt  <= 2'd0;
        end else begin
            // R_PUF dari fuzzy extractor: sekali, dan hanya sebelum dipakai
            if (r_valid && !v_rpuf && !rpuf_spent) begin
                k_rpuf <= r_puf;
                v_rpuf <= 1'b1;
            end

            if (kdf_wr) begin
                case (key_sel)
                    // ---- Rantai identitas: tulis sekali, butuh induknya ----
                    SEL_DEV: if (v_rpuf && !v_dev) begin
                        k_dev      <= kdf_key;
                        v_dev      <= 1'b1;
                        k_rpuf     <= 128'd0;     // R_PUF langsung dihapus
                        v_rpuf     <= 1'b0;
                        rpuf_spent <= 1'b1;
                    end
                    SEL_CA:  if (v_dev && !v_ca) begin k_ca <= kdf_key; v_ca <= 1'b1; end
                    SEL_DG:  if (v_dev && !v_dg) begin k_dg <= kdf_key; v_dg <= 1'b1; end

                    // ---- Kunci dari luar: tulis sekali ----
                    SEL_T:   if (!v_t && !t_locked) begin k_t <= kdf_key; v_t <= 1'b1; end
                    SEL_TA:  if (!v_ta) begin k_ta <= kdf_key; v_ta <= 1'b1; end

                    // ---- Kunci pintu & sesi: boleh ditulis ulang ----
                    SEL_ACC_ENC: begin k_acc_enc <= kdf_key; v_acc_enc <= 1'b1; end
                    SEL_ACC_MAC: begin k_acc_mac <= kdf_key; v_acc_mac <= 1'b1; end
                    SEL_S_ENC:   begin k_s_enc   <= kdf_key; v_s_enc   <= 1'b1; end
                    SEL_S_MAC:   begin k_s_mac   <= kdf_key; v_s_mac   <= 1'b1; end

                    // ---- Perintah ----
                    CMD_RETRY_RPUF: begin              // derau: coba rekonstruksi lagi
                        k_rpuf <= 128'd0;
                        v_rpuf <= 1'b0;
                        if (retry_cnt == 2'd2) rpuf_spent <= 1'b1;   // jatah habis
                        else                   retry_cnt  <= retry_cnt + 1'b1;
                    end
                    CMD_KILL_RPUF: begin               // helper data ditolak
                        k_rpuf     <= 128'd0;
                        v_rpuf     <= 1'b0;
                        rpuf_spent <= 1'b1;            // tidak ada K_DEV sampai reset
                    end
                    CMD_CLR_SESS: begin
                        k_acc_enc <= 128'd0;  v_acc_enc <= 1'b0;
                        k_acc_mac <= 128'd0;  v_acc_mac <= 1'b0;
                        k_s_enc   <= 128'd0;  v_s_enc   <= 1'b0;
                        k_s_mac   <= 128'd0;  v_s_mac   <= 1'b0;
                    end
                    CMD_ERASE_T: begin
                        k_t      <= 128'd0;
                        v_t      <= 1'b0;
                        t_locked <= 1'b1;
                    end

                    // SEL_NONE, SEL_RPUF, SEL_WRAP, cadangan: penulisan ditolak
                    default: ;
                endcase
            end
        end
    end

    // -------------------------------------------------------------------------
    // Pembacaan (kombinasional). Slot tidak sah selalu menghasilkan 0.
    // wrap_key HANYA berisi K_CA saat SEL_WRAP dan K_T masih ada.
    // -------------------------------------------------------------------------
    always @(*) begin
        key_out  = 128'd0;
        wrap_key = 128'd0;
        key_ok   = 1'b0;
        case (key_sel)
            SEL_RPUF:    if (v_rpuf)    begin key_out = k_rpuf;    key_ok = 1'b1; end
            SEL_DEV:     if (v_dev)     begin key_out = k_dev;     key_ok = 1'b1; end
            SEL_CA:      if (v_ca)      begin key_out = k_ca;      key_ok = 1'b1; end
            SEL_DG:      if (v_dg)      begin key_out = k_dg;      key_ok = 1'b1; end
            SEL_T:       if (v_t)       begin key_out = k_t;       key_ok = 1'b1; end
            SEL_TA:      if (v_ta)      begin key_out = k_ta;      key_ok = 1'b1; end
            SEL_ACC_ENC: if (v_acc_enc) begin key_out = k_acc_enc; key_ok = 1'b1; end
            SEL_ACC_MAC: if (v_acc_mac) begin key_out = k_acc_mac; key_ok = 1'b1; end
            SEL_S_ENC:   if (v_s_enc)   begin key_out = k_s_enc;   key_ok = 1'b1; end
            SEL_S_MAC:   if (v_s_mac)   begin key_out = k_s_mac;   key_ok = 1'b1; end
            SEL_WRAP:    if (v_t && v_ca) begin
                             key_out  = k_t;
                             wrap_key = k_ca;
                             key_ok   = 1'b1;
                         end
            default: ;
        endcase
    end

endmodule