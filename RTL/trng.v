// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : trng
// Fungsi  : True Random Number Generator. Menghasilkan angka acak 32 bit untuk
//           nonce (RND.IC) dan bahan kunci sesi.
//
// Alur data:
//   trng_ro (ring oscillator bebas, di-XOR)
//     -> sinkronizer 2 FF -> sampel tiap SAMPLE_DIV siklus      (bit mentah)
//     -> health test NIST SP 800-90B: RCT + APT                   (pengawas)
//     -> von Neumann corrector (01->0, 10->1, 00/11 dibuang)      (hilangkan bias)
//     -> register geser 32 bit -> FIFO 4 kata                     (siap dibaca)
//
// Aturan keamanan:
//   1. Startup test: data baru dikeluarkan setelah satu jendela APT penuh
//      (APT_W sampel) lulus. Bit selama startup dibuang.
//   2. Kalau health test gagal: FIFO langsung dikosongkan, DATA selalu 0,
//      status fail TERKUNCI sampai reset (tidak bisa dihapus lewat bus).
//   3. zeroize/reset menghapus semua angka acak yang belum dipakai.
//   4. Pembacaan DATA bersifat "pop": angka acak yang sama tidak pernah
//      diberikan dua kali.
//
// Parameter health test (alpha = 2^-20, asumsi min-entropy H = 0,5 bit/sampel):
//   RCT_C = 1 + ceil(20 / H)                         = 41
//   APT_C = 1 + CRITBINOM(1024, 2^-H, 1 - 2^-20)     = 793   (W = 1024)
//   Nilai H harus divalidasi dengan data asli dari FPGA. Jika H terukur
//   berbeda, hitung ulang RCT_C dan APT_C.
//
// Format bus (standar JATI final, mengikuti bus_mux):
//   req[45:34] alamat 12 bit -> [11:8] ID slave (TRNG = 2), [7:0] register
//   req[33:2]  data tulis 32 bit, req[1] we, req[0] re
//   rdata TER-REGISTER: sah satu siklus setelah permintaan baca (sama dengan
//   slave lain dan bus_mux yang mengunci pilihan slave saat baca).
//
// Peta register (nomor register = addr[7:0]):
//   0x00 CTRL   (R/W) bit0 = enable
//   0x01 STATUS (R)   bit0 enable, bit1 ready, bit2 data_valid, bit3 fail,
//                     bit4 rct_fail, bit5 apt_fail, bit[10:8] jumlah isi FIFO
//   0x02 DATA   (R)   kata acak 32 bit, membaca = mengambil (pop)
// =============================================================================

module trng #(
    parameter [3:0]   SLAVE_ID   = 4'h2,
    parameter integer N_RO       = 8,
    parameter integer SAMPLE_DIV = 32,     // minimal 2
    parameter integer RCT_C      = 41,
    parameter integer APT_W      = 1024,
    parameter integer APT_C      = 793
)(
    input  wire        clk_sys,
    input  wire        rst_sync_n,
    input  wire        zeroize,
    input  wire [45:0] req,
    output reg  [31:0] rdata
);

    // -------------------------------------------------------------------------
    // Dekode bus
    // -------------------------------------------------------------------------
    localparam [7:0] REG_CTRL = 8'h00, REG_STATUS = 8'h01, REG_DATA = 8'h02;

    wire [11:0] addr  = req[45:34];
    wire [31:0] wdata = req[33:2];
    wire        we    = req[1];
    wire        re    = req[0];
    wire        sel   = (addr[11:8] == SLAVE_ID);
    wire [7:0]  ra    = addr[7:0];

    wire clr = zeroize | ~rst_sync_n;   // hapus asinkron (fail-safe)

    // -------------------------------------------------------------------------
    // Sumber entropi
    // -------------------------------------------------------------------------
    reg  enable;
    wire raw;
    wire fifo_full;
    reg  rct_fail, apt_fail, ready;          // dideklarasikan di sini karena
    wire fail = rct_fail | apt_fail;         // dipakai oleh blok pencuplik di bawah
    reg  pause;        // B3: FIFO penuh -> ring oscillator dimatikan (hemat daya,
                       //     juga mengurangi derau EM yang bisa mengganggu PUF)
    reg  [2:0] warm;   // sampel dibuang setelah RO hidup lagi (jitter belum terkumpul)

    trng_ro #(.N_RO(N_RO)) u_src (
        .en  (enable && !pause),
        .raw (raw)
    );

    // -------------------------------------------------------------------------
    // Sinkronizer + pencuplikan setiap SAMPLE_DIV siklus
    // (jeda antar-sampel memberi waktu jitter RO terakumulasi)
    // -------------------------------------------------------------------------
    reg        raw_s1, raw_s2;
    reg [15:0] div_cnt;
    reg        samp, samp_v;

    always @(posedge clk_sys or posedge clr) begin
        if (clr) begin
            raw_s1 <= 1'b0;  raw_s2 <= 1'b0;
            div_cnt <= 16'd0;
            samp <= 1'b0;    samp_v <= 1'b0;
            pause <= 1'b0;   warm <= 3'd0;
        end else begin
            raw_s1 <= raw;
            raw_s2 <= raw_s1;
            samp_v <= 1'b0;
            pause  <= enable && ready && !fail && fifo_full;
            if (enable && !pause) begin
                if (div_cnt == SAMPLE_DIV - 1) begin
                    div_cnt <= 16'd0;
                    samp    <= raw_s2;
                    if (warm != 3'd0) warm <= warm - 1'b1;   // buang sampel pemanasan
                    else              samp_v <= 1'b1;
                end else
                    div_cnt <= div_cnt + 1'b1;
            end else begin
                div_cnt <= 16'd0;
                if (pause) warm <= 3'd4;
            end
        end
    end

    // -------------------------------------------------------------------------
    // Health test NIST SP 800-90B
    // -------------------------------------------------------------------------
    // Repetition Count Test: nilai yang sama berulang >= RCT_C kali
    reg        rct_have, rct_last;
    reg [15:0] rct_run;
    // Adaptive Proportion Test: nilai referensi muncul >= APT_C kali per jendela
    reg        apt_ref;
    reg [15:0] apt_idx, apt_cnt;

    // (rct_fail, apt_fail, ready, fail dideklarasikan di atas, sebelum dipakai)

    wire rct_hit = samp_v && rct_have && (samp == rct_last) && (rct_run + 1 >= RCT_C);
    wire apt_hit = samp_v && (apt_idx != 0) && (samp == apt_ref) && (apt_cnt + 1 >= APT_C);

    always @(posedge clk_sys or posedge clr) begin
        if (clr) begin
            rct_have <= 1'b0;  rct_last <= 1'b0;  rct_run <= 16'd0;
            apt_ref  <= 1'b0;  apt_idx  <= 16'd0; apt_cnt <= 16'd0;
            rct_fail <= 1'b0;  apt_fail <= 1'b0;  ready   <= 1'b0;
        end else if (!enable) begin
            // Sumber dimatikan: startup test harus diulang saat dinyalakan lagi.
            // Status fail TIDAK dihapus.
            rct_have <= 1'b0;  rct_run <= 16'd0;
            apt_idx  <= 16'd0; apt_cnt <= 16'd0;
            ready    <= 1'b0;
        end else if (samp_v) begin
            // ---- RCT ----
            if (!rct_have || samp != rct_last) begin
                rct_have <= 1'b1;
                rct_last <= samp;
                rct_run  <= 16'd1;
            end else begin
                rct_run <= rct_run + 1'b1;
            end
            if (rct_hit) rct_fail <= 1'b1;

            // ---- APT ----
            if (apt_idx == 0) begin
                apt_ref <= samp;
                apt_cnt <= 16'd1;
                apt_idx <= 16'd1;
            end else begin
                if (samp == apt_ref) apt_cnt <= apt_cnt + 1'b1;
                if (apt_hit) apt_fail <= 1'b1;
                if (apt_idx == APT_W - 1) begin
                    apt_idx <= 16'd0;
                    // Startup selesai: satu jendela penuh tanpa kegagalan
                    if (!fail && !rct_hit && !apt_hit) ready <= 1'b1;
                end else
                    apt_idx <= apt_idx + 1'b1;
            end
        end
    end

    // -------------------------------------------------------------------------
    // Von Neumann corrector + register geser 32 bit
    // -------------------------------------------------------------------------
    reg        vn_have, vn_first;
    reg [31:0] shreg;
    reg [5:0]  sh_cnt;
    reg        word_v;     // satu kata baru siap dimasukkan ke FIFO
    reg [31:0] word;

    always @(posedge clk_sys or posedge clr) begin
        if (clr) begin
            vn_have <= 1'b0;  vn_first <= 1'b0;
            shreg   <= 32'd0; sh_cnt   <= 6'd0;
            word_v  <= 1'b0;  word     <= 32'd0;
        end else begin
            word_v <= 1'b0;
            if (!enable || !ready || fail) begin
                vn_have <= 1'b0;
                sh_cnt  <= 6'd0;
                shreg   <= 32'd0;
            end else if (samp_v) begin
                if (!vn_have) begin
                    vn_first <= samp;
                    vn_have  <= 1'b1;
                end else begin
                    vn_have <= 1'b0;
                    if (vn_first != samp) begin            // 10 -> 1, 01 -> 0
                        if (sh_cnt == 6'd31) begin
                            word   <= {shreg[30:0], vn_first};
                            word_v <= 1'b1;
                            sh_cnt <= 6'd0;
                            shreg  <= 32'd0;
                        end else begin
                            shreg  <= {shreg[30:0], vn_first};
                            sh_cnt <= sh_cnt + 1'b1;
                        end
                    end
                end
            end
        end
    end

    // -------------------------------------------------------------------------
    // FIFO 4 kata (flip-flop, agar bisa dihapus seketika)
    // -------------------------------------------------------------------------
    reg [31:0] fifo0, fifo1, fifo2, fifo3;
    reg [1:0]  wr_ptr, rd_ptr;
    reg [2:0]  f_cnt;

    wire data_valid = (f_cnt != 3'd0) && !fail;
    assign fifo_full = (f_cnt == 3'd4);
    wire pop  = sel && re && (ra == REG_DATA) && data_valid;
    wire push = word_v && !fail && (f_cnt != 3'd4);   // FIFO penuh: kata baru dibuang

    reg [31:0] f_head;
    always @(*) begin
        case (rd_ptr)
            2'd0: f_head = fifo0;
            2'd1: f_head = fifo1;
            2'd2: f_head = fifo2;
            default: f_head = fifo3;
        endcase
    end

    always @(posedge clk_sys or posedge clr) begin
        if (clr) begin
            fifo0 <= 32'd0; fifo1 <= 32'd0; fifo2 <= 32'd0; fifo3 <= 32'd0;
            wr_ptr <= 2'd0; rd_ptr <= 2'd0; f_cnt <= 3'd0;
        end else if (fail) begin
            // Health test gagal: buang semua isi FIFO
            fifo0 <= 32'd0; fifo1 <= 32'd0; fifo2 <= 32'd0; fifo3 <= 32'd0;
            wr_ptr <= 2'd0; rd_ptr <= 2'd0; f_cnt <= 3'd0;
        end else begin
            if (push) begin
                case (wr_ptr)
                    2'd0: fifo0 <= word;
                    2'd1: fifo1 <= word;
                    2'd2: fifo2 <= word;
                    default: fifo3 <= word;
                endcase
                wr_ptr <= wr_ptr + 1'b1;
            end
            if (pop) begin
                // Kata yang sudah dibaca langsung dihapus dari FIFO
                case (rd_ptr)
                    2'd0: fifo0 <= 32'd0;
                    2'd1: fifo1 <= 32'd0;
                    2'd2: fifo2 <= 32'd0;
                    default: fifo3 <= 32'd0;
                endcase
                rd_ptr <= rd_ptr + 1'b1;
            end
            case ({push, pop})
                2'b10: f_cnt <= f_cnt + 1'b1;
                2'b01: f_cnt <= f_cnt - 1'b1;
                default: ;
            endcase
        end
    end

    // -------------------------------------------------------------------------
    // Register CTRL
    // -------------------------------------------------------------------------
    always @(posedge clk_sys or posedge clr) begin
        if (clr)
            enable <= 1'b0;
        else if (sel && we && ra == REG_CTRL)
            enable <= wdata[0];
    end

    // -------------------------------------------------------------------------
    // Pembacaan bus (TER-REGISTER: sah satu siklus setelah permintaan)
    // -------------------------------------------------------------------------
    reg [31:0] rdata_c;
    always @(*) begin
        rdata_c = 32'd0;
        case (ra)
            REG_CTRL:   rdata_c = {31'd0, enable};
            REG_STATUS: rdata_c = {21'd0, f_cnt, 2'b00, apt_fail, rct_fail,
                                   fail, data_valid, ready, enable};
            REG_DATA:   if (data_valid) rdata_c = f_head;
            default:    rdata_c = 32'd0;
        endcase
    end

    always @(posedge clk_sys or posedge clr) begin
        if (clr)              rdata <= 32'd0;
        else if (sel && re)   rdata <= rdata_c;   // kata acak diambil di tepi yang sama (pop)
    end

endmodule