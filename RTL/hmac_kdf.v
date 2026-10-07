// Modul: hmac_kdf
// Deskripsi: Pengontrol HMAC-SHA256 standar (RFC 2104 / FIPS 198-1) dan Key
//            Derivation Function (KDF) berbasis HMAC, dengan otomasi
//            pemrosesan blok ke sha256_core (chaining multi-blok).
//
// Algoritma (kunci 128-bit di-pad nol ke 512-bit, pesan <= 55 byte):
//   inner = SHA256( (K ^ ipad) || msg )          -> 2 blok: [K^ipad] [msg||pad||len]
//   HMAC  = SHA256( (K ^ opad) || inner )        -> 2 blok: [K^opad] [inner||pad||len]
//   Blok pertama tiap pass didahului sha_init; blok kedua melanjutkan state H
//   (tanpa init) sehingga hasilnya identik dengan HMAC-SHA256 standar.
//
// Pemetaan Bus req[45:0]: {addr[11:0], wdata[31:0], we, re}
// - 0x000       Control Register (W): bit0 = Start HMAC, bit1 = Start KDF
//                                (R): {is_kdf_mode, 0}
//   STATUS bit2 = pol_err (A1): mode HMAC biasa dengan kunci KDF-only dan
//                 pesan < 40 byte ditolak; operasi tidak dijalankan.
// - 0x004       Status Register  (R): bit0 = Busy, bit1 = Done (sticky)
// - 0x008-0x024 Digest / KDF Output Words 0..7 (R, word 0 = MSB)
// - 0x028       MSG_LEN (R/W): panjang pesan dalam byte, 0..55 (nilai > 55 di-clamp ke 55)
// - 0x02C-0x060 MSG words 0..13 (W): big-endian, byte 0 pesan = wdata[31:24]
//               Byte di luar MSG_LEN diabaikan (diganti padding 0x80 / 0x00).
//               MSG_LEN dan MSG hanya bisa ditulis saat idle.
// KDF: kdf_key = HMAC(key_in, msg)[255:128]; msg bertindak sebagai label/context.

module hmac_kdf (
    input  wire         clk_sys,
    input  wire         rst_sync_n,
    input  wire         zeroize,

    // Bus Slave Interconnect (Slave 0: Base 0x000)
    input  wire [45:0]  req,
    output reg  [31:0]  rdata,

    // Jalur Kunci Terisolasi (Dedicated Key Path)
    input  wire [127:0] key_in,      // Dari key_manager
    input  wire         key_kdf_only,// A1: kunci hanya boleh untuk KDF
    output reg  [127:0] kdf_key,     // Kunci sesi hasil derivasi
    output reg          kdf_wr,      // Strobe tulis ke key_manager

    // Antarmuka Master ke sha256_core
    output reg  [34:0]  sha_ctl,     // {sha_init, sha_next, sha_start, block_in[31:0]}
    input  wire [255:0] digest,
    input  wire         sha_ready
);

    // Parsing Bus Request
    wire [11:0] addr  = req[45:34];
    wire [31:0] wdata = req[33:2];
    // PERBAIKAN (review JATI): dekode alamat slave. Sebelumnya modul ini
    // bereaksi pada SEMUA penulisan bus, sehingga misalnya menulis CTRL=1 ke
    // TRNG ikut memicu HMAC.
    wire        sel   = (addr[11:8] == 4'h0);
    wire        we    = req[1] && sel;
    wire        re    = req[0] && sel;
    wire [7:0]  a8    = addr[7:0];

    // Decode area MSG: 0x02C .. 0x060, word-aligned
    wire        msg_sel = (a8 >= 8'h2C) && (a8 <= 8'h60) && (a8[1:0] == 2'b00);
    wire [7:0]  msg_off = a8 - 8'h2C;
    wire [3:0]  msg_idx = msg_off[5:2];

    // State Machine Otomasi HMAC / KDF
    localparam S_IDLE   = 3'd0;
    localparam S_INIT   = 3'd1;  // sha_init pulse (awal tiap pass)
    localparam S_STREAM = 3'd2;  // stream 16 kata blok aktif
    localparam S_CALC   = 3'd3;  // sha_start pulse
    localparam S_WAIT   = 3'd4;  // tunggu 64 ronde selesai
    localparam S_FINISH = 3'd5;

    reg [2:0]   state;
    reg [4:0]   word_idx;
    reg         phase;          // 0 = pass dalam (ipad), 1 = pass luar (opad)
    reg         blk;            // 0 = blok kunci, 1 = blok pesan / inner_hash
    reg         sha_busy_seen;  // sha_ready harus turun dulu sebelum dipercaya
    reg [127:0] key_lat;        // kunci di-latch saat start (stabil selama operasi)
    reg [255:0] inner_hash;
    reg [255:0] result_digest;
    reg         is_kdf_mode;
    reg         busy;
    reg         done;
    reg         pol_err;        // A1: permintaan ditolak kebijakan kunci

    reg [31:0]  msg_mem [0:13];
    reg [7:0]   msg_len;
    integer     i;

    // Persiapan Key Padded (K_pad = key 128 bit di-pad nol menjadi 512 bit)
    wire [31:0] key_words [0:15];
    assign key_words[0]  = key_lat[127:96];
    assign key_words[1]  = key_lat[95:64];
    assign key_words[2]  = key_lat[63:32];
    assign key_words[3]  = key_lat[31:0];
    genvar g;
    generate
        for (g = 4; g < 16; g = g + 1) begin : key_pad_zero
            assign key_words[g] = 32'h00000000;
        end
    endgenerate

    // Konstanta padding HMAC
    localparam [31:0] IPAD_WORD = 32'h36363636;
    localparam [31:0] OPAD_WORD = 32'h5C5C5C5C;

    // Satu kata blok pesan: byte < len = data, byte == len = 0x80, sisanya 0x00
    function [31:0] msg_block_word;
        input [3:0]  idx;
        input [31:0] mw;
        input [7:0]  len;
        integer      k;
        reg   [7:0]  pos;
        reg   [7:0]  bv;
        begin
            msg_block_word = 32'd0;
            for (k = 0; k < 4; k = k + 1) begin
                pos = {idx, 2'b00} + k;
                if (pos < len)       bv = mw[31 - 8*k -: 8];
                else if (pos == len) bv = 8'h80;
                else                 bv = 8'h00;
                msg_block_word[31 - 8*k -: 8] = bv;
            end
        end
    endfunction

    // Panjang total pass dalam dalam bit = (64 + len) * 8
    wire [7:0] len_plus_blk = msg_len + 8'd64;

    // Kata yang akan di-stream ke sha256_core pada (phase, blk, word_idx)
    wire [3:0] widx = word_idx[3:0];
    reg  [31:0] cur_word;
    always @(*) begin
        if (!blk) begin
            // Blok 0: (K ^ ipad) atau (K ^ opad), 16 kata penuh
            cur_word = key_words[widx] ^ (phase ? OPAD_WORD : IPAD_WORD);
        end else if (!phase) begin
            // Blok 1 pass dalam: msg || 0x80 || 0... || panjang bit
            if (widx == 4'd15)      cur_word = {21'd0, len_plus_blk, 3'b000};
            else if (widx == 4'd14) cur_word = 32'd0;
            else                    cur_word = msg_block_word(widx, msg_mem[widx], msg_len);
        end else begin
            // Blok 1 pass luar: inner_hash (MSB dulu) || 0x80000000 || 0... || 0x300 (768 bit)
            if (widx < 4'd8)        cur_word = inner_hash[(7 - widx[2:0]) * 32 +: 32];
            else if (widx == 4'd8)  cur_word = 32'h80000000;
            else if (widx == 4'd15) cur_word = 32'h00000300;
            else                    cur_word = 32'd0;
        end
    end

    // --- Pengendali Siklus HMAC / KDF ---
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            state         <= S_IDLE;
            sha_ctl       <= 35'd0;
            inner_hash    <= 256'd0;
            result_digest <= 256'd0;
            key_lat       <= 128'd0;
            kdf_key       <= 128'd0;
            kdf_wr        <= 1'b0;
            word_idx      <= 5'd0;
            phase         <= 1'b0;
            blk           <= 1'b0;
            is_kdf_mode   <= 1'b0;
            busy          <= 1'b0;
            done          <= 1'b0;
            pol_err       <= 1'b0;
            sha_busy_seen <= 1'b0;
            msg_len       <= 8'd0;
            for (i = 0; i < 14; i = i + 1) msg_mem[i] <= 32'd0;
        end else if (zeroize) begin
            // Instant wipe seluruh register kunci, pesan dan komputasi
            state         <= S_IDLE;
            sha_ctl       <= 35'd0;
            inner_hash    <= 256'd0;
            result_digest <= 256'd0;
            key_lat       <= 128'd0;
            kdf_key       <= 128'd0;
            kdf_wr        <= 1'b0;
            word_idx      <= 5'd0;
            phase         <= 1'b0;
            blk           <= 1'b0;
            is_kdf_mode   <= 1'b0;
            busy          <= 1'b0;
            done          <= 1'b0;
            pol_err       <= 1'b0;
            sha_busy_seen <= 1'b0;
            msg_len       <= 8'd0;
            for (i = 0; i < 14; i = i + 1) msg_mem[i] <= 32'd0;
        end else begin
            kdf_wr <= 1'b0; // Default pulse
            // PERBAIKAN (review JATI): kunci hasil KDF hanya ada selama pulsa
            // kdf_wr, lalu dihapus dari register ini.
            if (kdf_wr) kdf_key <= 128'd0;

            case (state)
                S_IDLE: begin
                    // 'done' sticky: dibersihkan hanya saat operasi baru dimulai
                    if (we) begin
                        if (a8 == 8'h00) begin
                            // PERBAIKAN A1: kunci KDF-only (R_PUF, K_DEV) tidak boleh
                            // dipakai mode HMAC biasa (hasil terbaca bus) dengan pesan
                            // pendek, karena HMAC(K_DEV, "JATI-CA") = K_CA.
                            if (wdata[0] && !wdata[1] && key_kdf_only && msg_len < 8'd40) begin
                                pol_err <= 1'b1;
                                done    <= 1'b0;
                            end else if (wdata[0] || wdata[1]) begin // Trigger Start
                                pol_err     <= 1'b0;
                                is_kdf_mode <= wdata[1];
                                busy        <= 1'b1;
                                done        <= 1'b0;
                                key_lat     <= key_in;      // latch kunci
                                phase       <= 1'b0;
                                blk         <= 1'b0;
                                state       <= S_INIT;
                            end
                        end else if (a8 == 8'h28) begin
                            msg_len <= (wdata > 32'd55) ? 8'd55 : wdata[7:0];
                        end else if (msg_sel) begin
                            msg_mem[msg_idx] <= wdata;
                        end
                    end
                end

                // Awal pass: SHA state <- IV
                S_INIT: begin
                    sha_ctl  <= {1'b1, 1'b0, 1'b0, 32'd0}; // sha_init = 1
                    word_idx <= 5'd0;
                    state    <= S_STREAM;
                end

                // Stream 16 kata blok aktif (sha_next = 1)
                S_STREAM: begin
                    sha_ctl <= {1'b0, 1'b1, 1'b0, cur_word};
                    if (word_idx == 5'd15)
                        state <= S_CALC;
                    else
                        word_idx <= word_idx + 1'b1;
                end

                S_CALC: begin
                    sha_ctl       <= {1'b0, 1'b0, 1'b1, 32'd0}; // sha_start = 1
                    sha_busy_seen <= 1'b0;
                    state         <= S_WAIT;
                end

                S_WAIT: begin
                    sha_ctl <= 35'd0;
                    // sha_ready masih 1 (basi) pada siklus pertama setelah sha_start:
                    // tunggu turun dulu, lalu naik lagi.
                    if (!sha_ready)
                        sha_busy_seen <= 1'b1;
                    else if (sha_busy_seen) begin
                        sha_busy_seen <= 1'b0;
                        word_idx      <= 5'd0;
                        if (!blk) begin
                            // Blok kunci selesai -> blok kedua, lanjut chaining (tanpa init)
                            blk   <= 1'b1;
                            state <= S_STREAM;
                        end else if (!phase) begin
                            // Pass dalam selesai -> simpan, mulai pass luar
                            inner_hash <= digest;
                            phase      <= 1'b1;
                            blk        <= 1'b0;
                            state      <= S_INIT;
                        end else begin
                            // Pass luar selesai -> HMAC final
                            result_digest <= digest;
                            state         <= S_FINISH;
                        end
                    end
                end

                S_FINISH: begin
                    busy       <= 1'b0;
                    done       <= 1'b1;
                    inner_hash <= 256'd0;   // hapus nilai antara
                    key_lat    <= 128'd0;   // hapus salinan kunci
                    if (is_kdf_mode) begin
                        kdf_key <= result_digest[255:128]; // 128 bit MSB sebagai kunci sesi
                        kdf_wr  <= 1'b1;                   // Trigger write ke key_manager
                        // PERBAIKAN (review JATI): pada mode KDF, hasil HMAC ADALAH
                        // kunci. Sebelumnya hasil ini tetap bisa dibaca lewat bus
                        // (register 0x08..0x24) -> kebocoran kunci. Sekarang dihapus.
                        result_digest <= 256'd0;
                    end
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    // --- Antarmuka Pembacaan Register via Bus ---
    // rdata di-reset dan di-wipe saat zeroize
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n)
            rdata <= 32'd0;
        else if (zeroize)
            rdata <= 32'd0;
        else if (re) begin
            case (a8)
                8'h00: rdata <= {30'd0, is_kdf_mode, 1'b0};
                8'h04: rdata <= {29'd0, pol_err, done, busy};
                8'h08: rdata <= result_digest[255:224];
                8'h0C: rdata <= result_digest[223:192];
                8'h10: rdata <= result_digest[191:160];
                8'h14: rdata <= result_digest[159:128];
                8'h18: rdata <= result_digest[127:96];
                8'h1C: rdata <= result_digest[95:64];
                8'h20: rdata <= result_digest[63:32];
                8'h24: rdata <= result_digest[31:0];
                8'h28: rdata <= {24'd0, msg_len};
                default: rdata <= 32'h00000000;
            endcase
        end
    end

endmodule