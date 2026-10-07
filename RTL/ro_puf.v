// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : ro_puf
// Fungsi  : Mengukur frekuensi dua ring oscillator (RO) sekaligus dari bank
//           1024 RO, atas permintaan fuzzy_ext.
//
// Alur satu pengukuran:
//   1. Terima start + indeks RO A dan RO B (puf_ctl), simpan indeksnya.
//   2. Lepas clear penghitung, lalu nyalakan HANYA dua RO terpilih selama
//      WIN siklus clk_sys (default 1024 siklus = 20,48 us pada 50 MHz).
//   3. Matikan RO, tunggu SETTLE siklus agar penghitung benar-benar diam.
//   4. Ambil hasil kedua penghitung, kirim dengan pulsa cnt_done 1 siklus.
//   5. Hapus penghitung dan hasil (cnt = 0 di luar pulsa cnt_done).
//
// Kenapa penghitung ripple?
//   RO bisa berosilasi ratusan MHz, terlalu cepat untuk penghitung sinkron
//   16 bit biasa. Pada penghitung ripple, hanya bit 0 yang melihat frekuensi
//   penuh RO; tiap bit berikutnya berjalan setengahnya. Hasilnya dibaca
//   SETELAH RO dimatikan dan nilainya diam, jadi aman tanpa sinkronizer.
//
// Aturan keamanan:
//   1. Hanya dua RO yang menyala, dan hanya selama jendela ukur: mengurangi
//      derau, saling pengaruh antar-RO, dan kebocoran lewat konsumsi daya.
//   2. Hitungan mentah membocorkan bit kunci, jadi cnt hanya bernilai selama
//      satu siklus cnt_done lalu dihapus, begitu juga penghitung internal.
//   3. Start diabaikan selama pengukuran masih berjalan.
//
// Kontrak dengan fuzzy_ext:
//   puf_ctl[9:0] RO A, puf_ctl[19:10] RO B, puf_ctl[20] start (pulsa)
//   cnt[15:0] hitungan RO A, cnt[31:16] hitungan RO B, cnt_done pulsa
//
// Bank RO ada di modul terpisah "ro_puf_array":
//   - RTL/ro_puf_array.v     : RO sungguhan untuk Quartus
//   - SIM/ro_puf_array_sim.v : model untuk ModelSim (JANGAN ke Quartus)
// =============================================================================

module ro_puf #(
    parameter integer WIN     = 1024,   // lama jendela ukur (siklus clk_sys)
    parameter integer SETTLE  = 8,      // jeda setelah RO dimatikan
    parameter integer N_STAGE = 3       // tahap per RO (ganjil)
)(
    input  wire        clk_sys,
    input  wire        rst_sync_n,
    input  wire [20:0] puf_ctl,
    output wire [31:0] cnt,
    output reg         cnt_done
);

    // -------------------------------------------------------------------------
    // Bank ring oscillator
    // -------------------------------------------------------------------------
    reg  [9:0] sa, sb;
    reg        ro_en;
    wire       ro_a, ro_b;

    ro_puf_array #(.N_STAGE(N_STAGE)) u_arr (
        .sel_a (sa),
        .sel_b (sb),
        .en    (ro_en),
        .ro_a  (ro_a),
        .ro_b  (ro_b)
    );

    // -------------------------------------------------------------------------
    // Penghitung ripple 16 bit (domain RO), clear asinkron dari domain clk_sys
    // -------------------------------------------------------------------------
    reg         ctr_clr;
    wire [15:0] ca, cb;

    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : g_ca
            reg q;
            if (i == 0) begin : b0
                always @(posedge ro_a or posedge ctr_clr)
                    if (ctr_clr) q <= 1'b0; else q <= ~q;
            end else begin : bn
                always @(negedge ca[i-1] or posedge ctr_clr)
                    if (ctr_clr) q <= 1'b0; else q <= ~q;
            end
            assign ca[i] = q;
        end

        for (i = 0; i < 16; i = i + 1) begin : g_cb
            reg q;
            if (i == 0) begin : b0
                always @(posedge ro_b or posedge ctr_clr)
                    if (ctr_clr) q <= 1'b0; else q <= ~q;
            end else begin : bn
                always @(negedge cb[i-1] or posedge ctr_clr)
                    if (ctr_clr) q <= 1'b0; else q <= ~q;
            end
            assign cb[i] = q;
        end
    endgenerate

    // -------------------------------------------------------------------------
    // State machine pengukuran (domain clk_sys)
    // -------------------------------------------------------------------------
    localparam [2:0] S_IDLE = 3'd0, S_CLR = 3'd1, S_SET = 3'd2, S_RUN = 3'd3,
                     S_SETTLE = 3'd4, S_CAP = 3'd5, S_DONE = 3'd6;

    reg [2:0]  st;
    reg [15:0] tcnt;
    reg [31:0] cnt_q;

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            st       <= S_IDLE;
            sa       <= 10'd0;
            sb       <= 10'd0;
            ro_en    <= 1'b0;
            ctr_clr  <= 1'b1;
            tcnt     <= 16'd0;
            cnt_q    <= 32'd0;
            cnt_done <= 1'b0;
        end else begin
            cnt_done <= 1'b0;
            case (st)
                S_IDLE: begin
                    ctr_clr <= 1'b1;
                    ro_en   <= 1'b0;
                    if (puf_ctl[20]) begin
                        sa <= puf_ctl[9:0];
                        sb <= puf_ctl[19:10];
                        st <= S_CLR;
                    end
                end

                S_CLR: begin            // lepas clear, RO masih mati
                    ctr_clr <= 1'b0;
                    tcnt    <= 16'd0;
                    st      <= S_SET;
                end

                S_SET: begin            // nyalakan dua RO terpilih
                    ro_en <= 1'b1;
                    tcnt  <= 16'd0;
                    st    <= S_RUN;
                end

                S_RUN: begin            // tepat WIN siklus
                    if (tcnt == WIN - 1) begin
                        ro_en <= 1'b0;
                        tcnt  <= 16'd0;
                        st    <= S_SETTLE;
                    end else
                        tcnt <= tcnt + 1'b1;
                end

                S_SETTLE: begin         // tunggu penghitung ripple diam
                    if (tcnt == SETTLE - 1) st <= S_CAP;
                    else                    tcnt <= tcnt + 1'b1;
                end

                S_CAP: begin
                    cnt_q    <= {cb, ca};
                    cnt_done <= 1'b1;
                    st       <= S_DONE;
                end

                S_DONE: begin           // hapus hasil dan penghitung
                    cnt_q   <= 32'd0;
                    ctr_clr <= 1'b1;
                    st      <= S_IDLE;
                end

                default: st <= S_IDLE;
            endcase
        end
    end

    // Hitungan hanya terlihat selama pulsa cnt_done
    assign cnt = cnt_done ? cnt_q : 32'd0;

endmodule