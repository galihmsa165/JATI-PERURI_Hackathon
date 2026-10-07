// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : jati_top   (top-level chip)
//
// Menyambungkan semua blok sesuai skematik:
//   uart <-> apdu_parser <-> ctrl_fsm <-> bus_mux <-> 6 slave bus
//   key_manager -> (jalur kunci) -> hmac_kdf, aes128_sm
//   ro_puf <-> fuzzy_ext -> key_manager
//   tamper_sensor -> zeroize -> semua blok penyimpan rahasia
//
// Peta ID slave bus (bus_mux s_rdata):
//   0 HMAC [31:0], 1 AES [63:32], 2 TRNG [95:64], 3 MEM [127:96],
//   4 LC [159:128], 5 FE [191:160]
//
// Parameter khusus simulasi (nilai default = nilai untuk FPGA):
//   BAUD_RATE, TRNG_DIV, PUF_WIN, GLITCH_EN, DLY_BASE
// Revisi keamanan & optimasi (v3): lihat header ctrl_fsm.v dan tiap modul.
// Parameter kalibrasi hardware: TAMPER_N_CAN
// =============================================================================

module jati_top #(
    parameter integer CLK_FREQ  = 50_000_000,
    parameter integer BAUD_RATE = 921600,   // B2: 8x lebih cepat (adaptor USB-TTL 3,3 V)
    parameter integer TRNG_DIV  = 32,
    parameter integer PUF_WIN   = 512,      // B2: rekonstruksi 2x lebih cepat
    parameter integer DLY_BASE  = 65536,    // A5: jeda dasar setelah EXTERNAL AUTH gagal
    parameter integer GLITCH_EN = 1,         // 0 untuk chip final
    // Panjang canary timing tamper_sensor (GENAP). Kalibrasi dengan Timing
    // Analyzer: jalur launch -> can_viol harus LULUS di semua corner (tanpa
    // alarm palsu) dengan slack kecil agar peka terhadap penurunan tegangan.
    parameter integer TAMPER_N_CAN = 26
)(
    input  wire       clk_50,
    input  wire       rst_n,
    input  wire       uart_rx,
    input  wire       glitch_test_en,
    output wire       uart_tx,
    output wire [3:0] led_status,
    output wire       pll_locked
);

    // ---------------- Clock, reset, zeroize ----------------
    wire clk_pll, clk_sys, rst_sync_n, zeroize;

    clk_rst u_clk (
        .clk_50 (clk_50), .rst_n (rst_n),
        .clk_pll (clk_pll), .rst_sync_n (rst_sync_n), .pll_locked (pll_locked)
    );

    glitch_inj #(.ENABLE(GLITCH_EN)) u_glitch (
        .clk_pll (clk_pll), .glitch_test_en (glitch_test_en), .clk_sys (clk_sys)
    );

    // ---------------- UART + APDU ----------------
    wire [7:0]  rx_data, tx_data;
    wire        rx_valid, rx_ready, tx_valid, tx_ready;
    wire [48:0] cmd;
    wire        cmd_valid, cmd_crc_err;
    wire [24:0] rsp;
    wire        rsp_valid;
    wire [17:0] buf_req;
    wire [7:0]  buf_rdata;

    uart #(.CLK_FREQ(CLK_FREQ), .BAUD_RATE(BAUD_RATE)) u_uart (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n),
        .rx (uart_rx), .tx (uart_tx),
        .rx_data (rx_data), .rx_valid (rx_valid), .rx_ready (rx_ready),
        .tx_data (tx_data), .tx_valid (tx_valid), .tx_ready (tx_ready)
    );

    apdu_parser u_apdu (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n),
        .rx_data (rx_data), .rx_valid (rx_valid), .rx_ready (rx_ready),
        .tx_data (tx_data), .tx_valid (tx_valid), .tx_ready (tx_ready),
        .cmd (cmd), .cmd_valid (cmd_valid), .cmd_crc_err (cmd_crc_err),
        .rsp (rsp), .rsp_valid (rsp_valid),
        .buf_req (buf_req), .buf_rdata (buf_rdata)
    );

    // ---------------- FSM + bus ----------------
    wire [45:0]  m_req, s_req;
    wire [31:0]  m_rdata;
    wire [31:0]  rd_hmac, rd_aes, rd_trng, rd_mem, rd_lc, rd_fe;
    wire [3:0]   key_sel;
    wire         key_ok, key_kdf_only, fsm_fault;

    ctrl_fsm #(.DLY_BASE(DLY_BASE)) u_fsm (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .cmd (cmd), .cmd_valid (cmd_valid), .cmd_crc_err (cmd_crc_err),
        .rsp (rsp), .rsp_valid (rsp_valid),
        .buf_req (buf_req), .buf_rdata (buf_rdata),
        .m_req (m_req), .m_rdata (m_rdata),
        .key_sel (key_sel), .key_ok (key_ok), .fsm_fault (fsm_fault)
    );

    bus_mux u_bus (
        .clk_sys (clk_sys), .m_req (m_req), .m_rdata (m_rdata), .s_req (s_req),
        .s_rdata ({rd_fe, rd_lc, rd_mem, rd_trng, rd_aes, rd_hmac})
    );

    // ---------------- Kriptografi ----------------
    wire [127:0] key_out, wrap_key, kdf_key;
    wire         kdf_wr;
    wire [34:0]  sha_ctl;
    wire [255:0] digest;
    wire         sha_ready;

    hmac_kdf u_hmac (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .req (s_req), .rdata (rd_hmac),
        .key_in (key_out), .key_kdf_only (key_kdf_only),
        .kdf_key (kdf_key), .kdf_wr (kdf_wr),
        .sha_ctl (sha_ctl), .digest (digest), .sha_ready (sha_ready)
    );

    sha256_core u_sha (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .sha_ctl (sha_ctl), .digest (digest), .sha_ready (sha_ready)
    );

    aes128_sm u_aes (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .req (s_req), .rdata (rd_aes),
        .key_in (key_out), .wrap_key (wrap_key)
    );

    trng #(.SLAVE_ID(4'h2), .SAMPLE_DIV(TRNG_DIV)) u_trng (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .req (s_req), .rdata (rd_trng)
    );

    // ---------------- Memori + lifecycle ----------------
    wire       we_en, ever_locked, lc_fault;
    wire [2:0] tamper_cause;
    wire       tamper_alarm;

    dg_memory u_mem (
        .clk_sys (clk_sys), .req (s_req), .we_en (we_en), .rdata (rd_mem)
    );

    lifecycle u_lc (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .req (s_req), .tamper_cause (tamper_cause),
        .lc_nv (8'd0), .lc_nv_valid (1'b0),           // A15: OTP pada ASIC
        .rdata (rd_lc), .we_en (we_en), .ever_locked (ever_locked),
        .lc_fault (lc_fault), .led (led_status)
    );

    // ---------------- PUF + kunci ----------------
    wire [20:0]  puf_ctl;
    wire [31:0]  puf_cnt;
    wire         puf_done;
    wire [127:0] r_puf;
    wire         r_valid;

    ro_puf #(.WIN(PUF_WIN)) u_puf (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n),
        .puf_ctl (puf_ctl), .cnt (puf_cnt), .cnt_done (puf_done)
    );

    fuzzy_ext #(.SLAVE_ID(4'h5)) u_fe (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .req (s_req), .rdata (rd_fe),
        .puf_ctl (puf_ctl), .cnt (puf_cnt), .cnt_done (puf_done),
        .r_puf (r_puf), .r_valid (r_valid)
    );

    key_manager u_km (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .zeroize (zeroize),
        .key_sel (key_sel), .r_puf (r_puf), .r_valid (r_valid),
        .kdf_key (kdf_key), .kdf_wr (kdf_wr), .scan_mode (1'b0),   // A10: DFT pada ASIC
        .key_out (key_out), .wrap_key (wrap_key), .key_ok (key_ok),
        .key_kdf_only (key_kdf_only)
    );

    // ---------------- Keamanan fisik ----------------
    tamper_sensor #(.N_CAN(TAMPER_N_CAN)) u_tamper (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n),
        .fsm_fault (fsm_fault | lc_fault),            // A2/A3: fault logika apa pun
        .tamper_alarm (tamper_alarm), .tamper_cause (tamper_cause)
    );

    zeroize u_zero (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n),
        .tamper_alarm (tamper_alarm), .zeroize (zeroize)
    );

endmodule