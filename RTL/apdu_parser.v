// Modul: apdu_parser
// Deskripsi: Framing paket APDU ISO/IEC 7816-4, validasi CRC-16, 
//            serta buffer command dan response.
// Format paket fisik UART:
// Dengan Le : [SYNC 0x5A] [CLA] [INS] [P1] [P2] [Lc] [DATA (Lc byte)] [Le] [CRC16_H] [CRC16_L]
// Tanpa Le  : [SYNC 0x5B] [CLA] [INS] [P1] [P2] [Lc] [DATA (Lc byte)]      [CRC16_H] [CRC16_L]
// CRC-16 mencakup SYNC .. byte terakhir sebelum CRC (termasuk Le bila ada).
// Byte SYNC membedakan "Le tidak ada" (Le = 0) dari "Le = 00" (Le = 256), sesuai
// ISO/IEC 7816-4; satu byte Le tidak cukup mewakili 257 nilai (0..256).

module apdu_parser (
    input  wire        clk_sys,
    input  wire        rst_sync_n,

    // Antarmuka UART RX
    input  wire [7:0]  rx_data,
    input  wire        rx_valid,
    output reg         rx_ready,

    // Antarmuka UART TX
    output reg  [7:0]  tx_data,
    output reg         tx_valid,
    input  wire        tx_ready,

    // Antarmuka ke ctrl_fsm
    // cmd[48:0] = {CLA[7:0], INS[7:0], P1[7:0], P2[7:0], Lc[7:0], Le[8:0]}
    //              [48:41] [40:33] [32:25] [24:17] [16:9]  [8:0]
    // Le (9 bit) sudah diterjemahkan: tidak ada -> 0, 01..FF -> 1..255, 00 -> 256.
    // cmd_crc_err valid bersamaan dengan cmd_valid (1 = CRC frame tidak cocok).
    output reg  [48:0] cmd,
    output reg         cmd_valid,
    output reg         cmd_crc_err,

    // Respons dari ctrl_fsm
    // rsp[24:0] = {SW1[7:0], SW2[7:0], resp_len[7:0], send_trigger}
    input  wire [24:0] rsp,
    input  wire        rsp_valid,

    // Akses buffer internal oleh ctrl_fsm
    // buf_req[17:0] = {wr_en, rd_en, addr[7:0], wdata[7:0]}
    input  wire [17:0] buf_req,
    output reg  [7:0]  buf_rdata
);

    // CRC-16 CCITT Function (Polynomial 0x1021)
    function [15:0] update_crc16;
        input [15:0] crc_cur;
        input [7:0]  d_in;
        reg   [15:0] crc;
        integer b;
        begin
            crc = crc_cur ^ {d_in, 8'h00};
            for (b = 0; b < 8; b = b + 1) begin
                if (crc[15])
                    crc = (crc << 1) ^ 16'h1021;
                else
                    crc = crc << 1;
            end
            update_crc16 = crc;
        end
    endfunction

    // Buffer Memori Internal (256 byte RAM untuk Command & Response)
    reg [7:0] packet_ram [0:255];

    // Status FSM RX
    localparam RX_IDLE     = 4'd0;
    localparam RX_CLA      = 4'd1;
    localparam RX_INS      = 4'd2;
    localparam RX_P1       = 4'd3;
    localparam RX_P2       = 4'd4;
    localparam RX_LEN      = 4'd5;
    localparam RX_DATA     = 4'd6;
    localparam RX_CRC1     = 4'd7;
    localparam RX_CRC2     = 4'd8;
    localparam RX_DISPATCH = 4'd9;
    localparam RX_LE       = 4'd10;

    reg [3:0]  rx_state;
    reg [7:0]  reg_cla, reg_ins, reg_p1, reg_p2, reg_len;
    reg [8:0]  reg_le;       // Le sudah diterjemahkan (0..256)
    reg        rx_has_le;    // 1 = frame membawa byte Le (SYNC 0x5A)
    reg [7:0]  rx_byte_idx;
    reg [15:0] rx_crc;
    reg [7:0]  rx_crc_hi;

    // Status FSM TX
    localparam TX_IDLE     = 3'd0;
    localparam TX_SEND_SW1 = 3'd1;
    localparam TX_SEND_SW2 = 3'd2;
    localparam TX_SEND_LEN = 3'd3;
    localparam TX_SEND_DAT = 3'd4;
    localparam TX_SEND_CR1 = 3'd5;
    localparam TX_SEND_CR2 = 3'd6;

    reg [2:0]  tx_state;
    reg [7:0]  tx_sw1, tx_sw2, tx_len;
    reg [7:0]  tx_byte_idx;
    reg [15:0] tx_crc;
    reg        tx_gap;     // FIX: byte issued, waiting for UART to take it (ready drops)

    // --- Akses Buffer RAM oleh ctrl_fsm ---
    wire       fsm_buf_wr   = buf_req[17];
    wire       fsm_buf_rd   = buf_req[16];
    wire [7:0] fsm_buf_addr = buf_req[15:8];
    wire [7:0] fsm_buf_wdat = buf_req[7:0];

    // FIX: single write port. RX payload writes and ctrl_fsm writes used to come from
    // two different always blocks (multi-driver, not synthesizable as RAM).
    // The RX path has priority while a payload byte is arriving.
    // OPTIMASI B1 (review JATI): SATU port baca sinkron dipakai bergantian oleh
    // ctrl_fsm dan pengirim TX (keduanya tidak pernah aktif bersamaan), sehingga
    // buffer 256 byte dipetakan ke satu blok M10K, bukan ~2.000 flip-flop.
    wire       tx_rd   = (tx_state == TX_SEND_LEN) || (tx_state == TX_SEND_DAT);
    wire [7:0] rd_addr = tx_rd ? tx_byte_idx : fsm_buf_addr;
    reg  [7:0] ram_q;
    always @(posedge clk_sys) begin
        if (rx_state == RX_DATA && rx_valid)
            packet_ram[rx_byte_idx] <= rx_data;
        else if (fsm_buf_wr)
            packet_ram[fsm_buf_addr] <= fsm_buf_wdat;
        if (fsm_buf_rd || tx_rd)
            ram_q <= packet_ram[rd_addr];
    end
    always @(*) buf_rdata = ram_q;

    // --- FSM Penerima Paket APDU (RX) ---
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            rx_state    <= RX_IDLE;
            rx_ready    <= 1'b1;
            cmd_valid   <= 1'b0;
            cmd_crc_err <= 1'b0;
            cmd         <= 49'd0;
            rx_byte_idx <= 8'd0;
            rx_crc      <= 16'hFFFF;
            reg_cla     <= 8'd0;
            reg_ins     <= 8'd0;
            reg_p1      <= 8'd0;
            reg_p2      <= 8'd0;
            reg_len     <= 8'd0;
            reg_le      <= 9'd0;
            rx_has_le   <= 1'b0;
            rx_crc_hi   <= 8'd0;
        end else begin
            // Reset strobe valid setelah FSM master merespons
            if (cmd_valid)
                cmd_valid <= 1'b0;

            case (rx_state)
                RX_IDLE: begin
                    rx_ready <= 1'b1;
                    // Sinkronisasi: 0x5A = frame dengan Le, 0x5B = frame tanpa Le
                    if (rx_valid && (rx_data == 8'h5A || rx_data == 8'h5B)) begin
                        rx_has_le <= (rx_data == 8'h5A);
                        reg_le    <= 9'd0;                       // Le tidak ada -> 0
                        rx_crc    <= update_crc16(16'hFFFF, rx_data);
                        rx_state  <= RX_CLA;
                    end
                end

                RX_CLA: begin
                    if (rx_valid) begin
                        reg_cla  <= rx_data;
                        rx_crc   <= update_crc16(rx_crc, rx_data);
                        rx_state <= RX_INS;
                    end
                end

                RX_INS: begin
                    if (rx_valid) begin
                        reg_ins  <= rx_data;
                        rx_crc   <= update_crc16(rx_crc, rx_data);
                        rx_state <= RX_P1;
                    end
                end

                RX_P1: begin
                    if (rx_valid) begin
                        reg_p1   <= rx_data;
                        rx_crc   <= update_crc16(rx_crc, rx_data);
                        rx_state <= RX_P2;
                    end
                end

                RX_P2: begin
                    if (rx_valid) begin
                        reg_p2   <= rx_data;
                        rx_crc   <= update_crc16(rx_crc, rx_data);
                        rx_state <= RX_LEN;
                    end
                end

                RX_LEN: begin
                    if (rx_valid) begin
                        reg_len     <= rx_data;
                        rx_crc      <= update_crc16(rx_crc, rx_data);
                        rx_byte_idx <= 8'd0;
                        if (rx_data == 8'd0)    // Tidak ada payload
                            rx_state <= rx_has_le ? RX_LE : RX_CRC1;
                        else
                            rx_state <= RX_DATA;
                    end
                end

                RX_DATA: begin
                    if (rx_valid) begin
                        rx_crc <= update_crc16(rx_crc, rx_data);
                        if (rx_byte_idx + 1'b1 >= reg_len) begin
                            rx_state <= rx_has_le ? RX_LE : RX_CRC1;
                        end else begin
                            rx_byte_idx <= rx_byte_idx + 1'b1;
                        end
                    end
                end

                // Le: panjang respons yang diharapkan host (setelah DATA, sebelum CRC).
                // Terjemahan ISO 7816-4: byte 00 = 256, 01..FF = 1..255.
                RX_LE: begin
                    if (rx_valid) begin
                        reg_le   <= (rx_data == 8'h00) ? 9'd256 : {1'b0, rx_data};
                        rx_crc   <= update_crc16(rx_crc, rx_data);
                        rx_state <= RX_CRC1;
                    end
                end

                RX_CRC1: begin
                    if (rx_valid) begin
                        rx_crc_hi <= rx_data;
                        rx_state  <= RX_CRC2;
                    end
                end

                RX_CRC2: begin
                    if (rx_valid) begin
                        // FIX: a 'wire' declaration inside a procedural block is illegal
                        // Verilog; compare inline instead.
                        cmd         <= {reg_cla, reg_ins, reg_p1, reg_p2, reg_len, reg_le};
                        cmd_crc_err <= (rx_crc != {rx_crc_hi, rx_data});
                        cmd_valid   <= 1'b1;
                        rx_state  <= RX_IDLE;
                    end
                end

                default: rx_state <= RX_IDLE;
            endcase
        end
    end

    // --- FSM Pengirim Respons APDU (TX) ---
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            tx_state    <= TX_IDLE;
            tx_valid    <= 1'b0;
            tx_data     <= 8'd0;
            tx_sw1      <= 8'd0;
            tx_sw2      <= 8'd0;
            tx_len      <= 8'd0;
            tx_byte_idx <= 8'd0;
            tx_crc      <= 16'hFFFF;
            tx_gap      <= 1'b0;
        end else begin
            // FIX: tx_valid is a 1-cycle strobe (it used to stay high for the whole frame)
            tx_valid <= 1'b0;
            // After a byte is issued, wait until the UART has gone busy before
            // sending the next one (otherwise a still-high tx_ready overwrites tx_data).
            if (tx_gap && !tx_ready)
                tx_gap <= 1'b0;

            case (tx_state)
                TX_IDLE: begin
                    if (rsp_valid && rsp[0]) begin // Trigger kirim aktif
                        tx_sw1      <= rsp[24:17];
                        tx_sw2      <= rsp[16:9];
                        tx_len      <= rsp[8:1];
                        tx_crc      <= update_crc16(16'hFFFF, rsp[24:17]);
                        tx_state    <= TX_SEND_SW1;
                        tx_byte_idx <= 8'd0;
                    end
                end

                TX_SEND_SW1: begin
                    if (tx_ready && !tx_gap) begin
                        tx_gap   <= 1'b1;
                        tx_data  <= tx_sw1;
                        tx_valid <= 1'b1;
                        tx_crc   <= update_crc16(tx_crc, tx_sw2);
                        tx_state <= TX_SEND_SW2;
                    end
                end

                TX_SEND_SW2: begin
                    if (tx_ready && !tx_gap) begin
                        tx_gap   <= 1'b1;
                        tx_data  <= tx_sw2;
                        tx_valid <= 1'b1;
                        tx_crc   <= update_crc16(tx_crc, tx_len);
                        tx_state <= TX_SEND_LEN;
                    end
                end

                TX_SEND_LEN: begin
                    if (tx_ready && !tx_gap) begin
                        tx_gap   <= 1'b1;
                        tx_data <= tx_len;
                        tx_valid <= 1'b1;
                        if (tx_len == 8'd0)
                            tx_state <= TX_SEND_CR1;
                        else
                            tx_state <= TX_SEND_DAT;
                    end
                end

                TX_SEND_DAT: begin
                    if (tx_ready && !tx_gap) begin
                        tx_gap   <= 1'b1;
                        tx_data  <= ram_q;                    // B1: dari port baca bersama
                        tx_valid <= 1'b1;
                        tx_crc   <= update_crc16(tx_crc, ram_q);
                        if (tx_byte_idx + 1'b1 >= tx_len)
                            tx_state <= TX_SEND_CR1;
                        else
                            tx_byte_idx <= tx_byte_idx + 1'b1;
                    end
                end

                TX_SEND_CR1: begin
                    if (tx_ready && !tx_gap) begin
                        tx_gap   <= 1'b1;
                        tx_data  <= tx_crc[15:8];
                        tx_valid <= 1'b1;
                        tx_state <= TX_SEND_CR2;
                    end
                end

                TX_SEND_CR2: begin
                    if (tx_ready && !tx_gap) begin
                        tx_gap   <= 1'b1;
                        tx_data  <= tx_crc[7:0];
                        tx_valid <= 1'b1;
                        tx_state <= TX_IDLE;
                    end
                end

                default: tx_state <= TX_IDLE;
            endcase
        end
    end

endmodule