// Modul: uart
// Deskripsi: UART TX/RX 8N1 dengan handshake valid/ready

module uart #(
    parameter CLK_FREQ  = 50_000_000,
    parameter BAUD_RATE = 115200
)(
    input  wire       clk_sys,
    input  wire       rst_sync_n,
    input  wire       rx,
    output reg        tx,
    output reg  [7:0] rx_data,
    output reg        rx_valid,
    input  wire       rx_ready,
    input  wire [7:0] tx_data,
    input  wire       tx_valid,
    output reg        tx_ready
);

    localparam CLKS_PER_BIT = CLK_FREQ / BAUD_RATE;
    localparam HALF_BIT     = CLKS_PER_BIT / 2;

    // =========================================================================
    // UART RX State Machine
    // =========================================================================
    localparam RX_IDLE  = 2'd0;
    localparam RX_START = 2'd1;
    localparam RX_DATA  = 2'd2;
    localparam RX_STOP  = 2'd3;

    reg [1:0]  rx_sync;      // 2-FF synchronizer (rx is asynchronous)
    reg [1:0]  rx_state;
    reg [15:0] rx_clk_cnt;
    reg [2:0]  rx_bit_idx;
    reg [7:0]  rx_shreg;

    wire rx_s = rx_sync[1];

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            rx_sync    <= 2'b11;
            rx_state   <= RX_IDLE;
            rx_clk_cnt <= 16'd0;
            rx_bit_idx <= 3'd0;
            rx_shreg   <= 8'd0;
            rx_data    <= 8'd0;
            rx_valid   <= 1'b0;
        end else begin
            rx_sync <= {rx_sync[0], rx};

            // Consumer acknowledges the received byte
            if (rx_valid && rx_ready)
                rx_valid <= 1'b0;

            case (rx_state)
                // Wait for falling edge (start bit)
                RX_IDLE: begin
                    if (!rx_s) begin
                        rx_state   <= RX_START;
                        rx_clk_cnt <= 16'd0;
                    end
                end

                // Wait half a bit, then re-check the start bit in its middle
                RX_START: begin
                    if (rx_clk_cnt == HALF_BIT - 1) begin
                        rx_clk_cnt <= 16'd0;
                        if (!rx_s) begin
                            rx_state   <= RX_DATA;
                            rx_bit_idx <= 3'd0;
                        end else begin
                            rx_state <= RX_IDLE; // glitch, not a real start bit
                        end
                    end else begin
                        rx_clk_cnt <= rx_clk_cnt + 1'b1;
                    end
                end

                // Sample each data bit in the middle of the bit (LSB first)
                RX_DATA: begin
                    if (rx_clk_cnt == CLKS_PER_BIT - 1) begin
                        rx_clk_cnt           <= 16'd0;
                        rx_shreg[rx_bit_idx] <= rx_s;
                        rx_bit_idx           <= rx_bit_idx + 1'b1;
                        if (rx_bit_idx == 3'd7)
                            rx_state <= RX_STOP;
                    end else begin
                        rx_clk_cnt <= rx_clk_cnt + 1'b1;
                    end
                end

                // Check stop bit in its middle; only then publish the byte
                RX_STOP: begin
                    if (rx_clk_cnt == CLKS_PER_BIT - 1) begin
                        rx_clk_cnt <= 16'd0;
                        rx_state   <= RX_IDLE;
                        if (rx_s) begin          // valid stop bit
                            rx_data  <= rx_shreg;
                            rx_valid <= 1'b1;
                        end                      // else: framing error, drop byte
                    end else begin
                        rx_clk_cnt <= rx_clk_cnt + 1'b1;
                    end
                end
            endcase
        end
    end

    // =========================================================================
    // UART TX State Machine
    // =========================================================================
    reg [15:0] tx_clk_cnt;
    reg [3:0]  tx_bit_idx;
    reg [9:0]  tx_frame; // 1 start + 8 data + 1 stop

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            tx         <= 1'b1;
            tx_ready   <= 1'b1;
            tx_clk_cnt <= 16'd0;
            tx_bit_idx <= 4'd0;
            tx_frame   <= 10'h3FF;
        end else begin
            if (tx_ready) begin
                if (tx_valid) begin
                    tx_frame   <= {1'b1, tx_data, 1'b0}; // Stop(1), Data(8), Start(0)
                    tx         <= 1'b0;                  // drive start bit immediately
                    tx_ready   <= 1'b0;
                    tx_clk_cnt <= 16'd0;
                    tx_bit_idx <= 4'd0;
                end
            end else begin
                if (tx_clk_cnt < CLKS_PER_BIT - 1) begin
                    tx_clk_cnt <= tx_clk_cnt + 1'b1;
                end else begin
                    tx_clk_cnt <= 16'd0;
                    if (tx_bit_idx < 4'd9) begin
                        // advance to the next bit of the frame
                        tx_bit_idx <= tx_bit_idx + 1'b1;
                        tx         <= tx_frame[tx_bit_idx + 1'b1];
                    end else begin
                        // stop bit has been held for a full bit time
                        tx_ready <= 1'b1;
                    end
                end
            end
        end
    end

endmodule