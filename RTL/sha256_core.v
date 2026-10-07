// Modul: sha256_core (Full Cryptographic Implementation)
// Reference: FIPS PUB 180-4 Secure Hash Standard (SHA-256)
// Port matching schematic: sha_ctl[34:0] = {sha_init, sha_next, sha_start, block_in[31:0]}

module sha256_core (
    input  wire         clk_sys,
    input  wire         rst_sync_n,
    input  wire         zeroize,
    input  wire [34:0]  sha_ctl,        // Dari hmac_kdf
    output wire [255:0] digest,         // Ke hmac_kdf
    output reg          sha_ready
);

    wire        sha_init  = sha_ctl[34];
    wire        sha_next  = sha_ctl[33]; // Write word into W[0..15]
    wire        sha_start = sha_ctl[32]; // Start 64 rounds
    wire [31:0] block_in  = sha_ctl[31:0];

    // --- State Variables H0 to H7 ---
    reg [31:0] H [0:7];
    reg [31:0] a, b, c, d, e, f, g, h;

    // --- Message Schedule Memory (16 x 32-bit circular/shift buffer) ---
    reg [31:0] w_mem [0:15];
    reg [3:0]  w_wr_ptr;

    // --- Control FSM & Round Counter ---
    reg [5:0] round_cnt;
    reg       busy;

    // Standard SHA-256 initial constants
    localparam [31:0] H0_INIT = 32'h6a09e667;
    localparam [31:0] H1_INIT = 32'hbb67ae85;
    localparam [31:0] H2_INIT = 32'h3c6ef372;
    localparam [31:0] H3_INIT = 32'ha54ff53a;
    localparam [31:0] H4_INIT = 32'h510e527f;
    localparam [31:0] H5_INIT = 32'h9b05688c;
    localparam [31:0] H6_INIT = 32'h1f83d9ab;
    localparam [31:0] H7_INIT = 32'h5be0cd19;

    // Output digest concatenation
    assign digest = {H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]};

    // --- Bitwise Right Rotation / Shift Helper Functions ---
    function [31:0] ror;
        input [31:0] value;
        input [4:0]  shift;
        begin
            ror = (value >> shift) | (value << (32 - shift));
        end
    endfunction

    // --- Non-linear & Diffusion Functions ---
    wire [31:0] ch_out  = (e & f) ^ (~e & g);
    wire [31:0] maj_out = (a & b) ^ (a & c) ^ (b & c);
    wire [31:0] sum0    = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    wire [31:0] sum1    = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    
    // Sigma functions for message schedule expansion
    wire [31:0] sig0 = ror(w_mem[1], 7)  ^ ror(w_mem[1], 18)  ^ (w_mem[1] >> 3);
    wire [31:0] sig1 = ror(w_mem[14], 17) ^ ror(w_mem[14], 19) ^ (w_mem[14] >> 10);

    // Current word Wt selection
    wire [31:0] w_new = w_mem[0] + sig0 + w_mem[9] + sig1;
    wire [31:0] w_curr = (round_cnt < 16) ? w_mem[round_cnt[3:0]] : w_new;

    // 64-Round Constants K[t]
    reg [31:0] k_curr;
    always @(*) begin
        case (round_cnt)
            6'd0:  k_curr = 32'h428a2f98; 6'd1:  k_curr = 32'h71374491;
            6'd2:  k_curr = 32'hb5c0fbcf; 6'd3:  k_curr = 32'he9b5dba5;
            6'd4:  k_curr = 32'h3956c25b; 6'd5:  k_curr = 32'h59f111f1;
            6'd6:  k_curr = 32'h923f82a4; 6'd7:  k_curr = 32'hab1c5ed5;
            6'd8:  k_curr = 32'hd807aa98; 6'd9:  k_curr = 32'h12835b01;
            6'd10: k_curr = 32'h243185be; 6'd11: k_curr = 32'h550c7dc3;
            6'd12: k_curr = 32'h72be5d74; 6'd13: k_curr = 32'h80deb1fe;
            6'd14: k_curr = 32'h9bdc06a7; 6'd15: k_curr = 32'hc19bf174;
            6'd16: k_curr = 32'he49b69c1; 6'd17: k_curr = 32'hefbe4786;
            6'd18: k_curr = 32'h0fc19dc6; 6'd19: k_curr = 32'h240ca1cc;
            6'd20: k_curr = 32'h2de92c6f; 6'd21: k_curr = 32'h4a7484aa;
            6'd22: k_curr = 32'h5cb0a9dc; 6'd23: k_curr = 32'h76f988da;
            6'd24: k_curr = 32'h983e5152; 6'd25: k_curr = 32'ha831c66d;
            6'd26: k_curr = 32'hb00327c8; 6'd27: k_curr = 32'hbf597fc7;
            6'd28: k_curr = 32'hc6e00bf3; 6'd29: k_curr = 32'hd5a79147;
            6'd30: k_curr = 32'h06ca6351; 6'd31: k_curr = 32'h14292967;
            6'd32: k_curr = 32'h27b70a85; 6'd33: k_curr = 32'h2e1b2138;
            6'd34: k_curr = 32'h4d2c6dfc; 6'd35: k_curr = 32'h53380d13;
            6'd36: k_curr = 32'h650a7354; 6'd37: k_curr = 32'h766a0abb;
            6'd38: k_curr = 32'h81c2c92e; 6'd39: k_curr = 32'h92722c85;
            6'd40: k_curr = 32'ha2bfe8a1; 6'd41: k_curr = 32'ha81a664b;
            6'd42: k_curr = 32'hc24b8b70; 6'd43: k_curr = 32'hc76c51a3;
            6'd44: k_curr = 32'hd192e819; 6'd45: k_curr = 32'hd6990624;
            6'd46: k_curr = 32'hf40e3585; 6'd47: k_curr = 32'h106aa070;
            6'd48: k_curr = 32'h19a4c116; 6'd49: k_curr = 32'h1e376c08;
            6'd50: k_curr = 32'h2748774c; 6'd51: k_curr = 32'h34b0bcb5;
            6'd52: k_curr = 32'h391c0cb3; 6'd53: k_curr = 32'h4ed8aa4a;
            6'd54: k_curr = 32'h5b9cca4f; 6'd55: k_curr = 32'h682e6ff3;
            6'd56: k_curr = 32'h748f82ee; 6'd57: k_curr = 32'h78a5636f;
            6'd58: k_curr = 32'h84c87814; 6'd59: k_curr = 32'h8cc70208;
            6'd60: k_curr = 32'h90befffa; 6'd61: k_curr = 32'ha4506ceb;
            6'd62: k_curr = 32'hbef9a3f7; 6'd63: k_curr = 32'hc67178f2;
        endcase
    end

    // Intermediate Compression Sums (T1 & T2)
    wire [31:0] t1 = h + sum1 + ch_out + k_curr + w_curr;
    wire [31:0] t2 = sum0 + maj_out;

    integer i;

    // --- Main Cryptographic State Machine ---
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            H[0] <= H0_INIT; H[1] <= H1_INIT; H[2] <= H2_INIT; H[3] <= H3_INIT;
            H[4] <= H4_INIT; H[5] <= H5_INIT; H[6] <= H6_INIT; H[7] <= H7_INIT;
            a <= 32'd0; b <= 32'd0; c <= 32'd0; d <= 32'd0;
            e <= 32'd0; f <= 32'd0; g <= 32'd0; h <= 32'd0;
            w_wr_ptr  <= 4'd0;
            round_cnt <= 6'd0;
            busy      <= 1'b0;
            sha_ready <= 1'b1;
            for (i = 0; i < 16; i = i + 1) w_mem[i] <= 32'd0;
        end else if (zeroize) begin
            // Instant Hardware Wipe
            H[0] <= 32'd0; H[1] <= 32'd0; H[2] <= 32'd0; H[3] <= 32'd0;
            H[4] <= 32'd0; H[5] <= 32'd0; H[6] <= 32'd0; H[7] <= 32'd0;
            a <= 32'd0; b <= 32'd0; c <= 32'd0; d <= 32'd0;
            e <= 32'd0; f <= 32'd0; g <= 32'd0; h <= 32'd0;
            w_wr_ptr  <= 4'd0;
            round_cnt <= 6'd0;
            busy      <= 1'b0;
            sha_ready <= 1'b0;
            for (i = 0; i < 16; i = i + 1) w_mem[i] <= 32'd0;
        end else begin
            // 1. Initialize State Constants
            if (sha_init && !busy) begin
                H[0] <= H0_INIT; H[1] <= H1_INIT; H[2] <= H2_INIT; H[3] <= H3_INIT;
                H[4] <= H4_INIT; H[5] <= H5_INIT; H[6] <= H6_INIT; H[7] <= H7_INIT;
                w_wr_ptr  <= 4'd0;
                sha_ready <= 1'b1;
                busy      <= 1'b0;
            end
            
            // 2. Stream Data Word into Block Buffer W[0..15]
            if (sha_next && !busy) begin
                w_mem[w_wr_ptr] <= block_in;
                w_wr_ptr        <= w_wr_ptr + 1'b1;
            end

            // 3. Trigger 64-Round Compression Cycle
            if (sha_start && !busy) begin
                busy      <= 1'b1;
                sha_ready <= 1'b0;
                round_cnt <= 6'd0;
                // Load working variables from current state
                a <= H[0]; b <= H[1]; c <= H[2]; d <= H[3];
                e <= H[4]; f <= H[5]; g <= H[6]; h <= H[7];
            end else if (busy) begin
                // Execute one compression round per clock (rounds 0..63)
                h <= g;
                g <= f;
                f <= e;
                e <= d + t1;
                d <= c;
                c <= b;
                b <= a;
                a <= t1 + t2;

                // Shift the message schedule window from round 16 onward.
                // At round t (t >= 16) w_mem holds W[t-16..t-1], so w_new = W[t].
                if (round_cnt >= 6'd16) begin
                    for (i = 0; i < 15; i = i + 1) begin
                        w_mem[i] <= w_mem[i+1];
                    end
                    w_mem[15] <= w_new;
                end

                if (round_cnt == 6'd63) begin
                    // Final round (63): fold the NEW working variables into H0-H7
                    // (the registers a..h only get these values on the next edge)
                    H[0] <= H[0] + (t1 + t2);
                    H[1] <= H[1] + a;
                    H[2] <= H[2] + b;
                    H[3] <= H[3] + c;
                    H[4] <= H[4] + (d + t1);
                    H[5] <= H[5] + e;
                    H[6] <= H[6] + f;
                    H[7] <= H[7] + g;

                    busy      <= 1'b0;
                    sha_ready <= 1'b1;
                    w_wr_ptr  <= 4'd0;
                end else begin
                    round_cnt <= round_cnt + 1'b1;
                end
            end
        end
    end

endmodule