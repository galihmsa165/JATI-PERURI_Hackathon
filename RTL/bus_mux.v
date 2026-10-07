module bus_mux (
    input  wire         clk_sys,
    input  wire [45:0]  m_req,
    output reg  [31:0]  m_rdata,
    output wire [45:0]  s_req,
    input  wire [191:0] s_rdata
);
    assign s_req = m_req;
    reg [3:0] sel_q;
    always @(posedge clk_sys)
        if (m_req[0]) sel_q <= m_req[45:42];   // latch slave select on read

    always @(*) case (sel_q)
        4'h0: m_rdata = s_rdata[31:0];
        4'h1: m_rdata = s_rdata[63:32];
        4'h2: m_rdata = s_rdata[95:64];
        4'h3: m_rdata = s_rdata[127:96];
        4'h4: m_rdata = s_rdata[159:128];
        4'h5: m_rdata = s_rdata[191:160];
        default: m_rdata = 32'h0;
    endcase
endmodule