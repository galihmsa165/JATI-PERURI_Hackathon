// Modul: dg_memory
// Deskripsi: BRAM Data Groups dengan proteksi write-lock via we_en
// Alamat bus: 0x3XX (addr[11:8] == 4'h3) -> 256 kata x 32 bit (1 KB)

module dg_memory (
    input  wire        clk_sys,
    input  wire [45:0] req,             // {addr[11:0], wdata[31:0], we, re}
    input  wire        we_en,           // Enable write dari modul lifecycle
    output reg  [31:0] rdata
);

    // Parsing struktur paket bus
    wire [11:0] addr  = req[45:34];
    wire [31:0] wdata = req[33:2];
    wire        we    = req[1];
    wire        re    = req[0];

    // Address decode: only respond to the 0x3XX window. Without this, writes
    // to other slaves (e.g. lifecycle at 0x400) were also stored here.
    wire sel = (addr[11:8] == 4'h3);

    // RAM 256 kata x 32 bit target Altera M10K BRAM
    // (a 0x3XX window only has 8 usable address bits; widen the bus address
    //  map if the full 16 KB is needed)
    (* ramstyle = "M10K" *) reg [31:0] mem [0:255];

    // Initial contents = 0 (supported by Altera M10K and avoids X in simulation)
    integer n;
    initial begin
        for (n = 0; n < 256; n = n + 1)
            mem[n] = 32'd0;
    end

    // Logika baca dan tulis sinkron
    always @(posedge clk_sys) begin
        if (we && we_en && sel) begin
            mem[addr[7:0]] <= wdata;
        end
        if (re && sel) begin
            rdata <= mem[addr[7:0]];
        end
    end

endmodule