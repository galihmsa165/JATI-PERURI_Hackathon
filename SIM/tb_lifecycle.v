// =============================================================================
// Testbench lifecycle yang diperkeras (A2, A15)
// =============================================================================
`timescale 1ns/1ps
module tb_lifecycle;
    reg clk = 0, rst = 0, z = 0;
    always #10 clk = ~clk;
    reg  [45:0] req = 0;
    reg  [7:0]  nv = 0;
    reg         nv_v = 0;
    wire [31:0] rd;
    wire        we_en, el, flt;
    wire [3:0]  led;
    integer errors = 0;
    reg [31:0] v;

    lifecycle dut (.clk_sys(clk), .rst_sync_n(rst), .zeroize(z), .req(req), .tamper_cause(3'b000),
                   .lc_nv(nv), .lc_nv_valid(nv_v), .rdata(rd), .we_en(we_en),
                   .ever_locked(el), .lc_fault(flt), .led(led));

    task wr(input [1:0] s); begin @(posedge clk); #1 req = {4'h4, 8'h00, 30'd0, s, 1'b1, 1'b0}; @(posedge clk); #1 req = 0; end endtask
    task rdd(output [31:0] d); begin @(posedge clk); #1 req = {4'h4, 8'h00, 32'd0, 1'b0, 1'b1}; @(posedge clk); #1 req = 0; d = rd; end endtask
    task do_reset; begin rst = 0; repeat (3) @(posedge clk); #1 rst = 1; repeat (3) @(posedge clk); #1; end endtask
    task check(input ok, input [8*64-1:0] m);
        begin if (ok) $display("[LULUS] %0s", m); else begin $display("[GAGAL] %0s", m); errors = errors + 1; end end
    endtask

    initial begin
        do_reset();
        rdd(v);
        check(v[1:0] == 2'b00 && el === 1'b0 && we_en === 1'b0, "1. Reset: BLANK, belum pernah LOCKED");
        wr(2'b01); rdd(v);
        check(v[1:0] == 2'b01 && we_en === 1'b1, "2. BLANK -> PERSO, memori bisa ditulis");
        wr(2'b00); rdd(v);
        check(v[1:0] == 2'b01, "3. Tidak bisa mundur ke BLANK");
        wr(2'b10); rdd(v);
        check(v[1:0] == 2'b10 && el === 1'b1 && we_en === 1'b0 && v[5] === 1'b1, "4. PERSO -> LOCKED, ever_locked menyala");

        // Fault: 1 bit status LOCKED (0x4B) dibalik menjadi BLANK-ish
        @(posedge clk); #1 force dut.st = 8'h4A;
        @(posedge clk); #1 release dut.st;
        repeat (3) @(posedge clk); rdd(v);
        check(flt === 1'b1 && v[1:0] == 2'b11 && v[6] === 1'b1, "5. Bit status dibalik: lc_fault, dipaksa TERMINATED");

        do_reset();
        wr(2'b01);
        @(posedge clk); #1 force dut.el = 8'h5B;            // pola ever_locked rusak
        @(posedge clk); #1 release dut.el;
        repeat (3) @(posedge clk); rdd(v);
        check(flt === 1'b1 && we_en === 1'b0, "6. Pola ever_locked rusak: fault, tulis memori mati");

        // A15: status dimuat dari OTP saat reset
        nv = 8'h4B; nv_v = 1;
        do_reset(); rdd(v);
        check(v[1:0] == 2'b10 && el === 1'b1 && we_en === 1'b0, "7. OTP berisi LOCKED: chip langsung LOCKED setelah reset");
        wr(2'b01); rdd(v);
        check(v[1:0] == 2'b10, "8. Dari OTP LOCKED tidak bisa kembali ke PERSO");
        nv_v = 0;

        do_reset(); wr(2'b01);
        @(posedge clk); #1 z = 1; @(posedge clk); #1 z = 0; rdd(v);
        check(v[1:0] == 2'b11 && led == 4'b1000, "9. Zeroize: TERMINATED permanen");

        if (errors == 0) $display("\n=== SEMUA TES LULUS ==="); else $display("\n=== %0d TES GAGAL ===", errors);
        $finish;
    end
endmodule