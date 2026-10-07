`timescale 1ns/1ps
module tb_aes;
reg clk=0, rst=0, z=0; always #10 clk=~clk;
reg [45:0] req=0; wire [31:0] rd; reg [127:0] key=0, wk=0;
aes128_sm dut(.clk_sys(clk),.rst_sync_n(rst),.zeroize(z),.req(req),.rdata(rd),.key_in(key),.wrap_key(wk));
integer errors=0, cyc;
task wr(input [7:0] a, input [31:0] d); begin @(posedge clk); #1 req={4'h1,a,d,1'b1,1'b0}; @(posedge clk); #1 req=0; end endtask
task rdd(input [7:0] a, output [31:0] d); begin @(posedge clk); #1 req={4'h1,a,32'd0,1'b0,1'b1}; @(posedge clk); #1 req=0; d=rd; end endtask
task blk(input [127:0] x, input [3:0] ctrl, output [127:0] y);
  reg [31:0] a,b,c,d,s; begin
  if (!ctrl[2]) begin wr(8'h10,x[127:96]); wr(8'h14,x[95:64]); wr(8'h18,x[63:32]); wr(8'h1C,x[31:0]); end
  wr(8'h00,{28'd0,ctrl}); cyc=0; s=1;
  while (s[0]) begin rdd(8'h04,s); cyc=cyc+2; end
  rdd(8'h30,a); rdd(8'h34,b); rdd(8'h38,c); rdd(8'h3C,d); y={a,b,c,d}; end endtask
task setiv(input [127:0] v); begin wr(8'h20,v[127:96]); wr(8'h24,v[95:64]); wr(8'h28,v[63:32]); wr(8'h2C,v[31:0]); end endtask
task check(input ok, input [8*60-1:0] m); begin if (ok) $display("[LULUS] %0s",m); else begin $display("[GAGAL] %0s",m); errors=errors+1; end end endtask
reg [127:0] y, y2;
initial begin
 #50 rst=1;
 key=128'h000102030405060708090a0b0c0d0e0f;
 blk(128'h00112233445566778899aabbccddeeff, 4'b0001, y);
 check(y==128'h69c4e0d86a7b0430d8cdb78070b4c55a, "1. FIPS-197 C.1 enkripsi");
 blk(y, 4'b0011, y2);
 check(y2==128'h00112233445566778899aabbccddeeff, "2. FIPS-197 C.1 dekripsi");
 key=128'h2b7e151628aed2a6abf7158809cf4f3c;
 blk(128'h3243f6a8885a308d313198a2e0370734, 4'b0001, y);
 check(y==128'h3925841d02dc09fbdc118597196a0b32, "3. FIPS-197 Appendix B");
 // SP 800-38A F.2.1 CBC-AES128.Encrypt
 setiv(128'h000102030405060708090a0b0c0d0e0f);
 blk(128'h6bc1bee22e409f96e93d7e117393172a, 4'b1001, y);
 blk(128'hae2d8a571e03ac9c9eb76fac45af8e51, 4'b1001, y2);
 check(y==128'h7649abac8119b246cee98e9b12e9197d && y2==128'h5086cb9b507219ee95db113a917678b2, "4. SP 800-38A CBC enkripsi (2 blok)");
 setiv(128'h000102030405060708090a0b0c0d0e0f);
 blk(128'h7649abac8119b246cee98e9b12e9197d, 4'b1011, y);
 blk(128'h5086cb9b507219ee95db113a917678b2, 4'b1011, y2);
 check(y==128'h6bc1bee22e409f96e93d7e117393172a && y2==128'hae2d8a571e03ac9c9eb76fac45af8e51, "5. SP 800-38A CBC dekripsi (2 blok)");
 key=128'h000102030405060708090a0b0c0d0e0f; wk=128'h00112233445566778899aabbccddeeff;
 blk(128'd0, 4'b0101, y);
 check(y==128'h69c4e0d86a7b0430d8cdb78070b4c55a && dut.din==128'd0, "6. WRAP: DIN dari wrap_key, lalu dihapus");
 check(dut.rk==0 && dut.key0==0 && dut.st==0, "7. Kunci dan state dihapus setelah blok");
 $display("        (siklus polling enkripsi terakhir ~%0d)", cyc);
 if (errors==0) $display("\n=== SEMUA TES LULUS ==="); else $display("\n=== %0d TES GAGAL ===",errors);
 $finish;
end
endmodule