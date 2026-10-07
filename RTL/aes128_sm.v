// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : aes128_sm   (revisi optimasi B1: datapath 32 bit)
// Fungsi  : AES-128 (FIPS-197) untuk secure messaging, ECB/CBC, enkripsi dan
//           dekripsi, plus mode WRAP untuk membungkus K_CA dengan K_T.
// Alamat bus: ID 1 (addr[11:8] == 4'h1), slave 1 pada bus_mux (s_rdata[63:32])
//
// OPTIMASI UKURAN (dibanding versi 1 putaran per siklus):
//   - Datapath 32 bit: satu KOLOM per siklus, sehingga hanya butuh 4 S-box
//     enkripsi + 4 S-box dekripsi (versi lama: 16 + 16 S-box paralel + 4
//     S-box penjadwal kunci).
//   - Penjadwalan kunci on-the-fly: hanya 1 round key yang disimpan
//     (versi lama menyimpan 11 round key = 1.408 flip-flop). S-box penjadwal
//     kunci memakai 4 S-box yang sama dengan datapath enkripsi.
//   - Waktu: enkripsi ~52 siklus, dekripsi ~62 siklus per blok (versi lama
//     ~24). Tidak terasa di sistem: 1 jawaban UART 40 byte = ~175.000 siklus.
//
// Register (tidak berubah dari versi sebelumnya, FSM tidak perlu diubah):
//   0x00 CTRL  (W): bit0 START, bit1 DECRYPT, bit2 WRAP (DIN = wrap_key,
//                   kunci = key_in), bit3 CBC.  (R): {cbc, wrap, decrypt, 0}
//   0x04 STATUS(R): bit0 busy, bit1 done (sticky, bersih saat START)
//   0x10..0x1C DIN (W), 0x20..0x2C IV (R/W), 0x30..0x3C DOUT (R, 0 saat busy)
//   Word 0 = MSB = byte pertama (urutan FIPS-197).
// Keamanan: kunci di-latch saat START; round key, kunci, state, dan DIN mode
//   WRAP dihapus setelah setiap blok; zeroize menghapus semuanya.
// =============================================================================

module aes128_sm (
    input  wire         clk_sys,
    input  wire         rst_sync_n,
    input  wire         zeroize,
    input  wire [45:0]  req,
    output reg  [31:0]  rdata,
    input  wire [127:0] key_in,
    input  wire [127:0] wrap_key
);

    wire [11:0] addr  = req[45:34];
    wire [31:0] wdata = req[33:2];
    wire        sel   = (addr[11:8] == 4'h1);
    wire        we    = req[1] && sel;
    wire        re    = req[0] && sel;
    wire [7:0]  a8    = addr[7:0];

    localparam [2:0] S_IDLE = 3'd0, S_KEXP = 3'd1, S_INIT = 3'd2, S_KEY = 3'd3,
                     S_COL  = 3'd4, S_FIN  = 3'd5;

    reg [2:0]   state;
    reg [127:0] din, iv, dout;
    reg [127:0] key0, rk, st, ns;
    reg         cfg_dec, cfg_wrap, cfg_cbc;
    reg [3:0]   round;      // enkripsi: 1..10, dekripsi: 9..0 (+ ekspansi 1..10)
    reg [1:0]   col;
    reg         busy, done;

    // =========================================================================
    // Tabel S-box dan aritmetika GF(2^8)
    // =========================================================================
    function [7:0] sbox;
        input [7:0] x;
        begin
            case (x)
                8'h00: sbox = 8'h63;
                8'h01: sbox = 8'h7c;
                8'h02: sbox = 8'h77;
                8'h03: sbox = 8'h7b;
                8'h04: sbox = 8'hf2;
                8'h05: sbox = 8'h6b;
                8'h06: sbox = 8'h6f;
                8'h07: sbox = 8'hc5;
                8'h08: sbox = 8'h30;
                8'h09: sbox = 8'h01;
                8'h0a: sbox = 8'h67;
                8'h0b: sbox = 8'h2b;
                8'h0c: sbox = 8'hfe;
                8'h0d: sbox = 8'hd7;
                8'h0e: sbox = 8'hab;
                8'h0f: sbox = 8'h76;
                8'h10: sbox = 8'hca;
                8'h11: sbox = 8'h82;
                8'h12: sbox = 8'hc9;
                8'h13: sbox = 8'h7d;
                8'h14: sbox = 8'hfa;
                8'h15: sbox = 8'h59;
                8'h16: sbox = 8'h47;
                8'h17: sbox = 8'hf0;
                8'h18: sbox = 8'had;
                8'h19: sbox = 8'hd4;
                8'h1a: sbox = 8'ha2;
                8'h1b: sbox = 8'haf;
                8'h1c: sbox = 8'h9c;
                8'h1d: sbox = 8'ha4;
                8'h1e: sbox = 8'h72;
                8'h1f: sbox = 8'hc0;
                8'h20: sbox = 8'hb7;
                8'h21: sbox = 8'hfd;
                8'h22: sbox = 8'h93;
                8'h23: sbox = 8'h26;
                8'h24: sbox = 8'h36;
                8'h25: sbox = 8'h3f;
                8'h26: sbox = 8'hf7;
                8'h27: sbox = 8'hcc;
                8'h28: sbox = 8'h34;
                8'h29: sbox = 8'ha5;
                8'h2a: sbox = 8'he5;
                8'h2b: sbox = 8'hf1;
                8'h2c: sbox = 8'h71;
                8'h2d: sbox = 8'hd8;
                8'h2e: sbox = 8'h31;
                8'h2f: sbox = 8'h15;
                8'h30: sbox = 8'h04;
                8'h31: sbox = 8'hc7;
                8'h32: sbox = 8'h23;
                8'h33: sbox = 8'hc3;
                8'h34: sbox = 8'h18;
                8'h35: sbox = 8'h96;
                8'h36: sbox = 8'h05;
                8'h37: sbox = 8'h9a;
                8'h38: sbox = 8'h07;
                8'h39: sbox = 8'h12;
                8'h3a: sbox = 8'h80;
                8'h3b: sbox = 8'he2;
                8'h3c: sbox = 8'heb;
                8'h3d: sbox = 8'h27;
                8'h3e: sbox = 8'hb2;
                8'h3f: sbox = 8'h75;
                8'h40: sbox = 8'h09;
                8'h41: sbox = 8'h83;
                8'h42: sbox = 8'h2c;
                8'h43: sbox = 8'h1a;
                8'h44: sbox = 8'h1b;
                8'h45: sbox = 8'h6e;
                8'h46: sbox = 8'h5a;
                8'h47: sbox = 8'ha0;
                8'h48: sbox = 8'h52;
                8'h49: sbox = 8'h3b;
                8'h4a: sbox = 8'hd6;
                8'h4b: sbox = 8'hb3;
                8'h4c: sbox = 8'h29;
                8'h4d: sbox = 8'he3;
                8'h4e: sbox = 8'h2f;
                8'h4f: sbox = 8'h84;
                8'h50: sbox = 8'h53;
                8'h51: sbox = 8'hd1;
                8'h52: sbox = 8'h00;
                8'h53: sbox = 8'hed;
                8'h54: sbox = 8'h20;
                8'h55: sbox = 8'hfc;
                8'h56: sbox = 8'hb1;
                8'h57: sbox = 8'h5b;
                8'h58: sbox = 8'h6a;
                8'h59: sbox = 8'hcb;
                8'h5a: sbox = 8'hbe;
                8'h5b: sbox = 8'h39;
                8'h5c: sbox = 8'h4a;
                8'h5d: sbox = 8'h4c;
                8'h5e: sbox = 8'h58;
                8'h5f: sbox = 8'hcf;
                8'h60: sbox = 8'hd0;
                8'h61: sbox = 8'hef;
                8'h62: sbox = 8'haa;
                8'h63: sbox = 8'hfb;
                8'h64: sbox = 8'h43;
                8'h65: sbox = 8'h4d;
                8'h66: sbox = 8'h33;
                8'h67: sbox = 8'h85;
                8'h68: sbox = 8'h45;
                8'h69: sbox = 8'hf9;
                8'h6a: sbox = 8'h02;
                8'h6b: sbox = 8'h7f;
                8'h6c: sbox = 8'h50;
                8'h6d: sbox = 8'h3c;
                8'h6e: sbox = 8'h9f;
                8'h6f: sbox = 8'ha8;
                8'h70: sbox = 8'h51;
                8'h71: sbox = 8'ha3;
                8'h72: sbox = 8'h40;
                8'h73: sbox = 8'h8f;
                8'h74: sbox = 8'h92;
                8'h75: sbox = 8'h9d;
                8'h76: sbox = 8'h38;
                8'h77: sbox = 8'hf5;
                8'h78: sbox = 8'hbc;
                8'h79: sbox = 8'hb6;
                8'h7a: sbox = 8'hda;
                8'h7b: sbox = 8'h21;
                8'h7c: sbox = 8'h10;
                8'h7d: sbox = 8'hff;
                8'h7e: sbox = 8'hf3;
                8'h7f: sbox = 8'hd2;
                8'h80: sbox = 8'hcd;
                8'h81: sbox = 8'h0c;
                8'h82: sbox = 8'h13;
                8'h83: sbox = 8'hec;
                8'h84: sbox = 8'h5f;
                8'h85: sbox = 8'h97;
                8'h86: sbox = 8'h44;
                8'h87: sbox = 8'h17;
                8'h88: sbox = 8'hc4;
                8'h89: sbox = 8'ha7;
                8'h8a: sbox = 8'h7e;
                8'h8b: sbox = 8'h3d;
                8'h8c: sbox = 8'h64;
                8'h8d: sbox = 8'h5d;
                8'h8e: sbox = 8'h19;
                8'h8f: sbox = 8'h73;
                8'h90: sbox = 8'h60;
                8'h91: sbox = 8'h81;
                8'h92: sbox = 8'h4f;
                8'h93: sbox = 8'hdc;
                8'h94: sbox = 8'h22;
                8'h95: sbox = 8'h2a;
                8'h96: sbox = 8'h90;
                8'h97: sbox = 8'h88;
                8'h98: sbox = 8'h46;
                8'h99: sbox = 8'hee;
                8'h9a: sbox = 8'hb8;
                8'h9b: sbox = 8'h14;
                8'h9c: sbox = 8'hde;
                8'h9d: sbox = 8'h5e;
                8'h9e: sbox = 8'h0b;
                8'h9f: sbox = 8'hdb;
                8'ha0: sbox = 8'he0;
                8'ha1: sbox = 8'h32;
                8'ha2: sbox = 8'h3a;
                8'ha3: sbox = 8'h0a;
                8'ha4: sbox = 8'h49;
                8'ha5: sbox = 8'h06;
                8'ha6: sbox = 8'h24;
                8'ha7: sbox = 8'h5c;
                8'ha8: sbox = 8'hc2;
                8'ha9: sbox = 8'hd3;
                8'haa: sbox = 8'hac;
                8'hab: sbox = 8'h62;
                8'hac: sbox = 8'h91;
                8'had: sbox = 8'h95;
                8'hae: sbox = 8'he4;
                8'haf: sbox = 8'h79;
                8'hb0: sbox = 8'he7;
                8'hb1: sbox = 8'hc8;
                8'hb2: sbox = 8'h37;
                8'hb3: sbox = 8'h6d;
                8'hb4: sbox = 8'h8d;
                8'hb5: sbox = 8'hd5;
                8'hb6: sbox = 8'h4e;
                8'hb7: sbox = 8'ha9;
                8'hb8: sbox = 8'h6c;
                8'hb9: sbox = 8'h56;
                8'hba: sbox = 8'hf4;
                8'hbb: sbox = 8'hea;
                8'hbc: sbox = 8'h65;
                8'hbd: sbox = 8'h7a;
                8'hbe: sbox = 8'hae;
                8'hbf: sbox = 8'h08;
                8'hc0: sbox = 8'hba;
                8'hc1: sbox = 8'h78;
                8'hc2: sbox = 8'h25;
                8'hc3: sbox = 8'h2e;
                8'hc4: sbox = 8'h1c;
                8'hc5: sbox = 8'ha6;
                8'hc6: sbox = 8'hb4;
                8'hc7: sbox = 8'hc6;
                8'hc8: sbox = 8'he8;
                8'hc9: sbox = 8'hdd;
                8'hca: sbox = 8'h74;
                8'hcb: sbox = 8'h1f;
                8'hcc: sbox = 8'h4b;
                8'hcd: sbox = 8'hbd;
                8'hce: sbox = 8'h8b;
                8'hcf: sbox = 8'h8a;
                8'hd0: sbox = 8'h70;
                8'hd1: sbox = 8'h3e;
                8'hd2: sbox = 8'hb5;
                8'hd3: sbox = 8'h66;
                8'hd4: sbox = 8'h48;
                8'hd5: sbox = 8'h03;
                8'hd6: sbox = 8'hf6;
                8'hd7: sbox = 8'h0e;
                8'hd8: sbox = 8'h61;
                8'hd9: sbox = 8'h35;
                8'hda: sbox = 8'h57;
                8'hdb: sbox = 8'hb9;
                8'hdc: sbox = 8'h86;
                8'hdd: sbox = 8'hc1;
                8'hde: sbox = 8'h1d;
                8'hdf: sbox = 8'h9e;
                8'he0: sbox = 8'he1;
                8'he1: sbox = 8'hf8;
                8'he2: sbox = 8'h98;
                8'he3: sbox = 8'h11;
                8'he4: sbox = 8'h69;
                8'he5: sbox = 8'hd9;
                8'he6: sbox = 8'h8e;
                8'he7: sbox = 8'h94;
                8'he8: sbox = 8'h9b;
                8'he9: sbox = 8'h1e;
                8'hea: sbox = 8'h87;
                8'heb: sbox = 8'he9;
                8'hec: sbox = 8'hce;
                8'hed: sbox = 8'h55;
                8'hee: sbox = 8'h28;
                8'hef: sbox = 8'hdf;
                8'hf0: sbox = 8'h8c;
                8'hf1: sbox = 8'ha1;
                8'hf2: sbox = 8'h89;
                8'hf3: sbox = 8'h0d;
                8'hf4: sbox = 8'hbf;
                8'hf5: sbox = 8'he6;
                8'hf6: sbox = 8'h42;
                8'hf7: sbox = 8'h68;
                8'hf8: sbox = 8'h41;
                8'hf9: sbox = 8'h99;
                8'hfa: sbox = 8'h2d;
                8'hfb: sbox = 8'h0f;
                8'hfc: sbox = 8'hb0;
                8'hfd: sbox = 8'h54;
                8'hfe: sbox = 8'hbb;
                8'hff: sbox = 8'h16;
                default: sbox = 8'h00;
            endcase
        end
    endfunction

    // Inverse S-box (FIPS-197 Fig. 14)
    function [7:0] inv_sbox;
        input [7:0] x;
        begin
            case (x)
                8'h00: inv_sbox = 8'h52;
                8'h01: inv_sbox = 8'h09;
                8'h02: inv_sbox = 8'h6a;
                8'h03: inv_sbox = 8'hd5;
                8'h04: inv_sbox = 8'h30;
                8'h05: inv_sbox = 8'h36;
                8'h06: inv_sbox = 8'ha5;
                8'h07: inv_sbox = 8'h38;
                8'h08: inv_sbox = 8'hbf;
                8'h09: inv_sbox = 8'h40;
                8'h0a: inv_sbox = 8'ha3;
                8'h0b: inv_sbox = 8'h9e;
                8'h0c: inv_sbox = 8'h81;
                8'h0d: inv_sbox = 8'hf3;
                8'h0e: inv_sbox = 8'hd7;
                8'h0f: inv_sbox = 8'hfb;
                8'h10: inv_sbox = 8'h7c;
                8'h11: inv_sbox = 8'he3;
                8'h12: inv_sbox = 8'h39;
                8'h13: inv_sbox = 8'h82;
                8'h14: inv_sbox = 8'h9b;
                8'h15: inv_sbox = 8'h2f;
                8'h16: inv_sbox = 8'hff;
                8'h17: inv_sbox = 8'h87;
                8'h18: inv_sbox = 8'h34;
                8'h19: inv_sbox = 8'h8e;
                8'h1a: inv_sbox = 8'h43;
                8'h1b: inv_sbox = 8'h44;
                8'h1c: inv_sbox = 8'hc4;
                8'h1d: inv_sbox = 8'hde;
                8'h1e: inv_sbox = 8'he9;
                8'h1f: inv_sbox = 8'hcb;
                8'h20: inv_sbox = 8'h54;
                8'h21: inv_sbox = 8'h7b;
                8'h22: inv_sbox = 8'h94;
                8'h23: inv_sbox = 8'h32;
                8'h24: inv_sbox = 8'ha6;
                8'h25: inv_sbox = 8'hc2;
                8'h26: inv_sbox = 8'h23;
                8'h27: inv_sbox = 8'h3d;
                8'h28: inv_sbox = 8'hee;
                8'h29: inv_sbox = 8'h4c;
                8'h2a: inv_sbox = 8'h95;
                8'h2b: inv_sbox = 8'h0b;
                8'h2c: inv_sbox = 8'h42;
                8'h2d: inv_sbox = 8'hfa;
                8'h2e: inv_sbox = 8'hc3;
                8'h2f: inv_sbox = 8'h4e;
                8'h30: inv_sbox = 8'h08;
                8'h31: inv_sbox = 8'h2e;
                8'h32: inv_sbox = 8'ha1;
                8'h33: inv_sbox = 8'h66;
                8'h34: inv_sbox = 8'h28;
                8'h35: inv_sbox = 8'hd9;
                8'h36: inv_sbox = 8'h24;
                8'h37: inv_sbox = 8'hb2;
                8'h38: inv_sbox = 8'h76;
                8'h39: inv_sbox = 8'h5b;
                8'h3a: inv_sbox = 8'ha2;
                8'h3b: inv_sbox = 8'h49;
                8'h3c: inv_sbox = 8'h6d;
                8'h3d: inv_sbox = 8'h8b;
                8'h3e: inv_sbox = 8'hd1;
                8'h3f: inv_sbox = 8'h25;
                8'h40: inv_sbox = 8'h72;
                8'h41: inv_sbox = 8'hf8;
                8'h42: inv_sbox = 8'hf6;
                8'h43: inv_sbox = 8'h64;
                8'h44: inv_sbox = 8'h86;
                8'h45: inv_sbox = 8'h68;
                8'h46: inv_sbox = 8'h98;
                8'h47: inv_sbox = 8'h16;
                8'h48: inv_sbox = 8'hd4;
                8'h49: inv_sbox = 8'ha4;
                8'h4a: inv_sbox = 8'h5c;
                8'h4b: inv_sbox = 8'hcc;
                8'h4c: inv_sbox = 8'h5d;
                8'h4d: inv_sbox = 8'h65;
                8'h4e: inv_sbox = 8'hb6;
                8'h4f: inv_sbox = 8'h92;
                8'h50: inv_sbox = 8'h6c;
                8'h51: inv_sbox = 8'h70;
                8'h52: inv_sbox = 8'h48;
                8'h53: inv_sbox = 8'h50;
                8'h54: inv_sbox = 8'hfd;
                8'h55: inv_sbox = 8'hed;
                8'h56: inv_sbox = 8'hb9;
                8'h57: inv_sbox = 8'hda;
                8'h58: inv_sbox = 8'h5e;
                8'h59: inv_sbox = 8'h15;
                8'h5a: inv_sbox = 8'h46;
                8'h5b: inv_sbox = 8'h57;
                8'h5c: inv_sbox = 8'ha7;
                8'h5d: inv_sbox = 8'h8d;
                8'h5e: inv_sbox = 8'h9d;
                8'h5f: inv_sbox = 8'h84;
                8'h60: inv_sbox = 8'h90;
                8'h61: inv_sbox = 8'hd8;
                8'h62: inv_sbox = 8'hab;
                8'h63: inv_sbox = 8'h00;
                8'h64: inv_sbox = 8'h8c;
                8'h65: inv_sbox = 8'hbc;
                8'h66: inv_sbox = 8'hd3;
                8'h67: inv_sbox = 8'h0a;
                8'h68: inv_sbox = 8'hf7;
                8'h69: inv_sbox = 8'he4;
                8'h6a: inv_sbox = 8'h58;
                8'h6b: inv_sbox = 8'h05;
                8'h6c: inv_sbox = 8'hb8;
                8'h6d: inv_sbox = 8'hb3;
                8'h6e: inv_sbox = 8'h45;
                8'h6f: inv_sbox = 8'h06;
                8'h70: inv_sbox = 8'hd0;
                8'h71: inv_sbox = 8'h2c;
                8'h72: inv_sbox = 8'h1e;
                8'h73: inv_sbox = 8'h8f;
                8'h74: inv_sbox = 8'hca;
                8'h75: inv_sbox = 8'h3f;
                8'h76: inv_sbox = 8'h0f;
                8'h77: inv_sbox = 8'h02;
                8'h78: inv_sbox = 8'hc1;
                8'h79: inv_sbox = 8'haf;
                8'h7a: inv_sbox = 8'hbd;
                8'h7b: inv_sbox = 8'h03;
                8'h7c: inv_sbox = 8'h01;
                8'h7d: inv_sbox = 8'h13;
                8'h7e: inv_sbox = 8'h8a;
                8'h7f: inv_sbox = 8'h6b;
                8'h80: inv_sbox = 8'h3a;
                8'h81: inv_sbox = 8'h91;
                8'h82: inv_sbox = 8'h11;
                8'h83: inv_sbox = 8'h41;
                8'h84: inv_sbox = 8'h4f;
                8'h85: inv_sbox = 8'h67;
                8'h86: inv_sbox = 8'hdc;
                8'h87: inv_sbox = 8'hea;
                8'h88: inv_sbox = 8'h97;
                8'h89: inv_sbox = 8'hf2;
                8'h8a: inv_sbox = 8'hcf;
                8'h8b: inv_sbox = 8'hce;
                8'h8c: inv_sbox = 8'hf0;
                8'h8d: inv_sbox = 8'hb4;
                8'h8e: inv_sbox = 8'he6;
                8'h8f: inv_sbox = 8'h73;
                8'h90: inv_sbox = 8'h96;
                8'h91: inv_sbox = 8'hac;
                8'h92: inv_sbox = 8'h74;
                8'h93: inv_sbox = 8'h22;
                8'h94: inv_sbox = 8'he7;
                8'h95: inv_sbox = 8'had;
                8'h96: inv_sbox = 8'h35;
                8'h97: inv_sbox = 8'h85;
                8'h98: inv_sbox = 8'he2;
                8'h99: inv_sbox = 8'hf9;
                8'h9a: inv_sbox = 8'h37;
                8'h9b: inv_sbox = 8'he8;
                8'h9c: inv_sbox = 8'h1c;
                8'h9d: inv_sbox = 8'h75;
                8'h9e: inv_sbox = 8'hdf;
                8'h9f: inv_sbox = 8'h6e;
                8'ha0: inv_sbox = 8'h47;
                8'ha1: inv_sbox = 8'hf1;
                8'ha2: inv_sbox = 8'h1a;
                8'ha3: inv_sbox = 8'h71;
                8'ha4: inv_sbox = 8'h1d;
                8'ha5: inv_sbox = 8'h29;
                8'ha6: inv_sbox = 8'hc5;
                8'ha7: inv_sbox = 8'h89;
                8'ha8: inv_sbox = 8'h6f;
                8'ha9: inv_sbox = 8'hb7;
                8'haa: inv_sbox = 8'h62;
                8'hab: inv_sbox = 8'h0e;
                8'hac: inv_sbox = 8'haa;
                8'had: inv_sbox = 8'h18;
                8'hae: inv_sbox = 8'hbe;
                8'haf: inv_sbox = 8'h1b;
                8'hb0: inv_sbox = 8'hfc;
                8'hb1: inv_sbox = 8'h56;
                8'hb2: inv_sbox = 8'h3e;
                8'hb3: inv_sbox = 8'h4b;
                8'hb4: inv_sbox = 8'hc6;
                8'hb5: inv_sbox = 8'hd2;
                8'hb6: inv_sbox = 8'h79;
                8'hb7: inv_sbox = 8'h20;
                8'hb8: inv_sbox = 8'h9a;
                8'hb9: inv_sbox = 8'hdb;
                8'hba: inv_sbox = 8'hc0;
                8'hbb: inv_sbox = 8'hfe;
                8'hbc: inv_sbox = 8'h78;
                8'hbd: inv_sbox = 8'hcd;
                8'hbe: inv_sbox = 8'h5a;
                8'hbf: inv_sbox = 8'hf4;
                8'hc0: inv_sbox = 8'h1f;
                8'hc1: inv_sbox = 8'hdd;
                8'hc2: inv_sbox = 8'ha8;
                8'hc3: inv_sbox = 8'h33;
                8'hc4: inv_sbox = 8'h88;
                8'hc5: inv_sbox = 8'h07;
                8'hc6: inv_sbox = 8'hc7;
                8'hc7: inv_sbox = 8'h31;
                8'hc8: inv_sbox = 8'hb1;
                8'hc9: inv_sbox = 8'h12;
                8'hca: inv_sbox = 8'h10;
                8'hcb: inv_sbox = 8'h59;
                8'hcc: inv_sbox = 8'h27;
                8'hcd: inv_sbox = 8'h80;
                8'hce: inv_sbox = 8'hec;
                8'hcf: inv_sbox = 8'h5f;
                8'hd0: inv_sbox = 8'h60;
                8'hd1: inv_sbox = 8'h51;
                8'hd2: inv_sbox = 8'h7f;
                8'hd3: inv_sbox = 8'ha9;
                8'hd4: inv_sbox = 8'h19;
                8'hd5: inv_sbox = 8'hb5;
                8'hd6: inv_sbox = 8'h4a;
                8'hd7: inv_sbox = 8'h0d;
                8'hd8: inv_sbox = 8'h2d;
                8'hd9: inv_sbox = 8'he5;
                8'hda: inv_sbox = 8'h7a;
                8'hdb: inv_sbox = 8'h9f;
                8'hdc: inv_sbox = 8'h93;
                8'hdd: inv_sbox = 8'hc9;
                8'hde: inv_sbox = 8'h9c;
                8'hdf: inv_sbox = 8'hef;
                8'he0: inv_sbox = 8'ha0;
                8'he1: inv_sbox = 8'he0;
                8'he2: inv_sbox = 8'h3b;
                8'he3: inv_sbox = 8'h4d;
                8'he4: inv_sbox = 8'hae;
                8'he5: inv_sbox = 8'h2a;
                8'he6: inv_sbox = 8'hf5;
                8'he7: inv_sbox = 8'hb0;
                8'he8: inv_sbox = 8'hc8;
                8'he9: inv_sbox = 8'heb;
                8'hea: inv_sbox = 8'hbb;
                8'heb: inv_sbox = 8'h3c;
                8'hec: inv_sbox = 8'h83;
                8'hed: inv_sbox = 8'h53;
                8'hee: inv_sbox = 8'h99;
                8'hef: inv_sbox = 8'h61;
                8'hf0: inv_sbox = 8'h17;
                8'hf1: inv_sbox = 8'h2b;
                8'hf2: inv_sbox = 8'h04;
                8'hf3: inv_sbox = 8'h7e;
                8'hf4: inv_sbox = 8'hba;
                8'hf5: inv_sbox = 8'h77;
                8'hf6: inv_sbox = 8'hd6;
                8'hf7: inv_sbox = 8'h26;
                8'hf8: inv_sbox = 8'he1;
                8'hf9: inv_sbox = 8'h69;
                8'hfa: inv_sbox = 8'h14;
                8'hfb: inv_sbox = 8'h63;
                8'hfc: inv_sbox = 8'h55;
                8'hfd: inv_sbox = 8'h21;
                8'hfe: inv_sbox = 8'h0c;
                8'hff: inv_sbox = 8'h7d;
                default: inv_sbox = 8'h00;
            endcase
        end
    endfunction

    function [7:0] xtime;
        input [7:0] x;
        begin
            xtime = {x[6:0], 1'b0} ^ (x[7] ? 8'h1B : 8'h00);
        end
    endfunction

    function [7:0] mul9;
        input [7:0] x;
        reg [7:0] x2, x4, x8;
        begin
            x2 = xtime(x); x4 = xtime(x2); x8 = xtime(x4);
            mul9 = x8 ^ x;
        end
    endfunction

    function [7:0] mul11;
        input [7:0] x;
        reg [7:0] x2, x4, x8;
        begin
            x2 = xtime(x); x4 = xtime(x2); x8 = xtime(x4);
            mul11 = x8 ^ x2 ^ x;
        end
    endfunction

    function [7:0] mul13;
        input [7:0] x;
        reg [7:0] x2, x4, x8;
        begin
            x2 = xtime(x); x4 = xtime(x2); x8 = xtime(x4);
            mul13 = x8 ^ x4 ^ x;
        end
    endfunction

    function [7:0] mul14;
        input [7:0] x;
        reg [7:0] x2, x4, x8;
        begin
            x2 = xtime(x); x4 = xtime(x2); x8 = xtime(x4);
            mul14 = x8 ^ x4 ^ x2;
        end
    endfunction

    function [7:0] rcon_f;
        input [3:0] n;
        begin
            case (n)
                4'd1: rcon_f = 8'h01;  4'd2: rcon_f = 8'h02;  4'd3: rcon_f = 8'h04;
                4'd4: rcon_f = 8'h08;  4'd5: rcon_f = 8'h10;  4'd6: rcon_f = 8'h20;
                4'd7: rcon_f = 8'h40;  4'd8: rcon_f = 8'h80;  4'd9: rcon_f = 8'h1B;
                4'd10: rcon_f = 8'h36; default: rcon_f = 8'h00;
            endcase
        end
    endfunction

    // byte (baris r, kolom c) dari state 128 bit
    function [7:0] sb_at;
        input [127:0] s;
        input [1:0]   r;
        input [1:0]   c;
        begin
            sb_at = s[127 - 8*({2'b00, r} + 4*c) -: 8];
        end
    endfunction

    // =========================================================================
    // 4 S-box maju (dipakai bergantian: kolom enkripsi atau penjadwal kunci)
    // 4 S-box balik (kolom dekripsi)
    // =========================================================================
    wire [31:0] w3   = rk[31:0];
    wire [31:0] w_inv = rk[31:0] ^ rk[63:32];          // w3 lama = w7 ^ w6 (ekspansi balik)
    wire        key_phase = (state == S_KEY) || (state == S_KEXP);
    wire [31:0] kw   = (state == S_KEY && cfg_dec) ? w_inv : w3;
    wire [31:0] rotw = {kw[23:0], kw[31:24]};

    // Byte masukan kolom: enkripsi = ShiftRows, dekripsi = InvShiftRows
    wire [1:0] c0 = col, c1 = col + 2'd1, c2 = col + 2'd2, c3 = col + 2'd3;
    wire [1:0] d1 = col - 2'd1, d2 = col - 2'd2, d3 = col - 2'd3;

    wire [7:0] fin0 = key_phase ? rotw[31:24] : sb_at(st, 2'd0, c0);
    wire [7:0] fin1 = key_phase ? rotw[23:16] : sb_at(st, 2'd1, c1);
    wire [7:0] fin2 = key_phase ? rotw[15:8]  : sb_at(st, 2'd2, c2);
    wire [7:0] fin3 = key_phase ? rotw[7:0]   : sb_at(st, 2'd3, c3);
    wire [7:0] fo0 = sbox(fin0), fo1 = sbox(fin1), fo2 = sbox(fin2), fo3 = sbox(fin3);

    wire [7:0] io0 = inv_sbox(sb_at(st, 2'd0, c0));
    wire [7:0] io1 = inv_sbox(sb_at(st, 2'd1, d1));
    wire [7:0] io2 = inv_sbox(sb_at(st, 2'd2, d2));
    wire [7:0] io3 = inv_sbox(sb_at(st, 2'd3, d3));

    // ---- Penjadwal kunci ----
    wire [3:0]  rc_n  = (state == S_KEY && cfg_dec) ? (round + 4'd1) : round;
    wire [31:0] tword = {fo0 ^ rcon_f(rc_n), fo1, fo2, fo3};
    // maju: K_i -> K_(i+1)
    wire [31:0] n0 = rk[127:96] ^ tword;
    wire [31:0] n1 = rk[95:64]  ^ n0;
    wire [31:0] n2 = rk[63:32]  ^ n1;
    wire [31:0] n3 = rk[31:0]   ^ n2;
    wire [127:0] rk_next = {n0, n1, n2, n3};
    // balik: K_(i+1) -> K_i
    wire [31:0] p3 = rk[31:0]   ^ rk[63:32];
    wire [31:0] p2 = rk[63:32]  ^ rk[95:64];
    wire [31:0] p1 = rk[95:64]  ^ rk[127:96];
    wire [31:0] p0 = rk[127:96] ^ tword;
    wire [127:0] rk_prev = {p0, p1, p2, p3};

    // ---- Kolom enkripsi: SubBytes + ShiftRows + MixColumns + AddRoundKey ----
    wire        last_e = (round == 4'd10);
    wire [31:0] rkc    = rk[127 - 32*col -: 32];
    wire [7:0]  em0 = xtime(fo0) ^ (xtime(fo1) ^ fo1) ^ fo2 ^ fo3;
    wire [7:0]  em1 = fo0 ^ xtime(fo1) ^ (xtime(fo2) ^ fo2) ^ fo3;
    wire [7:0]  em2 = fo0 ^ fo1 ^ xtime(fo2) ^ (xtime(fo3) ^ fo3);
    wire [7:0]  em3 = (xtime(fo0) ^ fo0) ^ fo1 ^ fo2 ^ xtime(fo3);
    wire [31:0] ecol = (last_e ? {fo0, fo1, fo2, fo3} : {em0, em1, em2, em3}) ^ rkc;

    // ---- Kolom dekripsi: InvShiftRows + InvSubBytes + AddRoundKey + InvMixColumns ----
    wire        last_d = (round == 4'd0);
    wire [7:0]  a0 = io0 ^ rkc[31:24], a1 = io1 ^ rkc[23:16], a2 = io2 ^ rkc[15:8], a3 = io3 ^ rkc[7:0];
    wire [7:0]  dm0 = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
    wire [7:0]  dm1 = mul9(a0)  ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
    wire [7:0]  dm2 = mul13(a0) ^ mul9(a1)  ^ mul14(a2) ^ mul11(a3);
    wire [7:0]  dm3 = mul11(a0) ^ mul13(a1) ^ mul9(a2)  ^ mul14(a3);
    wire [31:0] dcol = last_d ? {a0, a1, a2, a3} : {dm0, dm1, dm2, dm3};

    wire [31:0] ncol = cfg_dec ? dcol : ecol;
    wire [127:0] ns_full = (col == 2'd3) ? {ns[127:32], ncol} : ns;   // kolom terakhir

    wire [127:0] blk_in = (cfg_cbc && !cfg_dec) ? (din ^ iv) : din;

    // =========================================================================
    // Kendali
    // =========================================================================
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            state <= S_IDLE; din <= 128'd0; iv <= 128'd0; dout <= 128'd0;
            key0 <= 128'd0; rk <= 128'd0; st <= 128'd0; ns <= 128'd0;
            cfg_dec <= 1'b0; cfg_wrap <= 1'b0; cfg_cbc <= 1'b0;
            round <= 4'd0; col <= 2'd0; busy <= 1'b0; done <= 1'b0;
        end else if (zeroize) begin
            state <= S_IDLE; din <= 128'd0; iv <= 128'd0; dout <= 128'd0;
            key0 <= 128'd0; rk <= 128'd0; st <= 128'd0; ns <= 128'd0;
            busy <= 1'b0; done <= 1'b0;
        end else begin
            case (state)
                S_IDLE: if (we) begin
                    if (a8 == 8'h00 && wdata[0]) begin
                        cfg_dec  <= wdata[1];
                        cfg_wrap <= wdata[2];
                        cfg_cbc  <= wdata[3];
                        key0     <= key_in;
                        rk       <= key_in;
                        if (wdata[2]) din <= wrap_key;
                        busy     <= 1'b1;
                        done     <= 1'b0;
                        round    <= 4'd1;
                        state    <= wdata[1] ? S_KEXP : S_INIT;
                    end
                    else if (a8[7:4] == 4'h1) din[127 - 32*a8[3:2] -: 32] <= wdata;
                    else if (a8[7:4] == 4'h2) iv [127 - 32*a8[3:2] -: 32] <= wdata;
                end

                // Dekripsi: putar penjadwal kunci maju sampai K10
                S_KEXP: begin
                    rk <= rk_next;
                    if (round == 4'd10) state <= S_INIT;
                    else                round <= round + 4'd1;
                end

                // AddRoundKey awal (enkripsi: K0, dekripsi: K10)
                S_INIT: begin
                    st    <= blk_in ^ rk;
                    round <= cfg_dec ? 4'd9 : 4'd1;
                    state <= S_KEY;
                end

                // Kunci ronde berikutnya (enkripsi: maju, dekripsi: balik)
                S_KEY: begin
                    rk    <= cfg_dec ? rk_prev : rk_next;
                    col   <= 2'd0;
                    state <= S_COL;
                end

                // Satu kolom per siklus
                S_COL: begin
                    ns[127 - 32*col -: 32] <= ncol;
                    if (col != 2'd3) col <= col + 2'd1;
                    else begin
                        st <= ns_full;
                        if ((!cfg_dec && last_e) || (cfg_dec && last_d)) state <= S_FIN;
                        else begin
                            round <= cfg_dec ? round - 4'd1 : round + 4'd1;
                            state <= S_KEY;
                        end
                    end
                end

                S_FIN: begin
                    if (cfg_dec) begin
                        dout <= cfg_cbc ? (st ^ iv) : st;
                        if (cfg_cbc) iv <= din;
                    end else begin
                        dout <= st;
                        if (cfg_cbc) iv <= st;
                    end
                    // Hapus material kunci dan data antara
                    key0 <= 128'd0; rk <= 128'd0; ns <= 128'd0; st <= 128'd0;
                    if (cfg_wrap) din <= 128'd0;
                    busy  <= 1'b0;
                    done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n)   rdata <= 32'd0;
        else if (zeroize)  rdata <= 32'd0;
        else if (re) begin
            if (a8 == 8'h00)            rdata <= {28'd0, cfg_cbc, cfg_wrap, cfg_dec, 1'b0};
            else if (a8 == 8'h04)       rdata <= {30'd0, done, busy};
            else if (a8[7:4] == 4'h2)   rdata <= iv[127 - 32*a8[3:2] -: 32];
            else if (a8[7:4] == 4'h3)   rdata <= busy ? 32'd0 : dout[127 - 32*a8[3:2] -: 32];
            else                        rdata <= 32'd0;
        end
    end

endmodule