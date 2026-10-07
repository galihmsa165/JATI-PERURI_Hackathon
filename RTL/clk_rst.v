// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : clk_rst
// Fungsi  : Membangkitkan clock sistem (lewat PLL) dan reset global yang aman.
//
// Alur:
//   clk_50 --> [PLL pll_sys] --> clk_pll  (ke glitch_inj, lalu menjadi clk_sys)
//   rst_n  --+--> reset PLL
//            +--> [gabung dengan pll_locked] --> [sinkronizer 3 FF]
//                 --> [penahan reset HOLD_CYCLES] --> rst_sync_n
//
// Prinsip desain:
//   1. Assert asinkron, deassert sinkron: reset langsung aktif tanpa menunggu
//      clock, tetapi dilepas tepat pada tepi clock agar semua register keluar
//      dari reset pada siklus yang sama (tanpa metastabilitas).
//   2. Reset ditahan selama PLL belum terkunci. Kalau PLL kehilangan kunci
//      (misalnya clock masukan diganggu), seluruh chip otomatis direset:
//      fail-safe.
//   3. Reset diperpanjang minimal HOLD_CYCLES siklus. Pulsa reset sependek
//      apa pun tetap menghasilkan reset penuh, dan blok seperti zeroize
//      dijamin melihat beberapa tepi clock selama reset aktif.
//
// Antarmuka:
//   clk_50     : clock 50 MHz dari osilator papan
//   rst_n      : tombol reset, aktif rendah (asinkron)
//   clk_pll    : clock 50 MHz bersih dari PLL
//   rst_sync_n : reset global aktif rendah, tersinkron ke clk_pll
//   pll_locked : status kunci PLL (untuk LED/debug)
//
// Catatan PLL:
//   Modul ini memanggil "pll_sys". Di Quartus, pll_sys dibuat lewat
//   IP Catalog (PLL Intel FPGA IP). Di ModelSim, pakai model pll_sys_sim.v.
//   JANGAN memasukkan pll_sys_sim.v ke proyek Quartus.
//
// Catatan domain clock:
//   rst_sync_n tersinkron ke clk_pll. clk_sys berasal dari clk_pll (lewat
//   glitch_inj) dengan frekuensi dan fase yang sama, jadi aman dipakai di
//   domain clk_sys. Di chip final clk_sys = clk_pll.
// =============================================================================

module clk_rst #(
    parameter integer HOLD_CYCLES = 16   // panjang minimum reset setelah sinkron
)(
    input  wire clk_50,
    input  wire rst_n,
    output wire clk_pll,
    output wire rst_sync_n,
    output wire pll_locked
);

    // -------------------------------------------------------------------------
    // 1. PLL: 50 MHz -> 50 MHz bersih, dengan sinyal locked
    // -------------------------------------------------------------------------
    pll_sys u_pll (
        .refclk   (clk_50),
        .rst      (~rst_n),      // reset PLL aktif tinggi
        .outclk_0 (clk_pll),
        .locked   (pll_locked)
    );

    // -------------------------------------------------------------------------
    // 2. Sumber reset asinkron: aktif jika tombol ditekan ATAU PLL belum kunci
    // -------------------------------------------------------------------------
    wire arst_n = rst_n & pll_locked;

    // -------------------------------------------------------------------------
    // 3. Sinkronizer 3 tahap: assert asinkron, deassert sinkron
    //    Nilai awal 0 = chip dalam keadaan reset saat FPGA baru dikonfigurasi.
    // -------------------------------------------------------------------------
    reg [2:0] sync_ff = 3'b000;

    always @(posedge clk_pll or negedge arst_n) begin
        if (!arst_n)
            sync_ff <= 3'b000;
        else
            sync_ff <= {sync_ff[1:0], 1'b1};
    end

    wire sync_ok = sync_ff[2];

    // -------------------------------------------------------------------------
    // 4. Penahan reset: lepas reset hanya setelah HOLD_CYCLES siklus stabil
    // -------------------------------------------------------------------------
    localparam integer CW = $clog2(HOLD_CYCLES + 1);

    reg [CW-1:0] hold_cnt  = {CW{1'b0}};
    reg          rst_out_n = 1'b0;

    always @(posedge clk_pll or negedge arst_n) begin
        if (!arst_n) begin
            hold_cnt  <= {CW{1'b0}};
            rst_out_n <= 1'b0;
        end else if (!sync_ok) begin
            hold_cnt  <= {CW{1'b0}};
            rst_out_n <= 1'b0;
        end else if (hold_cnt < HOLD_CYCLES) begin
            hold_cnt  <= hold_cnt + 1'b1;
            rst_out_n <= 1'b0;
        end else begin
            rst_out_n <= 1'b1;
        end
    end

    assign rst_sync_n = rst_out_n;

endmodule