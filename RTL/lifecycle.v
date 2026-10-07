// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : lifecycle   (revisi keamanan A2 + A15)
// Fungsi  : Status siklus hidup BLANK -> PERSO -> LOCKED -> TERMINATED,
//           proteksi tulis memori paspor (we_en), dan LED status.
// Alamat bus: ID 4 (addr[11:8] == 4'h4)
//
// PERBAIKAN KEAMANAN
//   A2 (fault injection pada lifecycle):
//     1. Status disimpan sebagai kode Hamming (8,4) diperluas, jarak minimal
//        4 bit. Membalik 1-3 bit selalu menghasilkan kode tidak sah ->
//        lc_fault = 1 (ke tamper_sensor) dan status dipaksa TERMINATED.
//        Versi lama (2 bit biasa): satu bit terbalik LOCKED (10) -> BLANK (00),
//        lalu START PERSO + READ polos membuka seluruh memori.
//     2. Penanda "pernah LOCKED" (ever_locked) disimpan sebagai pola 8 bit
//        (0xA5 = ya, 0x5A = belum; nilai lain = fault). Begitu LOCKED,
//        we_en mati selamanya dan FSM menolak READ polos dan personalisasi.
//   A15 (lifecycle volatil di FPGA):
//     Port lc_nv / lc_nv_valid disiapkan untuk OTP/eFuse pada ASIC: saat
//     reset, status dimuat dari memori non-volatil. Pada FPGA keduanya
//     diikat ke 0 (status awal BLANK).
//
// Register bus
//   tulis (alamat berapa pun di ID 4): wdata[1:0] = status tujuan
//     01 PERSO (dari BLANK), 10 LOCKED (dari PERSO), 11 TERMINATED (dari mana saja)
//   baca : {25'd0, lc_fault, ever_locked, tamper_cause[2:0], state[1:0]}
// =============================================================================

module lifecycle (
    input  wire        clk_sys,
    input  wire        rst_sync_n,
    input  wire        zeroize,
    input  wire [45:0] req,             // {addr[11:0], wdata[31:0], we, re}
    input  wire [2:0]  tamper_cause,
    input  wire [7:0]  lc_nv,           // ASIC: kode status dari OTP
    input  wire        lc_nv_valid,     // ASIC: 1 = OTP berisi status
    output reg  [31:0] rdata,
    output wire        we_en,
    output wire        ever_locked,
    output reg         lc_fault,
    output reg  [3:0]  led
);

    // Kode Hamming (8,4) diperluas, jarak minimal 4 (0x00/0xFF tidak dipakai)
    localparam [7:0] C_BLANK = 8'h1E, C_PERSO = 8'h2D, C_LOCKED = 8'h4B, C_TERM = 8'h78;
    localparam [7:0] EL_YES  = 8'hA5, EL_NO   = 8'h5A;
    localparam [1:0] LC_BLANK = 2'b00, LC_PERSO = 2'b01, LC_LOCKED = 2'b10, LC_TERM = 2'b11;

    reg [7:0] st;      // status terkode
    reg [7:0] el;      // ever_locked terkode

    wire [11:0] addr  = req[45:34];
    wire [31:0] wdata = req[33:2];
    wire        sel   = (addr[11:8] == 4'h4);
    wire        we    = req[1] && sel;
    wire        re    = req[0] && sel;

    // Dekode (kode tidak sah -> dianggap TERMINATED)
    reg [1:0] dec;
    reg       st_ok;
    always @(*) begin
        st_ok = 1'b1;
        case (st)
            C_BLANK:  dec = LC_BLANK;
            C_PERSO:  dec = LC_PERSO;
            C_LOCKED: dec = LC_LOCKED;
            C_TERM:   dec = LC_TERM;
            default:  begin dec = LC_TERM; st_ok = 1'b0; end
        endcase
    end
    wire el_ok = (el == EL_YES) || (el == EL_NO);

    assign ever_locked = (el != EL_NO);          // pola rusak = dianggap pernah LOCKED
    assign we_en       = (st == C_PERSO) && (el == EL_NO);

    // A15: status dari OTP dimuat sinkron pada siklus pertama setelah reset
    //      (nilai reset asinkron harus konstan)
    reg nv_done;

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            st       <= C_BLANK;
            el       <= EL_NO;
            nv_done  <= 1'b0;
            lc_fault <= 1'b0;
            led      <= 4'b0001;
        end else if (zeroize) begin
            st  <= C_TERM;
            el  <= EL_YES;
            led <= 4'b1111;
        end else if (!nv_done) begin
            nv_done <= 1'b1;
            if (lc_nv_valid) begin
                st <= lc_nv;
                el <= (lc_nv == C_LOCKED || lc_nv == C_TERM) ? EL_YES : EL_NO;
            end
        end else begin
            if (!st_ok || !el_ok) begin
                lc_fault <= 1'b1;                // fault terdeteksi -> kunci permanen
                st       <= C_TERM;
                el       <= EL_YES;
            end else if (we) begin
                case (wdata[1:0])
                    LC_PERSO:  if (st == C_BLANK && el == EL_NO) st <= C_PERSO;
                    LC_LOCKED: if (st == C_PERSO) begin st <= C_LOCKED; el <= EL_YES; end
                    LC_TERM:   begin st <= C_TERM; el <= EL_YES; end
                    default:   ;
                endcase
            end

            case (dec)
                LC_BLANK:  led <= 4'b0001;
                LC_PERSO:  led <= 4'b0010;
                LC_LOCKED: led <= 4'b0100;
                default:   led <= 4'b1000;
            endcase
        end
    end

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n)  rdata <= 32'd0;
        else if (re)      rdata <= {25'd0, lc_fault, ever_locked, tamper_cause, dec};
    end

endmodule