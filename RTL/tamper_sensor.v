// =============================================================================
// JATI - Secure Element e-Paspor
// Modul   : tamper_sensor
// Fungsi  : Mendeteksi serangan fisik dan menyalakan tamper_alarm (terkunci
//           sampai reset). tamper_alarm memicu modul zeroize.
//
// Tiga detektor (tamper_cause):
//   bit 0  DETEKTOR GLITCH CLOCK (lebar pulsa)
//          clk_sys dilewatkan delay line N_PW tahap. Pada setiap tepi clock,
//          tap ujung delay line menunjukkan nilai clock N_PW*tau yang lalu:
//            - di tepi turun, tap harus 1 (fase tinggi >= N_PW*tau)
//            - di tepi naik,  tap harus 0 (fase rendah >= N_PW*tau)
//          Pulsa clock yang lebih pendek dari ambang -> glitch terdeteksi.
//   bit 1  CANARY TIMING (penurunan tegangan / overclock)
//          Sinyal launch berbalik tiap siklus dan merambat lewat delay line
//          N_CAN tahap (sekitar 80% periode clock). Kalau tegangan turun
//          (gerbang melambat) atau clock dipercepat, sinyal terlambat tiba
//          -> pelanggaran setup terdeteksi SEBELUM logika utama ikut salah.
//   bit 0  juga dipakai WATCHDOG CLOCK (A11): clock dihentikan/diperlambat
//          drastis, dideteksi oleh ring oscillator independen (clk_watchdog).
//   bit 2  FSM FAULT
//          Dari ctrl_fsm: state tidak sah akibat fault injection.
//
// Aturan keamanan:
//   1. tamper_alarm dan tamper_cause adalah KELUARAN REGISTER (bebas glitch),
//      syarat dari modul zeroize yang memakainya sebagai clear asinkron.
//   2. Alarm dan penyebab terkunci (sticky) sampai reset.
//   3. Detektor clock dan canary baru aktif ARM_CYCLES siklus setelah reset
//      (delay line belum stabil saat menyala). Pada jendela ini belum ada
//      kunci di chip: rekonstruksi PUF butuh ribuan siklus.
//
// Catatan hardware:
//   - Delay line memakai rantai inverter dengan (* keep *). Delay "#" hanya
//     untuk simulasi; Quartus memakai delay LUT asli (sekitar 0,5-1 ns/tahap).
//   - N_PW dan N_CAN HARUS dikalibrasi di papan: naikkan N_CAN sampai canary
//     hampir terpicu pada 50 MHz, lalu kurangi beberapa tahap sebagai margin.
//     Gunakan glitch_inj untuk memastikan glitch terdeteksi.
//   - Quartus akan memberi peringatan "clock used as data" dan "ignored delay".
//     Untuk modul ini, keduanya disengaja.
//   - Versi ASIC: detektor tegangan analog (SKY130) melengkapi canary ini.
// =============================================================================
`timescale 1ns/1ps

module tamper_sensor #(
    parameter integer N_PW       = 8,     // tahap detektor lebar pulsa (GENAP)
    parameter integer N_CAN      = 26,    // tahap canary timing (GENAP)
    parameter integer STAGE_PS   = 600,   // delay per tahap, KHUSUS simulasi
    parameter integer ARM_CYCLES = 8,
    parameter integer WD_LIMIT   = 128    // watchdog: periode RO tanpa clock
)(
    input  wire       clk_sys,
    input  wire       rst_sync_n,
    input  wire       fsm_fault,
    output wire       tamper_alarm,
    output reg  [2:0] tamper_cause
);

    genvar i;

    // =========================================================================
    // 1. Detektor glitch clock (lebar pulsa)
    // =========================================================================
    (* keep *) wire [N_PW:0] pw;
    assign pw[0] = clk_sys;
    generate
        for (i = 0; i < N_PW; i = i + 1) begin : g_pw
            assign #(STAGE_PS / 1000.0) pw[i+1] = ~pw[i];
        end
    endgenerate
    wire pw_tap = pw[N_PW];          // clk_sys tertunda N_PW*tau (polaritas sama)

    reg hi_short;   // fase TINGGI terlalu pendek (dicek di tepi turun)
    reg lo_short;   // fase RENDAH terlalu pendek (dicek di tepi naik)

    always @(negedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) hi_short <= 1'b0;
        else             hi_short <= ~pw_tap;
    end

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) lo_short <= 1'b0;
        else             lo_short <= pw_tap;
    end

    // =========================================================================
    // 2. Canary timing
    // =========================================================================
    reg launch;
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) launch <= 1'b0;
        else             launch <= ~launch;
    end

    (* keep *) wire [N_CAN:0] cn;
    assign cn[0] = launch;
    generate
        for (i = 0; i < N_CAN; i = i + 1) begin : g_can
            assign #(STAGE_PS / 1000.0) cn[i+1] = ~cn[i];
        end
    endgenerate

    reg can_viol;
    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) can_viol <= 1'b0;
        else             can_viol <= (cn[N_CAN] != launch);   // terlambat tiba
    end

    // =========================================================================
    // 3. Penunda aktivasi setelah reset
    // =========================================================================
    reg [7:0] arm_cnt;
    wire      armed = (arm_cnt == ARM_CYCLES);

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n)  arm_cnt <= 8'd0;
        else if (!armed)  arm_cnt <= arm_cnt + 1'b1;
    end

    // =========================================================================
    // 4. Alarm dan penyebab (register, terkunci sampai reset)
    // =========================================================================
    wire det_glitch = armed && (hi_short || lo_short);
    wire det_timing = armed && can_viol;
    wire det_fsm    = fsm_fault;

    // =========================================================================
    // 5. Watchdog clock berhenti (A11)
    //    wd_stop langsung masuk ke tamper_alarm (tanpa clock), sehingga zeroize
    //    bekerja walaupun clk_sys mati. Saat clock kembali, penyebab dicatat.
    // =========================================================================
    wire wd_stop;
    reg  wd_s1, wd_s2;
    clk_watchdog #(.LIMIT(WD_LIMIT)) u_wd (
        .clk_sys (clk_sys), .rst_sync_n (rst_sync_n), .stop (wd_stop)
    );
    always @(posedge clk_sys or negedge rst_sync_n)
        if (!rst_sync_n) begin wd_s1 <= 1'b0; wd_s2 <= 1'b0; end
        else             begin wd_s1 <= wd_stop; wd_s2 <= wd_s1; end

    reg alarm_q;
    assign tamper_alarm = alarm_q | wd_stop;    // OR dua register: bebas glitch

    always @(posedge clk_sys or negedge rst_sync_n) begin
        if (!rst_sync_n) begin
            alarm_q      <= 1'b0;
            tamper_cause <= 3'b000;
        end else begin
            if (det_glitch || wd_s2) tamper_cause[0] <= 1'b1;
            if (det_timing) tamper_cause[1] <= 1'b1;
            if (det_fsm)    tamper_cause[2] <= 1'b1;
            if (det_glitch || det_timing || det_fsm || wd_s2)
                alarm_q <= 1'b1;
        end
    end

endmodule