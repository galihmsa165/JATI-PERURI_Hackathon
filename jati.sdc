# =============================================================================
# JATI - Batasan timing (TimeQuest)
# Tambahkan ke proyek: Assignments -> Settings -> Timing Analyzer -> SDC files
# =============================================================================

# Clock masukan 50 MHz
create_clock -name clk_50 -period 20.000 [get_ports {clk_50}]

# Clock keluaran PLL (clk_pll -> glitch_inj -> clk_sys) dibuat otomatis
derive_pll_clocks
derive_clock_uncertainty

# Masukan asinkron: sudah disinkronkan di dalam desain
set_false_path -from [get_ports {rst_n}]
set_false_path -from [get_ports {uart_rx}]
set_false_path -from [get_ports {glitch_test_en}]

# Keluaran lambat (LED dan UART), tidak kritis timing
set_false_path -to [get_ports {led_status[*]}]
set_false_path -to [get_ports {pll_locked}]
set_false_path -to [get_ports {uart_tx}]

# -----------------------------------------------------------------------------
# Sensor dan penyuntik glitch: BUKAN jalur fungsional
# -----------------------------------------------------------------------------
# 1. glitch_inj (khusus demo): sinyal trig sengaja membuat pulsa sempit di
#    jaringan clock. Jalur ini ADALAH serangan, bukan data yang harus tiba
#    tepat waktu. Hilang sama sekali di chip final (GLITCH_EN = 0).
set_false_path -from [get_registers {*u_glitch*trig*}]

# 2. Detektor lebar pulsa tamper_sensor: delay line sengaja mencuplik clock
#    itu sendiri (clock dipakai sebagai data). Analisis setup/hold biasa tidak
#    bermakna untuk register ini; kalibrasinya lewat N_PW di papan.
set_false_path -to [get_registers {*u_tamper*lo_short*}]
set_false_path -to [get_registers {*u_tamper*hi_short*}]

# Catatan: canary timing (launch -> can_viol) SENGAJA tetap dianalisis.
# Slack-nya dipakai untuk kalibrasi TAMPER_N_CAN di jati_top.

# -----------------------------------------------------------------------------
# Revisi v3: watchdog clock (A11)
# -----------------------------------------------------------------------------
# Register watchdog di-clock oleh ring oscillator independen dan sengaja
# asinkron terhadap clk_sys (keluarannya memicu zeroize tanpa clock).
set_false_path -from [get_registers {*u_wd*}]
set_false_path -to   [get_registers {*u_tamper*wd_s1*}]
