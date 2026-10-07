# =============================================================================
# JATI - Penempatan pin untuk DE10-Nano (5CSEBA6U23I7)
# Jalankan di Quartus: Tools -> Tcl Scripts -> pilih file ini -> Run
# (proyek harus sedang terbuka)
# =============================================================================

# Clock 50 MHz dari osilator papan (FPGA_CLK1_50)
set_location_assignment PIN_V11  -to clk_50

# Tombol KEY0 sebagai reset (aktif rendah: ditekan = 0)
set_location_assignment PIN_AH17 -to rst_n

# Saklar SW0 untuk demo glitch (naik = satu glitch)
set_location_assignment PIN_Y24  -to glitch_test_en

# LED0..LED3 = status lifecycle, LED4 = PLL terkunci
set_location_assignment PIN_W15  -to led_status[0]
set_location_assignment PIN_AA24 -to led_status[1]
set_location_assignment PIN_V16  -to led_status[2]
set_location_assignment PIN_V15  -to led_status[3]
set_location_assignment PIN_AF26 -to pll_locked

# UART ke adaptor USB-TTL lewat header GPIO 0 (JP1)
# (DE10-Nano User Manual, Figure 3-20 dan Table 3-10)
#   uart_rx = GPIO_0[0] = PIN_V12 = kaki header nomor 1  <- TX adaptor
#   uart_tx = GPIO_0[1] = PIN_E8  = kaki header nomor 2  -> RX adaptor
#   GND     = kaki header nomor 12 (atau 30)             -- GND adaptor
set_location_assignment PIN_V12  -to uart_rx
set_location_assignment PIN_E8   -to uart_tx

# Standar tegangan semua pin: 3,3 V LVTTL
foreach p {clk_50 rst_n glitch_test_en uart_rx uart_tx pll_locked
           led_status[0] led_status[1] led_status[2] led_status[3]} {
    set_instance_assignment -name IO_STANDARD "3.3-V LVTTL" -to $p
}

# Pin yang tidak dipakai dijadikan input (aman untuk papan)
set_global_assignment -name RESERVE_ALL_UNUSED_PINS_WEAK_PULLUP "AS INPUT TRI-STATED"

puts "Penempatan pin JATI selesai."
