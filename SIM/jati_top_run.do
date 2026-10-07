vlib work
vlog -timescale 1ns/1ps pll_sys_sim.v trng_ro_sim.v ro_puf_array_sim.v wd_ro_sim.v ../RTL/clk_watchdog.v ../RTL/clk_rst.v ../RTL/glitch_inj.v ../RTL/uart.v ../RTL/apdu_parser.v ../RTL/ctrl_fsm.v ../RTL/bus_mux.v ../RTL/hmac_kdf.v ../RTL/sha256_core.v ../RTL/aes128_sm.v ../RTL/trng.v ../RTL/dg_memory.v ../RTL/lifecycle.v ../RTL/ro_puf.v ../RTL/fuzzy_ext.v ../RTL/key_manager.v ../RTL/tamper_sensor.v ../RTL/zeroize.v ../RTL/jati_top.v tb_jati_top.v
vsim -voptargs=+acc -onfinish stop work.tb_jati_top
add wave -divider "Pin chip"
add wave /tb_jati_top/clk_50 /tb_jati_top/rst_n /tb_jati_top/uart_rx_line /tb_jati_top/uart_tx_line /tb_jati_top/glitch_test_en
add wave -radix binary /tb_jati_top/led_status
add wave -divider "Perintah dan jawaban"
add wave -radix hex /tb_jati_top/dut/cmd /tb_jati_top/dut/rsp
add wave /tb_jati_top/dut/cmd_valid /tb_jati_top/dut/rsp_valid
add wave -divider "FSM"
add wave -radix hex /tb_jati_top/dut/u_fsm/state /tb_jati_top/dut/key_sel /tb_jati_top/dut/u_fsm/ac_q /tb_jati_top/dut/u_fsm/ta_q
add wave -radix unsigned /tb_jati_top/dut/u_fsm/step /tb_jati_top/dut/u_fsm/fail_cnt
add wave -divider "Keamanan"
add wave /tb_jati_top/dut/tamper_alarm /tb_jati_top/dut/zeroize /tb_jati_top/dut/lc_fault /tb_jati_top/dut/u_tamper/wd_stop
add wave -radix binary /tb_jati_top/dut/tamper_cause
run -all
wave zoom full
