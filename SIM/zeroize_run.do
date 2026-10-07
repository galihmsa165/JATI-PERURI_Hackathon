vlib work
vlog -timescale 1ns/1ps ../RTL/zeroize.v tb_zeroize.v
vsim -voptargs=+acc -onfinish stop work.tb_zeroize
add wave /tb_zeroize/clk_sys /tb_zeroize/rst_sync_n /tb_zeroize/tamper_alarm
add wave /tb_zeroize/dut/armed_a /tb_zeroize/dut/armed_b /tb_zeroize/zeroize
run -all
wave zoom full