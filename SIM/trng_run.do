vlib work
vlog -timescale 1ns/1ps trng_ro_sim.v ../RTL/trng.v tb_trng.v
vsim -voptargs=+acc -onfinish stop work.tb_trng
add wave -divider "Bus"
add wave /tb_trng/clk_sys /tb_trng/rst_sync_n /tb_trng/zeroize
add wave -radix hex /tb_trng/req /tb_trng/rdata
add wave -divider "Sumber dan sampel"
add wave /tb_trng/dut/enable /tb_trng/dut/raw /tb_trng/dut/samp_v /tb_trng/dut/samp
add wave -divider "Health test"
add wave -radix unsigned /tb_trng/dut/rct_run /tb_trng/dut/apt_idx /tb_trng/dut/apt_cnt
add wave /tb_trng/dut/ready /tb_trng/dut/rct_fail /tb_trng/dut/apt_fail
add wave -divider "Keluaran"
add wave -radix unsigned /tb_trng/dut/sh_cnt /tb_trng/dut/f_cnt
add wave /tb_trng/dut/word_v
add wave -radix hex /tb_trng/dut/word
run -all
wave zoom full
