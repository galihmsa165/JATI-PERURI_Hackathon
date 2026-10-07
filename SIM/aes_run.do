vlib work
vlog -timescale 1ns/1ps ../RTL/aes128_sm.v tb_aes.v
vsim -voptargs=+acc -onfinish stop work.tb_aes
add wave /tb_aes/clk
add wave -radix unsigned /tb_aes/dut/state /tb_aes/dut/round /tb_aes/dut/col
add wave -radix hex /tb_aes/dut/st /tb_aes/dut/rk /tb_aes/dut/dout
run -all
wave zoom full
