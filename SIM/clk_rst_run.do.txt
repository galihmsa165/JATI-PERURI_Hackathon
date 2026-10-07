vlib work
vlog -timescale 1ns/1ps pll_sys_sim.v ../RTL/clk_rst.v tb_clk_rst.v
vsim -voptargs=+acc -onfinish stop work.tb_clk_rst
add wave /tb_clk_rst/clk_50 /tb_clk_rst/rst_n /tb_clk_rst/pll_locked /tb_clk_rst/clk_pll
add wave /tb_clk_rst/dut/arst_n /tb_clk_rst/dut/sync_ff
add wave -radix unsigned /tb_clk_rst/dut/hold_cnt
add wave /tb_clk_rst/rst_sync_n
run -all
wave zoom full