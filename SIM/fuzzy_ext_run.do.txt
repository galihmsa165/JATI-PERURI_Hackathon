vlib work
vlog -timescale 1ns/1ps ../RTL/fuzzy_ext.v tb_fuzzy_ext.v
vsim -voptargs=+acc -onfinish stop work.tb_fuzzy_ext
add wave -divider "Bus"
add wave /tb_fuzzy_ext/clk_sys /tb_fuzzy_ext/rst_sync_n /tb_fuzzy_ext/zeroize
add wave -radix hex /tb_fuzzy_ext/req /tb_fuzzy_ext/rdata
add wave -divider "Antarmuka ro_puf"
add wave -radix hex /tb_fuzzy_ext/puf_ctl /tb_fuzzy_ext/cnt
add wave /tb_fuzzy_ext/cnt_done
add wave -divider "State machine"
add wave -radix unsigned /tb_fuzzy_ext/dut/state /tb_fuzzy_ext/dut/g /tb_fuzzy_ext/dut/v /tb_fuzzy_ext/dut/votes
add wave /tb_fuzzy_ext/dut/helper_locked /tb_fuzzy_ext/dut/err
add wave -radix unsigned /tb_fuzzy_ext/dut/unstable
add wave -divider "Keluaran ke key_manager"
add wave /tb_fuzzy_ext/r_valid
add wave -radix hex /tb_fuzzy_ext/r_puf /tb_fuzzy_ext/dut/R
run -all
wave zoom full