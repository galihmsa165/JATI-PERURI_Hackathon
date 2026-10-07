vlib work
vlog -timescale 1ns/1ps ../RTL/lifecycle.v tb_lifecycle.v
vsim -voptargs=+acc -onfinish stop work.tb_lifecycle
add wave /tb_lifecycle/clk
add wave -radix hex /tb_lifecycle/dut/st /tb_lifecycle/dut/el
add wave /tb_lifecycle/we_en /tb_lifecycle/el /tb_lifecycle/flt
run -all
wave zoom full
