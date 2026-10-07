vlib work
vlog -timescale 1ns/1ps ro_puf_array_sim.v ../RTL/ro_puf.v ../RTL/fuzzy_ext.v tb_ro_puf.v
vsim -voptargs=+acc -onfinish stop work.tb_ro_puf
add wave -divider "Kontrol"
add wave /tb_ro_puf/clk_sys /tb_ro_puf/rst_sync_n
add wave -radix hex /tb_ro_puf/puf_ctl
add wave -radix unsigned /tb_ro_puf/dut/st /tb_ro_puf/dut/sa /tb_ro_puf/dut/sb
add wave -divider "Ring oscillator dan penghitung"
add wave /tb_ro_puf/dut/ro_en /tb_ro_puf/dut/ctr_clr /tb_ro_puf/dut/ro_a /tb_ro_puf/dut/ro_b
add wave -radix unsigned /tb_ro_puf/dut/ca /tb_ro_puf/dut/cb
add wave -divider "Keluaran"
add wave /tb_ro_puf/cnt_done
add wave -radix hex /tb_ro_puf/cnt
add wave -divider "Integrasi: kunci chip A dan B"
add wave /tb_ro_puf/rv_a /tb_ro_puf/rv_b
add wave -radix hex /tb_ro_puf/R_A /tb_ro_puf/R_B
run -all
wave zoom full
