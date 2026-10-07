vlib work
vlog -timescale 1ns/1ps ../RTL/glitch_inj.v tb_glitch_inj.v
vsim -voptargs=+acc -onfinish stop work.tb_glitch_inj
add wave /tb_glitch_inj/clk_pll /tb_glitch_inj/glitch_test_en
add wave /tb_glitch_inj/dut/g_inj/en_s2 /tb_glitch_inj/dut/g_inj/en_s3 /tb_glitch_inj/dut/g_inj/trig
add wave /tb_glitch_inj/dut/g_inj/pulse
add wave /tb_glitch_inj/clk_sys /tb_glitch_inj/clk_sys_bp
run -all
wave zoom full
