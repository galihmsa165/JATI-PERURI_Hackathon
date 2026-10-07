vlib work
vlog -timescale 1ns/1ps wd_ro_sim.v ../RTL/clk_watchdog.v ../RTL/tamper_sensor.v tb_tamper_sensor.v
vsim -voptargs=+acc -onfinish stop work.tb_tamper_sensor
add wave /tb_tamper_sensor/clk_sys /tb_tamper_sensor/rst_sync_n /tb_tamper_sensor/clk_stop
add wave /tb_tamper_sensor/dut/u_wd/stop /tb_tamper_sensor/tamper_alarm
add wave -radix binary /tb_tamper_sensor/tamper_cause
run -all
wave zoom full
