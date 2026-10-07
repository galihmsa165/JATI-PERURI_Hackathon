vlib work
vlog -timescale 1ns/1ps ../RTL/key_manager.v tb_key_manager.v
vsim -voptargs=+acc -onfinish stop work.tb_key_manager
add wave -divider "Kontrol"
add wave /tb_key_manager/clk_sys /tb_key_manager/rst_sync_n /tb_key_manager/zeroize
add wave -radix hex /tb_key_manager/key_sel
add wave /tb_key_manager/kdf_wr /tb_key_manager/r_valid
add wave -radix hex /tb_key_manager/kdf_key /tb_key_manager/r_puf
add wave -divider "Keluaran"
add wave -radix hex /tb_key_manager/key_out /tb_key_manager/wrap_key
add wave /tb_key_manager/key_ok
add wave -divider "Status internal"
add wave /tb_key_manager/dut/v_rpuf /tb_key_manager/dut/v_dev /tb_key_manager/dut/v_ca /tb_key_manager/dut/v_dg
add wave /tb_key_manager/dut/v_t /tb_key_manager/dut/v_ta /tb_key_manager/dut/v_s_enc
add wave /tb_key_manager/dut/rpuf_spent /tb_key_manager/dut/t_locked
run -all
wave zoom full