vlib work
vlog -timescale 1ns/1ps ../RTL/key_manager.v ../RTL/hmac_kdf.v ../RTL/sha256_core.v tb_key_policy.v
vsim -voptargs=+acc -onfinish stop work.tb_key_policy
add wave /tb_key_policy/clk /tb_key_policy/kdf_only /tb_key_policy/hm/pol_err /tb_key_policy/hm/done
add wave -radix hex /tb_key_policy/key_sel
run -all
wave zoom full
