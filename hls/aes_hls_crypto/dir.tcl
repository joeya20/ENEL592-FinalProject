set_directive_top -name aes_encrypt "aes_encrypt"
set_directive_bind_storage -type rom_np -impl lutram "aes_encrypt" sBoxClean
set_directive_pipeline "aes_encrypt/aes_encrypt_label5"
set_directive_bind_storage -type ram_1p -impl lutram "reconfigure" sBoxMasked
set_directive_array_partition -dim 2 -type complete "reconfigure" sBoxMasked
set_directive_unroll "reconfigure/L1"
set_directive_pipeline "reconfigure/L2"
set_directive_unroll "reconfigure/L3"
set_directive_unroll "subBytes/subBytes_label6"
set_directive_unroll "shiftRows/shiftRows_label7"
set_directive_unroll "invShiftRows/invShiftRows_label8"
set_directive_unroll "mixColumns/mixColumns_label9"
set_directive_unroll "invMixColumns/invMixColumns_label10"
