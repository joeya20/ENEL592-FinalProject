config_interface -register_io scalar_out
set_directive_top -name serpent_encrypt "serpent_encrypt"
set_directive_bind_storage -type rom_np -impl lutram "serpent_encrypt" sbox
set_directive_pipeline "serpent_encrypt/serpent_encrypt_label0"
set_directive_unroll "substitutionLayer/substitutionLayer_label1"
set_directive_unroll "initialPermutation/initialPermutation_label2"
set_directive_unroll "finalPermutation/finalPermutation_label3"
set_directive_unroll "reverseWord/reverseWord_label4"