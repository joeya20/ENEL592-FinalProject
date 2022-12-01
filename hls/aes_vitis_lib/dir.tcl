set_directive_top -name dut "dut"
set_directive_inline "aesTable::aesTable"
set_directive_bind_storage -type rom_np -impl lutram "aesTable::aesTable" ssbox
set_directive_bind_storage -type rom_np -impl lutram "aesTable::aesTable" iibox
set_directive_bind_storage -type rom_np -impl lutram "aesTable::aesTable" i32box
set_directive_bind_storage -type rom_np -impl lutram "aesTable::aesTable" p16box
set_directive_inline "aesEnc<256>::aesEnc"
set_directive_array_partition -type complete -dim 1 "aesEnc<256>::aesEnc" key_list
set_directive_inline -off "aesEnc<256>::updateKey"
set_directive_inline -off "aesEnc<256>::updateKey_2"
set_directive_pipeline -II 1 "dut/dut_label24"
set_directive_unroll "aesEnc<256>::process/process_label1"
set_directive_unroll "aesEnc<256>::process/process_label2"
set_directive_unroll "aesEnc<256>::process/process_label3"
set_directive_pipeline -II 1 "aesEnc<256>::updateKey_2/updateKey_2_label4"
