config_interface -register_io scalar_out -s_axilite_auto_restart_counter 1
set_directive_top -name present_encrypt "present_encrypt"
set_directive_pipeline "present_encrypt/ENCRL"
set_directive_bind_storage -type ram_1p -impl lutram "reconfigure" sBoxMasked
set_directive_array_partition -dim 2 -type complete "reconfigure" sBoxMasked
set_directive_unroll "reconfigure/L1"
set_directive_pipeline "reconfigure/L2"
set_directive_unroll "reconfigure/L3"
set_directive_unroll "sLayer/SLAYERL"
set_directive_unroll "pLayer/PLAYERL"
set_directive_unroll "pInvLayer/PINVLAYERL"
