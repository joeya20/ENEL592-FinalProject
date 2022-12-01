// ==============================================================
// RTL generated by Vitis HLS - High-Level Synthesis from C, C++ and OpenCL v2022.1 (64-bit)
// Version: 2022.1
// Copyright (C) Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
// 
// ===========================================================

`timescale 1 ns / 1 ps 

module fir_fir_Pipeline_MAC (
        ap_clk,
        ap_rst,
        ap_start,
        ap_done,
        ap_idle,
        ap_ready,
        x,
        fir_ap_int_32_ap_int_32_shift_reg_1_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_2_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_3_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_4_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_5_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_6_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_7_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_8_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_9_load_1,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_10_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_long_unsigned_int128_signed_char_double_1_s_7,
        fir_ap_int_32_ap_int_32_shift_reg_l_unsigned_int128_signed_char_double_1_s_8,
        fir_ap_int_32_ap_int_32_shift_reg_lo_signed_char_double_1_s_9,
        fir_ap_int_32_ap_int_32_shift_reg_loa_double_1_s_10,
        fir_ap_int_32_ap_int_32_shift_reg_load_1_s_11,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_16_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_12,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_18_load_1,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_19_load_1,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_20_load_1,
        fir_ap_int_32_ap_int_32_shift_reg_long_unsigned_int128_signed_char_double_1_s,
        fir_ap_int_32_ap_int_32_shift_reg_l_unsigned_int128_signed_char_double_1_s,
        fir_ap_int_32_ap_int_32_shift_reg_lo_signed_char_double_1_s,
        fir_ap_int_32_ap_int_32_shift_reg_loa_double_1_s,
        fir_ap_int_32_ap_int_32_shift_reg_load_1_s,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_26_load_1,
        fir_ap_int_32_ap_int_32_shift_reg,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_28_load_1,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_29_load_1,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_30_load_1,
        mux_case_31591_phi_reload,
        mux_case_32592_phi_reload,
        mux_case_33593_phi_reload,
        mux_case_34594_phi_reload,
        mux_case_35595_phi_reload,
        mux_case_36596_phi_reload,
        mux_case_37597_phi_reload,
        mux_case_38598_phi_reload,
        mux_case_39599_phi_reload,
        mux_case_40600_phi_reload,
        mux_case_41601_phi_reload,
        mux_case_42602_phi_reload,
        mux_case_43603_phi_reload,
        mux_case_44604_phi_reload,
        mux_case_45605_phi_reload,
        mux_case_46606_phi_reload,
        mux_case_47607_phi_reload,
        mux_case_48608_phi_reload,
        mux_case_49609_phi_reload,
        mux_case_50610_phi_reload,
        mux_case_51611_phi_reload,
        mux_case_52612_phi_reload,
        mux_case_53613_phi_reload,
        mux_case_54614_phi_reload,
        mux_case_55615_phi_reload,
        mux_case_56616_phi_reload,
        mux_case_57617_phi_reload,
        mux_case_58618_phi_reload,
        mux_case_59619_phi_reload,
        mux_case_60620_phi_reload,
        mux_case_61621_phi_reload,
        mux_case_62622_phi_reload,
        mux_case_63623_phi_reload,
        mux_case_64624_phi_reload,
        mux_case_65625_phi_reload,
        mux_case_66626_phi_reload,
        mux_case_67627_phi_reload,
        mux_case_68628_phi_reload,
        mux_case_69629_phi_reload,
        mux_case_70630_phi_reload,
        mux_case_71631_phi_reload,
        mux_case_72632_phi_reload,
        mux_case_73633_phi_reload,
        mux_case_74634_phi_reload,
        mux_case_75635_phi_reload,
        mux_case_76636_phi_reload,
        mux_case_77637_phi_reload,
        mux_case_78638_phi_reload,
        mux_case_79639_phi_reload,
        mux_case_80640_phi_reload,
        mux_case_81641_phi_reload,
        mux_case_82642_phi_reload,
        mux_case_83643_phi_reload,
        mux_case_84644_phi_reload,
        mux_case_85645_phi_reload,
        mux_case_86646_phi_reload,
        mux_case_87647_phi_reload,
        mux_case_88648_phi_reload,
        mux_case_89649_phi_reload,
        mux_case_90650_phi_reload,
        mux_case_91651_phi_reload,
        mux_case_92652_phi_reload,
        mux_case_93653_phi_reload,
        mux_case_94654_phi_reload,
        mux_case_95655_phi_reload,
        mux_case_96656_phi_reload,
        mux_case_97657_phi_reload,
        mux_case_98658_phi_reload,
        mux_case_99659_phi_reload,
        mux_case_100660_phi_reload,
        mux_case_101661_phi_reload,
        mux_case_102662_phi_reload,
        mux_case_103663_phi_reload,
        mux_case_104664_phi_reload,
        mux_case_105665_phi_reload,
        mux_case_106666_phi_reload,
        mux_case_107667_phi_reload,
        mux_case_108668_phi_reload,
        mux_case_109669_phi_reload,
        mux_case_110670_phi_reload,
        mux_case_111671_phi_reload,
        mux_case_112672_phi_reload,
        mux_case_113673_phi_reload,
        mux_case_114674_phi_reload,
        mux_case_115675_phi_reload,
        mux_case_116676_phi_reload,
        mux_case_117677_phi_reload,
        mux_case_118678_phi_reload,
        mux_case_119679_phi_reload,
        mux_case_120680_phi_reload,
        mux_case_121681_phi_reload,
        mux_case_122682_phi_reload,
        mux_case_123683_phi_reload,
        mux_case_124684_phi_reload,
        mux_case_125685_phi_reload,
        mux_case_126686_phi_reload,
        p_ZZ3firP6ap_intILi32EES0_E9shift_reg_127_load,
        acc_V_out,
        acc_V_out_ap_vld
);

parameter    ap_ST_fsm_state1 = 4'd1;
parameter    ap_ST_fsm_state2 = 4'd2;
parameter    ap_ST_fsm_state3 = 4'd4;
parameter    ap_ST_fsm_state4 = 4'd8;

input   ap_clk;
input   ap_rst;
input   ap_start;
output   ap_done;
output   ap_idle;
output   ap_ready;
input  [31:0] x;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_1_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_2_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_3_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_4_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_5_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_6_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_7_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_8_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_9_load_1;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_10_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_long_unsigned_int128_signed_char_double_1_s_7;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_l_unsigned_int128_signed_char_double_1_s_8;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_lo_signed_char_double_1_s_9;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_loa_double_1_s_10;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_load_1_s_11;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_16_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_12;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_18_load_1;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_19_load_1;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_20_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_long_unsigned_int128_signed_char_double_1_s;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_l_unsigned_int128_signed_char_double_1_s;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_lo_signed_char_double_1_s;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_loa_double_1_s;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg_load_1_s;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_26_load_1;
input  [31:0] fir_ap_int_32_ap_int_32_shift_reg;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_28_load_1;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_29_load_1;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_30_load_1;
input  [31:0] mux_case_31591_phi_reload;
input  [31:0] mux_case_32592_phi_reload;
input  [31:0] mux_case_33593_phi_reload;
input  [31:0] mux_case_34594_phi_reload;
input  [31:0] mux_case_35595_phi_reload;
input  [31:0] mux_case_36596_phi_reload;
input  [31:0] mux_case_37597_phi_reload;
input  [31:0] mux_case_38598_phi_reload;
input  [31:0] mux_case_39599_phi_reload;
input  [31:0] mux_case_40600_phi_reload;
input  [31:0] mux_case_41601_phi_reload;
input  [31:0] mux_case_42602_phi_reload;
input  [31:0] mux_case_43603_phi_reload;
input  [31:0] mux_case_44604_phi_reload;
input  [31:0] mux_case_45605_phi_reload;
input  [31:0] mux_case_46606_phi_reload;
input  [31:0] mux_case_47607_phi_reload;
input  [31:0] mux_case_48608_phi_reload;
input  [31:0] mux_case_49609_phi_reload;
input  [31:0] mux_case_50610_phi_reload;
input  [31:0] mux_case_51611_phi_reload;
input  [31:0] mux_case_52612_phi_reload;
input  [31:0] mux_case_53613_phi_reload;
input  [31:0] mux_case_54614_phi_reload;
input  [31:0] mux_case_55615_phi_reload;
input  [31:0] mux_case_56616_phi_reload;
input  [31:0] mux_case_57617_phi_reload;
input  [31:0] mux_case_58618_phi_reload;
input  [31:0] mux_case_59619_phi_reload;
input  [31:0] mux_case_60620_phi_reload;
input  [31:0] mux_case_61621_phi_reload;
input  [31:0] mux_case_62622_phi_reload;
input  [31:0] mux_case_63623_phi_reload;
input  [31:0] mux_case_64624_phi_reload;
input  [31:0] mux_case_65625_phi_reload;
input  [31:0] mux_case_66626_phi_reload;
input  [31:0] mux_case_67627_phi_reload;
input  [31:0] mux_case_68628_phi_reload;
input  [31:0] mux_case_69629_phi_reload;
input  [31:0] mux_case_70630_phi_reload;
input  [31:0] mux_case_71631_phi_reload;
input  [31:0] mux_case_72632_phi_reload;
input  [31:0] mux_case_73633_phi_reload;
input  [31:0] mux_case_74634_phi_reload;
input  [31:0] mux_case_75635_phi_reload;
input  [31:0] mux_case_76636_phi_reload;
input  [31:0] mux_case_77637_phi_reload;
input  [31:0] mux_case_78638_phi_reload;
input  [31:0] mux_case_79639_phi_reload;
input  [31:0] mux_case_80640_phi_reload;
input  [31:0] mux_case_81641_phi_reload;
input  [31:0] mux_case_82642_phi_reload;
input  [31:0] mux_case_83643_phi_reload;
input  [31:0] mux_case_84644_phi_reload;
input  [31:0] mux_case_85645_phi_reload;
input  [31:0] mux_case_86646_phi_reload;
input  [31:0] mux_case_87647_phi_reload;
input  [31:0] mux_case_88648_phi_reload;
input  [31:0] mux_case_89649_phi_reload;
input  [31:0] mux_case_90650_phi_reload;
input  [31:0] mux_case_91651_phi_reload;
input  [31:0] mux_case_92652_phi_reload;
input  [31:0] mux_case_93653_phi_reload;
input  [31:0] mux_case_94654_phi_reload;
input  [31:0] mux_case_95655_phi_reload;
input  [31:0] mux_case_96656_phi_reload;
input  [31:0] mux_case_97657_phi_reload;
input  [31:0] mux_case_98658_phi_reload;
input  [31:0] mux_case_99659_phi_reload;
input  [31:0] mux_case_100660_phi_reload;
input  [31:0] mux_case_101661_phi_reload;
input  [31:0] mux_case_102662_phi_reload;
input  [31:0] mux_case_103663_phi_reload;
input  [31:0] mux_case_104664_phi_reload;
input  [31:0] mux_case_105665_phi_reload;
input  [31:0] mux_case_106666_phi_reload;
input  [31:0] mux_case_107667_phi_reload;
input  [31:0] mux_case_108668_phi_reload;
input  [31:0] mux_case_109669_phi_reload;
input  [31:0] mux_case_110670_phi_reload;
input  [31:0] mux_case_111671_phi_reload;
input  [31:0] mux_case_112672_phi_reload;
input  [31:0] mux_case_113673_phi_reload;
input  [31:0] mux_case_114674_phi_reload;
input  [31:0] mux_case_115675_phi_reload;
input  [31:0] mux_case_116676_phi_reload;
input  [31:0] mux_case_117677_phi_reload;
input  [31:0] mux_case_118678_phi_reload;
input  [31:0] mux_case_119679_phi_reload;
input  [31:0] mux_case_120680_phi_reload;
input  [31:0] mux_case_121681_phi_reload;
input  [31:0] mux_case_122682_phi_reload;
input  [31:0] mux_case_123683_phi_reload;
input  [31:0] mux_case_124684_phi_reload;
input  [31:0] mux_case_125685_phi_reload;
input  [31:0] mux_case_126686_phi_reload;
input  [31:0] p_ZZ3firP6ap_intILi32EES0_E9shift_reg_127_load;
output  [31:0] acc_V_out;
output   acc_V_out_ap_vld;

reg ap_done;
reg ap_idle;
reg ap_ready;
reg acc_V_out_ap_vld;

(* fsm_encoding = "none" *) reg   [3:0] ap_CS_fsm;
wire    ap_CS_fsm_state1;
reg   [31:0] acc_V_fu_306;
wire   [31:0] acc_V_1_fu_1516_p2;
wire    ap_CS_fsm_state2;
wire   [0:0] tmp_fu_1106_p3;
wire    ap_CS_fsm_state4;
reg   [7:0] i_1_fu_310;
wire   [7:0] add_ln33_fu_1522_p2;
wire  signed [31:0] tmp_2_fu_1376_p130;
wire  signed [31:0] tmp_1_fu_1114_p130;
wire   [31:0] mul_ln886_fu_1510_p2;
reg   [3:0] ap_NS_fsm;
reg    ap_ST_fsm_state1_blk;
wire    ap_ST_fsm_state2_blk;
wire    ap_ST_fsm_state3_blk;
wire    ap_ST_fsm_state4_blk;
wire    ap_ce_reg;

// power-on initialization
initial begin
#0 ap_CS_fsm = 4'd1;
end

fir_mux_1288_32_1_1 #(
    .ID( 1 ),
    .NUM_STAGE( 1 ),
    .din0_WIDTH( 32 ),
    .din1_WIDTH( 32 ),
    .din2_WIDTH( 32 ),
    .din3_WIDTH( 32 ),
    .din4_WIDTH( 32 ),
    .din5_WIDTH( 32 ),
    .din6_WIDTH( 32 ),
    .din7_WIDTH( 32 ),
    .din8_WIDTH( 32 ),
    .din9_WIDTH( 32 ),
    .din10_WIDTH( 32 ),
    .din11_WIDTH( 32 ),
    .din12_WIDTH( 32 ),
    .din13_WIDTH( 32 ),
    .din14_WIDTH( 32 ),
    .din15_WIDTH( 32 ),
    .din16_WIDTH( 32 ),
    .din17_WIDTH( 32 ),
    .din18_WIDTH( 32 ),
    .din19_WIDTH( 32 ),
    .din20_WIDTH( 32 ),
    .din21_WIDTH( 32 ),
    .din22_WIDTH( 32 ),
    .din23_WIDTH( 32 ),
    .din24_WIDTH( 32 ),
    .din25_WIDTH( 32 ),
    .din26_WIDTH( 32 ),
    .din27_WIDTH( 32 ),
    .din28_WIDTH( 32 ),
    .din29_WIDTH( 32 ),
    .din30_WIDTH( 32 ),
    .din31_WIDTH( 32 ),
    .din32_WIDTH( 32 ),
    .din33_WIDTH( 32 ),
    .din34_WIDTH( 32 ),
    .din35_WIDTH( 32 ),
    .din36_WIDTH( 32 ),
    .din37_WIDTH( 32 ),
    .din38_WIDTH( 32 ),
    .din39_WIDTH( 32 ),
    .din40_WIDTH( 32 ),
    .din41_WIDTH( 32 ),
    .din42_WIDTH( 32 ),
    .din43_WIDTH( 32 ),
    .din44_WIDTH( 32 ),
    .din45_WIDTH( 32 ),
    .din46_WIDTH( 32 ),
    .din47_WIDTH( 32 ),
    .din48_WIDTH( 32 ),
    .din49_WIDTH( 32 ),
    .din50_WIDTH( 32 ),
    .din51_WIDTH( 32 ),
    .din52_WIDTH( 32 ),
    .din53_WIDTH( 32 ),
    .din54_WIDTH( 32 ),
    .din55_WIDTH( 32 ),
    .din56_WIDTH( 32 ),
    .din57_WIDTH( 32 ),
    .din58_WIDTH( 32 ),
    .din59_WIDTH( 32 ),
    .din60_WIDTH( 32 ),
    .din61_WIDTH( 32 ),
    .din62_WIDTH( 32 ),
    .din63_WIDTH( 32 ),
    .din64_WIDTH( 32 ),
    .din65_WIDTH( 32 ),
    .din66_WIDTH( 32 ),
    .din67_WIDTH( 32 ),
    .din68_WIDTH( 32 ),
    .din69_WIDTH( 32 ),
    .din70_WIDTH( 32 ),
    .din71_WIDTH( 32 ),
    .din72_WIDTH( 32 ),
    .din73_WIDTH( 32 ),
    .din74_WIDTH( 32 ),
    .din75_WIDTH( 32 ),
    .din76_WIDTH( 32 ),
    .din77_WIDTH( 32 ),
    .din78_WIDTH( 32 ),
    .din79_WIDTH( 32 ),
    .din80_WIDTH( 32 ),
    .din81_WIDTH( 32 ),
    .din82_WIDTH( 32 ),
    .din83_WIDTH( 32 ),
    .din84_WIDTH( 32 ),
    .din85_WIDTH( 32 ),
    .din86_WIDTH( 32 ),
    .din87_WIDTH( 32 ),
    .din88_WIDTH( 32 ),
    .din89_WIDTH( 32 ),
    .din90_WIDTH( 32 ),
    .din91_WIDTH( 32 ),
    .din92_WIDTH( 32 ),
    .din93_WIDTH( 32 ),
    .din94_WIDTH( 32 ),
    .din95_WIDTH( 32 ),
    .din96_WIDTH( 32 ),
    .din97_WIDTH( 32 ),
    .din98_WIDTH( 32 ),
    .din99_WIDTH( 32 ),
    .din100_WIDTH( 32 ),
    .din101_WIDTH( 32 ),
    .din102_WIDTH( 32 ),
    .din103_WIDTH( 32 ),
    .din104_WIDTH( 32 ),
    .din105_WIDTH( 32 ),
    .din106_WIDTH( 32 ),
    .din107_WIDTH( 32 ),
    .din108_WIDTH( 32 ),
    .din109_WIDTH( 32 ),
    .din110_WIDTH( 32 ),
    .din111_WIDTH( 32 ),
    .din112_WIDTH( 32 ),
    .din113_WIDTH( 32 ),
    .din114_WIDTH( 32 ),
    .din115_WIDTH( 32 ),
    .din116_WIDTH( 32 ),
    .din117_WIDTH( 32 ),
    .din118_WIDTH( 32 ),
    .din119_WIDTH( 32 ),
    .din120_WIDTH( 32 ),
    .din121_WIDTH( 32 ),
    .din122_WIDTH( 32 ),
    .din123_WIDTH( 32 ),
    .din124_WIDTH( 32 ),
    .din125_WIDTH( 32 ),
    .din126_WIDTH( 32 ),
    .din127_WIDTH( 32 ),
    .din128_WIDTH( 8 ),
    .dout_WIDTH( 32 ))
mux_1288_32_1_1_U131(
    .din0(32'd10),
    .din1(32'd11),
    .din2(32'd11),
    .din3(32'd8),
    .din4(32'd3),
    .din5(32'd4294967293),
    .din6(32'd4294967288),
    .din7(32'd4294967285),
    .din8(32'd4294967285),
    .din9(32'd4294967286),
    .din10(32'd4294967286),
    .din11(32'd4294967286),
    .din12(32'd4294967286),
    .din13(32'd4294967286),
    .din14(32'd4294967286),
    .din15(32'd4294967286),
    .din16(32'd4294967286),
    .din17(32'd4294967286),
    .din18(32'd4294967286),
    .din19(32'd4294967286),
    .din20(32'd4294967286),
    .din21(32'd4294967286),
    .din22(32'd4294967286),
    .din23(32'd4294967286),
    .din24(32'd4294967286),
    .din25(32'd4294967286),
    .din26(32'd4294967286),
    .din27(32'd4294967286),
    .din28(32'd4294967286),
    .din29(32'd4294967286),
    .din30(32'd4294967286),
    .din31(32'd4294967286),
    .din32(32'd4294967286),
    .din33(32'd4294967285),
    .din34(32'd4294967285),
    .din35(32'd4294967288),
    .din36(32'd4294967293),
    .din37(32'd3),
    .din38(32'd8),
    .din39(32'd11),
    .din40(32'd11),
    .din41(32'd10),
    .din42(32'd10),
    .din43(32'd10),
    .din44(32'd10),
    .din45(32'd10),
    .din46(32'd10),
    .din47(32'd10),
    .din48(32'd10),
    .din49(32'd11),
    .din50(32'd11),
    .din51(32'd8),
    .din52(32'd3),
    .din53(32'd4294967293),
    .din54(32'd4294967288),
    .din55(32'd4294967285),
    .din56(32'd4294967285),
    .din57(32'd4294967286),
    .din58(32'd4294967286),
    .din59(32'd4294967286),
    .din60(32'd4294967286),
    .din61(32'd4294967286),
    .din62(32'd4294967286),
    .din63(32'd4294967286),
    .din64(32'd4294967286),
    .din65(32'd4294967285),
    .din66(32'd4294967285),
    .din67(32'd4294967288),
    .din68(32'd4294967293),
    .din69(32'd3),
    .din70(32'd8),
    .din71(32'd11),
    .din72(32'd11),
    .din73(32'd10),
    .din74(32'd10),
    .din75(32'd10),
    .din76(32'd10),
    .din77(32'd10),
    .din78(32'd10),
    .din79(32'd10),
    .din80(32'd10),
    .din81(32'd11),
    .din82(32'd11),
    .din83(32'd8),
    .din84(32'd3),
    .din85(32'd4294967293),
    .din86(32'd4294967288),
    .din87(32'd4294967285),
    .din88(32'd4294967285),
    .din89(32'd4294967286),
    .din90(32'd4294967286),
    .din91(32'd4294967286),
    .din92(32'd4294967286),
    .din93(32'd4294967286),
    .din94(32'd4294967286),
    .din95(32'd4294967286),
    .din96(32'd4294967286),
    .din97(32'd4294967285),
    .din98(32'd4294967285),
    .din99(32'd4294967288),
    .din100(32'd4294967293),
    .din101(32'd3),
    .din102(32'd8),
    .din103(32'd11),
    .din104(32'd11),
    .din105(32'd10),
    .din106(32'd10),
    .din107(32'd10),
    .din108(32'd10),
    .din109(32'd10),
    .din110(32'd10),
    .din111(32'd10),
    .din112(32'd10),
    .din113(32'd10),
    .din114(32'd10),
    .din115(32'd10),
    .din116(32'd10),
    .din117(32'd10),
    .din118(32'd10),
    .din119(32'd10),
    .din120(32'd10),
    .din121(32'd10),
    .din122(32'd10),
    .din123(32'd10),
    .din124(32'd10),
    .din125(32'd10),
    .din126(32'd10),
    .din127(32'd10),
    .din128(i_1_fu_310),
    .dout(tmp_1_fu_1114_p130)
);

fir_mux_1288_32_1_1 #(
    .ID( 1 ),
    .NUM_STAGE( 1 ),
    .din0_WIDTH( 32 ),
    .din1_WIDTH( 32 ),
    .din2_WIDTH( 32 ),
    .din3_WIDTH( 32 ),
    .din4_WIDTH( 32 ),
    .din5_WIDTH( 32 ),
    .din6_WIDTH( 32 ),
    .din7_WIDTH( 32 ),
    .din8_WIDTH( 32 ),
    .din9_WIDTH( 32 ),
    .din10_WIDTH( 32 ),
    .din11_WIDTH( 32 ),
    .din12_WIDTH( 32 ),
    .din13_WIDTH( 32 ),
    .din14_WIDTH( 32 ),
    .din15_WIDTH( 32 ),
    .din16_WIDTH( 32 ),
    .din17_WIDTH( 32 ),
    .din18_WIDTH( 32 ),
    .din19_WIDTH( 32 ),
    .din20_WIDTH( 32 ),
    .din21_WIDTH( 32 ),
    .din22_WIDTH( 32 ),
    .din23_WIDTH( 32 ),
    .din24_WIDTH( 32 ),
    .din25_WIDTH( 32 ),
    .din26_WIDTH( 32 ),
    .din27_WIDTH( 32 ),
    .din28_WIDTH( 32 ),
    .din29_WIDTH( 32 ),
    .din30_WIDTH( 32 ),
    .din31_WIDTH( 32 ),
    .din32_WIDTH( 32 ),
    .din33_WIDTH( 32 ),
    .din34_WIDTH( 32 ),
    .din35_WIDTH( 32 ),
    .din36_WIDTH( 32 ),
    .din37_WIDTH( 32 ),
    .din38_WIDTH( 32 ),
    .din39_WIDTH( 32 ),
    .din40_WIDTH( 32 ),
    .din41_WIDTH( 32 ),
    .din42_WIDTH( 32 ),
    .din43_WIDTH( 32 ),
    .din44_WIDTH( 32 ),
    .din45_WIDTH( 32 ),
    .din46_WIDTH( 32 ),
    .din47_WIDTH( 32 ),
    .din48_WIDTH( 32 ),
    .din49_WIDTH( 32 ),
    .din50_WIDTH( 32 ),
    .din51_WIDTH( 32 ),
    .din52_WIDTH( 32 ),
    .din53_WIDTH( 32 ),
    .din54_WIDTH( 32 ),
    .din55_WIDTH( 32 ),
    .din56_WIDTH( 32 ),
    .din57_WIDTH( 32 ),
    .din58_WIDTH( 32 ),
    .din59_WIDTH( 32 ),
    .din60_WIDTH( 32 ),
    .din61_WIDTH( 32 ),
    .din62_WIDTH( 32 ),
    .din63_WIDTH( 32 ),
    .din64_WIDTH( 32 ),
    .din65_WIDTH( 32 ),
    .din66_WIDTH( 32 ),
    .din67_WIDTH( 32 ),
    .din68_WIDTH( 32 ),
    .din69_WIDTH( 32 ),
    .din70_WIDTH( 32 ),
    .din71_WIDTH( 32 ),
    .din72_WIDTH( 32 ),
    .din73_WIDTH( 32 ),
    .din74_WIDTH( 32 ),
    .din75_WIDTH( 32 ),
    .din76_WIDTH( 32 ),
    .din77_WIDTH( 32 ),
    .din78_WIDTH( 32 ),
    .din79_WIDTH( 32 ),
    .din80_WIDTH( 32 ),
    .din81_WIDTH( 32 ),
    .din82_WIDTH( 32 ),
    .din83_WIDTH( 32 ),
    .din84_WIDTH( 32 ),
    .din85_WIDTH( 32 ),
    .din86_WIDTH( 32 ),
    .din87_WIDTH( 32 ),
    .din88_WIDTH( 32 ),
    .din89_WIDTH( 32 ),
    .din90_WIDTH( 32 ),
    .din91_WIDTH( 32 ),
    .din92_WIDTH( 32 ),
    .din93_WIDTH( 32 ),
    .din94_WIDTH( 32 ),
    .din95_WIDTH( 32 ),
    .din96_WIDTH( 32 ),
    .din97_WIDTH( 32 ),
    .din98_WIDTH( 32 ),
    .din99_WIDTH( 32 ),
    .din100_WIDTH( 32 ),
    .din101_WIDTH( 32 ),
    .din102_WIDTH( 32 ),
    .din103_WIDTH( 32 ),
    .din104_WIDTH( 32 ),
    .din105_WIDTH( 32 ),
    .din106_WIDTH( 32 ),
    .din107_WIDTH( 32 ),
    .din108_WIDTH( 32 ),
    .din109_WIDTH( 32 ),
    .din110_WIDTH( 32 ),
    .din111_WIDTH( 32 ),
    .din112_WIDTH( 32 ),
    .din113_WIDTH( 32 ),
    .din114_WIDTH( 32 ),
    .din115_WIDTH( 32 ),
    .din116_WIDTH( 32 ),
    .din117_WIDTH( 32 ),
    .din118_WIDTH( 32 ),
    .din119_WIDTH( 32 ),
    .din120_WIDTH( 32 ),
    .din121_WIDTH( 32 ),
    .din122_WIDTH( 32 ),
    .din123_WIDTH( 32 ),
    .din124_WIDTH( 32 ),
    .din125_WIDTH( 32 ),
    .din126_WIDTH( 32 ),
    .din127_WIDTH( 32 ),
    .din128_WIDTH( 8 ),
    .dout_WIDTH( 32 ))
mux_1288_32_1_1_U132(
    .din0(x),
    .din1(fir_ap_int_32_ap_int_32_shift_reg_1_load_1),
    .din2(fir_ap_int_32_ap_int_32_shift_reg_2_load_1),
    .din3(fir_ap_int_32_ap_int_32_shift_reg_3_load_1),
    .din4(fir_ap_int_32_ap_int_32_shift_reg_4_load_1),
    .din5(fir_ap_int_32_ap_int_32_shift_reg_5_load_1),
    .din6(fir_ap_int_32_ap_int_32_shift_reg_6_load_1),
    .din7(fir_ap_int_32_ap_int_32_shift_reg_7_load_1),
    .din8(fir_ap_int_32_ap_int_32_shift_reg_8_load_1),
    .din9(fir_ap_int_32_ap_int_32_shift_reg_9_load_1),
    .din10(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_10_load_1),
    .din11(fir_ap_int_32_ap_int_32_shift_reg_long_unsigned_int128_signed_char_double_1_s_7),
    .din12(fir_ap_int_32_ap_int_32_shift_reg_l_unsigned_int128_signed_char_double_1_s_8),
    .din13(fir_ap_int_32_ap_int_32_shift_reg_lo_signed_char_double_1_s_9),
    .din14(fir_ap_int_32_ap_int_32_shift_reg_loa_double_1_s_10),
    .din15(fir_ap_int_32_ap_int_32_shift_reg_load_1_s_11),
    .din16(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_16_load_1),
    .din17(fir_ap_int_32_ap_int_32_shift_reg_12),
    .din18(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_18_load_1),
    .din19(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_19_load_1),
    .din20(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_20_load_1),
    .din21(fir_ap_int_32_ap_int_32_shift_reg_long_unsigned_int128_signed_char_double_1_s),
    .din22(fir_ap_int_32_ap_int_32_shift_reg_l_unsigned_int128_signed_char_double_1_s),
    .din23(fir_ap_int_32_ap_int_32_shift_reg_lo_signed_char_double_1_s),
    .din24(fir_ap_int_32_ap_int_32_shift_reg_loa_double_1_s),
    .din25(fir_ap_int_32_ap_int_32_shift_reg_load_1_s),
    .din26(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_26_load_1),
    .din27(fir_ap_int_32_ap_int_32_shift_reg),
    .din28(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_28_load_1),
    .din29(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_29_load_1),
    .din30(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_30_load_1),
    .din31(mux_case_31591_phi_reload),
    .din32(mux_case_32592_phi_reload),
    .din33(mux_case_33593_phi_reload),
    .din34(mux_case_34594_phi_reload),
    .din35(mux_case_35595_phi_reload),
    .din36(mux_case_36596_phi_reload),
    .din37(mux_case_37597_phi_reload),
    .din38(mux_case_38598_phi_reload),
    .din39(mux_case_39599_phi_reload),
    .din40(mux_case_40600_phi_reload),
    .din41(mux_case_41601_phi_reload),
    .din42(mux_case_42602_phi_reload),
    .din43(mux_case_43603_phi_reload),
    .din44(mux_case_44604_phi_reload),
    .din45(mux_case_45605_phi_reload),
    .din46(mux_case_46606_phi_reload),
    .din47(mux_case_47607_phi_reload),
    .din48(mux_case_48608_phi_reload),
    .din49(mux_case_49609_phi_reload),
    .din50(mux_case_50610_phi_reload),
    .din51(mux_case_51611_phi_reload),
    .din52(mux_case_52612_phi_reload),
    .din53(mux_case_53613_phi_reload),
    .din54(mux_case_54614_phi_reload),
    .din55(mux_case_55615_phi_reload),
    .din56(mux_case_56616_phi_reload),
    .din57(mux_case_57617_phi_reload),
    .din58(mux_case_58618_phi_reload),
    .din59(mux_case_59619_phi_reload),
    .din60(mux_case_60620_phi_reload),
    .din61(mux_case_61621_phi_reload),
    .din62(mux_case_62622_phi_reload),
    .din63(mux_case_63623_phi_reload),
    .din64(mux_case_64624_phi_reload),
    .din65(mux_case_65625_phi_reload),
    .din66(mux_case_66626_phi_reload),
    .din67(mux_case_67627_phi_reload),
    .din68(mux_case_68628_phi_reload),
    .din69(mux_case_69629_phi_reload),
    .din70(mux_case_70630_phi_reload),
    .din71(mux_case_71631_phi_reload),
    .din72(mux_case_72632_phi_reload),
    .din73(mux_case_73633_phi_reload),
    .din74(mux_case_74634_phi_reload),
    .din75(mux_case_75635_phi_reload),
    .din76(mux_case_76636_phi_reload),
    .din77(mux_case_77637_phi_reload),
    .din78(mux_case_78638_phi_reload),
    .din79(mux_case_79639_phi_reload),
    .din80(mux_case_80640_phi_reload),
    .din81(mux_case_81641_phi_reload),
    .din82(mux_case_82642_phi_reload),
    .din83(mux_case_83643_phi_reload),
    .din84(mux_case_84644_phi_reload),
    .din85(mux_case_85645_phi_reload),
    .din86(mux_case_86646_phi_reload),
    .din87(mux_case_87647_phi_reload),
    .din88(mux_case_88648_phi_reload),
    .din89(mux_case_89649_phi_reload),
    .din90(mux_case_90650_phi_reload),
    .din91(mux_case_91651_phi_reload),
    .din92(mux_case_92652_phi_reload),
    .din93(mux_case_93653_phi_reload),
    .din94(mux_case_94654_phi_reload),
    .din95(mux_case_95655_phi_reload),
    .din96(mux_case_96656_phi_reload),
    .din97(mux_case_97657_phi_reload),
    .din98(mux_case_98658_phi_reload),
    .din99(mux_case_99659_phi_reload),
    .din100(mux_case_100660_phi_reload),
    .din101(mux_case_101661_phi_reload),
    .din102(mux_case_102662_phi_reload),
    .din103(mux_case_103663_phi_reload),
    .din104(mux_case_104664_phi_reload),
    .din105(mux_case_105665_phi_reload),
    .din106(mux_case_106666_phi_reload),
    .din107(mux_case_107667_phi_reload),
    .din108(mux_case_108668_phi_reload),
    .din109(mux_case_109669_phi_reload),
    .din110(mux_case_110670_phi_reload),
    .din111(mux_case_111671_phi_reload),
    .din112(mux_case_112672_phi_reload),
    .din113(mux_case_113673_phi_reload),
    .din114(mux_case_114674_phi_reload),
    .din115(mux_case_115675_phi_reload),
    .din116(mux_case_116676_phi_reload),
    .din117(mux_case_117677_phi_reload),
    .din118(mux_case_118678_phi_reload),
    .din119(mux_case_119679_phi_reload),
    .din120(mux_case_120680_phi_reload),
    .din121(mux_case_121681_phi_reload),
    .din122(mux_case_122682_phi_reload),
    .din123(mux_case_123683_phi_reload),
    .din124(mux_case_124684_phi_reload),
    .din125(mux_case_125685_phi_reload),
    .din126(mux_case_126686_phi_reload),
    .din127(p_ZZ3firP6ap_intILi32EES0_E9shift_reg_127_load),
    .din128(i_1_fu_310),
    .dout(tmp_2_fu_1376_p130)
);

fir_mul_32s_32s_32_1_1 #(
    .ID( 1 ),
    .NUM_STAGE( 1 ),
    .din0_WIDTH( 32 ),
    .din1_WIDTH( 32 ),
    .dout_WIDTH( 32 ))
mul_32s_32s_32_1_1_U133(
    .din0(tmp_2_fu_1376_p130),
    .din1(tmp_1_fu_1114_p130),
    .dout(mul_ln886_fu_1510_p2)
);

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        ap_CS_fsm <= ap_ST_fsm_state1;
    end else begin
        ap_CS_fsm <= ap_NS_fsm;
    end
end

always @ (posedge ap_clk) begin
    if (((ap_start == 1'b1) & (1'b1 == ap_CS_fsm_state1))) begin
        acc_V_fu_306 <= 32'd0;
    end else if (((tmp_fu_1106_p3 == 1'd0) & (1'b1 == ap_CS_fsm_state2))) begin
        acc_V_fu_306 <= acc_V_1_fu_1516_p2;
    end
end

always @ (posedge ap_clk) begin
    if (((ap_start == 1'b1) & (1'b1 == ap_CS_fsm_state1))) begin
        i_1_fu_310 <= 8'd127;
    end else if (((tmp_fu_1106_p3 == 1'd0) & (1'b1 == ap_CS_fsm_state2))) begin
        i_1_fu_310 <= add_ln33_fu_1522_p2;
    end
end

always @ (*) begin
    if ((1'b1 == ap_CS_fsm_state4)) begin
        acc_V_out_ap_vld = 1'b1;
    end else begin
        acc_V_out_ap_vld = 1'b0;
    end
end

always @ (*) begin
    if ((ap_start == 1'b0)) begin
        ap_ST_fsm_state1_blk = 1'b1;
    end else begin
        ap_ST_fsm_state1_blk = 1'b0;
    end
end

assign ap_ST_fsm_state2_blk = 1'b0;

assign ap_ST_fsm_state3_blk = 1'b0;

assign ap_ST_fsm_state4_blk = 1'b0;

always @ (*) begin
    if (((1'b1 == ap_CS_fsm_state4) | ((ap_start == 1'b0) & (1'b1 == ap_CS_fsm_state1)))) begin
        ap_done = 1'b1;
    end else begin
        ap_done = 1'b0;
    end
end

always @ (*) begin
    if (((ap_start == 1'b0) & (1'b1 == ap_CS_fsm_state1))) begin
        ap_idle = 1'b1;
    end else begin
        ap_idle = 1'b0;
    end
end

always @ (*) begin
    if ((1'b1 == ap_CS_fsm_state4)) begin
        ap_ready = 1'b1;
    end else begin
        ap_ready = 1'b0;
    end
end

always @ (*) begin
    case (ap_CS_fsm)
        ap_ST_fsm_state1 : begin
            if (((ap_start == 1'b1) & (1'b1 == ap_CS_fsm_state1))) begin
                ap_NS_fsm = ap_ST_fsm_state2;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state1;
            end
        end
        ap_ST_fsm_state2 : begin
            if (((tmp_fu_1106_p3 == 1'd0) & (1'b1 == ap_CS_fsm_state2))) begin
                ap_NS_fsm = ap_ST_fsm_state2;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state3;
            end
        end
        ap_ST_fsm_state3 : begin
            ap_NS_fsm = ap_ST_fsm_state4;
        end
        ap_ST_fsm_state4 : begin
            ap_NS_fsm = ap_ST_fsm_state1;
        end
        default : begin
            ap_NS_fsm = 'bx;
        end
    endcase
end

assign acc_V_1_fu_1516_p2 = (mul_ln886_fu_1510_p2 + acc_V_fu_306);

assign acc_V_out = acc_V_fu_306;

assign add_ln33_fu_1522_p2 = ($signed(i_1_fu_310) + $signed(8'd255));

assign ap_CS_fsm_state1 = ap_CS_fsm[32'd0];

assign ap_CS_fsm_state2 = ap_CS_fsm[32'd1];

assign ap_CS_fsm_state4 = ap_CS_fsm[32'd3];

assign tmp_fu_1106_p3 = i_1_fu_310[32'd7];

endmodule //fir_fir_Pipeline_MAC
