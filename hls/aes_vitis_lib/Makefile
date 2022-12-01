TOP=dut
FILE=flist.f
TB=src/tb.cpp
TARGET=work
TCL1=dir.tcl
TCL2=dir2.tcl
TCL3=dir3.tcl
run:
	@rm -rf $(TARGET)*
	@python3 ../../detection_flow/detection.py -t $(TOP) -f $(FILE) -s $(TB) -c $(TCL1) -c $(TCL2) -c $(TCL3) -w $(TARGET) --cosim