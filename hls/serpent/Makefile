TOP=serpent_encrypt
FILE=flist.f
TB=src/serpent_test.cpp
TARGET=work
TCL1=dir.tcl
TCL2=dir2.tcl

run:
	@rm -rf $(TARGET)*
	@python3 ../../detection_flow/detection.py -t $(TOP) -f $(FILE) -s $(TB) -c $(TCL1) -c $(TCL2) -w $(TARGET) --cosim