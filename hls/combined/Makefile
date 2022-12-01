TOP=compute
FILE=flist.f
TB=src/tb.cpp
TARGET=work
TCL1=dir.tcl
TCL2=dir1.tcl
TCL3=dir2.tcl
TCL4=dir3.tcl
TARGET2=work_fib
TOP2=fib
TB2=src/tb_fib.cpp
TARGET3=work_fact
TOP3=fact
TB3=src/tb_fact.cpp
run:
	@rm -rf $(TARGET)*
	@python3 ../../detection_flow/detection.py -t $(TOP) -f $(FILE) -s $(TB) -c $(TCL1) -c $(TCL2)  -w $(TARGET) --cosim
	@python3 ../../detection_flow/detection.py -t $(TOP2) -f $(FILE) -s $(TB2) -c $(TCL3)  -w $(TARGET2) --cosim
	@python3 ../../detection_flow/detection.py -t $(TOP3) -f $(FILE) -s $(TB3) -c $(TCL4)  -w $(TARGET3) --cosim