# Bitcoin mining with SAT solver

Prerequisites:

1. Python 2
2. https://www.cprover.org/cbmc/


Run instruction:

1. Add block header data to a json file `block.json`
2. Run `./make_c.py ./block.json <true|false> <range>`
   1. ./block.json - block header value
   2. true/false = sat/unsat
   3. range - nonce range
3. cbmc -DCBMC ./mine.c --Z3
   1. use cbmc -h to find other options for the SAT solve backend (insted of Z3 )
