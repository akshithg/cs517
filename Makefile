clean:
	rm -rf *.cnf *.sat *.out

premine: clean
	gcc ./mine.c
	./a.out

sat: clean
	./make_c.py ./125552.json true 2
	cbmc -DCBMC ./mine.c

unsat: clean
	./make_c.py ./125552.json false 2
	cbmc -DCBMC ./mine.c
