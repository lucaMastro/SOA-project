all:
	./load.sh
clean:
	./unload.sh
update:
	./unload.sh
	./load.sh
