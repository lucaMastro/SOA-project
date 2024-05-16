
all:
	gcc -c ./lib/input_password.c -o ./lib/input_password.o
	gcc -c ./lib/system_calls.c -o ./lib/system_calls.o
	mkdir ./bin
	gcc -o ./bin/add_path ./add_path.c ./lib/system_calls.o ./lib/input_password.o
	gcc -o ./bin/rm_path ./rm_path.c ./lib/system_calls.o ./lib/input_password.o
	gcc -o ./bin/get_paths ./get_paths.c ./lib/system_calls.o ./lib/input_password.o
	gcc -o ./bin/change_pass ./change_password.c ./lib/system_calls.o ./lib/input_password.o
	gcc -o ./bin/change_state ./change_monitor_state.c ./lib/system_calls.o ./lib/input_password.o

clean:
	rm -rf ./bin
	rm -f ./lib/*.o

