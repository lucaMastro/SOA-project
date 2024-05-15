#include <stdio.h>
#include <termios.h>
#include <unistd.h>

char getch() {
    int ch;
    // struct to hold the terminal settings
    struct termios old_settings, new_settings;

    fflush(stdout);
    // take default setting in old_settings
    tcgetattr(STDIN_FILENO, &old_settings);
    // make of copy of it (Read my previous blog to know
    // more about how to copy struct)
    new_settings = old_settings;
    // change the settings for by disabling ECHO mode
    // read man page of termios.h for more settings info
    new_settings.c_lflag &= ~(ICANON | ECHO);
    // apply these new settings
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    // now take the input in this mode
    ch = getchar();
    // reset back to default settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    return ch;
}

void get_pass(char *out_buffer, int buff_size) {
    int i = 0;
    char c;
    while (i < buff_size - 1) {
        c = getch();
        if (c == '\n' || c == '\r') {
            out_buffer[i] = '\0';
            printf("\n");
            break;

        // 127 is backspace ASCII code
        } else if (c == 127 || c == 8) {
            if (i > 0) {
                // delete char from console
                printf("\b \b");
                i--;
            }
        } else {
            out_buffer[i++] = c;
            printf("*");
        }
    }
    out_buffer[buff_size - 1] = '\0';
    return;
}
