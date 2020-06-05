#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#define SYSCALL_OFFSET 439
#define MAX_ARG_LENGTH_Z 65

char option = 0;
struct user_entry{
    char surname[MAX_ARG_LENGTH_Z];
    char name[MAX_ARG_LENGTH_Z];
    char phone_number[MAX_ARG_LENGTH_Z];
    char email[MAX_ARG_LENGTH_Z];
};

struct user_entry entry;
int action = 0;

int parse_args(int argc, char **argv){
    char options[] = "gidsnte";
    int option = 0;
    void *jump = &&read_option;
    for(int i = 1; i < argc; i++){
        goto *jump;
        read_option:
            if(argv[i][0] == '-'){
                option = (int)(strchr(options, argv[i][1]) - options);
                if(option > 6){
                    printf("Uncknown option: -%c.\n" , argv[i][1]);
                    return -1;
                }
                if(option < 3)
                    action = option;
                else
                    jump = &&read_value;
                continue;
            }
            else{
                printf("Option expected. Got \"%s\" instead.\n", argv[i]);
                return -1;
            }

        read_value:
            option -= 3;
            memset((char *)&entry + MAX_ARG_LENGTH_Z * option, 0, MAX_ARG_LENGTH_Z);
            strncpy((char *)&entry + MAX_ARG_LENGTH_Z * option, argv[i], MAX_ARG_LENGTH_Z);
            jump = &&read_option;
            continue;
    }
    if(jump == &&read_value){
        printf("Value expected. Got end of string instead.\n");
        return -1;
    }
    return 0;
}

void print_entry(struct user_entry *entry){
    printf("Surname:\t%s\n", entry->surname);
    printf("Name:\t\t%s\n", entry->name);
    if(*(entry->phone_number))
        printf("Phone number:\t%s\n", entry->phone_number);
    if(*(entry->email))
        printf("Email:\t\t%s\n", entry->email);
}

int main(int argc, char *argv[])
{
    if(parse_args(argc, argv))
        return -1;
    long status;
    switch(action){
        case 0:
            status = syscall(SYSCALL_OFFSET + action, &entry, entry.surname, entry.name);
            break;
        case 2:
            status = syscall(SYSCALL_OFFSET + action, entry.surname, entry.name);
            break;
        case 1:
            status = syscall(SYSCALL_OFFSET + action, &entry);
            break;
    }
    if(status)
        printf("Call was not successfull. Syscall returned %ld\n", status);
    else{
        printf("Call OK.\n");
        if(action == 0){
            print_entry(&entry);
        }
    }
    printf("Bye.\n");
    return 0;
}
