#include<linux/fs.h>
#include<asm/uaccess.h>
#include<linux/slab.h>
#include<linux/string.h>
#include<linux/syscalls.h>
#include<linux/err.h>

#define MAX_ARG_LENGTH 64
#define MAX_ARG_LENGTH_Z (MAX_ARG_LENGTH + 1)

struct user_entry{
	char surname[MAX_ARG_LENGTH_Z];
	char name[MAX_ARG_LENGTH_Z];
	char phone_number[MAX_ARG_LENGTH_Z];
	char email[MAX_ARG_LENGTH_Z];
};

ssize_t get_arg_size(const char *arg){
    size_t result;
	if(arg == NULL)
		return -1; // arg is null
	result = strnlen_user(arg, MAX_ARG_LENGTH + 1);
	if(result < 2 || result > MAX_ARG_LENGTH + 1)
		return -1;
	return result;
}

int send_to_tchardev(const char *usrspace_str, size_t length){
       struct file *file;
       mm_segment_t fs;
       loff_t pos = 0;
       int status = 0;
       fs = get_fs();
       set_fs(KERNEL_DS);
       file = filp_open("/dev/tchardev", O_WRONLY, 0);
       if(IS_ERR(file))
            printk(KERN_ERR "Error opening file!");
       else
            printk(KERN_DEBUG "File opening is OK");
       if(IS_ERR(file) || vfs_write(file, usrspace_str, length, &pos) < 0)
            status = -16;
       if(!IS_ERR(file)){
            filp_close(file, NULL);
            printk(KERN_DEBUG "File close OK");
       }
       set_fs(fs);
       printk(KERN_DEBUG "Status is %d", status);
       return status;
}


int read_from_tchardev(char *to, size_t length){
       struct file *file;
       mm_segment_t fs;
       loff_t pos = 0;
       int status = 0;
       fs = get_fs();
       set_fs(KERNEL_DS);
       file = filp_open("/dev/tchardev", O_RDONLY, 0);
       if(IS_ERR(file))
            printk(KERN_ERR "Error opening file!");
       else
            printk(KERN_DEBUG "File opening is OK");

       if(IS_ERR(file) || vfs_read(file, to, length, &pos) < 0)
            status = -17;
       if(!IS_ERR(file)){
            printk(KERN_DEBUG "File closing commenced");
            filp_close(file, NULL);
            printk(KERN_DEBUG "File close OK");
       }
       set_fs(fs);
       printk(KERN_DEBUG "Status is %d", status);
       return status;
}

int valid_entry(struct user_entry *entry){
	return entry->surname == NULL || entry->name == NULL;
}

int parse_user_entry(struct user_entry *at_usr, char *k_str, size_t buffer_length){
	char prefix[] = {'S', 'N', 'P', 'E'};
	char offset[] = {8, 6, 13, 7}; // offsets of printed payload
	int i = 0, j = 0, a = 0, value_begin = 0;
	void *jump = &&read_prefix;

    printk(KERN_DEBUG "-> Parsing state: \n%s", k_str);
	// if k_str starts with "[Error.X]"
	if(k_str[0] == '[' && k_str[1] == 'E')
		return k_str[7]; // 7 is error code position

    printk(KERN_DEBUG "-> Parsing. Parsing entry.\n");

	for(; i < buffer_length; i++){
		goto *jump;

		read_prefix:
        printk(KERN_DEBUG "-> Parsing. At %d. Reading prefix.\n", i);
		for(; j < 4; j++){
			if(k_str[i] == prefix[j]){
				a = j;
				j = 0;
				break;
			}
		}
		if(j == 4) // if uncknown prefix it's either exit or format error
            return k_str[i] == '\0' ? 0 : -7;

		value_begin = i + offset[a] + 1;
		i += offset[a];
		printk(KERN_DEBUG "-> Parsing. At %d. Prefix is %d. Value begin is %d\n.", i, a, value_begin);
		jump = &&read_value;
		continue;

		read_value:
        printk(KERN_DEBUG "-> Parsing. At %d. Reading value.\n", i);
		if(k_str[i] == '\n' || k_str[i] == '\0')
		{
                        int struct_offset = MAX_ARG_LENGTH_Z * a;
                        printk(KERN_DEBUG "-> Parsing. At %d. Terminator caught.\n", i);
			printk(KERN_DEBUG "-> Parsing. At %d. Copying %d bytes from %d.\n", i, i - value_begin, value_begin);
            if(copy_to_user((char *)at_usr + struct_offset, k_str + value_begin, i - value_begin))
                return -17;
			if(k_str[i] == '\0')
				break;
            jump = &&read_prefix;
		}
		continue;
	}
	return 0;
}

char *build_get_str(const char *usr_surname, const char *usr_name, size_t *length){
    size_t result_length = 0;
    char *result, *curstr;
    ssize_t name_size = get_arg_size(usr_name);
	ssize_t surname_size = get_arg_size(usr_surname);
	if(surname_size < 0 || name_size < 0)
        return NULL;

    result_length = 6 + surname_size; // 6 is lengthof("-g -s ") withought leading 0
    result_length += 3 + name_size; // 3 is lengthof("-n ") withought leading 0

    *length = result_length;
    result = kmalloc(result_length, GFP_USER);
    curstr = result;

    strcpy(curstr, "-g -s ");

    curstr += 6;
    if(copy_from_user(curstr, usr_surname, surname_size))
        goto copy_error;
    if(name_size < 0)
        return result;

    curstr += surname_size - 1;
    strcpy(curstr, " -n ");
    curstr += 4;
    if(copy_from_user(curstr, usr_name, name_size))
        goto copy_error;
    return result;
    copy_error:
        printk(KERN_ERR "-> String building. Copy error\n.");
        kfree(result);
        return NULL;
}

int get_subentry_len(char *which){
    char *end = strnchr(which, MAX_ARG_LENGTH_Z, 0);
    return end ? end - ((char *)which) : 0; // leading zero is excluded
}

char *build_insert_str(struct user_entry *k_entry, size_t *length){
    int surname_size, name_size, pnumber_size, email_size;
    size_t result_length = 10; // 10 is length of "-i -s  -n "whithought leading zero
    char *result, *curstr;
    surname_size = get_subentry_len(k_entry->surname);
    printk(KERN_DEBUG "-> String building. Surname size: %d\n", surname_size);
    if(surname_size == 0)
        return NULL;
    result_length += surname_size;

    name_size = get_subentry_len(k_entry->name);
    printk(KERN_DEBUG "-> String building. Name size: %d\n", name_size);
    if(name_size == 0)
        return NULL;
    result_length += name_size;

    pnumber_size = get_subentry_len(k_entry->phone_number);
    printk(KERN_DEBUG "-> String building. Phone number size: %d\n", pnumber_size);
    if(pnumber_size)
        result_length += 4 + pnumber_size;

    email_size = get_subentry_len(k_entry->email);
    printk(KERN_DEBUG "-> String building. Email size: %d\n", email_size);
    if(email_size)
        result_length += 4 + email_size;

    result_length++; // add leading zero
    *length = result_length;
    result = kmalloc(result_length, GFP_USER);
    curstr = result;
    strcpy(curstr, "-i -s ");
    curstr += 6;
    strcpy(curstr, k_entry->surname);
    curstr += surname_size;
    strcpy(curstr, " -n ");
    curstr += 4;
    strcpy(curstr, k_entry->name);
    curstr += name_size;
    if(pnumber_size){
        strcpy(curstr, " -t ");
        curstr += 4;
        strcpy(curstr, k_entry->phone_number);
        curstr += pnumber_size;
    }
    if(email_size){
        strcpy(curstr, " -e ");
        curstr += 4;
        strcpy(curstr, k_entry->email);
        curstr += email_size;
    }
    *curstr = 0;
    return result;
}

SYSCALL_DEFINE3(get_user, struct user_entry*, at, const char *, surname, const char *, name){
	size_t length = 0;
	long state = 0;
	char *str;

    str = build_get_str(surname, name, &length);
	if(!str)
		return -8;

    state = send_to_tchardev(str, length);
    kfree(str);
	if(state)
		return -16; // sending error

	str = kzalloc(MAX_ARG_LENGTH * 8, GFP_USER);
	if(!str)
		return -8;

    state = read_from_tchardev(str, MAX_ARG_LENGTH * 8);
	if(state)
		state =  -17; // reading error
	else
        state = parse_user_entry(at, str, MAX_ARG_LENGTH * 8);
	kfree(str);
	return state;
}

SYSCALL_DEFINE1(insert_user, struct user_entry *, entry){
	struct user_entry k_entry;
	size_t length = 0;
	long state = 0;
	char *str;
	state = copy_from_user(&k_entry, entry, sizeof(struct user_entry));
	if(state)
		return -8;

    str = build_insert_str(&k_entry, &length);
    if(!str)
        return -8;

    state = send_to_tchardev(str, length);
    kfree(str);
    if(state){
    	return -16; // sending error
    }

	str = kzalloc(64, GFP_USER);
	if(!str)
		return -8;

	if(read_from_tchardev(str, 64))
		state = -17;
    else if(str[0] == '[' && str[1] == 'O') // if response string starts with [OK.X]
    	state =  0;
    else // otherwise, try reading the error code in [7]
    	state = str[7] >= 0 ? str[7] : -17;
    kfree(str);
    return state;
}

SYSCALL_DEFINE2(del_user, char *, surname, char *, name){
	size_t length = 0;
	long state = 0;
	char *str;

    str = build_get_str(surname, name, &length);
	if(!str)
		return -8;
    // change "-g -s " get request prefix to "-d -s " prefix of delete request
    str[1] = 'd';

    state = send_to_tchardev(str, length);
    kfree(str);
	if(state)
		return -16; // sending error

    str = kzalloc(64, GFP_USER);
	if(!str)
		return -8;

    if(read_from_tchardev(str, 64))
		state = -17;
    else if(str[0] == '[' && str[1] == 'O') // if response string starts with [OK.X]
    	state =  0;
    else // otherwise, try reading the error code in [7]
    	state = str[7] >= 0 ? str[7] : -17;
    kfree(str);
    return state;
}
