#include<linux/fs.h>
#include<asm/uaccess.h>
#include<linux/slab.h>
#include<linux/vmalloc.h>
#include<linux/string.h>
#include<linux/syscalls.h>

#define MAX_ARG_LENGTH 64

struct user_entry{
	char *surname;
	char *name;
	char *phone_number;
	char *email;
};

struct list_node{
	const char *value;
	size_t length;
	struct list_node *next;
	int is_our_str : 1;
};

size_t get_arg_size(const char *arg){
    size_t result;
	if(arg == NULL)
		return -1; // arg is null
	result = strnlen_user(arg, MAX_ARG_LENGTH + 1); // + 1 since null-char is inclusive
	if(result < 2 || result > MAX_ARG_LENGTH + 1)
		return -2; // arg is out of valid length range
	return result;
}

struct list_node *node_usr_with_length(const char *from, size_t length){
	struct list_node *node = kmalloc(sizeof(struct list_node), GFP_KERNEL);
	if(!node)
		return NULL;
	node->value = from;
	node->length = length;
	node->next = NULL;
	node->is_our_str = 0;
        return node;
}

struct list_node *node_usr(const char *from){
	struct list_node *node;
	size_t len = get_arg_size(from);
    if(len < 0)
    	return NULL;
    node = kmalloc(sizeof(struct list_node), GFP_KERNEL);
	if(!node)
		return NULL;
	node->value = from;
	node->length = len;
	node->next = NULL;
	node->is_our_str = 0;
        return node;
}

struct list_node *node_from_krnl_str(char *from){
	struct list_node *node = kmalloc(sizeof(struct list_node), GFP_KERNEL);
	char *str;
	if(!node)
		goto exit;
	node->length = strlen(from);
	str = vmalloc_user(node->length);
	if(!node->value)
		goto error_on_vmalloc;
	if(copy_to_user(str, from, node->length))
		goto error_on_copy;
	node->value = str;
	node->next = NULL;
	node->is_our_str = 1;
	return node;

	error_on_copy:
	vfree(node->value);
	error_on_vmalloc:
	kfree(node);
	exit:
	return NULL;
}

void free_node_list(struct list_node *first){
	struct list_node *cur = first, *next;
	while(cur){
		if(cur->is_our_str)
			vfree(cur->value);
		next = cur;
		vfree(cur);
		cur = next;
	}
}

char *build_string(struct list_node *first, size_t length){
	struct list_node *cur = first;
	char *str = vmalloc_user(length);
	long status = 0;
	size_t i = 0;
	if(!str || !cur)
		return NULL;
	while(cur->next){
		status = copy_to_user(str + i, cur->value, cur->length - 1);
		if(status)
			goto error_on_copy;
		i += cur->length - 1;
		cur = cur->next;
	}
	if(cur){
		status = copy_to_user(str + i, cur->value, cur->length);
		if(status)
			goto error_on_copy;
	}
	return str;

	error_on_copy:
	vfree(str);
	return NULL;
}

size_t send_to_tchardev(const char *usrspace_str, size_t length){
       struct file *file;
       mm_segment_t fs;
       loff_t pos = 0;
       size_t status = 0;
       fs = get_fs();
       set_fs(KERNEL_DS);
       file = filp_open("/dev/tchardev", O_WRONLY, 0);
       if(!(file && !vfs_write(file, usrspace_str, length, &pos)))
               status = -16;
       filp_close(file, NULL);
       set_fs(fs);
       return status;
}

size_t read_from_tchardev(char *to, size_t length){
       struct file *file;
       mm_segment_t fs;
       loff_t pos = 0;
       size_t status = 0;
       fs = get_fs();
       set_fs(KERNEL_DS);
       file = filp_open("/dev/tchardev", O_RDONLY, 0);
       if(!(file && !vfs_read(file, to, length, &pos)))
                 status = -17;
       filp_close(file, NULL);
       set_fs(fs);
       return status;
}

int valid_entry(struct user_entry *entry){
	return entry->surname == NULL || entry->name == NULL;
}

size_t parse_user_entry(struct user_entry **at, const char *k_str, size_t buffer_length){
	struct user_entry *entry;
	size_t i = 0;
	size_t value_begin = 0;
	char prefix[] = {'S', 'N', 'E', 'T'};
	char tab[] = {8, 6, 7, 13};
	int j = 0, a = 0, error = -8;
	void *jump = &&read_prefix;
	// if k_str starts with "[Error.X]"
	if(k_str[0] == '[' && k_str[1] == 'E'){
		*at = NULL;
		return k_str[7];
	}
	entry = kzalloc(sizeof(struct user_entry), GFP_KERNEL);
	for(; i < buffer_length; i++){
		goto *jump;
		read_prefix:
		for(; j < 4; j++){
			if(prefix[j] == k_str[i]){
				a = j;
				break;
			}
		}
		if(j == 4)
			goto format_error;
		value_begin += tab[a] + 1;
		i += tab[a];
		jump = &&read_value;
		continue;

		read_value:
		if(k_str[i] == '\n' || k_str[i] == '\0')
		{
			vfree((char **)entry + a);
			((char **)entry)[a] = vmalloc(i - value_begin + 1);
			if(!((char **)entry)[a])
				goto memory_error;
			copy_to_user(((char **)entry)[a], k_str + value_begin, i - value_begin);
			put_user('\0', ((char **)entry)[a] + i - value_begin);
			jump = &&read_prefix;
			if(k_str[i] == '\0')
				break;
		}
		continue;
	}
	if(valid_entry(entry))
	{
		*at = entry;
		return 0;
	}

format_error:
	error = -17;
memory_error:
	for(j = 0; j < 4; j++)
		vfree(((char **)entry)[j]);
	kfree(entry);
	*at = NULL;
	return error;
}

void free_vstr_entry(struct user_entry *entry){
	if(entry){
		vfree(entry->surname);
		vfree(entry->name);
		vfree(entry->phone_number);
		vfree(entry->email);
		kfree(entry);
	}
}

SYSCALL_DEFINE3(get_user, struct user_entry*, at, const char *, surname, const char *, name){
	struct user_entry *inner_entry;
	size_t name_size = get_arg_size(surname);
	size_t surname_size = get_arg_size(name);
	size_t length = 0;
	size_t state = 0;
	struct list_node *first, *cur;
	char *str;
	// begin initialising list
	if(surname_size < 0 || name_size < 0)
		return -1; // unspecified surname or name
	first = node_from_krnl_str("-g -s ");
	if(!first)
		return -8; // memory error
	cur = first;
	length += cur->length - 1;
	cur->next = node_usr_with_length(surname, surname_size);
	if(!cur->next){
		free_node_list(first);
		return -8;
	}
	cur = cur->next;
	length += cur->length - 1;
	cur->next = node_from_krnl_str(" -n ");
	if(!cur->next){
		free_node_list(first);
		return -8;
	}
	cur->next->length += cur->length - 1;
	cur = cur->next;
	length += cur->length - 1;
	cur->next = node_usr_with_length(name, name_size);
	if(!cur->next){
		free_node_list(first);
		return -8;
	}
	length += cur->length;
	cur = cur->next;
	// end initialising list
	str = build_string(first, length);
	if(!str){
		free_node_list(first);
		return -8;
	}
	if(send_to_tchardev(str, length)){
		vfree(str);
		free_node_list(first);
		return -16; // sending error
	}
	vfree(str);
	free_node_list(first);
	str = kzalloc(MAX_ARG_LENGTH * 8, GFP_USER);
	if(!str)
		return -8;
	if(read_from_tchardev(str, MAX_ARG_LENGTH * 8)){
		vfree(str);
		return -17; // reading error
	}
	state = parse_user_entry(&inner_entry, str, MAX_ARG_LENGTH * 8);
	kfree(str);
	if(state)
		return state;
	state = copy_to_user(at, inner_entry, sizeof(struct user_entry));
	if(state)
		free_vstr_entry(inner_entry);
	return state;
}

SYSCALL_DEFINE1(insert_user, struct user_entry *, entry){
    char surname_prefix[] = " -s ";
    char name_prefix[] = " -n ";
    char phone_number_prefix[] = " -t ";
    char email_prefix[] = " -e ";
    char *prefices[4];
    char *str;
	struct list_node *first, *cur;
	struct user_entry inner;
	size_t state = 0;
	size_t length = 0;
	int j = 0;
    prefices[0] = surname_prefix;
    prefices[1] = name_prefix;
    prefices[2] = phone_number_prefix;
    prefices[3] = email_prefix;
	state = copy_from_user(&inner, entry, sizeof(struct user_entry));
	if(state)
		return -8;
	if(!valid_entry(&inner))
		return -1;
	first = node_from_krnl_str("-i");
    if(!first)
    	return -8;
    length += first->length;
    cur = first;
    for(j = 0; j < 4; j++){
        if(((char **)&inner)[j] || j < 2){
        	cur->next = node_from_krnl_str(prefices[j]);
            cur = cur->next;
            if(!cur){
            	free_node_list(first);
                return -8;
            }
            length += cur->length - 1;
            cur->next = node_usr(((char **)&inner)[j]);
            cur = cur->next;
            if(!cur){
            	free_node_list(first);
                return -8;
            }
            length += cur->length - 1;
        }
    }
    str = build_string(first, length);
    if(!str){
    	free_node_list(first);
        vfree(str);
    }
    if(send_to_tchardev(str, length)){
    	vfree(str);
    	free_node_list(first);
    	return -16; // sending error
	}
	vfree(str);
	free_node_list(first);
	str = kzalloc(64, GFP_USER);
	if(!str)
		return -8;
	if(read_from_tchardev(str, 64))
		state = -17;

    if(str[0] == '[' && str[1] == 'O')
    	state = 0;
    else
    	state = str[7] > 0 ? str[7] : -17;
    kfree(str);
        return state;
}

SYSCALL_DEFINE2(del_user, char *, surname, char *, name){
	size_t name_size = get_arg_size(surname);
	size_t surname_size = get_arg_size(name);
	size_t length = 0;
	size_t state = 0;
	struct list_node *first, *cur;
	char *str;
	// begin initialising list
	if(surname_size < 0 || name_size < 0)
		return -1; // unspecified surname or name
	first = node_from_krnl_str("-d -s ");
	if(!first)
		return -8; // memory error
	cur = first;
	length += cur->length - 1;
	cur->next = node_usr_with_length(surname, surname_size);
	if(!cur->next){
		free_node_list(first);
		return -8; // memory error
	}
	cur = cur->next;
	length += cur->length - 1;
	cur->next = node_from_krnl_str(" -n ");
	if(!cur->next){
		free_node_list(first);
		return -8;
	}
	cur->next->length += cur->length - 1;
	cur = cur->next;
	length += cur->length - 1;
	cur->next = node_usr_with_length(name, name_size);
	if(cur->next){
		free_node_list(first);
		return -8;
	}
	length += cur->length;
	cur = cur->next;
	// end initialising list
	str = build_string(first, length);
	if(!str){
		free_node_list(first);
		return -8;
	}
	if(send_to_tchardev(str, length)){
		vfree(str);
		free_node_list(first);
		return -16; // sending error
	}
	vfree(str);
	free_node_list(first);
        str = kzalloc(64, GFP_USER);
	if(!str)
		return -8;
	if(read_from_tchardev(str, 64))
            state = -17;

        if(str[0] == '[' && str[1] == 'O')
             state = 0;
        else
             state = str[7] > 0 ? str[7] : -17;
        kfree(str);
        return state;
}
