/*
 * Hugo Gonzalez 2015.
 * dexstrings  - Extract information from .dex files
 *
 * compile:
 *     gcc -g -o dexstrings dexstrings.c -lm
 *     some warnings will be showed, you can ignore that.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/stat.h>

#define VERSION "0.6"

typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;

typedef struct {
	char dex[3];
	char newline[1];
	char ver[3];
	char zero[1];
} dex_magic;

typedef struct {
	dex_magic magic;
	u4 checksum[1];
	unsigned char signature[20];
	u4 file_size[1];
	u4 header_size[1];
	u4 endian_tag[1];
	u4 link_size[1];
	u4 link_off[1];
	u4 map_off[1];
	u4 string_ids_size[1];
	u4 string_ids_off[1];
	u4 type_ids_size[1];
	u4 type_ids_off[1];
	u4 proto_ids_size[1];
	u4 proto_ids_off[1];
	u4 field_ids_size[1];
	u4 field_ids_off[1];
	u4 method_ids_size[1];
	u4 method_ids_off[1];
	u4 class_defs_size[1];
	u4 class_defs_off[1];
	u4 data_size[1];
	u4 data_off[1];
} dex_header;

typedef struct {
	u4 class_idx[1];
	u4 access_flags[1];
	u4 superclass_idx[1];
	u4 interfaces_off[1];
	u4 source_file_idx[1];
	u4 annotations_off[1];
	u4 class_data_off[1];
	u4 static_values_off[1];
} class_def_struct;

typedef struct {
	u2 class_idx[1];
	u2 proto_idx[1];
	u4 name_idx[1];
} method_id_struct;

typedef struct {
	u4 string_data_off[1];
} string_id_struct;

typedef struct {
	u4 descriptor_idx[1];
} type_id_struct;

typedef struct {
    u4 shorty_idx[1];
    u4 return_type_idx[1];
    u4 parameters_off[1];
} proto_id_struct;

typedef struct {
    u2 class_idx[1];
    u2 type_idx[1];
    u4 name_idx[1];
} field_id_struct;


void printStrings2(u1 *file, u4 offset)
{
    u1 *uValues = file;
    int uLebValue, uLebValueLength;
    char *stringData;


    printf("%x, ",offset);
    /* Replace the uleb128_value function to put it inline */
    //uLebValue = uleb128_value(uValues+offset);
    u1 *ptr = uValues+offset;
    int result = *(ptr++);
    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    } 
    printf ("%i, ",result);
	stringData = malloc(result * sizeof(u1)+1);
    memcpy(stringData, ptr , result);
	stringData[result]='\0';	
	printf(".:%s:.\n",stringData);
	free(stringData);

}


void help_show_message(char name[])
{
	fprintf(stderr, "Usage: %s  <file.dex> [options]\n",name);
	fprintf(stderr, " options:\n");
 //   fprintf(stderr, "\t-a\tprint all the strings\n");
 //   fprintf(stderr, "\t-l\tprint all the strings with they classification\n");
    fprintf(stderr, "\t-t\tprint only the text strings\n");
 //   fprintf(stderr, "\t-c\tprint only the name of the classes\n");
 //   fprintf(stderr, "\t-m\tprint only the name of the methods\n");
}
int main(int argc, char *argv[])
{
	char *dexfile;
	FILE *input;
    u1 *fileinmemory;
	int i,c,j;

    int iFound;
    int iOnlyStrings=0;


	dex_header* header;
	class_def_struct class_def_item;

	method_id_struct method_id_item;
	method_id_struct* method_id_list;

	string_id_struct string_id_item;
	string_id_struct* string_id_list;

	type_id_struct type_id_item;
	type_id_struct* type_id_list;

    proto_id_struct* proto_id_list;
    field_id_struct* field_id_list; 
    class_def_struct* class_def_list;

	printf ("\n=== dexstrings %s - (c) 2015 Hugo Gonzalez @hugo_glez\n", VERSION);

	if (argc < 2) {
		help_show_message(argv[0]);
		return 1;
	}

	dexfile=argv[1];
	input = fopen(dexfile, "rb");
	if (input == NULL) {
		fprintf(stderr, "ERROR: Can't open dex file!\n");
		perror(dexfile);
		exit(1);
	}

    // Obtain the size of the file
    int fd = fileno(input);
    struct stat buffs;
    fstat(fd,&buffs);
    int filesize = buffs.st_size;

    // allocate memory, load all the file in memory
    fileinmemory = malloc(filesize*sizeof(u1));
    if (fileinmemory == NULL) {
        fprintf(stderr, "ERROR: Can't allocate memory!\n");
    }
	fread(fileinmemory,1,filesize,input); // file in memory contains the binary
    fclose(input);


    
    //  TODO : read all the parameters and DO something
        while ((c = getopt(argc, argv, "t")) != -1) {
                switch(c) {
     		case 't':
			    iOnlyStrings=2;
			    break;
            default:
                        help_show_message(argv[0]);
                        return 1;
                }
        }

	/* print dex header information */
    printf ("Dex file: %s\n",dexfile);

    header = (struct dex_header *)fileinmemory;

	if ( (strncmp(header->magic.dex,"dex",3) != 0) || 
	     (strncmp(header->magic.newline,"\n",1) != 0) || 
	     (strncmp(header->magic.zero,"\0",1) != 0 ) ) {
		fprintf (stderr, "ERROR: not a dex file\n");
		fclose(input);
		exit(1);
	}

	if (strncmp(header->magic.ver,"035",3) != 0) {
		fprintf (stderr,"Warning: Dex file version != 035\n");
	}


	if (*header->header_size != 0x70) {
		fprintf (stderr,"Warning: Header size != 0x70\n");
	}

	if (*header->endian_tag != 0x12345678) {
		fprintf (stderr,"Warning: Endian tag != 0x12345678\n");
	}




    //type_id_list = (struct type_id_struct *)fileinmemory + *header->type_ids_off;
    //proto_id_list = (struct proto_id_struct *) fileinmemory + *header->proto_ids_off;
    //field_id_list = (struct field_id_struct *) fileinmemory + *header->field_ids_off;
    //method_id_list = (struct method_id_struct *) fileinmemory + *header->method_ids_off;
    //class_id_list = (struct class_id_struct *) fileinmemory + *header->class_ids_off;

	/* strings */
    u2 strptr = sizeof(string_id_struct);
    
    //u2 strptr = 2;

	printf("======================\n");
	for (i= 0; i < *header->string_ids_size; i++) {
        string_id_list = (struct string_id_struct *) (fileinmemory + *header->string_ids_off + strptr * i); 
        iFound = 0;
		if (iOnlyStrings == 0) printf("%d : ", i);
        // check if the other guys are using this string.
        // types
        for (j=0; j < *header->type_ids_size; j++)
        {
            type_id_list = (struct type_id_struct *)(fileinmemory + *header->type_ids_off + sizeof(type_id_struct) * j);
            if (i == *type_id_list->descriptor_idx) { 
                if (iOnlyStrings == 0) printf("T");
                iFound++;
            }
        }
        // proto
        for (j=0; j < *header->proto_ids_size; j++)
        {
            proto_id_list = (struct proto_id_struct *)(fileinmemory + *header->proto_ids_off + sizeof(proto_id_struct) * j);
            if (i == *proto_id_list->shorty_idx)  { 
                if (iOnlyStrings == 0) printf("P");
                iFound++;
            }
        }
        // field
        for (j=0; j < *header->field_ids_size; j++)
        {
            field_id_list = (struct field_id_struct *)(fileinmemory + *header->field_ids_off + sizeof(field_id_struct) * j);
            if (i == *field_id_list->name_idx) {
                if (iOnlyStrings == 0) printf("F");
                iFound++;
            }
        }
        // method
        for (j=0; j < *header->method_ids_size; j++)
        {
            method_id_list = (struct method_id_struct *)(fileinmemory + *header->method_ids_off + sizeof(method_id_struct) * j);
            if (i == *method_id_list->name_idx) {
                if (iOnlyStrings == 0) printf("M");
                iFound++;
            }
        }
        // class
        for (j=0; j < *header->class_defs_size; j++)
        {
            class_def_list = (struct class_def_struct *)(fileinmemory + *header->class_defs_off + sizeof(class_def_struct) * j);
            if (i == *class_def_list->class_idx) {
                if (iOnlyStrings == 0) printf("C");
                iFound++;
            }
            if (i == *class_def_list->source_file_idx) {
                if (iOnlyStrings == 0) printf("S");
                iFound++;
            }
        }

		if (iOnlyStrings == 0) {
		    printf(" : ");
		    printStrings2(fileinmemory, *string_id_list->string_data_off); 
        }
        else {
            if (iFound == 0) {
            printf("%d : ", i);
		    printStrings2(fileinmemory, *string_id_list->string_data_off); 
            }
        }
	}

/*

	for (i=0;i<sizeof(method_id_item)*(*header.method_ids_size);i+=8) {
		printf ("method_id_list[%d]class=%x\n", i/8, *method_id_list[i/8].class_idx);
		printf ("method_id_list[%d]proto=%x\n", i/8, *method_id_list[i/8].proto_idx);
		printf ("method_id_list[%d]name=%x\n\n", i/8, *method_id_list[i/8].name_idx);
	}
*/


	free(fileinmemory);
	//free(method_id_list);
	//free(string_id_list);

	//fclose(input);
	return 0;
}
