#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE (1<<12)
#define NUM_ITERATIONS 1

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static void out_32bit(uint16_t port_16, uint32_t value_32_bit){
	asm("outl %0,%1" : /* empty */ : "a" (value_32_bit), "Nd" (port_16) : "memory");

}

static void in_32bit(uint16_t port,uint32_t *value_32_bit){
	asm volatile("inl %1, %0" : "=a" (*value_32_bit) : "d" (port));
}


void HC_print8bit(uint8_t val)
{
	outb(0xE9, val);
}

void HC_print32bit(uint32_t val)
{
	out_32bit(0xEB,val);
}

void HC_printStr(char *str)
{	
	uint32_t gva = str-(char*)0;
	out_32bit(0xED,gva);
}

void HC_countDirtyPage(){

	out_32bit(0xAA,(uint32_t)0);
}



// int *address[100000];

uint32_t HC_get_ws_size(){
	int size;
	in_32bit(0xAB,&size);
	return size;
}

void HC_get_ws_addresses(uint32_t ws_addresses){
	out_32bit(0xAC,ws_addresses);
}

// void HC_outArrayaddr(uint64_t *addr){
// 	out_32bit(0xAC,addr-(uint64_t*)0);
// }


void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	HC_printStr("Started Running\n");


	for(uint32_t iteration_no = 0;iteration_no<NUM_ITERATIONS;iteration_no++){

		
		uint32_t ws_size = HC_get_ws_size();
		HC_print32bit(ws_size);
		uint32_t ws_addresses[ws_size];
		HC_get_ws_addresses((uint32_t)&ws_addresses);

		for(uint32_t i=0;i<ws_size;i++){
			// HC_print32bit(ws_addresses[i]);
			uint32_t ws_address = ws_addresses[i]*PAGE_SIZE;
			*(long *) ws_address = *(long *) ws_address;
		}

		HC_countDirtyPage();
	}

	// *(long *) 0x4000 = *(long *) 0x4000;
	// *(long *) 0x5000 = *(long *) 0x5000;
	*(long *) 0x6000 = *(long *) 0x6000;
	*(long *) 0x7000 = *(long *) 0x7000;
	*(long *) 0x8000 = *(long *) 0x8000;
	*(long *) 0x9000 = *(long *) 0x9000;
	*(long *) 0xA000 = *(long *) 0xA000;
	*(long *) 0x8741814 = *(long *) 0x8741814;
	HC_countDirtyPage();

	*(long *) 0x400 = 42;

	for (;;)
		asm("hlt" : /* empty */ : "a" (42) : "memory");
}
