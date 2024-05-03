#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <stddef.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <math.h>

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)


uint64_t PAGE_SIZE = 0x1000;
uint64_t PTE_ENTRY_SIZE = 0x8;
#define CURRENT_TIME ((double)clock() / CLOCKS_PER_SEC)
#define QUANTUM 5 //1 second

uint64_t TOTAL_MEM_SIZE = (1<<30);
#define STACK_TOP (1<<21)
#define MAX_WS_SIZE 20000
#define N_SLOTS 2

// #define DEVICE_NAME "/dev/ioctl_device"


// #define MAJOR_NUM 100
// #define IOCTL_INVALIDATE_TLB _IOW(MAJOR_NUM, 0, unsigned long)
// static inline void flush_tlb(unsigned long hva,int tlb_invalidator_fd){

// 	if(ioctl(tlb_invalidator_fd,IOCTL_INVALIDATE_TLB,hva)==-1){
// 		perror("ioctl");
// 	}
	
// }



struct vm
{
    int dev_fd;
    int kvm_version;
    int vm_fd;
	char *mem[N_SLOTS];
	size_t total_mem_size;
};

struct vcpu
{
    int vcpu_id;
    int vcpu_fd;
    pthread_t vcpu_thread;
    struct kvm_run *kvm_run;
    int kvm_run_mmap_size;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    void *(*vcpu_thread_func)(void *);
};

timer_t timer;
int turn = 0;

void create_timer(int interval){

    struct itimerspec its;

    its.it_value.tv_sec = interval;
    its.it_value.tv_nsec = 0;

    its.it_interval.tv_sec = interval;
    its.it_interval.tv_nsec = 0;

    timer_create(CLOCK_MONOTONIC, NULL, &timer);

    timer_settime(timer, 0, &its, NULL);
}


void vm_init(struct vm *vm, size_t total_mem_size)
{
	int kvm_version;

	vm->dev_fd = open("/dev/kvm", O_RDWR);
	if (vm->dev_fd < 0) {
		perror("open /dev/kvm");
		exit(1);
	}

	kvm_version = ioctl(vm->dev_fd, KVM_GET_API_VERSION, 0);
	if (kvm_version < 0) {
		perror("KVM_GET_API_VERSION");
		exit(1);
	}

	if (kvm_version != KVM_API_VERSION) {
		fprintf(stderr, "Got KVM api version %d, expected %d\n",
			kvm_version, KVM_API_VERSION);
		exit(1);
	}

	vm->vm_fd = ioctl(vm->dev_fd, KVM_CREATE_VM, 0);
	if (vm->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		exit(1);
	}

	if (ioctl(vm->vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
			perror("KVM_SET_TSS_ADDR");
	exit(1);
	
	}

	uint64_t slot_size = total_mem_size/N_SLOTS;

	for(uint32_t i=0;i<N_SLOTS;i++){
		(vm->mem)[i] = mmap(NULL, slot_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

		if ((vm->mem)[i] == MAP_FAILED) {
			perror("mmap mem");
			exit(1);
		}

		// madvise((vm->mem)[i], slot_size, MADV_MERGEABLE);

		struct kvm_userspace_memory_region memreg;

		vm->total_mem_size = total_mem_size;
		memreg.slot = i;
		memreg.flags = KVM_MEM_LOG_DIRTY_PAGES;
		memreg.guest_phys_addr = ((uint64_t)i)*(slot_size);
		memreg.memory_size = slot_size;
		memreg.userspace_addr = (unsigned long)((vm->mem)[i]);

		if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
			perror("KVM_SET_USER_MEMORY_REGION");
			exit(1);
		}
	}
	
}

void vcpu_init(struct vm *vm, struct vcpu *vcpu)
{
	int vcpu_mmap_size;

	vcpu->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
                exit(1);
	}

	vcpu_mmap_size = ioctl(vm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vcpu_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
                exit(1);
	}

	vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vcpu->vcpu_fd, 0);
	if (vcpu->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		exit(1);
	}
}

int count_set_bits(uint64_t word) {
    int count = 0;
	// printf("Word: %lu\n",word);
    while (word) {
        count += (word&1);
        word >>= 1;
    }
    return count;
}

int count_dirty_pages(void *dirty_bitmap, size_t bitmap_size) {
    int dirty_page_count = 0;

    size_t bitmap_words = bitmap_size / sizeof(uint64_t);

    uint64_t *bitmap = (uint64_t *)dirty_bitmap;
	// printf("Words: %d",bitmap_words);
    for (size_t i = 0; i < bitmap_words; i++) {
        dirty_page_count += count_set_bits(bitmap[i]);
		// printf("Dirty Page Count %d\n",dirty_page_count);
    }
    return dirty_page_count;
}

int run_vm(struct vm *vm, struct vcpu *vcpu, size_t sz,int n_sampling_slots)
{
    static sigset_t sig_mask;
    sigfillset(&sig_mask);
    sigdelset(&sig_mask, SIGALRM); 
    struct kvm_signal_mask *signal_mask = malloc(sizeof(struct kvm_signal_mask) + sizeof(sigset_t));
    if (signal_mask == NULL) {
        perror("Failed to allocate memory for kvm_signal_mask");
        exit(1);
    }
    signal_mask->len = 8;

    memcpy(signal_mask->sigset, &sig_mask, signal_mask->len);

    if (ioctl(vcpu->vcpu_fd, KVM_SET_SIGNAL_MASK, signal_mask) < 0) {
        perror("Failed to set signal mask for VM");
        exit(1);
    }
    
    create_timer(QUANTUM);
	
	struct kvm_regs regs;
	uint64_t memval = 0;
	struct kvm_dirty_log dirty_log ;

	long page_size = sysconf(_SC_PAGE_SIZE);
	long total_slot_pages = vm->total_mem_size/(page_size*N_SLOTS);

	size_t bitmap_size = (size_t)ceil((double)(total_slot_pages) / 8);
	bitmap_size = ((bitmap_size + 7) / 8) * 8;
	uint32_t current_ws_size = 0;
	// int tlb_invalidator_fd = open(DEVICE_NAME,O_RDWR);
	
	for (;;) {

		ioctl(vcpu->vcpu_fd, KVM_RUN, 0);


		switch (vcpu->kvm_run->exit_reason) {
		case KVM_EXIT_HLT:
			goto check;

		case KVM_EXIT_INTR:

			memset(&dirty_log, 0, sizeof(dirty_log));
				dirty_log.slot=0;
				dirty_log.dirty_bitmap = malloc(bitmap_size);

				// int dirty_page_count = count_dirty_pages(dirty_log.dirty_bitmap,bitmap_size);
				// printf("Number of dirty pages in memory slot %d before: %d\n", dirty_log.slot, dirty_page_count);

				if(ioctl(vm->vm_fd, KVM_GET_DIRTY_LOG, &dirty_log)<0){
					perror("KVM_GET_DIRTY_LOG");
				}

				int dirty_page_count = count_dirty_pages(dirty_log.dirty_bitmap,bitmap_size);
				printf("Number of dirty pages in memory slot %d after: %d\n", 0, dirty_page_count);

				printf("\n");

			sigset_t mask;
            sigemptyset(&mask);  // Clear the signal set
            sigaddset(&mask, SIGALRM);  // Add SIGALRM to the set

            struct timespec timeout;
            timeout.tv_sec = 0;
            timeout.tv_nsec = 0;

            // Wait for signals with timeout
            siginfo_t info;
            if (sigtimedwait(&mask, &info, &timeout) == -1) {
                // Handle error or timeout here
            }
            continue;

		case KVM_EXIT_IO:

			if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
			    && vcpu->kvm_run->io.port == 0xE9) {
				char *p = (char *)vcpu->kvm_run;
				fwrite(p + vcpu->kvm_run->io.data_offset,
				       vcpu->kvm_run->io.size, 1, stdout);
				fflush(stdout);
				continue;
			}

			if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
			    && vcpu->kvm_run->io.port == 0xEB) {

				uint32_t *value_32_bit = (uint32_t *)((char *)vcpu->kvm_run+vcpu->kvm_run->io.data_offset);

				char buffer[20];
				snprintf(buffer, sizeof(buffer), "%u\n", *value_32_bit);

				fwrite(buffer, sizeof(char), strlen(buffer), stdout);
				fflush(stdout);
				continue;
			}

			if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
			    && vcpu->kvm_run->io.port == 0xED) {
				
				unsigned long *gva_address = (unsigned long *)((char *)vcpu->kvm_run+vcpu->kvm_run->io.data_offset);
				unsigned long gva = *gva_address;

				uint64_t slot_size = vm->total_mem_size/N_SLOTS;
				uint32_t slot_no = gva/slot_size;

				unsigned long hva = gva+(unsigned long)vm->mem[slot_no];

				char* str = (char*)hva;
				for(;str!=NULL && *str!='\0';str++){
					fwrite(str,sizeof(char),1,stdout);
					fflush(stdout);
				}
				

				continue;
			}
			if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
			    && vcpu->kvm_run->io.port == 0xAA) {
				
				int total_dirty_page_count = 0;

				for(int i=0;i<N_SLOTS;i++){

				memset(&dirty_log, 0, sizeof(dirty_log));
				dirty_log.slot=i;
				dirty_log.dirty_bitmap = malloc(bitmap_size);

				if(ioctl(vm->vm_fd, KVM_GET_DIRTY_LOG, &dirty_log)<0){
					perror("KVM_GET_DIRTY_LOG");
				}

				total_dirty_page_count += count_dirty_pages(dirty_log.dirty_bitmap,bitmap_size);
				}

				printf("Number of dirty pages in memory slot %d after: %d\n", 0, total_dirty_page_count);
				continue;
			}

			//CODE TO GIVE RANDOM WS INPUT TO GUEST
			if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN
			    && vcpu->kvm_run->io.port == 0xAB) {
				

				uint32_t *size = (uint32_t *)((char *)vcpu->kvm_run+vcpu->kvm_run->io.data_offset);
				uint32_t page_size = sysconf(_SC_PAGE_SIZE);
				// uint32_t n_pages=(vm->total_mem_size-STACK_TOP)/page_size;
				// uint32_t n_pages = 10;

				*size = (rand()%(MAX_WS_SIZE+1));
				current_ws_size = *size;
				continue;
			}

			//CODE TO GIVE RANDOM NUMBER OF PAGE ADDRESS TO GUEST
			//INCOMPLETE
			if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
			    && vcpu->kvm_run->io.port == 0xAC) {
				
				unsigned long *starting_addr_gva = (unsigned long *)((char *)vcpu->kvm_run+vcpu->kvm_run->io.data_offset);
				unsigned long starting_gva = *starting_addr_gva;

				uint64_t slot_size = vm->total_mem_size/N_SLOTS;
				uint32_t slot_no = starting_gva/slot_size;
				
				unsigned long starting_hva = starting_gva+(unsigned long)vm->mem[slot_no];
				// uint32_t* ptr = starting_hva;
				// for(int i=0;i<current_ws_size;i++){
				// 	printf("%u ",*ptr);
				// 	ptr++;
				// }
				uint32_t page_size = sysconf(_SC_PAGE_SIZE);
				// uint32_t n_pages=(vm->total_mem_size - STACK_TOP)/page_size;
				uint32_t n_pages=20000;


				uint32_t *numbers = (uint32_t *)malloc(n_pages * sizeof(uint32_t));
				if (numbers == NULL) {
					printf("Memory allocation failed.\n");
					return;
				}

				for (int i = 0; i < n_pages; i++) {
					numbers[i] = (uint32_t)i;
				}


				for (int i = n_pages - 1; i > 0; i--) {
					int j = rand() % (i + 1);
					uint32_t temp = numbers[i];
					numbers[i] = numbers[j];
					numbers[j] = temp;
				}

				
				// printf("Random numbers from 0 to %d without repetition:\n", n_pages - 1);
				uint32_t *ws_addresses_ptr = starting_hva;
				for (uint32_t i = 0; i < current_ws_size; i++) {
					// printf("%d ", numbers[i]);
					*ws_addresses_ptr = (numbers[i]);
					ws_addresses_ptr++;
				}

				printf("\n");

				free(numbers);


				
				continue;
			}




			/* fall through */
		default:
			fprintf(stderr,	"Got exit_reason %d,"
				" expected KVM_EXIT_HLT (%d)\n",
				vcpu->kvm_run->exit_reason, KVM_EXIT_HLT);
			exit(1);
		}
	}

 check:
	if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}

	if (regs.rax != 42) {
		printf("Wrong result: {E,R,}AX is %lld\n", regs.rax);
		return 0;
	}

	memcpy(&memval, &(vm->mem)[0][0x400], sz);
	if (memval != 42) {
		printf("Wrong result: memory at 0x400 is %lld\n",
		       (unsigned long long)memval);
		return 0;
	}

	return 1;
}


extern const unsigned char guest64[], guest64_end[];

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1,
		.g = 1, /* 4KB granularity */
	};

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint64_t pmlu_addr = 0x2000;
	uint64_t* pmlu = (void *)((vm->mem)[0] + pmlu_addr);

	uint64_t pml4_addr = 0x3000;
	uint64_t *pml4 = (void *)((vm->mem)[0] + pml4_addr);

	uint64_t pdpt_addr = 0x4000;
	uint64_t *pdpt = (void *)((vm->mem)[0] + pdpt_addr);

	pmlu[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pml4_addr;

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;

	uint64_t nentries_middle_pt = vm->total_mem_size/(1<<21);
	// printf("Middle Page table entries%lu\n",nentries_middle_pt);
	for(uint64_t i=0;i<nentries_middle_pt;i++){

		uint64_t pd_addr = 0x5000+(i*PAGE_SIZE);
		// printf("pdaddr :%ld\n",pd_addr);
		uint64_t *pd = (void *)((vm->mem)[0] + pd_addr);

		pdpt[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

		for(uint64_t j=0;j<(PAGE_SIZE/PTE_ENTRY_SIZE);j++){

			pd[j] = PDE64_PRESENT | PDE64_RW | PDE64_USER | (PAGE_SIZE*j);
		}
	}
	
	sregs->cr3 = pmlu_addr;
	sregs->cr4 = CR4_PAE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = EFER_LME | EFER_LMA;
	setup_64bit_code_segment(sregs);
}

int run_long_mode(struct vm *vm, struct vcpu *vcpu,int n_sampling_slots)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 64-bit mode\n");

        if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_long_mode(vm, &sregs);
	
    if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = STACK_TOP;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy((vm->mem)[0], guest64, guest64_end-guest64);
	return run_vm(vm, vcpu, 8,n_sampling_slots);
}


int main(int argc,char* argv[])
{	
	srand(time(NULL));
	if(argc < 2){
		printf("Usage ./simple-kvm <number of slots to be sampled from>");
		exit(1);
	}

	// Blocking SIGALRM signal for the calling thread
    sigset_t mask;
    sigemptyset(&mask);  // Clear the signal set
    sigaddset(&mask, SIGALRM);  // Add SIGALRM to the set
    sigprocmask(SIG_BLOCK, &mask, NULL);  // Block SIGALRM
	
	struct vm vm;
	struct vcpu vcpu;

	vm_init(&vm, TOTAL_MEM_SIZE);

	vcpu_init(&vm, &vcpu); 	

	int n_sampling_slots = atoi(argv[1]);
	printf("Sampling from %d Slots\n",n_sampling_slots);

	return !run_long_mode(&vm, &vcpu,n_sampling_slots);

}
