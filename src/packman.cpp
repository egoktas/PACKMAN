/*
 * Author: Enes Goktas
 * Last edited: 24 April 2014
 * License: PACKMAN is licensed under the MIT License. 
 *          See LICENSE.txt
 */

#include <iostream>		// I/O STREAM
#include <iomanip>		// I/O MANIPulation
#include <fstream>		// File STREAM
#include <sstream>		// String STREAM
#include <algorithm>	// transform() string
#include "pin.H"		// PIN
#include <stdio.h>      // sprintf 
#include <time.h>       // clock_t, clock, CLOCKS_PER_SEC 
#include <math.h>       // sqrt 

namespace WINDOWS{
	#include <Windows.h>    
}

using namespace std;

typedef unsigned int	uint;
typedef unsigned short	ushort;

 string strToLower(string str){
	string copy(str); 
	std::transform(copy.begin(), copy.end(), copy.begin(), ::tolower);
	return copy;
 }
 
 
/* ================================================================== */
/* ================================================================== */
/* ========================= LOG TYPES ============================== */
/* ================================================================== */
/* ================================================================== */
 
#define LT_MAX_LENGTH	12
#define LT_EXEMEMORY	"EXEMEMORY"
#define LT_DLLMGMT		"DLLMGMT"
#define LT_THREADMGMT	"THREADMGMT"
#define LT_LIBCALL		"LIBCALL"
#define LT_CALLDETAILS	"CALLDETAILS"
#define LT_NEWLEVEL		"*NEWLEVEL*"
#define LT_ERROR		"!! ERROR !!"
#define LT_CHILDPROC	"CHILDPROC"
#define LT_DIRECTCALL	"DIRECTCALL"

string getLogType(string log_type)
{
	stringstream res;
	res << left << setw(LT_MAX_LENGTH) << log_type << ":: ";
	return res.str();
}

/* ================================================================== */
/* ================================================================== */
/* ========================= LOG TYPES ============================== */
/* ================================================================== */
/* ================================================================== */
 
 
/* ================================================================== */
/* ================================================================== */
/* ==================== PROCEDURE REFERRERS ========================= */
/* ================================================================== */
/* ================================================================== */
 
enum REF_SOURCE { 
	//RS_NULL,
	RS_REGISTER, 
	RS_CURRENT_MEMORY_REGION, 
	RS_UNKNOWN_MEMORY_REGION
};

typedef struct ProcRef {
	uint proc;		// address of the library procedure/function
	uint ref;		// address in the main executable that contains the PROCedure address
	REF_SOURCE ref_source;
	ProcRef * next;
} ProcRef;

ProcRef * new_ProcRef(uint proc, uint ref, REF_SOURCE ref_source){
	ProcRef * res = new ProcRef;
	res->proc		= proc;
	res->ref		= ref;
	res->ref_source = ref_source;
	res->next		= NULL;
	return res;	
}

ProcRef * new_ProcRef(ProcRef * pr){
	return new_ProcRef(pr->proc, pr->ref, pr->ref_source);
}

bool isPREqual(ProcRef * lhs, ProcRef * rhs){
	return lhs->proc == rhs->proc && lhs->ref == rhs->ref && lhs->ref_source == rhs->ref_source;
}

// sorted on referrer
// test with has_ProcRef before calling this function to prevent
//		duplicates of procref with ref==0 (in case of "REGISTER" ref_source)
ProcRef * insert_ProcRef(ProcRef ** head, ProcRef * _pr_){
	if(head == NULL || _pr_ == NULL) return NULL;

	ProcRef * pr = new_ProcRef(_pr_);

	if(*head == NULL) {
		*head = pr;
		return *head;
	}

	ProcRef * curr = *head;
	while(curr->next != NULL && curr->next->ref < pr->ref){
		curr = curr->next;
	}

	// if already in list
	if(isPREqual(curr, pr) || (curr->next != NULL && isPREqual(curr->next,pr))){
		delete pr;
		return *head;
	}

	if(curr == *head && pr->ref < curr->ref){
		// curr still equal to head AND
		// pr should be inserted before head
		pr->next = curr;
		curr = *head = pr;
	}else{
		// insert pr after curr
		pr->next = curr->next;
		curr->next = pr;
	}

	return curr;
}

void insert_ProcRef_list(ProcRef ** dst, ProcRef * src){
	if(dst == NULL) return;

	while(src != NULL){
		insert_ProcRef(dst, src);
		src = src->next;
	}
}

bool has_ProcRef(ProcRef ** head, ProcRef * pr){
	if(head == NULL || *head == NULL || pr == NULL) 
		return false;

	ProcRef * curr = *head;
	while(curr != NULL && !isPREqual(curr,pr)){
		curr = curr->next;
	}

	return curr != NULL;
}

/* ================================================================== */
/* ================================================================== */
/* ==================== PROCEDURE REFERRERS ========================= */
/* ================================================================== */
/* ================================================================== */


/* ================================================================== */
/* ================================================================== */
/* =================== Handling of Memory Blocks ==================== */
/* ================================================================== */
/* ================================================================== */

#define MAX_LINE_LENGTH 160

typedef struct MemBlock {
	uint begin;		// Begin address
	uint end;		// End address
	MemBlock * next; // Pointer to the next Memory Block
} MemBlock;

typedef struct Level {
	uint id;						//Level number
	uint oep;					//Level's OEP
	MemBlock * write_list;			//Written addresses
	ProcRef * procref_list;	//Current level's library calls
	Level * next; 					//Pointer to the next level
} Level;

Level * new_Level(uint id){
	Level * res = new Level;
	res->id			=   id;
	res->write_list	= NULL;
	res->procref_list	 = NULL;
	res->next		= NULL;
	return res;
}

MemBlock * new_MemBlock(uint begin, uint end){
	MemBlock * res = new MemBlock;
	res->begin	= begin;
	res->end	= end;
	res->next	= NULL;
	return res;	
}

MemBlock * new_MemBlock(MemBlock * block){
	return new_MemBlock(block->begin, block->end);
}

template< typename T >
string int_to_hex(T value){
	stringstream stream;

	stream << "0x" << setw(sizeof(T)*2) << setfill('0') << hex << value;

	return stream.str();
}

MemBlock * getGaps(MemBlock * block, uint max_interval){
	if(block == NULL) return NULL;

	// head
	MemBlock * result = new_MemBlock(0, block->begin - 1);
	MemBlock * curr = result;

	// middle
	while(block->next != NULL){
		uint interval = block->next->begin - block->end - 1;

		if(interval > max_interval){
			// add block
			curr->next = new_MemBlock(block->end + 1 , block->next->begin - 1);
			curr = curr->next;
		}

		block = block->next;
	}

	//tail
	curr->next = new_MemBlock(block->end + 1, 0); 

	return result;
}

MemBlock * insert_MemBlock(MemBlock ** head, MemBlock * block);
void insert_MemBlock_list(MemBlock ** dst, MemBlock * src){
	if(dst == NULL) return;

	/*if(*dst == NULL) {
		*dst = src;
		return;
	}*/

	while(src != NULL){
		insert_MemBlock(dst, src);
		src = src->next;
	}
}

MemBlock * getGaps(Level * level, uint max_interval){
	MemBlock * result = NULL;

	while(level != NULL){
		insert_MemBlock_list(&result, level->write_list);

		level = level->next;
	}

	MemBlock * gaps = getGaps(result, max_interval);
	return gaps;
}

// Perform merge after insertion
// returns:
//	-	lhs if merged
//	-	rhs if NO merge (i.e. end of list reached)
//	-	NULL if FAIL or NO merge
MemBlock * merge(MemBlock * lhs, MemBlock * rhs){
	if(lhs == NULL || rhs == NULL) {
		// lhs == NULL : FAIL => return NULL;
		// rhs == NULL : NO merge => return rhs(NULL);
		return NULL;
	}

	if(rhs->end <= lhs->end){
		// rhs is contained in lhs
		lhs->next = rhs->next;
		delete rhs;
	}else if(rhs->begin <= lhs->end +1){
		// rhs is partly in lhs
		// do a merge
		lhs->end = rhs->end;
		lhs->next = rhs->next;
		delete rhs;
	}else{
		return rhs;
	}

	return lhs;
}

MemBlock * insert_MemBlock(MemBlock ** head, MemBlock * _block_){
	if(head == NULL || _block_ == NULL) return NULL;

	MemBlock * block = new_MemBlock(_block_);

	if(*head == NULL) {
		*head = block;
		return *head;
	}

	// find the node that should precede block;
	MemBlock * curr = *head;
	while(curr->next != NULL && curr->next->begin < block->begin){
		// next node's begin address is smaller than block's addr
		curr = curr->next;
	}

	if(curr == *head && block->begin < curr->begin){
		// curr still equal to head AND
		// block should be inserted before head
		block->next = curr;
		curr = *head = block;
	}else{
		// insert block after curr
		block->next = curr->next;
		curr->next = block;
	}

	// while it equals curr, a merge occured
	MemBlock *res = curr;
	while(res != NULL && (res == curr || res == curr->next)){
		// continue while res points to curr or to curr->next
		// but stop when res reaches the end, which is NULL
		res = merge(res, res->next);
	}

	return curr;
}

bool isSameRegion(MemBlock * a, MemBlock * b){
	if(a == NULL || b == NULL) return false;

	return a->begin == b->begin && a->end == b->end;
}

void delete_MemBlock(MemBlock ** head, MemBlock * block){
	if(head == NULL || *head == NULL || block == NULL) return;

	MemBlock * curr = insert_MemBlock(head, block);
	if(curr == NULL) return;

	if(isSameRegion(curr,block)){
		// this can only be the head since begins are equal
		// advance head to delete first
		if(*head != curr) {
			LOG(getLogType(LT_ERROR)+"ERROR IN delete_MemBlock(..)\n");
			exit(1);
		}

		*head = curr->next;
		delete curr;
		return;
	}else if(curr->next != NULL && isSameRegion(curr->next, block)){
		// delete next complete region
		MemBlock * temp = curr->next;
		curr->next = curr->next->next;
		delete temp;
		return;
	}
	
	// decide which block contains the added block
	MemBlock * containsblock = NULL;
	if(block->end <= curr->end){ 
		containsblock = curr;
	}else{
		containsblock = curr->next;
	}

	if(block->end == containsblock->end){
		// remove at the end of containsblock
		containsblock->end = block->begin - 1;
	}else if(block->begin == containsblock->begin){
		// remove at the beginning of containsblock
		containsblock->begin = block->end + 1;
	}else{
		// remove at the middle of containsblock => SPLIT
		MemBlock * splittedblock = new MemBlock;
		splittedblock->begin = block->end + 1;
		splittedblock->end = containsblock->end;
		splittedblock->next = containsblock->next;
		
		containsblock->end = block->begin - 1;
		containsblock->next = splittedblock;
	}
}

bool has_MemBlock(MemBlock ** head, MemBlock * block){
	if(head == NULL || *head == NULL || block == NULL) 
		return false;

	// find the node that should precede block;
	MemBlock * curr = *head;
	while(curr->next != NULL && curr->next->begin < block->begin){
		// next node's begin address is smaller than block's addr
		curr = curr->next;
	}

	if(block->begin <= curr->end && block->end >= curr->begin){
		return true;
	}else if(curr->next != NULL && block->end >= curr->next->begin && block->begin <= curr->next->end){
		return true;
	}

	return false;
}

/* ================================================================== */
/* ================================================================== */
/* =================== Handling of Memory Blocks ==================== */
/* ================================================================== */
/* ================================================================== */



/* ================================================================== */
// Global variables 
/* ================================================================== */

#define INTERBLOCK_INTERVAL 0x200
#define INITIAL_LEVEL_ID 1
#define THRESHOLD_WRITTEN_INSTR_EXECUTION 5
Level * levels; // All Levels
Level * cl; // Current Level

IMG img_glb;
MemBlock * loaded_modules;
MemBlock * user_memory; // memory allocated by the malware
uint user_memory_alloc_size_temp = 0;
UINT32 img_base = 0;
UINT32 img_end = 0;

UINT32 threadCount = 0;
UINT32 userThreadCount = 0; // nr of Threads created with LIBCALL: CreateThread

bool log_disabled = false;
RTN last_bbl_rtn;
UINT32 last_bbl_addr = 0;

UINT32 latest_branch_src = 0;
UINT32 latest_branch_dest = 0;
UINT32 latest_branch_count = 1;

bool isBranchToCreateProcessA = false;
bool isBranchToWriteProcessMemory = false;
bool isBranchToCreateThread = false;

/* ===================================================================== */
// Multi Threading
/* ===================================================================== */
// Force each thread's data to be in its own data cache line so that
// multiple threads do not contend for the same data cache line.
// This avoids the false sharing problem.
#define PADSIZE 52  // 64 byte line size: 64-4-4-4

// key for accessing TLS storage in the threads. initialized once in main()
static TLS_KEY tls_key;

//
// Detailed info about specific library calls
//
enum CALLED_PROC { 
	/*
	* to add a new proc:
	* - add a CALLED_PROC enum entry
	* - add entry to getProcName && getCalledProc
	* - add the instrumentation code in the imgLoad function
	* - add the Before and After functions
	*/
	NO_CALLED_PROC, 
	CREATE_PROCESS_A, 
	CREATE_THREAD, 
	WRITE_PROCESS_MEMORY, 
	VIRTUAL_ALLOC_EX,
	VIRTUAL_ALLOC,
	VIRTUAL_FREE,
	NT_ALLOCATE_VIRTUAL_MEMORY,
	ZW_ALLOCATE_VIRTUAL_MEMORY,
	OPEN_SC_MANAGER_A,				//OpenSCManagerA
	OPEN_SERVICE_A					//OpenServiceA
};

// a running count of the instructions
class thread_data_t
{
  public:
    thread_data_t() : 
		written_instr_execution_count(0),
		temp_long_jump(0),
		temp_level_oep(NULL),
		addr_latest_exec_instr(0) {}
    UINT32 written_instr_execution_count;
	UINT32 temp_long_jump;
	MemBlock * temp_level_oep;
	UINT32 addr_latest_exec_instr;
	CALLED_PROC calledProc;
    UINT8 _pad[PADSIZE-sizeof(enum CALLED_PROC)];
};

// function to access thread-specific data
thread_data_t* get_tls(THREADID threadid){
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    return tdata;
}

string getProcName(CALLED_PROC cp){
	string res;
	switch (cp){
		case NO_CALLED_PROC: 
			res = "NO_CALLED_PROC"; break;
		case CREATE_PROCESS_A: 
			res = "CreateProcessA"; break;
		case CREATE_THREAD:
			res = "CreateThread"; break;
		case WRITE_PROCESS_MEMORY:
			res = "WriteProcessMemory"; break;
		case VIRTUAL_ALLOC_EX:
			res = "VirtualAllocEx"; break;
		case VIRTUAL_ALLOC:
			res = "VirtualAlloc"; break;
		case VIRTUAL_FREE:
			res = "VirtualFree"; break;
		case NT_ALLOCATE_VIRTUAL_MEMORY:
			res = "NtAllocateVirtualMemory"; break;
		case ZW_ALLOCATE_VIRTUAL_MEMORY:
			res = "ZwAllocateVirtualMemory"; break;
		case OPEN_SC_MANAGER_A:
			res = "OpenSCManagerA"; break;
		case OPEN_SERVICE_A:
			res = "OpenServiceA"; break;
		default: 
			LOG(getLogType(LT_ERROR)+"## error:getProcName ## should not get here ##\n");
	}	
	return res;
}

CALLED_PROC getCalledProc(string procName){
	CALLED_PROC res;
	if(procName == "CreateProcessA"){
		res = CREATE_PROCESS_A;
	}else if(procName == "CreateThread"){
		res = CREATE_THREAD;
	}else if(procName == "WriteProcessMemory"){
		res = WRITE_PROCESS_MEMORY;
	}else if(procName == "VirtualAllocEx"){
		res = VIRTUAL_ALLOC_EX;
	}else if(procName == "VirtualAlloc"){
		res = VIRTUAL_ALLOC;
	}else if(procName == "VirtualFree"){
		res = VIRTUAL_FREE;
	}else if(procName == "NtAllocateVirtualMemory"){
		res = NT_ALLOCATE_VIRTUAL_MEMORY;
	}else if(procName == "ZwAllocateVirtualMemory"){
		res = ZW_ALLOCATE_VIRTUAL_MEMORY;
	}else if(procName == "OpenSCManagerA"){
		res = OPEN_SC_MANAGER_A;
	}else if(procName == "OpenServiceA"){
		res = OPEN_SERVICE_A;
	}else{ // procName == anything else
		res = NO_CALLED_PROC;
	}
	return res;
}

void setCalledProc(string proc){
	THREADID tid = PIN_ThreadId();
	get_tls(tid)->calledProc = getCalledProc(proc);
}

bool isCalledProc(CALLED_PROC cp){
	THREADID tid = PIN_ThreadId();
	return get_tls(tid)->calledProc == cp;
}

void clearCalledProc(){
	THREADID tid = PIN_ThreadId();
	get_tls(tid)->calledProc = NO_CALLED_PROC;
}

string getCurrentProcName(){
	THREADID tid = PIN_ThreadId();
	return getProcName(get_tls(tid)->calledProc);
}

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobPinPath32(KNOB_MODE_WRITEONCE,  "pintool",
    "pin_path_32", ".", "specify directory for MyPinTool output");

KNOB<string> KnobProcessID(KNOB_MODE_WRITEONCE,  "pintool",
    "process_id", ".", "specify directory for MyPinTool output");

KNOB<string> KnobToolDllFile(KNOB_MODE_WRITEONCE,  "pintool",
    "tool_dll_file", ".", "specify directory for MyPinTool output");

KNOB<string> KnobExeLogPath(KNOB_MODE_WRITEONCE,  "pintool",
    "exe_log_path", ".", "specify directory for MyPinTool output");

KNOB<string> KnobToolName(KNOB_MODE_WRITEONCE,  "pintool",
    "tool_name", ".", "specify directory for MyPinTool output");  

KNOB<string> KnobTimeStamp(KNOB_MODE_WRITEONCE,  "pintool",
    "ts", "9999-99-99_99-99", "specify a timestamp for MyPinTool output");
/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

bool isAtLastDirectory(const char * directory){
	uint name_table_rva = *(uint *) directory;
	directory += 0x04;
	uint timestamp = *(uint *) directory;
	directory += 0x04;
	uint forwarder_chain = *(uint *) directory;
	directory += 0x04;
	uint name_rva = *(uint *) directory;
	directory += 0x04;
	uint address_table_rva = *(uint *) directory;
	return name_table_rva==0 && timestamp==0 
		&& forwarder_chain==0 && forwarder_chain==0 
		&& address_table_rva==0;
}

bool isAtLastAddress(const char * import_addr){
	return *(uint *)import_addr == 0;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
VOID Fini(INT32 code, VOID *v);

enum RET_VAL { ACCESS_VIOLATION, NOT_OK, OK };
// ACCESS_VIOLATION -> the address being tested is not in the memory regions allocated by the malware

RET_VAL isAtBase(uint b_a){ // base_address
	// check access violation 
	MemBlock * b_block = new_MemBlock(b_a,b_a);
	if(!has_MemBlock(&user_memory, b_block)){
		delete b_block;
		return ACCESS_VIOLATION;
	}delete b_block;

	// b_a is in memory allocated by malware
	char * pe  = (char*) (*(uint*)(b_a + 0x3C) + b_a);
	char * b_p = (char *) b_a;
	if(*b_p == 'M' && *(b_p+1) == 'Z' && *pe == 'P' && *(pe+1) == 'E'){
		return OK;
	}else{
		return NOT_OK;
	}
}

void writeToBuf(char * buf, uint index, uint val){
	char * val_arr = (char *) &val;
	buf[index] = val_arr[0];
	buf[index+1] = val_arr[1];
	buf[index+2] = val_arr[2];
	buf[index+3] = val_arr[3];
}

void writeToBuf(char * buf, uint index, ushort val){
	char * val_arr = (char *) &val;
	buf[index] = val_arr[0];
	buf[index+1] = val_arr[1];
}

string getThreadAndLevelLOGPrefix(THREADID tid){
	string res = "";
	if(threadCount > 0){
		res = "[T:"+decstr(tid)+"|L:"+decstr(cl->id)+"] ";
	}
	return res;
}

void constructHeader(char ** hdr, uint * hdr_size, uint code_base, uint code_size, uint entry_point, THREADID tid){
	if(code_base < 0x1000) LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"#[constructHeader]# code_base is lower than 0x1000; expected to be higher ## \n");
	uint image_base = code_base - 0x1000;

	uint sz = 0x200;
	char * res = new char[sz];

	memset(res, 0x0, sz*sizeof(char));
	writeToBuf(res, 0x00,                     (ushort) 0x5A4D); // = 0x4D 0x5A = M Z
	uint pe_offset = 0x000000B8;
	writeToBuf(res, 0x3C,                           pe_offset); // set PE_OFFSET

	writeToBuf(res, pe_offset,              (uint) 0x00004550); // = 0x50 0x45 0x00 0x00 = P E _ _

	uint coff_hdr_offset = pe_offset + 0x04;
	writeToBuf(res, coff_hdr_offset,        (ushort)   0x014C); // 0x014C = Machine Type
	writeToBuf(res, coff_hdr_offset + 0x02, (ushort)   0x0001); // 0x0001 = # Sections
	writeToBuf(res, coff_hdr_offset + 0x10, (ushort)   0x00E0); // 0x00E0 = Size of Optional Header
	writeToBuf(res, coff_hdr_offset + 0x12, (ushort)   0x0103); // Characteristics: 0x0001=RELOC_STRIPPED | 0x0002=EXE_IMG | 0x0100=32BIT_MACHINE

	uint opt_hdr_offset = pe_offset + 0x18;
	writeToBuf(res, opt_hdr_offset,         (ushort)   0x010B); // Magic, normal executable
	res[opt_hdr_offset+0x02] = 0x0A; // Major Linker Version
	writeToBuf(res, opt_hdr_offset + 0x04,          code_size); // Size of Code
	writeToBuf(res, opt_hdr_offset + 0x10,  entry_point - image_base); // Address of Entry Point
	writeToBuf(res, opt_hdr_offset + 0x14,  (uint) 0x00001000); // Base of Code
	writeToBuf(res, opt_hdr_offset + 0x1C,         image_base); // Image Base
	writeToBuf(res, opt_hdr_offset + 0x20,  (uint) 0x00001000); // Section Alignment
	writeToBuf(res, opt_hdr_offset + 0x24,  (uint) 0x00000200); // File Alignment
	writeToBuf(res, opt_hdr_offset + 0x28,  (ushort)   0x0005); // Major O/S version
	writeToBuf(res, opt_hdr_offset + 0x2A,  (ushort)   0x0001); // Minor O/S version
	writeToBuf(res, opt_hdr_offset + 0x30,  (ushort)   0x0005); // Major Subsystem version
	writeToBuf(res, opt_hdr_offset + 0x32,  (ushort)   0x0001); // Minor Subsystem version
	// code_size should be a multiple of page_size(0x1000)
	uint img_size = code_size + 0x1000; // 0x1000 = hdr size when loaded
	writeToBuf(res, opt_hdr_offset + 0x38,           img_size); // Size of Image
	writeToBuf(res, opt_hdr_offset + 0x3C,                 sz); // Size of Headers
	writeToBuf(res, opt_hdr_offset + 0x44,  (ushort)   0x0003); // Subsystem: 0x0003 = IMAGE_SUBSYSTEM_WINDOWS_CUI
	writeToBuf(res, opt_hdr_offset + 0x46,  (ushort)   0x8100); // DLL Characteristics: 0x0100=NX_COMPAT | 0x8000=TERMINAL_SERVER_AWARE
	writeToBuf(res, opt_hdr_offset + 0x48,  (uint) 0x00100000); // Size of Stack Reserve
	writeToBuf(res, opt_hdr_offset + 0x4C,  (uint) 0x00001000); // Size of Stack Commit
	writeToBuf(res, opt_hdr_offset + 0x50,  (uint) 0x00100000); // Size of Heap Reserve
	writeToBuf(res, opt_hdr_offset + 0x54,  (uint) 0x00001000); // Size of Heap Commit
	writeToBuf(res, opt_hdr_offset + 0x5C,  (uint) 0x00000010); // # Data Directories

	uint section_offset = opt_hdr_offset + 0xE0; // 0xE0 = optional header size
	writeToBuf(res, section_offset,         (uint) 0x7478742E); // Name: [0x2E 0x74 0x78 0x74] : [. t x t]
	writeToBuf(res, section_offset + 0x08,          code_size); // Virtual Size
	writeToBuf(res, section_offset + 0x0C,  (uint) 0x00001000); // RVA
	writeToBuf(res, section_offset + 0x10,          code_size); // Size of Raw Data
	writeToBuf(res, section_offset + 0x14,  (uint) 0x00000200); // Pointer to Raw Data
	writeToBuf(res, section_offset + 0x24,  (uint) 0x60000020); // # Characteristics

	*hdr = res;
	*hdr_size = sz;
}

MemBlock * getCodeBlock(uint code_base){
	MemBlock * curr = user_memory;
	while(curr != NULL && curr->begin != code_base){
		curr = curr->next;
	}
	return curr;
}

void dumpWithNewEntryPoint(uint pe_oep, THREADID tid){
	uint dump_base = pe_oep & 0xFFFFF000; // set page start

	RET_VAL res;
	while((res = isAtBase(dump_base)) == NOT_OK){
		dump_base -= 1; // enter previous page
		dump_base &= 0xFFFFF000; // go to beginning of page
	}

	// border between allocated memory / regions not clear... 
	// a base may be incorrect, because it may a base of another allocation
	if(res == ACCESS_VIOLATION){
		dump_base += 0x1000;

		char * hdr;
		uint hdr_size;
		uint code_base = dump_base;
		MemBlock * code_block = getCodeBlock(code_base);
		if(code_block == NULL){
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+getLogType(LT_NEWLEVEL)+"#[dumpWithNewEntryPoint]# NOT_FOUND ## aborted DUMP; but process continues ! \n");
			return;
		}
		uint code_size = code_block->end - code_base + 1;
		uint entry_point = pe_oep;
		constructHeader(&hdr, &hdr_size, code_base, code_size, entry_point, tid);

		string dump_file_name = KnobExeLogPath.Value()+"\\";
		dump_file_name		 += "dump_level_"+decstr(cl->id)+"_procID_"+KnobProcessID.Value()+"_threadID_"+decstr(tid)+"_custom._exe_";
		fstream df (dump_file_name.c_str(), ios::in | ios::out | ios::trunc | ios::binary); // dump file

		if (df.is_open()) { /* ok, proceed with output */ 
			df.write(hdr, hdr_size);
			df.write((char *) code_base, code_size);
			df.close();
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"new level is in memory chunk ["+int_to_hex(code_base)+".."+int_to_hex(code_block->end)+"]("+int_to_hex(code_size)+") and has *NO* PE file header\n");
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"dumped new level to file "+dump_file_name+"\n");
		}else{
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"# Unable to open file to dump new level; filename:["+dump_file_name+"] \n");
			exit(EXIT_FAILURE);
		}

	}else{ // res == OK
		string dump_file_name = KnobExeLogPath.Value()+"\\"; 
		dump_file_name		 += "dump_level_"+decstr(cl->id)+"_procID_"+KnobProcessID.Value()+"_threadID_"+decstr(tid)+"._exe_";
		fstream df (dump_file_name.c_str(), ios::in | ios::out | ios::trunc | ios::binary);
		
		if (df.is_open()) { 
			uint pe_base  = *(uint*)(dump_base + 0x3C) + dump_base;
			streamsize size = *(uint*)(pe_base + 0x50); // get Size Of Image

			df.write((char *) dump_base,size);

			// fix the section sizes in dumped file
			short nr_sections = *(short*)(pe_base + 0x06);
			uint section_rva = pe_base + 0xF8 - dump_base;
			uint virtual_size_offset = 0x08;
			uint virtual_addr_offset = 0x0C;
			uint raw_size_offset	 = 0x10;
			uint raw_addr_offset	 = 0x14;
			const uint nr_bytes = 8;
			char virt_data[nr_bytes];
			for(short i = 0; i < nr_sections; i++){
				df.seekg(section_rva + virtual_size_offset);
				df.read(virt_data, nr_bytes);

				df.seekp(section_rva + raw_size_offset);
				df.write(virt_data, nr_bytes);

				section_rva += 0x28; // next section header
			}

			// fix oep in dumped file
			df.seekp(pe_base + 0x28 - dump_base);
			uint oep_rva = pe_oep - dump_base;
			df.write((char *) &oep_rva, sizeof(uint));

			df.close();
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"new level is in memory chunk ["+int_to_hex(dump_base)+".."+int_to_hex(dump_base+(uint)size-1)+"]("+int_to_hex((uint)size)+") and has a PE file header\n");
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"dumped new level to file "+dump_file_name+"\n");
		}else{
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"# Unable to open file to dump new level; filename:["+dump_file_name+"] \n");
			exit(EXIT_FAILURE);
		}

	}
}

void checkForNewLevel(MemBlock * exec_block){	
	THREADID tid = PIN_ThreadId();
	string s = getThreadAndLevelLOGPrefix(tid);
	thread_data_t* tdata = get_tls(tid);

	if(has_MemBlock(&cl->write_list, exec_block)){
		if(tdata->written_instr_execution_count == 0){
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"a potential new level detected\n");
			tdata->temp_level_oep = new_MemBlock(exec_block);
		    tdata->temp_long_jump = tdata->addr_latest_exec_instr;
		}
		tdata->written_instr_execution_count++;
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"#"+decstr(tdata->written_instr_execution_count)+" executed a written instruction @"+int_to_hex(exec_block->begin)+"\n");
		if(tdata->written_instr_execution_count == THRESHOLD_WRITTEN_INSTR_EXECUTION){
			// execution 5 contiguous tainted instructions detected! = new level
			cl->next = new_Level(cl->id+1);

			cl = cl->next;
			cl->oep = tdata->temp_level_oep->begin;

			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"detected a new level! its entry point is "+int_to_hex(cl->oep)+"\n");

			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"instruction that jumped to the new level is at "+int_to_hex(tdata->temp_long_jump)+"\n");

			dumpWithNewEntryPoint(cl->oep, tid);

			tdata->temp_long_jump = 0;
			tdata->temp_level_oep = NULL;
			tdata->written_instr_execution_count = 0;
		}
	}else if(tdata->written_instr_execution_count != 0){
		// detection of new level failed
		// -> no consecutive execution of 5 written instrucitons!
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_NEWLEVEL)+"detection of new level failed\n");

		tdata->temp_long_jump = 0;
		delete tdata->temp_level_oep;
		tdata->written_instr_execution_count = 0;
	}
}

// Left as future work
BOOL checkSensitiveFunctions(MemBlock * exec_block){	
	return false;
}

VOID checkStopCondition(MemBlock * exec_block){	
	BOOL detectedCoreMalware = checkSensitiveFunctions(exec_block);
	
	if(detectedCoreMalware){
		LOG("FOUND CORE OF THE MALWARE!!\n");
		exit(1);
	}
}

VOID SaveWrite(ADDRINT ins_ea, UINT32 ins_size, ADDRINT mem_ea, UINT32 mem_size, THREADID tid){
	MemBlock * exec_block = new_MemBlock((uint)ins_ea, (uint)ins_ea+ins_size-1);
	MemBlock * write_block = new_MemBlock((uint)mem_ea, (uint)mem_ea+mem_size-1);
	
	checkStopCondition(exec_block);
	checkForNewLevel(exec_block);
	insert_MemBlock(&cl->write_list, write_block); // write_list = log of writes in current level
	
	delete exec_block;
	delete write_block;

	thread_data_t* tdata = get_tls(tid);
	tdata->addr_latest_exec_instr = (UINT32) ins_ea;
}

VOID CheckInstruction(ADDRINT ins_ea, UINT32 ins_size, THREADID tid){
	MemBlock * exec_block = new_MemBlock((uint)ins_ea, (uint)ins_ea+ins_size-1);

	checkStopCondition(exec_block);
	checkForNewLevel(exec_block);

	delete exec_block;
	
	thread_data_t* tdata = get_tls(tid);
	tdata->addr_latest_exec_instr = (UINT32) ins_ea;
}

string FormatAddress(ADDRINT address, RTN rtn)
{
    string s = StringFromAddrint(address);
    
    if (RTN_Valid(rtn))
    {
		string imgname = IMG_Name(SEC_Img(RTN_Sec(rtn)));
		string filename = imgname.substr( imgname.find_last_of("\\") + 1 );
        s += " " + filename + "::";
        s += RTN_Name(rtn);
    }

    return s;
}

BOOL exitsMainIMG(ADDRINT src, ADDRINT dest){
	UINT32 _src = (UINT32) src;
	UINT32 _dest = (UINT32) dest;
	return (_src >= img_base && _src <= img_end) 
		&& (_dest <= img_base || _dest >= img_end);
}

BOOL isBranchOrCallToLoadedModuleFromNonLoadedModule(ADDRINT src, ADDRINT dest){
	UINT32 _src = (UINT32) src;
	UINT32 _dest = (UINT32) dest;

	MemBlock * src_b = new_MemBlock(_src,_src);
	MemBlock * dest_b = new_MemBlock(_dest,_dest);
	bool result = !has_MemBlock(&loaded_modules, src_b) && has_MemBlock(&loaded_modules, dest_b);
	delete src_b;
	delete dest_b;

	return result;
}

VOID DirectCall(string * str){
	LOG(*str);
}

BOOL isRefSourceInCurrentMemoryRegion(uint referrer_addr, uint ins_addr){
	MemBlock * mb_ra = new_MemBlock(referrer_addr,referrer_addr);
	// check if referrer_addr is in any memory block allocated by the malware
	if(!has_MemBlock(&user_memory, mb_ra)){
		delete mb_ra;
		return false;
	}delete mb_ra;

	// find the memory block in which referrer_addr is contained
	MemBlock * curr = user_memory;
	while(curr != NULL && !(curr->begin <= referrer_addr && referrer_addr <= curr->end)){
		curr = curr->next;
	}

	if(curr == NULL){
		return false;
	}

	if(curr->begin <= ins_addr && ins_addr <= curr->end){
		return true;
	}

	return false;
}

VOID IndirectCall(THREADID tid, ADDRINT ins_addr, UINT32 ins_size, BOOL isCall, BOOL isMemRead, 
	ADDRINT referrer_addr, UINT32 referrer_size, string * reg_name, ADDRINT branch_target_addr, string * disasm){
	if(isBranchOrCallToLoadedModuleFromNonLoadedModule(ins_addr, branch_target_addr)){
		if(!log_disabled) log_disabled = true; 

		PIN_LockClient();
		RTN branch_target_RTN = RTN_FindByAddress(branch_target_addr);
		PIN_UnlockClient();

		const string rtn_name = RTN_Name(branch_target_RTN);
		if(!isCalledProc(NO_CALLED_PROC)) {
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"## [IndirectCall] ## The thread should be in one PROCedure at a time! Function that did not return:"+getCurrentProcName()+" \n");
			clearCalledProc();
		}
		setCalledProc(rtn_name);
		
		REF_SOURCE ref_source;
		if(isMemRead){
			// check in which region the referrer's address is
			if(isRefSourceInCurrentMemoryRegion((uint)referrer_addr, (uint)ins_addr)){
				ref_source = RS_CURRENT_MEMORY_REGION;
			}else{
				ref_source = RS_UNKNOWN_MEMORY_REGION;
			}
		}else if(reg_name != NULL){
			ref_source = RS_REGISTER;
			referrer_addr = 0x0;
		}

		// create pr
		ProcRef * pr = new_ProcRef((uint)branch_target_addr, (uint)referrer_addr, ref_source);
		if(!has_ProcRef(&cl->procref_list,pr)){
			insert_ProcRef(&cl->procref_list, pr);
		}

		string s = "";

		s += "@"+int_to_hex(ins_addr);
		s+= " "+*disasm+"=";
		
		if(ref_source != RS_REGISTER){
			if((*disasm).find("[0x") == string::npos){
				s += "["+int_to_hex(referrer_addr)+"]=";
			}
		}

		PIN_LockClient();
		s+= FormatAddress(branch_target_addr, branch_target_RTN);
		PIN_UnlockClient();

		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_LIBCALL) +s+ "\n");
	}else if(exitsMainIMG(ins_addr, branch_target_addr)){
		string s = "Indirect || ";
		s += "Exits main EXEcutable || @"+int_to_hex(ins_addr);
		if(isCall){
			s+= " Call ";
		}else{
			s+= " Jump ";
		}
		s+= int_to_hex(branch_target_addr);
		
		if(!log_disabled) log_disabled = true;
		LOG(getThreadAndLevelLOGPrefix(tid)+ s+"\n");
		s="";
	}
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */
VOID Instruction(INS ins, VOID* v){

	THREADID tid = PIN_ThreadId();
	string *disptr = new string(INS_Disassemble(ins));

	if(INS_IsMemoryWrite(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)SaveWrite, 
								IARG_INST_PTR, 
								IARG_UINT32, INS_Size(ins),
								IARG_MEMORYWRITE_EA, 
								IARG_MEMORYWRITE_SIZE, 
								IARG_THREAD_ID,
								IARG_END);
	}else{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckInstruction, 
								IARG_INST_PTR, 
								IARG_UINT32, INS_Size(ins),
								IARG_THREAD_ID,
								IARG_END);
	}

	if(INS_IsDirectBranchOrCall(ins) && !INS_IsRet(ins)){
		ADDRINT src = INS_Address(ins);
		ADDRINT dest = INS_DirectBranchOrCallTargetAddress(ins);
		
		MemBlock * src_b = new_MemBlock((UINT32)src,(UINT32)src);
		MemBlock * dest_b = new_MemBlock((UINT32)dest,(UINT32)dest);
		BOOL isSrcInMalwareCode = has_MemBlock(&user_memory,src_b)  || has_MemBlock(&cl->write_list, src_b);
		BOOL isDstInMalwareCode = has_MemBlock(&user_memory,dest_b) || has_MemBlock(&cl->write_list, dest_b);
		BOOL isDstInLibraryCode = has_MemBlock(&loaded_modules,dest_b);
		delete src_b;
		delete dest_b;
		
		string s_dcall = "";

		s_dcall += "@"+int_to_hex(src);
		s_dcall += " "+*disptr+" ";

		PIN_LockClient();
		s_dcall += FormatAddress(dest, RTN_FindByAddress(dest));
		PIN_UnlockClient();
		
		if(isSrcInMalwareCode && isDstInLibraryCode){
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_DIRECTCALL)+s_dcall+"\n");
		}else if(isSrcInMalwareCode && !isDstInMalwareCode){
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"unexpected directcall from malware code to unknown memory:\n");
			LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+s_dcall+"\n");
		}
	}


	if(INS_IsIndirectBranchOrCall(ins) && !INS_IsRet(ins)){
		BOOL isCall = INS_IsCall(ins);
		BOOL isMemRead = INS_IsMemoryRead(ins);
		if(isMemRead){
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)IndirectCall, 
				IARG_THREAD_ID,
				IARG_INST_PTR, 
				IARG_UINT32, INS_Size(ins),
				IARG_BOOL, isCall,
				IARG_BOOL, isMemRead,
				IARG_MEMORYREAD_EA, 
				IARG_MEMORYREAD_SIZE, 
				IARG_PTR, NULL, // REG_NAME
				IARG_BRANCH_TARGET_ADDR,
				IARG_PTR, disptr,
				IARG_END);
		}else if(INS_OperandIsReg(ins, 0)){
			string s = REG_StringShort(INS_OperandReg(ins,0));
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)IndirectCall, 
				IARG_THREAD_ID,
				IARG_INST_PTR, 
				IARG_UINT32, INS_Size(ins),
				IARG_BOOL, isCall,
				IARG_BOOL, isMemRead,
				IARG_UINT32, 0x0,//IARG_MEMORYREAD_EA, 
				IARG_UINT32, 0x0,//IARG_MEMORYREAD_SIZE,
				IARG_PTR, new string(s),
				IARG_BRANCH_TARGET_ADDR,
				IARG_PTR, disptr,
				IARG_END);
		}else{
			LOG(getLogType(LT_ERROR)+"the indirect branch expects a memory read or a REGister ----\n");
		}
	}
}

clock_t execution_time;
VOID Fini(INT32 code, VOID *v)
{
	
	execution_time = clock() - execution_time;
	stringstream res;
    res <<  "===============================================" << endl;
	res <<  " Current level = " << cl->id << endl;
	res <<  " Execution time = " << (((float)execution_time*1000)/CLOCKS_PER_SEC) << " ms" << endl;
    res <<  " ===============================================" << endl;
	LOG(res.str());
}

/* ===================================================================== */
// Procedure Analysis routines
// Before and After functions
// (Each thread tracks its own Procedure calls)
/* ===================================================================== */
VOID CreateThreadBefore(WINDOWS::LPTHREAD_START_ROUTINE lpStartAddress, THREADID tid){
	if(!isCalledProc(CREATE_THREAD)) return;
	userThreadCount++;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"CreateThreadBefore; number of threads started by exe="+decstr(userThreadCount)+"; thread Entry Point="+int_to_hex((uint)lpStartAddress)+"\n");
}

VOID CreateThreadAfter(THREADID tid){
	if(!isCalledProc(CREATE_THREAD)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"CreateThreadAfter; done\n");
	clearCalledProc();
}

VOID CreateProcessABefore(THREADID tid){
	if(!isCalledProc(CREATE_PROCESS_A)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"CreateProcessBefore\n");
}

VOID CreateProcessAAfter(THREADID tid){
	if(!isCalledProc(CREATE_PROCESS_A)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"CreateProcessAfter; done\n");
	clearCalledProc();
}

VOID WriteProcessMemoryBefore(WINDOWS::HANDLE hProcess, void * dest, char * buf, uint buf_size, THREADID tid){
	if(!isCalledProc(WRITE_PROCESS_MEMORY)) return;

	uint size = MAX_PATH;
	char filename[MAX_PATH];
	uint res = WINDOWS::QueryFullProcessImageName(hProcess, 0, filename, (WINDOWS::PDWORD)&size); // 2nd arg: 0 = C:\.. & 1 = \Device\..
	if(res == 0){
		uint err = WINDOWS::GetLastError();
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"WriteProcessMemoryBefore; failed to get new process' image name; windows error code="+int_to_hex(err)+"\n");
		return;
	}
	uint id = WINDOWS::GetProcessId(hProcess);
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"WriteProcessMemoryBefore; target process handle="+hexstr(hProcess)+"; target process id=0x"+hexstr(id)+
		"; target process image name="+*(new string(filename))+"\n");
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"WriteProcessMemoryBefore; destination in target process="+int_to_hex((uint)dest)+"; buffer in this process=["+int_to_hex((uint)buf)+".."
		+int_to_hex((uint)(buf+buf_size-1))+"]; size="+int_to_hex(buf_size)+"\n");
}

VOID WriteProcessMemoryAfter(THREADID tid){
	if(!isCalledProc(WRITE_PROCESS_MEMORY)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"WriteProcessMemoryAfter; done \n");
	clearCalledProc();
}

VOID VirtualAllocExBefore(WINDOWS::HANDLE hProcess, uint pref_addr, uint size, THREADID tid){
	if(!isCalledProc(VIRTUAL_ALLOC_EX)) return;

	uint path_size = MAX_PATH;
	char filename[MAX_PATH];
	uint res = WINDOWS::QueryFullProcessImageName(hProcess, 0, filename, (WINDOWS::PDWORD)&path_size); // 2nd arg: 0 = C:\.. & 1 = \Device\..
	if(res == 0){
		uint err = WINDOWS::GetLastError();
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"VirtualAllocExBefore; failed to get new process' image name; windows error code="+int_to_hex(err)+"\n");
		return;
	}

	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualAllocExBefore; target process handle="+hexstr(hProcess)+"; allocate mem at address="+int_to_hex(pref_addr)+"; size="+int_to_hex(size)+"\n");
	user_memory_alloc_size_temp = size;
}

VOID VirtualAllocExAfter(uint alloc_addr, THREADID tid){
	if(!isCalledProc(VIRTUAL_ALLOC_EX)) return;
	if(user_memory_alloc_size_temp == 0) {
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualAllocExAfter; done; return value="+int_to_hex(alloc_addr)+"\n");
	}else if(alloc_addr == NULL){
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualAllocExAfter; done; return value="+int_to_hex(alloc_addr)+"\n");
	}else{
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualAllocExAfter; done; return value="+int_to_hex(alloc_addr)+"\n");

		uint mem_end = (((alloc_addr+user_memory_alloc_size_temp)-1)&0xFFFFF000)+0x1000-1;

		MemBlock * block = new_MemBlock(alloc_addr, mem_end);
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_EXEMEMORY)+"insert memory chunk ["+int_to_hex(alloc_addr)+".."+int_to_hex(mem_end)+"]("+int_to_hex(mem_end-alloc_addr+1)+") \n");
		insert_MemBlock(&user_memory, block);
		delete block;

		user_memory_alloc_size_temp = 0;
	}
	
	clearCalledProc();
}

VOID VirtualAllocBefore(uint pref_addr, uint size, THREADID tid){
	if(!isCalledProc(VIRTUAL_ALLOC)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualAllocBefore; allocate memory at address="+int_to_hex(pref_addr)+"; size="+int_to_hex(size)+"\n");
	user_memory_alloc_size_temp = size;
}

VOID VirtualAllocAfter(uint alloc_addr, THREADID tid){
	if(!isCalledProc(VIRTUAL_ALLOC)) return;
	if(user_memory_alloc_size_temp == 0) {
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"VirtualAllocAfter; done; return value="+int_to_hex(alloc_addr)+"\n");
	}else if(alloc_addr == NULL){
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_ERROR)+"VirtualAllocAfter; done: return value="+int_to_hex(alloc_addr)+"\n");
	}else{
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualAllocAfter; done; return value="+int_to_hex(alloc_addr)+"\n");

		uint mem_end = (((alloc_addr+user_memory_alloc_size_temp)-1)&0xFFFFF000)+0x1000-1;

		MemBlock * block = new_MemBlock(alloc_addr, mem_end);
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_EXEMEMORY)+"insert memory chunk ["+int_to_hex(alloc_addr)+".."+int_to_hex(mem_end)+"]("+int_to_hex(mem_end-alloc_addr+1)+") \n");
		insert_MemBlock(&user_memory, block);
		delete block;

		user_memory_alloc_size_temp = 0;
	}
	
	clearCalledProc();
}

VOID VirtualFreeBefore(uint addr, uint size, uint type, THREADID tid){
	if(!isCalledProc(VIRTUAL_FREE)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualFreeBefore; free memory chunk at address="+int_to_hex(addr)+"; size="+int_to_hex(size)+"; free type="+hexstr(type)+"\n");
}

VOID VirtualFreeAfter(THREADID tid){
	if(!isCalledProc(VIRTUAL_FREE)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"VirtualFreeAfter; done \n");
	clearCalledProc();
}

VOID NtAllocateVirtualMemoryBefore(WINDOWS::HANDLE processHandle, uint pref_addr, uint size, THREADID tid){
	if(!isCalledProc(NT_ALLOCATE_VIRTUAL_MEMORY)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"NtAllocateVirtualMemoryBefore; process handle="+int_to_hex((uint)processHandle)+
		"; allocate memory at address="+int_to_hex(pref_addr)+"; size="+int_to_hex(size)+"\n");
}

VOID NtAllocateVirtualMemoryAfter(THREADID tid){
	if(!isCalledProc(NT_ALLOCATE_VIRTUAL_MEMORY)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"NtAllocateVirtualMemoryAfter; done\n");
	clearCalledProc();
}

VOID ZwAllocateVirtualMemoryBefore(WINDOWS::HANDLE processHandle, uint pref_addr, uint size, THREADID tid){
	if(!isCalledProc(ZW_ALLOCATE_VIRTUAL_MEMORY)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"ZwAllocateVirtualMemoryBefore; process handle="+int_to_hex((uint)processHandle)+
		"; allocate memory at "+int_to_hex(pref_addr)+"; size "+int_to_hex(size)+"\n");
}

VOID ZwAllocateVirtualMemoryAfter(THREADID tid){
	if(!isCalledProc(ZW_ALLOCATE_VIRTUAL_MEMORY)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"ZwAllocateVirtualMemoryAfter; done\n");
	clearCalledProc();
}

VOID OpenSCManagerABefore(WINDOWS::LPCTSTR lpMachineName, WINDOWS::LPCTSTR lpDatabaseName, uint dwDesiredAccess, THREADID tid){
	if(!isCalledProc(OPEN_SC_MANAGER_A)) return;
	string machine_name = "LOCAL_COMPUTER";
	if(lpMachineName != NULL) machine_name = string(lpMachineName);
	string db_name = "DEFAULT_SERVICES_ACTIVE_DATABASE";
	if(lpDatabaseName != NULL) db_name = string(lpDatabaseName);
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"OpenSCManagerABefore; machine name="+machine_name+"; db name="+db_name+"; access type="+int_to_hex(dwDesiredAccess)+"\n");
}

VOID OpenSCManagerAAfter(THREADID tid){
	if(!isCalledProc(OPEN_SC_MANAGER_A)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"OpenSCManagerAAfter; done\n");
	clearCalledProc();
}

VOID OpenServiceABefore(WINDOWS::SC_HANDLE hSCManager, WINDOWS::LPCTSTR lpServiceName, uint dwDesiredAccess, THREADID tid){
	if(!isCalledProc(OPEN_SERVICE_A)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"OpenServiceABefore; service manager handle="+int_to_hex((uint)hSCManager)+
		"; service name="+string(lpServiceName)+"; access type="+int_to_hex(dwDesiredAccess)+"\n");
}

VOID OpenServiceAAfter(THREADID tid){
	if(!isCalledProc(OPEN_SERVICE_A)) return;
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CALLDETAILS)+"OpenServiceAAfter; done\n");
	clearCalledProc();
}

void ImgLoad(IMG img, VOID *v){
	THREADID tid = PIN_ThreadId();
	if(!img_base && IMG_IsMainExecutable(img)) {
		stringstream img_info;
		img_glb = img;
		img_base = IMG_LowAddress(img);
		img_end = IMG_HighAddress(img);
		img_info << "Instrumenting PE file: " << IMG_Name(img) << endl;
		img_info << " Loaded PE file at ["<< int_to_hex(img_base) <<".."<< int_to_hex(img_end) <<"]("<<int_to_hex(IMG_HighAddress(img) - img_base+1)<<")"<< endl;
		img_info << " Its Entry Point is " << int_to_hex(IMG_Entry(img)) << endl << endl;
		LOG(img_info.str());

		MemBlock * img_block = new_MemBlock(img_base,img_end);
		LOG(getLogType(LT_EXEMEMORY)+"insert memory chunk ["+int_to_hex(img_base)+".."+int_to_hex(img_end)+"]("+int_to_hex(img_end-img_base+1)+") \n");
		insert_MemBlock(&user_memory,img_block);
		delete img_block;
	}

	if(!IMG_IsMainExecutable(img)){
		UINT32 begin = IMG_LowAddress(img);
		UINT32 end   = IMG_HighAddress(img);
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_DLLMGMT)+"load at ["+int_to_hex(begin)+".."+int_to_hex(end)+"] "+IMG_Name(img)+"\n");
		MemBlock * module = new_MemBlock(begin,end);
		insert_MemBlock(&loaded_modules, module);
		delete module;
	}

	if(strToLower(IMG_Name(img)) == "c:\\windows\\system32\\kernelbase.dll"){
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
		{
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);

			RTN rtn;
			if (undFuncName == getProcName(WRITE_PROCESS_MEMORY)/*"WriteProcessMemory"*/){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn))
				{
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) WriteProcessMemoryBefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) WriteProcessMemoryAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}else if (undFuncName == getProcName(VIRTUAL_ALLOC_EX)/*"VirtualAllocEx"*/){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn))
				{
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) VirtualAllocExBefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) VirtualAllocExAfter, 
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}else if (undFuncName == getProcName(VIRTUAL_ALLOC)/*"VirtualAlloc"*/){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn))
				{
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) VirtualAllocBefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) VirtualAllocAfter, 
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}else if (undFuncName == getProcName(VIRTUAL_FREE)/*"VirtualFree"*/){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn))
				{
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) VirtualFreeBefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) VirtualFreeAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}
		}
	}

	if(strToLower(IMG_Name(img)) == "c:\\windows\\system32\\kernel32.dll"){ // is this a constant value/path??
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)){
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn;
			if (undFuncName == getProcName(CREATE_THREAD)/*"CreateThread"*/){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn)){
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) CreateThreadBefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) CreateThreadAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}else if (undFuncName == getProcName(CREATE_PROCESS_A)/*"CreateProcessA"*/){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn)){
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) CreateProcessABefore, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) CreateProcessAAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}
		}
	}
	
	if(strToLower(IMG_Name(img)) == "c:\\windows\\system32\\ntdll.dll"){
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)){
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn;
			if (undFuncName == "NtAllocateVirtualMemory"){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn)){
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) NtAllocateVirtualMemoryBefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // handle
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // pref addr
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // regionsize
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) NtAllocateVirtualMemoryAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}else if (undFuncName == "ZwAllocateVirtualMemory"){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn)){
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) ZwAllocateVirtualMemoryBefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // handle
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // pref addr
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // regionsize
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) ZwAllocateVirtualMemoryAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}
		}
	}
	
	if(strToLower(IMG_Name(img)) == "c:\\windows\\system32\\sechost.dll"){
		for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)){
			string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
			RTN rtn;
			if (undFuncName == "OpenSCManagerA"){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn)){
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) OpenSCManagerABefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) OpenSCManagerAAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}else if (undFuncName == "OpenServiceA"){
				rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));

				if (RTN_Valid(rtn)){
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) OpenServiceABefore, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) OpenServiceAAfter, 
						IARG_THREAD_ID,
						IARG_END);
					RTN_Close(rtn);
				}
			}
		}
	}
}

VOID ImgUnload(IMG img, VOID *v){
	if(!IMG_IsMainExecutable(img)){
		THREADID tid = PIN_ThreadId();
		UINT32 begin = IMG_LowAddress(img);
		UINT32 end   = IMG_HighAddress(img);
		LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_DLLMGMT)+"remove at ["+int_to_hex(begin)+".."+int_to_hex(end)+"] "+IMG_Name(img)+"\n");
		MemBlock * module = new_MemBlock(begin,end);
		delete_MemBlock(&loaded_modules, module);
		delete module;
	}
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;

	LOG(getThreadAndLevelLOGPrefix(threadid)+getLogType(LT_THREADMGMT)+"new thread with id "+decstr(threadid)+" started; new #threads is "+decstr(threadCount)+"\n");

    thread_data_t* tdata = new thread_data_t;

    PIN_SetThreadData(tls_key, tdata, threadid);
	
	get_tls(threadid)->calledProc = getCalledProc("none");
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	LOG(getThreadAndLevelLOGPrefix(threadid)+getLogType(LT_THREADMGMT)+"thread with id "+decstr(threadid)+" stopped; new #threads is "+decstr(threadCount)+"\n");
	threadCount--;
}

BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData)
{
    BOOL res;
    INT appArgc;
    CHAR const * const * appArgv;
	
	THREADID tid = PIN_ThreadId();
    OS_PROCESS_ID pid = CHILD_PROCESS_GetId(childProcess);

    CHILD_PROCESS_GetCommandLine(childProcess, &appArgc, &appArgv);
    string childApp(appArgv[0]);
	LOG(getThreadAndLevelLOGPrefix(tid)+getLogType(LT_CHILDPROC)+"started app "+childApp+" with process id "+decstr(pid)+"\n");
	
    //Set Pin's command line for child process
    INT pinArgc = 0;
    CHAR const * pinArgv[30];

	string pin = KnobPinPath32.Value();
    pinArgv[pinArgc++] = pin.c_str();
    pinArgv[pinArgc++] = "-follow_execv";
    pinArgv[pinArgc++] = "-smc_strict";
    pinArgv[pinArgc++] = "-logfile";
	string logfile_pin = KnobExeLogPath.Value()+"\\"+"pin_procID_"+decstr(pid)+"_parentID_"+KnobProcessID.Value()+".log";
    pinArgv[pinArgc++] = logfile_pin.c_str();
    pinArgv[pinArgc++] = "-t";
	string tool_dll = KnobToolDllFile.Value();
	pinArgv[pinArgc++] = tool_dll.c_str();
    pinArgv[pinArgc++] = "-logfile";
	string logfile_tool = KnobExeLogPath.Value()+"\\"+"tool_procID_"+decstr(pid)+"_parentID_"+KnobProcessID.Value()+".log";
    pinArgv[pinArgc++] = logfile_tool.c_str();
    pinArgv[pinArgc++] = "-ts";
    pinArgv[pinArgc++] = KnobTimeStamp.Value().c_str();
    pinArgv[pinArgc++] = "-pin_path_32";
	pinArgv[pinArgc++] = KnobPinPath32.Value().c_str();
    pinArgv[pinArgc++] = "-process_id";
	pinArgv[pinArgc++] = decstr(pid).c_str();
    pinArgv[pinArgc++] = "-exe_log_path";
	pinArgv[pinArgc++] = KnobExeLogPath.Value().c_str();
    pinArgv[pinArgc++] = "-tool_dll_file";
	pinArgv[pinArgc++] = KnobToolDllFile.Value().c_str();
    pinArgv[pinArgc++] = "-tool_name";
	pinArgv[pinArgc++] = KnobToolName.Value().c_str();
    pinArgv[pinArgc++] = "--";

    CHILD_PROCESS_SetPinCommandLine(childProcess, pinArgc, pinArgv);

    return TRUE;
}

int main(int argc, char *argv[])
{
	execution_time = clock();
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
	PIN_InitSymbols();
	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}

	levels = new_Level(INITIAL_LEVEL_ID); 
	cl = levels;
	last_bbl_rtn = RTN_Invalid();
	
    // Obtain a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(0);

	PIN_AddFollowChildProcessFunction(FollowChild, 0);

	IMG_AddInstrumentFunction(ImgLoad,0);
    IMG_AddUnloadFunction(ImgUnload, 0);
	
	PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

	INS_AddInstrumentFunction(Instruction, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
