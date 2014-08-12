
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <unordered_map>
#include <set>
#include <list>

namespace WINDOWS
{
	#include <Windows.h>
	#include <WinCrypt.h>
}

/* ================================================================== */
// Global variables 
/* ================================================================== */

class image_data
{
public:
	image_data() : hash(""), base(0x0), high(0x0) {};
	string hash;
	ADDRINT base;
	ADDRINT high;
};

class addr_info
{
public:
	addr_info() : eip(0x0), disass("") {};
	ADDRINT eip;
	string disass;
};
static std::ofstream out;
int all = 0;
std::list<addr_info> ai;
std::unordered_map<string, image_data> img_name_to_data;
std::unordered_map<string, string> img_name_to_hash;
std::unordered_map<string, set<ADDRINT>> img_name_to_valid_branch_locations;
/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}


long long milliseconds_now() {
    static WINDOWS::LARGE_INTEGER s_frequency;
    static BOOL s_use_qpc = WINDOWS::QueryPerformanceFrequency(&s_frequency);
    if (s_use_qpc) {
        WINDOWS::LARGE_INTEGER now;
        WINDOWS::QueryPerformanceCounter(&now);
        return (1000LL * now.QuadPart) / s_frequency.QuadPart;
    } else {
        return WINDOWS::GetTickCount();
    }
}


VOID ImageLoad(IMG img, VOID *v)
{
	if(IMG_Valid(img))
	{
		//long long start = milliseconds_now();
		string image_name = IMG_Name(img);
		ifstream current_image;
		current_image.open(image_name, ios::binary);
		if(current_image.is_open())
		{
			current_image.seekg(0, ios::end);
			std::streamoff size = current_image.tellg();
			char* mem = new char[size];
			current_image.seekg(0, ios::beg);
			current_image.read(mem, size);
			current_image.close();

			WINDOWS::DWORD dwStatus = 0;
			WINDOWS::PBYTE hash_length = NULL;
			WINDOWS::DWORD buffer_size = 16;
			WINDOWS::BOOL bResult = FALSE;
			WINDOWS::PBYTE hash_buffer;

			WINDOWS::HCRYPTPROV hProv = 0;
			WINDOWS::HCRYPTHASH hHash = 0;

			WINDOWS::CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

			WINDOWS::BYTE* b = reinterpret_cast<WINDOWS::BYTE*>(mem); 
			WINDOWS::CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
			WINDOWS::CryptHashData(hHash, b, size, 0);

			hash_buffer = new WINDOWS::BYTE[buffer_size];
			WINDOWS::CryptGetHashParam(hHash, HP_HASHVAL, hash_buffer, &buffer_size, 0);

			std::stringstream ss;			
			for(int i=0; i<16; i++)
			{
				ss << std::hex << std::setfill('0') << std::setw(2) << int(hash_buffer[i]);
			}

			image_data id;
			id.hash = ss.str();
			id.base = IMG_StartAddress(img);
			id.high = IMG_HighAddress(img);
			
			img_name_to_data[image_name] = id;
			delete[] hash_buffer;
			delete[] mem;

			ifstream inputs;
			stringstream s;
			s << "C:\\RopDetectorValues\\" << id.hash;
			inputs.open(s.str());
			if(inputs.is_open())
			{
				out << "DLL info found: " << image_name << std::endl;
				string name;
				std::getline(inputs, name);
				set<ADDRINT> locations;
				while(!inputs.eof())
				{
					string offset_str;
					ADDRINT offset;
					std::getline(inputs, offset_str);
					stringstream z(offset_str);
					z >> offset;
					locations.insert(offset);
				}
				img_name_to_valid_branch_locations[image_name] = locations;
				inputs.close();
			}
			else
			{
				out << "DLL not seen before:" << image_name << "  " << id.hash << std::endl;
				set<ADDRINT> empty_set;
				img_name_to_valid_branch_locations[image_name] = empty_set;
			}
		}
		//long long duration = milliseconds_now() - start;
		//out << "This took " << duration << " ms" << std::endl;
	}
}

VOID allins(ADDRINT eip, void* d, ADDRINT esp)
{
	string* disass = (string*)d;
	/*if(ai.size() > 50)
	{
		ai.pop_front();
	}
	addr_info t;
	t.eip = eip;
	t.disass = *disass;
	ai.push_back(t);*/
	if(all)
	{
		out << "0x" << std::hex << eip << ": " << *disass << std::endl;
	}
}
VOID indirect(ADDRINT eip, ADDRINT target, void* d, ADDRINT esp)
{
	string* disass = (string*)d;
	string current_name;
	//long long start = milliseconds_now();
	for(std::unordered_map<string, image_data>::iterator it = img_name_to_data.begin(); it != img_name_to_data.end(); it++)
	{
		image_data id = it->second;
		if(eip >= id.base && eip < id.high)
		{
			current_name = it->first;
		}
	}

	if(all)
	{
		out << "ESP: 0x" << std::hex << esp << std::endl;
		ADDRINT* esp_ptr = (ADDRINT*)esp;
		ADDRINT esp_ptr_value = *esp_ptr;
		out << "ESP points to: 0x" << esp_ptr_value << std::endl;
		out << "EIP: " << std::hex << "0x" << eip << ": " << *disass << std::endl;
		out << std::hex << "0x" << target << std::dec << std::endl;
	}

	for(std::unordered_map<string, image_data>::iterator it = img_name_to_data.begin(); it != img_name_to_data.end(); it++)
	{
		string target_name = it->first;
		image_data id = it->second;
		if(target >= id.base && target < id.high)
		{
			ADDRINT offset = target - id.base;
			if(!img_name_to_valid_branch_locations[target_name].count(offset))
			{
				out << "PARSEME -- " << target_name << " -- " << img_name_to_data[target_name].hash << " -- " << std::dec << offset << std::endl;
				out << "Current image: " << current_name << std::endl;
				out << "Target image: " << target_name << std::endl;
				out << "ESP: 0x" << std::hex << esp << std::endl;
				ADDRINT* esp_ptr = (ADDRINT*)esp;
				ADDRINT esp_ptr_value = *esp_ptr;
				out << "ESP points to: 0x" << esp_ptr_value << std::endl;
				out << "EIP: " << std::hex << "0x" << eip << ": " << *disass << std::endl;
				out << std::hex << "0x" << target << " offset: 0x" << offset << std::dec << std::endl;
				/*out << "previous instructions" << std::endl;
				for(std::list<addr_info>::iterator it = ai.begin(); it != ai.end(); it++)
				{
					addr_info t = *it;
					out << "0x" << std::hex << t.eip << ":  " << t.disass << std::endl;
				}*/
			}
			break;
		}
		out.flush();
	}
	//long long duration = milliseconds_now() - start;
	//out << "indirect us " << duration << std::endl;
}

VOID InstrumentInstructions(INS ins, VOID *v)
{
	ADDRINT c = INS_Address(ins);
	IMG i = IMG_FindByAddress(c);
	string disass = INS_Disassemble(ins);
	string* s = new string(disass);
	if(IMG_Valid(i))
	{
		if(INS_IsIndirectBranchOrCall(ins) && (INS_IsCall(ins) || INS_IsRet(ins)))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(indirect), IARG_ADDRINT, c, IARG_BRANCH_TARGET_ADDR, IARG_PTR, s, IARG_REG_VALUE, REG_STACK_PTR, IARG_END); 
		}
		/*if(ai.size() > 50)
		{
			ai.pop_front();
		}
		addr_info t;
		t.eip = c;
		t.disass = disass;
		ai.push_back(t);*/
	}
	//INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(allins), IARG_ADDRINT, c, IARG_PTR, s, IARG_REG_VALUE, REG_STACK_PTR, IARG_END); 
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
	PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();
    if (!fileName.empty())
	{
		out.open(fileName.c_str());
	}
	else
	{
		out.open("rop_hash_dump.txt");
	}

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
    INS_AddInstrumentFunction(InstrumentInstructions, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
