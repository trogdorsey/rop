
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
#include <set>

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

static std::ofstream out;

std::map<string, image_data> img_name_to_data;
std::map<string, set<ADDRINT>> img_name_to_valid_branch_locations;
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


VOID ImageLoad(IMG img, VOID *v)
{
	if(IMG_Valid(img))
	{
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

			set<ADDRINT> valid_targets;
			ADDRINT base = id.base;
			for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
			{
				if(SEC_Valid(sec) && SEC_IsExecutable(sec))
				{
					int new_rtn = 0;
					for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
					{
						// Prepare for processing of RTN, an  RTN is not broken up into BBLs,
						// it is merely a sequence of INSs 
						string rtn_name = RTN_Name(rtn);
						//out << image_name << " -- " << rtn_name << std::endl;
						RTN_Open(rtn);
						bool first = true;
						int nops=0;
						for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
						{
							ADDRINT a = INS_Address(ins);
							string d = INS_Disassemble(ins);
							
							if(d == "nop ")
							{
								nops++;
							}
							else
							{
								if(nops >= 5)
								{
									RTN_Close(rtn);
									stringstream ss;
									ss << "new_rtn_" << new_rtn;
									string new_rtn_name = ss.str();
									new_rtn++;
									rtn = RTN_CreateAt(a, new_rtn_name);
									//out << name << " -- " << new_rtn_name << std::endl;
									RTN_Open(rtn);
								}
								nops = 0;
							}
							
							//out << std::hex << a << ": " << std::dec << d << std::endl;
							if(first)
							{
								ADDRINT c = INS_Address(ins);
								valid_targets.insert(c - id.base);
								first = false;
							}
							if(INS_IsDirectBranchOrCall(ins))
							{
								ADDRINT t = INS_DirectBranchOrCallTargetAddress(ins);
								if(t >= id.base  && t < id.high)
								{
									valid_targets.insert(t-base);
								}
							}
							if(INS_IsCall(ins))
							{
								ADDRINT next = INS_NextAddress(ins);
								valid_targets.insert(next-base);
							}
						}
						// to preserve space, release data associated with RTN after we have processed it
						RTN_Close(rtn);
					}
				}
			}
			img_name_to_valid_branch_locations[image_name] = valid_targets;
		}
	}
}

VOID indirect(ADDRINT target)
{
	for(std::map<string, image_data>::iterator it = img_name_to_data.begin(); it != img_name_to_data.end(); it++)
	{
		string name = it->first;
		image_data id = it->second;
		if(target >= id.base && target < id.high)
		{
			img_name_to_valid_branch_locations[name].insert(target-id.base);
			break;
		}
	}
}

VOID InstrumentInstructions(INS ins, VOID *v)
{
	ADDRINT c = INS_Address(ins);
	IMG i = IMG_FindByAddress(c);
	if(IMG_Valid(i))
	{
		ADDRINT base = IMG_StartAddress(i);
		string name = IMG_Name(i);
		if(INS_IsCall(ins))
		{
			ADDRINT next = INS_NextAddress(ins);
			img_name_to_valid_branch_locations[name].insert(next-base);
		}
		if(INS_IsDirectBranchOrCall(ins))
		{
			ADDRINT t = INS_DirectBranchOrCallTargetAddress(ins);
			if(t < base)
			{
				out << "PROBLEMS" << std::endl;
			}
			img_name_to_valid_branch_locations[name].insert(t-base);
		}
		if(INS_IsIndirectBranchOrCall(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(indirect), IARG_BRANCH_TARGET_ADDR, IARG_END); 
		}
	}
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
	for(std::map<string, std::set<ADDRINT>>::iterator it = img_name_to_valid_branch_locations.begin(); it != img_name_to_valid_branch_locations.end(); it++)
	{
		set<ADDRINT> s = it->second;
		out << "###########################" << std::endl;
		out << it->first << std::endl;
		out << img_name_to_data[it->first].hash << std::endl;
		for(std::set<ADDRINT>::iterator sit = s.begin(); sit != s.end(); sit++)
		{
			out << *sit << std::endl;
		}
		out << "###########################" << std::endl;
	}
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
		out.open("hash_dump.txt");
	}

	INS_AddInstrumentFunction(InstrumentInstructions, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
        
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
