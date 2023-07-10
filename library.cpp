#include "library.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		PluginCommand::Register("Test Plugin\\Test", "It's a test action!", [](BinaryView* view) {
			for (auto& symbol: view->GetSymbols())
			{
				LogInfo("%s", symbol->GetFullName().c_str());
			}
		});
		return true;
	}

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
}
