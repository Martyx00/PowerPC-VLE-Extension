# CMAKE generated file: DO NOT EDIT!
# Generated by CMake Version 3.28
cmake_policy(SET CMP0009 NEW)

# BN_API_SOURCES at binaryninjaapi/CMakeLists.txt:16 (file)
file(GLOB NEW_GLOB LIST_DIRECTORIES true "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/*.cpp")
set(OLD_GLOB
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/activity.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/architecture.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/backgroundtask.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/basicblock.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/binaryninjaapi.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/binaryreader.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/binaryview.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/binaryviewtype.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/binarywriter.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/callingconvention.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/component.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/database.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/databuffer.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/datarenderer.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/debuginfo.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/demangle.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/downloadprovider.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/enterprise.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/exceptions.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/externallibrary.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/fileaccessor.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/filemetadata.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/flowgraph.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/flowgraphnode.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/function.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/functionrecognizer.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/highlevelil.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/highlevelilinstruction.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/http.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/interaction.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/languagerepresentation.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/linearviewcursor.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/linearviewobject.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/log.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/lowlevelil.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/lowlevelilinstruction.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/mainthread.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/mediumlevelil.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/mediumlevelilinstruction.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/metadata.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/platform.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/plugin.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/pluginmanager.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/project.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/relocationhandler.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/scriptingprovider.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/secretsprovider.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/settings.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/tempfile.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/transform.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/type.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/typearchive.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/typecontainer.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/typelibrary.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/typeparser.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/typeprinter.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/undoaction.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/update.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/user.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/websocketprovider.cpp"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/workflow.cpp"
  )
if(NOT "${NEW_GLOB}" STREQUAL "${OLD_GLOB}")
  message("-- GLOB mismatch!")
  file(TOUCH_NOCREATE "/home/martin/Code/PowerPC-VLE-Extension/cmake-build-debug/CMakeFiles/cmake.verify_globs")
endif()

# BN_API_SOURCES at binaryninjaapi/CMakeLists.txt:16 (file)
file(GLOB NEW_GLOB LIST_DIRECTORIES true "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/*.h")
set(OLD_GLOB
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/.doxygen.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/binaryninjaapi.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/binaryninjacore.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/enterprise.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/exceptions.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/highlevelilinstruction.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/http.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/lowlevelilinstruction.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/mediumlevelilinstruction.h"
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/rapidjsonwrapper.h"
  )
if(NOT "${NEW_GLOB}" STREQUAL "${OLD_GLOB}")
  message("-- GLOB mismatch!")
  file(TOUCH_NOCREATE "/home/martin/Code/PowerPC-VLE-Extension/cmake-build-debug/CMakeFiles/cmake.verify_globs")
endif()

# BN_API_SOURCES at binaryninjaapi/CMakeLists.txt:16 (file)
file(GLOB NEW_GLOB LIST_DIRECTORIES true "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/json/json-forwards.h")
set(OLD_GLOB
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/json/json-forwards.h"
  )
if(NOT "${NEW_GLOB}" STREQUAL "${OLD_GLOB}")
  message("-- GLOB mismatch!")
  file(TOUCH_NOCREATE "/home/martin/Code/PowerPC-VLE-Extension/cmake-build-debug/CMakeFiles/cmake.verify_globs")
endif()

# BN_API_SOURCES at binaryninjaapi/CMakeLists.txt:16 (file)
file(GLOB NEW_GLOB LIST_DIRECTORIES true "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/json/json.h")
set(OLD_GLOB
  "/home/martin/Code/PowerPC-VLE-Extension/binaryninjaapi/json/json.h"
  )
if(NOT "${NEW_GLOB}" STREQUAL "${OLD_GLOB}")
  message("-- GLOB mismatch!")
  file(TOUCH_NOCREATE "/home/martin/Code/PowerPC-VLE-Extension/cmake-build-debug/CMakeFiles/cmake.verify_globs")
endif()
