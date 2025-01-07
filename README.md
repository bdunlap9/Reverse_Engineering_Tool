# Reverse_Engineering_Tool
This tool is designed for advanced memory inspection and disassembly of process modules in a Windows environment. It provides the following key capabilities:

Enable Debug Privileges

Enables SeDebugPrivilege to access and inspect processes with elevated permissions.
Dynamic Module Enumeration

Lists all loaded modules of a target process using EnumProcessModules.
Exported Function Analysis

Extracts and analyzes exported functions from process modules using the PE file structure.
Disassembly

Uses the Capstone disassembly framework to disassemble functions and save them into separate .asm files.
File Mapping and Memory Analysis

Maps module files into memory and reads their export tables for analysis and disassembly.
Target Process Interaction

Allows interaction with processes identified by their Process ID (PID) for module and function analysis.
This tool is valuable for reverse engineering, debugging, and in-depth analysis of process behavior.

![Alt text](https://i.ibb.co/crF0xV7/memory.png)

![Alt text](https://i.ibb.co/1Ljqrk7/Untitled.png)]
