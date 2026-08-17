# Mach-O — Wikipedia

> **Source:** <https://en.wikipedia.org/wiki/Mach-O>  
> **Fetched:** 2026-08-17  
> **License:** Content © respective upstream authors.
Reproduced here as a developer reference for the mac-ify
codebase. The Mach-O format itself is publicly documented
in `<mach-o/loader.h>` and Apple's open documentation.

---

Jump to content

Main menu

Main menu

move to sidebar hide

Navigation 

  * [Main page](</wiki/Main_Page> "Visit the main page \[z\]")
  * [Contents](</wiki/Wikipedia:Contents> "Guides to browsing Wikipedia")
  * [Current events](</wiki/Portal:Current_events> "Articles related to current events")
  * [Random article](</wiki/Special:Random> "Visit a randomly selected article \[x\]")
  * [About Wikipedia](</wiki/Wikipedia:About> "Learn about Wikipedia and how it works")
  * [Contact us](<//en.wikipedia.org/wiki/Wikipedia:Contact_us> "How to contact Wikipedia")



Contribute 

  * [Help](</wiki/Help:Contents> "Guidance on how to use and edit Wikipedia")
  * [Learn to edit](</wiki/Help:Introduction> "Learn how to edit Wikipedia")
  * [Community portal](</wiki/Wikipedia:Community_portal> "The hub for editors")
  * [Recent changes](</wiki/Special:RecentChanges> "A list of recent changes to Wikipedia \[r\]")
  * [Upload file](</wiki/Wikipedia:File_upload_wizard> "Add images or other media for use on Wikipedia")
  * [Special pages](</wiki/Special:SpecialPages> "A list of all special pages \[q\]")



[ ](</wiki/Main_Page>)

[ Search ](</wiki/Special:Search> "Search Wikipedia \[f\]")

Search







Appearance




  * [Donate](<https://donate.wikimedia.org/?wmf_source=donate&wmf_medium=sidebar&wmf_campaign=en.wikipedia.org&uselang=en>)
  * [Create account](</w/index.php?title=Special:CreateAccount&returnto=Mach-O> "You are encouraged to create an account and log in; however, it is not mandatory")
  * [Log in](</w/index.php?title=Special:UserLogin&returnto=Mach-O> "You're encouraged to log in; however, it's not mandatory. \[o\]")



Personal tools

  * [ Donate](<https://donate.wikimedia.org/?wmf_source=donate&wmf_medium=sidebar&wmf_campaign=en.wikipedia.org&uselang=en>)
  * [ Create account](</w/index.php?title=Special:CreateAccount&returnto=Mach-O> "You are encouraged to create an account and log in; however, it is not mandatory")
  * [ Log in](</w/index.php?title=Special:UserLogin&returnto=Mach-O> "You're encouraged to log in; however, it's not mandatory. \[o\]")



## Contents

move to sidebar hide

  * (Top)
  * 1 File layout
  * 2 Header
  * 3 Multi-architecture binaries
  * 4 Load commands Toggle Load commands subsection
    * 4.1 Segment load command
      * 4.1.1 Segment number and section numbers
    * 4.2 Link libraries
      * 4.2.1 Link library ordinal numbers
    * 4.3 __LINKEDIT symbol table
      * 4.3.1 Symbol table organization
    * 4.4 __LINKEDIT Symbol table information
      * 4.4.1 Indirect table
    * 4.5 __LINKEDIT Compressed table
      * 4.5.1 Binding information
    * 4.6 Application main entry point
    * 4.7 Application UUID number
    * 4.8 Minimum OS version
  * 5 Other implementations Toggle Other implementations subsection
    * 5.1 Mach-O parsers and editors
    * 5.2 Mach-O runners
  * 6 See also
  * 7 References Toggle References subsection
    * 7.1 Bibliography
  * 8 External links



Toggle the table of contents

# Mach-O

8 languages

  * [Català](<https://ca.wikipedia.org/wiki/Mach-O> "Mach-O – Catalan")
  * [Deutsch](<https://de.wikipedia.org/wiki/Mach-O> "Mach-O – German")
  * [Français](<https://fr.wikipedia.org/wiki/Mach-O> "Mach-O – French")
  * [日本語](<https://ja.wikipedia.org/wiki/Mach-O> "Mach-O – Japanese")
  * [한국어](<https://ko.wikipedia.org/wiki/Mach-O> "Mach-O – Korean")
  * [Русский](<https://ru.wikipedia.org/wiki/Mach-O> "Mach-O – Russian")
  * [Українська](<https://uk.wikipedia.org/wiki/Mach-O> "Mach-O – Ukrainian")
  * [中文](<https://zh.wikipedia.org/wiki/Mach-O> "Mach-O – Chinese")



[Edit links](<https://www.wikidata.org/wiki/Special:EntityPage/Q2627217#sitelinks-wikipedia> "Edit interlanguage links")

  * [Article](</wiki/Mach-O> "View the content page \[c\]")
  * [Talk](</wiki/Talk:Mach-O> "Discuss improvements to the content page \[t\]")



English




  * [Read](</wiki/Mach-O>)
  * [Edit](</w/index.php?title=Mach-O&action=edit> "Edit this page \[e\]")
  * [View history](</w/index.php?title=Mach-O&action=history> "Past revisions of this page \[h\]")



Tools

Tools

move to sidebar hide

Actions 

  * [ Read](</wiki/Mach-O>)
  * [ Edit](</w/index.php?title=Mach-O&action=edit> "Edit this page \[e\]")
  * [ View history](</w/index.php?title=Mach-O&action=history> "Past revisions of this page \[h\]")



General 

  * [What links here](</wiki/Special:WhatLinksHere/Mach-O> "List of all English Wikipedia pages containing links to this page \[j\]")
  * [Related changes](</wiki/Special:RecentChangesLinked/Mach-O> "Recent changes in pages linked from this page \[k\]")
  * [Upload file](<//en.wikipedia.org/wiki/Wikipedia:File_Upload_Wizard> "Upload files \[u\]")
  * [Permanent link](</w/index.php?title=Mach-O&oldid=1366410267> "Permanent link to this revision of this page")
  * [Page information](</w/index.php?title=Mach-O&action=info> "More information about this page")
  * [Cite this page](</w/index.php?title=Special:CiteThisPage&page=Mach-O&id=1366410267&wpFormIdentifier=titleform> "Information on how to cite this page")
  * [Get shortened URL](</w/index.php?title=Special:UrlShortener&url=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FMach-O>)
  * [Switch to legacy parser](</w/index.php?title=Mach-O&useparsoid=0>)



Print/export 

  * [Download as PDF](</w/index.php?title=Special:DownloadAsPdf&page=Mach-O&action=show-download-screen> "Download this page as a PDF file")
  * [Printable version](</w/index.php?title=Mach-O&printable=yes> "Printable version of this page \[p\]")



In other projects 

  * [Wikidata item](<https://www.wikidata.org/wiki/Special:EntityPage/Q2627217> "Structured data on this page hosted by Wikidata \[g\]")



Appearance

move to sidebar hide

From Wikipedia, the free encyclopedia

File format for executables, object code, shared libraries, and core dumps

This article is about the file format. For other uses, see [Mach O](<https://en.wikipedia.org/wiki/Mach_O_\(disambiguation\)> "Mach O \(disambiguation\)").

| **This article has multiple issues.** Please help **[improve it](<https://en.wikipedia.org/wiki/Special:EditPage/Mach-O> "Special:EditPage/Mach-O")** or discuss these issues on the **[talk page](<https://en.wikipedia.org/wiki/Talk:Mach-O> "Talk:Mach-O")**. _([Learn how and when to remove these messages](<https://en.wikipedia.org/wiki/Help:Maintenance_template_removal> "Help:Maintenance template removal"))_ | | This article includes a list of [general references](<https://en.wikipedia.org/wiki/Wikipedia:Citing_sources#General_references> "Wikipedia:Citing sources") **but lacks sufficient corresponding[inline citations](<https://en.wikipedia.org/wiki/Wikipedia:Citing_sources#Inline_citations> "Wikipedia:Citing sources")**. Please help [improve this article](<https://en.wikipedia.org/w/index.php?title=Mach-O&action=edit>) by [introducing](<https://en.wikipedia.org/wiki/Wikipedia:When_to_cite> "Wikipedia:When to cite") more precise citations. _( February 2021)__([Learn how and when to remove this message](<https://en.wikipedia.org/wiki/Help:Maintenance_template_removal> "Help:Maintenance template removal"))_  
---|---  
| This article **contains an excessive amount of intricate[detail](<https://en.wikipedia.org/wiki/Wikipedia:DETAIL> "Wikipedia:DETAIL")**. Please help [improve it](<https://en.wikipedia.org/w/index.php?title=Mach-O&action=edit>) by [spinning off](<https://en.wikipedia.org/wiki/Wikipedia:Content_forks#Article_spinoffs:_.22Summary_style.22_meta-articles_and_summary_sections> "Wikipedia:Content forks") or [relocating](<https://en.wikipedia.org/wiki/Wikipedia:Handling_trivia#Recommendations_for_handling_trivia> "Wikipedia:Handling trivia") relevant information and removing excessive detail that goes against [Wikipedia's inclusion policy](<https://en.wikipedia.org/wiki/Wikipedia:What_Wikipedia_is_not> "Wikipedia:What Wikipedia is not"). _( July 2026)__([Learn how and when to remove this message](<https://en.wikipedia.org/wiki/Help:Maintenance_template_removal> "Help:Maintenance template removal"))_  
---|---  
  
_([Learn how and when to remove this message](<https://en.wikipedia.org/wiki/Help:Maintenance_template_removal> "Help:Maintenance template removal"))_  
  
Mach-O  
---  
[](<https://en.wikipedia.org/wiki/File:ExecutableBinaryIcon_\(macOS_Golden_Gate\).png> "macOS 27 Golden Gate Executable Binary icon")  
[Filename extension](<https://en.wikipedia.org/wiki/Filename_extension> "Filename extension")|  none, `.o`, `.dylib`, `.kext`[1]  
[Uniform Type Identifier (UTI)](<https://en.wikipedia.org/wiki/Uniform_Type_Identifier> "Uniform Type Identifier")| com.apple.mach-o-binary  
Developed by| [Carnegie Mellon University](<https://en.wikipedia.org/wiki/Carnegie_Mellon_University> "Carnegie Mellon University"), [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.")  
Type of format| [Binary](<https://en.wikipedia.org/wiki/Binary_file> "Binary file"), [executable](<https://en.wikipedia.org/wiki/Executable> "Executable"), [object](<https://en.wikipedia.org/wiki/Object_code> "Object code"), [shared libraries](<https://en.wikipedia.org/wiki/Shared_libraries> "Shared libraries"), [core dump](<https://en.wikipedia.org/wiki/Core_dump> "Core dump")  
[Container for](<https://en.wikipedia.org/wiki/Container_format> "Container format")| [ARM](<https://en.wikipedia.org/wiki/ARM_architecture> "ARM architecture"), [SPARC](<https://en.wikipedia.org/wiki/SPARC> "SPARC"), [PA-RISC](<https://en.wikipedia.org/wiki/PA-RISC> "PA-RISC"), [PowerPC](<https://en.wikipedia.org/wiki/PowerPC> "PowerPC") and [x86](<https://en.wikipedia.org/wiki/X86_architecture> "X86 architecture") [executable](<https://en.wikipedia.org/wiki/Executable> "Executable") code, memory image dumps  
  
**Mach-O** (**Mach object**) is a [file format](<https://en.wikipedia.org/wiki/File_format> "File format") for [executables](<https://en.wikipedia.org/wiki/Executable> "Executable"), [object code](<https://en.wikipedia.org/wiki/Object_code> "Object code"), [shared libraries](<https://en.wikipedia.org/wiki/Shared_libraries> "Shared libraries"), dynamically loaded code, and [core dumps](<https://en.wikipedia.org/wiki/Core_dump> "Core dump"). It was developed to replace the [a.out](<https://en.wikipedia.org/wiki/A.out> "A.out") format.

Mach-O is used by some systems based on the [Mach kernel](<https://en.wikipedia.org/wiki/Mach_kernel> "Mach kernel"). [NeXTSTEP](<https://en.wikipedia.org/wiki/NeXTSTEP> "NeXTSTEP"), [macOS](<https://en.wikipedia.org/wiki/MacOS> "MacOS"), and [iOS](<https://en.wikipedia.org/wiki/IOS> "IOS") are examples of systems that use this format for native executables, libraries and object code.

## File layout

[[edit](</w/index.php?title=Mach-O&action=edit&section=1> "Edit section: File layout")]

Each Mach-O file is made up of one Mach-O header, followed by a series of load commands, followed by one or more segments, each of which contains between 0 and 255 sections. Mach-O uses the REL [relocation](<https://en.wikipedia.org/wiki/Relocation_\(computer_science\)> "Relocation \(computer science\)") format to handle references to symbols. When looking up symbols, Mach-O uses a two-level [namespace](<https://en.wikipedia.org/wiki/Namespace> "Namespace") that encodes each symbol into an 'object/symbol name' pair that is then linearly searched for, first by the object and then the symbol name.[2]

The basic structure—a list of variable-length "load commands" that reference pages of data elsewhere in the file[3]—was also used in the executable file format for [Accent](<https://en.wikipedia.org/wiki/Accent_kernel> "Accent kernel").[_[citation needed](<https://en.wikipedia.org/wiki/Wikipedia:Citation_needed> "Wikipedia:Citation needed")_] The Accent file format was, in turn, based on an idea from [Spice Lisp](<https://en.wikipedia.org/wiki/Spice_Lisp> "Spice Lisp").[_[citation needed](<https://en.wikipedia.org/wiki/Wikipedia:Citation_needed> "Wikipedia:Citation needed")_]

All multi-byte values in all data structures are written in the [byte order](<https://en.wikipedia.org/wiki/Byte_order> "Byte order") of the host for which the code was produced.[4]

## Header

[[edit](</w/index.php?title=Mach-O&action=edit&section=2> "Edit section: Header")]

Mach-O file header[5] Offset| Bytes| Description  
---|---|---  
0| 4| Magic number  
4| 4| CPU type  
8| 4| CPU subtype  
12| 4| File type  
16| 4| Number of load commands  
20| 4| Size of load commands  
24| 4| Flags  
28| 4| Reserved (64-bit only)  
  
The magic number for 32-bit code is 0xfeedface while the magic number for 64-bit architectures is 0xfeedfacf.

The reserved value is only present in 64-bit Mach-O files. It is reserved for future use or extension of the 64-bit header.

The CPU type indicates the instruction set architecture for the code. If the file is for the 64-bit version of the instruction set architecture, the CPU type value has the 0x01000000 bit set. If the file is for the 64-bit version of the instruction set architecture but with 32-bit pointers, the CPU type value has the 0x02000000 bit set.

The CPU type values are as follows:[6][7]

CPU type Value| CPU type  
---|---  
0x00000001| [VAX](<https://en.wikipedia.org/wiki/VAX> "VAX")  
0x00000002| [ROMP](<https://en.wikipedia.org/wiki/IBM_ROMP> "IBM ROMP")  
0x00000004| [NS32032](<https://en.wikipedia.org/wiki/NS32000#32032> "NS32000")  
0x00000005| [NS32332](<https://en.wikipedia.org/wiki/NS32000#32332,_32532> "NS32000")  
0x00000006| [MC680x0](<https://en.wikipedia.org/wiki/Motorola_68000_series> "Motorola 68000 series")  
0x00000007| [x86](<https://en.wikipedia.org/wiki/X86> "X86")  
0x00000008| [MIPS](<https://en.wikipedia.org/wiki/MIPS_architecture> "MIPS architecture")  
0x00000009| [NS32352](<https://en.wikipedia.org/wiki/NS32000#32332,_32532> "NS32000")  
0x0000000B| [HP-PA](<https://en.wikipedia.org/wiki/PA-RISC> "PA-RISC")  
0x0000000C| [ARM](<https://en.wikipedia.org/wiki/ARM_architecture_family> "ARM architecture family")  
0x0000000D| [MC88000](<https://en.wikipedia.org/wiki/Motorola_88000> "Motorola 88000")  
0x0000000E| [SPARC](<https://en.wikipedia.org/wiki/SPARC> "SPARC")  
0x0000000F| [i860](<https://en.wikipedia.org/wiki/Intel_i860> "Intel i860") (big-endian)  
0x00000010| [i860](<https://en.wikipedia.org/wiki/Intel_i860> "Intel i860") (little-endian) or maybe [DEC Alpha](<https://en.wikipedia.org/wiki/DEC_Alpha> "DEC Alpha")[8]  
0x00000011| [RS/6000](<https://en.wikipedia.org/wiki/IBM_RS/6000> "IBM RS/6000")  
0x00000012| [PowerPC](<https://en.wikipedia.org/wiki/PowerPC> "PowerPC") / MC98000  
0x00000018| [RISC-V](<https://en.wikipedia.org/wiki/RISC-V> "RISC-V")  
  
Each CPU type has a set of CPU subtype values, indicating a particular model of that CPU type for which the code is intended. Newer models of a CPU type may support instructions, or other features, not supported by older CPU models, so that code compiled or written for a newer model might contain instructions that are [illegal instructions](<https://en.wikipedia.org/wiki/Illegal_instruction> "Illegal instruction") on an older model, causing that code to [trap](<https://en.wikipedia.org/wiki/Interrupt> "Interrupt") or otherwise fail to operate correctly when run on an older model. Code intended for an older model will run on newer models without problems.

If the CPU type is ARM then the subtypes are as follows:[6]

CPU subtype ARM Value| CPU version  
---|---  
0x00000000| All ARM processors  
0x00000001| Optimized for ARM-A500 ARCH or newer.  
0x00000002| Optimized for ARM-A500 or newer.  
0x00000003| Optimized for ARM-A440 or newer.  
0x00000004| Optimized for ARM-M4 or newer.  
0x00000005| Optimized for ARM-V4T or newer.  
0x00000006| Optimized for ARM-V6 or newer.  
0x00000007| Optimized for ARM-V5TEJ or newer.  
0x00000008| Optimized for ARM-XSCALE or newer.  
0x00000009| Optimized for ARM-V7 or newer.  
0x0000000A| Optimized for ARM-V7F (Cortex A9) or newer.  
0x0000000B| Optimized for ARM-V7S (Swift) or newer.  
0x0000000C| Optimized for ARM-V7K (Kirkwood40) or newer.  
0x0000000D| Optimized for ARM-V8 or newer.  
0x0000000E| Optimized for ARM-V6M or newer.  
0x0000000F| Optimized for ARM-V7M or newer.  
0x00000010| Optimized for ARM-V7EM or newer.  
  
If the CPU type is x86 then the subtypes are as follows:[6]

CPU subtype x86 Value| CPU version  
---|---  
0x00000003| All x86 processors.  
0x00000004| Optimized for 486 or newer.  
0x00000084| Optimized for 486SX or newer.  
0x00000056| Optimized for Pentium M5 or newer.  
0x00000067| Optimized for Celeron or newer.  
0x00000077| Optimized for Celeron Mobile.  
0x00000008| Optimized for Pentium 3 or newer.  
0x00000018| Optimized for Pentium 3-M or newer.  
0x00000028| Optimized for Pentium 3-XEON or newer.  
0x0000000A| Optimized for Pentium-4 or newer.  
0x0000000B| Optimized for Itanium or newer.  
0x0000001B| Optimized for Itanium-2 or newer.  
0x0000000C| Optimized for XEON or newer.  
0x0000001C| Optimized for XEON-MP or newer.  
  
After the subtype value is the file type value.

File type Value| Description  
---|---  
0x00000001| Relocatable object file.  
0x00000002| Demand paged executable file.  
0x00000003| Fixed VM shared library file.  
0x00000004| Core file.  
0x00000005| Preloaded executable file.  
0x00000006| Dynamically bound shared library file.  
0x00000007| Dynamic link editor.  
0x00000008| Dynamically bound bundle file.  
0x00000009| Shared library stub for static linking only, no section contents.  
0x0000000A| Companion file with only debug sections.  
0x0000000B| x86_64 kexts.  
0x0000000C| a file composed of other Mach-Os to be run in the same userspace sharing a single linkedit.  
  
After the file type value is the number of load commands and the total number of bytes the load commands are after the Mach-O header, then a 32-bit flag with the following possible settings.

Flag settings Flag in [ left shift ](<https://en.wikipedia.org/wiki/Arithmetic_shift> "Arithmetic shift")| Flag in binary| Description  
---|---|---  
1<<0| 0000_0000_0000_0000_0000_0000_0000_0001| The object file has no undefined references.  
1<<1| 0000_0000_0000_0000_0000_0000_0000_0010| The object file is the output of an incremental link against a base file and can't be link edited again.  
1<<2| 0000_0000_0000_0000_0000_0000_0000_0100| The object file is input for the dynamic linker and can't be statically link edited again.  
1<<3| 0000_0000_0000_0000_0000_0000_0000_1000| The object file's undefined references are bound by the dynamic linker when loaded.  
1<<4| 0000_0000_0000_0000_0000_0000_0001_0000| The file has its dynamic undefined references prebound.  
1<<5| 0000_0000_0000_0000_0000_0000_0010_0000| The file has its read-only and read-write segments split.  
1<<6| 0000_0000_0000_0000_0000_0000_0100_0000| The shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete).  
1<<7| 0000_0000_0000_0000_0000_0000_1000_0000| The image is using two-level name space bindings.  
1<<8| 0000_0000_0000_0000_0000_0001_0000_0000| The executable is forcing all images to use flat name space bindings.  
1<<9| 0000_0000_0000_0000_0000_0010_0000_0000| This umbrella guarantees no multiple definitions of symbols in its sub-images so the two-level namespace hints can always be used.  
1<<10| 0000_0000_0000_0000_0000_0100_0000_0000| Do not have dyld notify the prebinding agent about this executable.  
1<<11| 0000_0000_0000_0000_0000_1000_0000_0000| The binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set.  
1<<12| 0000_0000_0000_0000_0001_0000_0000_0000| Indicates that this binary binds to all two-level namespace modules of its dependent libraries.  
1<<13| 0000_0000_0000_0000_0010_0000_0000_0000| Safe to divide up the sections into sub-sections via symbols for dead code stripping.  
1<<14| 0000_0000_0000_0000_0100_0000_0000_0000| The binary has been canonicalized via the un-prebind operation.  
1<<15| 0000_0000_0000_0000_1000_0000_0000_0000| The final linked image contains external weak symbols.  
1<<16| 0000_0000_0000_0001_0000_0000_0000_0000| The final linked image uses weak symbols.  
1<<17| 0000_0000_0000_0010_0000_0000_0000_0000| When this bit is set, all stacks in the task will be given stack execution privilege.  
1<<18| 0000_0000_0000_0100_0000_0000_0000_0000| When this bit is set, the binary declares it is safe for use in processes with uid zero.  
1<<19| 0000_0000_0000_1000_0000_0000_0000_0000| When this bit is set, the binary declares it is safe for use in processes when UGID is true.  
1<<20| 0000_0000_0001_0000_0000_0000_0000_0000| When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported.  
1<<21| 0000_0000_0010_0000_0000_0000_0000_0000| When this bit is set, the OS will load the main executable at a random address.  
1<<22| 0000_0000_0100_0000_0000_0000_0000_0000| Only for use on dylibs. When linking against a dylib that has this bit set, the static linker will automatically not create a load command to the dylib if no symbols are being referenced from the dylib.  
1<<23| 0000_0000_1000_0000_0000_0000_0000_0000| Contains a section of type S_THREAD_LOCAL_VARIABLES.  
1<<24| 0000_0001_0000_0000_0000_0000_0000_0000| When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g. i386) that don't require it.  
1<<25| 0000_0010_0000_0000_0000_0000_0000_0000| The code was linked for use in an application.  
1<<26| 0000_0100_0000_0000_0000_0000_0000_0000| The external symbols listed in the nlist symbol table do not include all the symbols listed in the dyld info.  
1<<27| 0000_1000_0000_0000_0000_0000_0000_0000| Allow LC_MIN_VERSION_MACOS and LC_BUILD_VERSION load commands with the platforms macOS, macCatalyst, iOSSimulator, tvOSSimulator and watchOSSimulator.  
1<<31| 1000_0000_0000_0000_0000_0000_0000_0000| Only for use on dylibs. When this bit is set, the dylib is part of the dyld shared cache, rather than loose in the filesystem.  
7<<28|  The digits marked with "x" have no use, and are reserved for future use.  
  
Multiple binary digits can be set to one in the flags to identify any information or settings that apply to the binary.

Now the load commands are read as one has reached the end of the Mach-O header.

## Multi-architecture binaries

[[edit](</w/index.php?title=Mach-O&action=edit&section=3> "Edit section: Multi-architecture binaries")]

Multiple Mach-O files can be combined in a [multi-architecture binary](<https://en.wikipedia.org/wiki/Fat_binary#NeXT's/Apple's_multi-architecture_binaries> "Fat binary"). This allows a single binary file to contain code to support multiple instruction set architectures, for example for different generations and types of Apple devices, including different processor architectures[9] such as [ARM64](<https://en.wikipedia.org/wiki/ARM64> "ARM64") and [x86-64](<https://en.wikipedia.org/wiki/X86-64> "X86-64").[10]

All fields in the universal header are big-endian.[4]

The universal header is in the following form:[11]

Mach-O universal header Offset| Bytes| Description  
---|---|---  
0| 4| Magic number  
4| 4| Number of binaries  
  
The magic number in a multi-architecture binary is 0xcafebabe in big-endian byte order, so the first four bytes of the header will always be 0xca 0xfe 0xba 0xbe, in that order.

The number of binaries is the number of entries that follow the header.

The header is followed by a sequence of entries in the following form:[12]

Mach-O universal file entries Offset| Bytes| Description  
---|---|---  
0| 4| CPU type  
4| 4| CPU subtype  
8| 4| File offset  
12| 4| Size  
16| 4| Section alignment (power of 2)  
  
The sequence of entries is followed by a sequence of Mach-O images. Each entry refers to a Mach-O image.

The CPU type and subtype for an entry must be the same as the CPU type and subtype for the Mach-O image to which the entry refers.

The file offset and size are the offset in the file of the beginning of the Mach-O image, and the size of the Mach-O image, to which the entry refers.

The section alignment is the logarithm, base 2, of the byte alignment in the file required for the Mach-O image to which the entry refers; for example, a value of 14 means that the image must be aligned on a 214-byte boundary, i.e. a 16384-byte boundary. This is required by tools that modify the multi-architecture binary, in order for them to keep the image properly aligned.

## Load commands

[[edit](</w/index.php?title=Mach-O&action=edit&section=4> "Edit section: Load commands")]

The load commands are read immediately after the Mach-O header.

The Mach-O header specifies how many load commands exist after the Mach-O header and the size in bytes to where the load commands end. The size of load commands is used as a redundancy check.

When the last load command is read and the number of bytes for the load commands do not match, or if we go outside the number of bytes for load commands before reaching the last load command, then the file may be corrupted.

Each load command is a sequence of entries in the following form:[13]

Load command Offset| Bytes| Description  
---|---|---  
0| 4| Command type  
4| 4| Command size  
  
The load command type identifies what the parameters are in the load command. If a load command starts with 0x80000000 bit set, the load command is necessary in order to be able to load or run the binary. This allows older Mach-O loaders to skip commands not understood by the loader that are not mandatory for loading the application.

### Segment load command

[[edit](</w/index.php?title=Mach-O&action=edit&section=5> "Edit section: Segment load command")]

Mach-O binaries that use load command type 0x00000001 use the 32-bit version of the segment load command,[14] while 0x00000019 is used to specify the 64-bit version of the segment load command.,[15]

The segment load command varies whether the Mach-O header is 32-bit or 64-bit. This is because 64-bit processor architecture uses 64-bit addresses while 32-bit architectures use 32-bit addresses.

All virtual RAM addresses are added to a base address to keep applications spaced apart. Each section in a segment load command has a relocation list offset that specifies the offsets in the section that must be adjusted based on the application's base address. The relocations are unnecessary if the application can be placed at its defined RAM address locations such as a base address of zero.

Load command (Segment load32/64) Offset (32-bit)| Bytes (32-bit)| Offset (64-bit)| Bytes (64-bit)| Description  
---|---|---|---|---  
0| 4| 0| 4| 0x00000001 (Command type 32-bit) 0x00000019 (Command type 64-bit)  
4| 4| 4| 4| Command size  
8| 16| 8| 16| Segment name  
24| 4| 24| 8| Address  
28| 4| 32| 8| Address size  
32| 4| 40| 8| File offset  
36| 4| 48| 8| Size (bytes from file offset)  
40| 4| 56| 4| Maximum virtual memory protections  
44| 4| 60| 4| Initial virtual memory protections  
48| 4| 64| 4| Number of sections  
52| 4| 68| 4| Flag32  
  
A segment name cannot be larger than 16 text characters in bytes. The unused characters are 0x00 in value.

The segment command contains the address to write the section in virtual address space plus the application's base address. The number of bytes to write to the address location (address size).

After the address information is the file offset the segment data is located in the Mach-O binary, and the number of bytes to read from the file.

When the address size is larger than the number of bytes to read from the file, the rest of the bytes in RAM space are set 0x00.

There is a segment that is called `__PAGEZERO`, which has a file offset of zero and a size of zero in the file. It has a defined virtual memory address and size. Its access permissions are set to zero as well, meaning it cannot be used at all (any access to this segment will cause a page fault). The purpose of this segment is to catch invalid NULL pointers (which have a value of zero). On 32-bit environments, the default size of this segment is 4 KiB, while on 64-bit environments it is 4 GiB (this catches invalid 32-bit NULL pointers which may have been truncated during a round-trip assignment through a 32-bit integer.) The size of this segment is configurable through the `-pagezero_size` compiler/linker flag.

When a segment is initially placed in the virtual address space, it is given the CPU access permissions specified by the initial virtual memory protections value. The permissions on a region of the virtual address space may be changed by application or library code with calls to routines such as mprotect(); the maximum virtual memory protections limit what permissions may be granted for access to the segment.

Permissions Permission bit in binary| Description  
---|---  
00000000000000000000000000000001| The section allows the CPU to read data from this section (Read setting).  
00000000000000000000000000000010| The section allows the CPU to write data to this section (Write setting).  
00000000000000000000000000000100| The section allows the CPU to execute code in this section (Execute setting).  
xxxxxxxxxxxxxxxxxxxxxxxxxxxxx000| The digits marked with "x" have no use, and are reserved for future use.  
  
Then after the CPU address protection settings is the number of sections that are within this segment that are read after the segments flag settings.

The segment flag settings are as follows:

Segment flag settings. Flag32 in binary| Description  
---|---  
00000000000000000000000000000001| The file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks in core files).  
00000000000000000000000000000010| This segment is the VM that is allocated by a fixed VM library, for overlap checking in the link editor.  
00000000000000000000000000000100| This segment has nothing that was relocated in it and nothing relocated to it, that is it maybe safely replaced without relocation.  
00000000000000000000000000001000| This segment is protected. If the segment starts at file offset 0, the first page of the segment is not protected. All other pages of the segment are protected.  
00000000000000000000000000010000| This segment is made read-only after relocations are applied if needed.  
xxxxxxxxxxxxxxxxxxxxxxxxxxx00000| The digits marked with "x" have no use, and are reserved for future use.  
  
The number of sections in the segment is a set of entries that are read as follows:

Segment section32/64 Offset (32-bit)| Bytes (32-bit)| Offset (64-bit)| Bytes (64-bit)| Description  
---|---|---|---|---  
0| 16| 0| 16| Section name  
16| 16| 16| 16| Segment name  
32| 4| 32| 8| Section address  
36| 4| 40| 8| Section size  
40| 4| 48| 4| Section file offset  
44| 4| 52| 4| Alignment  
48| 4| 56| 4| Relocations file offset  
52| 4| 60| 4| Number of relocations  
56| 4| 64| 4| Flag/Type  
60| 4| 68| 4| Reserved1  
64| 4| 72| 4| Reserved2  
N/A| N/A| 76| 4| Reserved3 (64-bit only)  
  
The section's segment name must match the segment's load command name. The sections entries locate to data in the segment. Each section locates to the relocation entries for adjusting addresses in the section if the application base address is added to anything other than zero.

The section size applies to both the size of the section at its address location and size in the file at its offset location.

The section Flag/Type value is read as follows:

Section flag settings Flag in binary| Description  
---|---  
10000000000000000000000000000000xxxxxxxx| Section contains only true machine instructions  
01000000000000000000000000000000xxxxxxxx| Section contains coalesced symbols that are not to be in a ranlib table of contents  
00100000000000000000000000000000xxxxxxxx| Ok to strip static symbols in this section in files with the MH_DYLDLINK flag  
00010000000000000000000000000000xxxxxxxx| No dead stripping  
00001000000000000000000000000000xxxxxxxx| Blocks are live if they reference live blocks  
00000100000000000000000000000000xxxxxxxx| Used with i386 code stubs written on by dyld  
00000010000000000000000000000000xxxxxxxx| A debug section  
00000000000000000000010000000000xxxxxxxx| Section contains some machine instructions  
00000000000000000000001000000000xxxxxxxx| Section has external relocation entries  
00000000000000000000000100000000xxxxxxxx| Section has local relocation entries  
  
Any of the settings that apply to the section have a binary digit set one. The last eight binary digits is the section type value.

Section type value Flag in binary| Description  
---|---  
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx00000110| Section with only non-lazy symbol pointers  
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx00000111| Section with only lazy symbol pointers  
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx00001000| Section with only symbol stubs  
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx00001100| Zero fill on demand section (that can be larger than 4 gigabytes)  
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx00010000| Section with only lazy symbol pointers to lazy loaded dylibs  
  
The Mach-O loader records the symbol pointer sections and symbol stub sections. They are sequentially used by the indirect symbol table to load in method calls.

The size of each symbol stub is stored in reserved2 value. Each pointer is 32-bit address locations in 32-bit Mach-O and 64-bit address locations in 64-bit Mach-O. Once the section end is reached, we move to the next section while reading the indirect symbol table.

#### Segment number and section numbers

[[edit](</w/index.php?title=Mach-O&action=edit&section=6> "Edit section: Segment number and section numbers")]

The segments and sections are located by segment number and section number in the compressed and uncompressed link edit information sections.

A segment value of 3 would mean the offset to the data of the fourth segment load command in the Mach-O file starting from zero up (0,1,2,3 = 4th segment).

Sections are also numbered from sections 1 and up. Section value zero is used in the symbol table for symbols that are not defined in any section (undefined). Such as a method, or data that exist within another binaries symbol table section.

A segment that has seven sections would mean the last section is 8. Then if the following segment load command has three sections they are labelled as sections 9, 10, and 11. A section number of 10 would mean the second segment, section 2.

One would not be able to properly read the symbol table and linking information if we do not store the order the sections are read in and their address/file offset position.

One can easily use file offset without using the RAM addresses and relocations to build a symbol reader and to read the link edit sections and even map method calls or design a disassembler.

If building a Mach-O loader, then you want to dump the sections to the defined RAM addresses plus a base address to keep applications spaced apart so they do not write over one another.

The segment names and section names can be renamed to anything you like and there link will be no problems locating the appropriate sections by section number, or segment number as long as you do not alter the order the segment commands go in.

### Link libraries

[[edit](</w/index.php?title=Mach-O&action=edit&section=7> "Edit section: Link libraries")]

Link libraries are the same as any other Mach-O binary, just that there is no command that specifies the main entry point at which the program begins.

There are three load commands for loading a link library file.

Load command type 0x0000000C are for the full file path to the dynamically linked shared library.

Load command type 0x0000000D are for dynamically linked shared locations from the application's current path.

Load command type 0x00000018 is for a dynamically linked shared library that is allowed to be missing. The symbol names exist in other link libraries and are used if the library is missing meaning all symbols are weak imported.

The link library command is read as follows:

Load command (link library) Offset| Bytes| Description  
---|---|---  
0| 4| 0x0000000C (Command type) 0x0000000D (Command type) 0x00000018 (Command type)  
4| 4| Command size  
8| 4| String offset (always offset 24)  
12| 4| Time date stamp  
16| 4| Current version  
20| 4| Compatible version  
24| Command size - 24| File path string  
  
The file path name begins at the string offset, which is always 24. The number of bytes per text character is the remaining bytes in command size. The end of the library file path is identified by a character that is 0x00. The remaining 0x00 values are used as padding, if any.

#### Link library ordinal numbers

[[edit](</w/index.php?title=Mach-O&action=edit&section=8> "Edit section: Link library ordinal numbers")]

The library is located by ordinal number in the compressed and uncompressed link edit information sections.

Link libraries are numbered from ordinal 1 and up. The ordinal value zero is used in the symbol table to specify the symbol does not exist as an external symbol in another Mach-O binary.

The link edit information will have no problem locating the appropriate library to read by ordinal number as long as one does not alter the order in which the link library commands go in.

Link library command 0x00000018 should be avoided for performance reasons, as in the case the library is missing, then a search must be performed through all loaded link libraries.

### `__LINKEDIT` symbol table

[[edit](</w/index.php?title=Mach-O&action=edit&section=9> "Edit section: __LINKEDIT symbol table")]

Mach-O application files and link libraries both have a symbol table command.

The command is read as follows:

Load command (Symbol table) Offset| Bytes| Description  
---|---|---  
0| 4| 0x00000002 (Command type)  
4| 4| Command size (always 24)  
8| 4| Symbols (file offset relative to Mach-O header)  
12| 4| Number of symbols  
16| 4| String table (file offset relative to Mach-O header)  
20| 4| String table size  
  
The symbol file offset is the offset relative to the start of the Mach-O header to where the symbol entries begins in the file. The number of symbol entries marks the end of the symbol table.

A symbol has a name offset that should never exceed the string table size. Each symbol name offset is added to the string table file offset which in turn is relative to the start of the Mach-O header. Each symbol name ends with a 0x00 byte value.

The symbol address uses a 32-bit address for 32-bit Mach-O files and a 64-bit address for 64-bit Mach-O files.

Each symbol entry is read as follows:

Symbol32/64 Offset (32-bit)| Bytes (32-bit)| Offset (64-bit)| Bytes (64-bit)| Description  
---|---|---|---|---  
0| 4| 0| 4| Name offset  
4| 1| 4| 1| Symbol type  
5| 1| 5| 1| Section number 0 to 255  
6| 2| 6| 2| Data info (library ordinal number)  
8| 4| 8| 8| Symbol address  
  
The symbol name offset is added to the string table offset. The last text character byte is read as 0x00.

The symbol type value has multiple adjustable sections in binary. The symbol type is read as follows:

Symbol type sections Binary digits| Description  
---|---  
???xxxxx| Local debugging symbols  
xxxx???x| Symbol address type  
xxx?xxx?| Symbol visibility setting flags  
  
The digits marked ? are used for the specified purpose; the digits marked x are used for other purposes.

The three first binary digits are symbols that locate to function names relative to compiled machine code instructions and line numbers by address location. This information allows us to generate line numbers to the location your code crashed. Local debugging symbols are only useful when designing the application, but are not needed to run the application.

Symbol address type Binary value| Description  
---|---  
xxxx000x| Symbol undefined  
xxxx001x| Symbol absolute  
xxxx101x| Symbol indirect  
xxxx110x| Symbol prebound undefined  
xxxx111x| Symbol defined in section number  
  
The following flag settings:

Symbol visibility setting flags Binary value| Description  
---|---  
xxx1xxx0| Private symbol  
xxx0xxx1| External symbol  
  
External symbols are symbols that have a defined address in the link library and can be copied to an undefined symbol in a Mach-O application. The address location is added to the link library base address.

A private symbol is skipped even if it matches the name of an undefined symbol. A private and external symbol can only be set to an undefined symbol if it is in the same file.

After the symbol type is the section number the symbol exists in. The section number is a byte value (0 to 255). You can add more sections than 255 using segment load commands, but the section numbers are then outside the byte value range used in the symbol entries.

A section number of zero means the symbol is not in any section of the application, the address location of the symbol is zero, and is set as Undefined. A matching External symbol name has to be found in a link library that has the symbol address.

The data info field contains the link library ordinal number that the external symbol can be found in with the matching symbol name. The data info bit field breaks down as follows:

Symbol data info sections Binary digits| Description  
---|---  
????????xxxxxxxx| Library ordinal number 0 to 255  
xxxxxxxx????xxxx| Dynamic loader flag options  
xxxxxxxxxxxx????| Address type option  
  
The library ordinal number is set zero if the symbol is an external symbol, or exists in the current file. Only undefined symbols use the data info section to specify a library ordinal number and linker options.

The dynamic loader flag options are as follows:

Dynamic loader flag options Binary digits| Description  
---|---  
xxxxxxxx0001xxxx| Must be set for any defined symbol that is referenced by dynamic-loader.  
xxxxxxxx0010xxxx| Used by the dynamic linker at runtime.  
xxxxxxxx0100xxxx| If the dynamic linker cannot find a definition for this symbol, it sets the address of this symbol to 0.  
xxxxxxxx1000xxxx| If the static linker or the dynamic linker finds another definition for this symbol, the definition is ignored.  
  
Any of the four options that apply can be set.

The address type option values are as follows:

Dynamic loader address options Binary digits| Description  
---|---  
xxxxxxxxxxxx0000| Non Lazy loaded pointer method call  
xxxxxxxxxxxx0001| Lazy loaded pointer method call  
xxxxxxxxxxxx0010| Method call defined in this library/program  
xxxxxxxxxxxx0011| Private Method call defined in this library/program  
xxxxxxxxxxxx0100| Private Non Lazy loaded pointer method call  
xxxxxxxxxxxx0101| Private Lazy loaded pointer method call  
  
Only one address type value can be set by value. A pointer is a value that is read by the program machine code to call a method from another binary file. Private means other programs are not intended to be able to read or call the function/methods other than the binary itself. Lazy means the pointer locates to the dyld_stub_binder which looks for the symbol then calls the method, then replaces the dyld_stub_binder location with the location to the symbol. Any more calls done from machine code in the binary will now locate to the address of the symbol and will not call the dyld_stub_binder.

#### Symbol table organization

[[edit](</w/index.php?title=Mach-O&action=edit&section=10> "Edit section: Symbol table organization")]

The symbol table entries are all stored in order by type. The first symbols that are read are local debug symbols if any, then private symbols, then external symbols, and finally the undefined symbols that link to another binary symbol table containing the external symbol address in another Mach-O binary.

The symbol table information load command 0x0000000B always exists if there is a symbol table section in the Mach-O binary. The command tells the linker how many local symbols there are, how many private, how many external, and how many undefined. It also identifies the symbol number they start at. The symbol table information is used before reading the symbol entries by the dynamic linker as it tells the dynamic linker where to start reading the symbols to load in undefined symbols and where to start reading to look for matching external symbols without having to read all the symbol entries.

The order the symbols go in the symbol section should never be altered as each symbol is numbered from zero up. The symbol table information command uses the symbol numbers for the order to load the undefined symbols into the stubs and pointer sections. Altering the order would cause the wrong method to be called during machine code execution.

### `__LINKEDIT` Symbol table information

[[edit](</w/index.php?title=Mach-O&action=edit&section=11> "Edit section: __LINKEDIT Symbol table information")]

The symbol table information command is used by the dynamic linker to know where to read the symbol table entries under symbol table command 0x00000002, for fast lookup of undefined symbols and external symbols while linking.

The command is read as follows:

Load command (Symbol table information) Offset| Bytes| Description  
---|---|---  
0| 4| 0x0000000B (Command type)  
4| 4| Command size (always 80)  
8| 4| Local symbol index  
12| 4| Number of local symbols  
16| 4| External symbols index  
20| 4| Number of external symbols  
24| 4| Undefined symbols index  
28| 4| Number of undefined symbols  
32| 4| Content table offset  
36| 4| Number of content table entries  
40| 4| Module table offset  
44| 4| Number of module table entries  
48| 4| Offset to referenced symbol table  
52| 4| Number of referenced symbol table entries  
56| 4| Indirect symbol table offset  
60| 4| Indirect symbol table entries  
64| 4| External relocation offset  
68| 4| Number of external relocation entries  
72| 4| Local relocation offset  
76| 4| Number of Local relocation entries  
  
The symbol index is multiplied by 12 for Mach-O 32-bit, or 16 for Mach-O 64-bit plus the symbol table entries offset to find the offset to read the symbol entries by symbol number index.

The local symbol index is zero as it is at the start of the symbol entries. The local symbols are used for debugging information.

Number of local symbols is how many exist after the symbol index.

The same two properties are repeated for external symbols and undefined symbols for fast reading of the symbol table entries.

There is a small index/size gap between local symbols and external symbols if there are private symbols.

Any file offsets that are zero are unused.

#### Indirect table

[[edit](</w/index.php?title=Mach-O&action=edit&section=12> "Edit section: Indirect table")]

The Mach-O loader records the symbol pointer sections and symbol stub sections during the segment load commands. They are sequentially used by the indirect symbol table to load in method calls. Once the section end is reached, we move to the next.

The Indirect symbol table offset locates to a set of 32-bit (4-byte) values that are used as a symbol number index.

The order the symbol index numbers go is the order we write each symbol address one after another in the pointer and stub sections.

The symbol stub section contains machine code instructions with JUMP instructions to the indirect symbol address to call a method/function from another Mach-O binary. The size of each JUMP instruction is based on processor type and is stored in the reserved2 value under the section32/64 of a segment load command.

The pointer sections are 32-bit (4-byte) address values for 32-bit Mach-O binaries and 64-bit (8-byte) address values for 64-bit Mach-O binaries. Pointers are read by machine code and the read value is used as the location to call the method/function rather than containing machine code instructions.

A symbol index number 0x40000000 bit set are absolute methods meaning the pointer locates to the exact address of a method.

A symbol index number 0x80000000 bit set are local methods meaning the pointer itself located to the method and that there is no method name (Local method).

If you are designing a disassembler you can easily map just the symbol name to the offset address of each stub and pointer to show the method or function call taking place without looking for the undefined symbol address location in other Mach-O files.

### `__LINKEDIT` Compressed table

[[edit](</w/index.php?title=Mach-O&action=edit&section=13> "Edit section: __LINKEDIT Compressed table")]

If the compressed link edit table command exists, then the undefined/external symbols in the symbol table are no longer needed. The indirect symbol table and location of the stubs and pointer sections are no longer required.

The indirect symbol table still exists in the case of building backwards compatible Mach-O files that load on newer and older OS versions.

Load command (Compressed link edit table) Offset| Bytes| Description  
---|---|---  
0| 4| 0x00000022 (Command type)  
4| 4| Command size (always 48 bytes)  
8| 4| Rebase file offset  
12| 4| Rebase size  
16| 4| Bind file offset  
20| 4| Bind size  
24| 4| Weak bind file offset  
28| 4| Weak bind size  
32| 4| Lazy bind file offset  
36| 4| Lazy bind size  
40| 4| Export file offset  
44| 4| Export size  
  
Any file offsets that are zero are sections that are unused.

#### Binding information

[[edit](</w/index.php?title=Mach-O&action=edit&section=14> "Edit section: Binding information")]

The bind, weak bind, and lazy bind sections are read using the same operation code format.

Originally the symbol table would define the address type in the data info field in the symbol table as lazy, weak, or non-lazy.

Weak binding means that if the set library to look in by library ordinal number, and the set symbol name does not exist but exists under a different previously loaded Mach-O file then the symbol location is used from the other Mach-O file.

Lazy means the address that is written located to the dyld_stub_binder, which looks for the symbol then calls the method, then replaces the dyld_stub_binder location with the location to the symbol. Any more calls done from machine code in the binary will now locate to the address of the symbol and will not call the dyld_stub_binder.

The plain old bind section does not do any fancy loading or address tricks. The symbol must exist in the set library ordinal.

A byte value that is 0x1X sets the link library ordinal number. The hex digit that is X is a 0 to 15 library ordinal number.

A byte value that is 0x20 to 0x2F sets the link library ordinal number to the value that is read after the operation code.

The byte sequence 0x20 0x84 0x01 set ordinal number 132.

The number value after the operation code is encoded as a [LEB128](<https://en.wikipedia.org/wiki/LEB128> "LEB128") number. The last 7 binary digits are added together to form a larger number as long as the last binary digit is set one in value. This allows us to encode variable length number values.

A byte value that is 0x4X sets the symbol name. The hex digit marked X sets the flag setting.

Flag setting 8 means the method is weak imported. Flag setting 1 means the method is non weak imported.

The byte sequence 0x48 0x45 0x78 0x61 0x6D 0x70 0x6C 0x65 0x00 sets the symbol name Example. The last text character byte is 0x00. It is also weak imported, meaning it can be replaced if another exportable symbol is found with the same name.

A byte value 0x7X sets the current location. The hex digit marked X is the selected segment 0 to 15. After the operation code is the added offset as a [LEB128](<https://en.wikipedia.org/wiki/LEB128> "LEB128") number to the segment offset.

The byte sequence 0x72 0x8C 0x01 sets the location to the third segment load command address and adds 140 to the address.

Operation code 0x90 to 0x9F binds the current set location to the set symbol name and library ordinal. Increments the current set location by the size 4 bytes for a 32-bit Mach-O binary or increments the set address by 8 for a 64-bit Mach-O binary.

The byte sequence 0x11 0x72 0x8C 0x01 0x48 0x45 0x78 0x61 0x6D 0x70 0x6C 0x65 0x00 0x90 0x48 0x45 0x78 0x61 0x6D 0x70 0x6C 0x65 0x32 0x00 0x90

Sets link library ordinal 1. Set location to segment number 2, and adds 140 to the current location. Looks for a symbol named Example in the selected library ordinal number. Operation code 0x90 writes the symbol address and increments the current set address. The operation code after that sets the next symbol name to look for a symbol named Example2. Operation code 0x90 writes the symbol address and increments the current set address.

The new format removes the repeated fields in the symbol table and makes the indirect symbol table obsolete.

### Application main entry point

[[edit](</w/index.php?title=Mach-O&action=edit&section=15> "Edit section: Application main entry point")]

A load command starting with type 0x00000028 is used to specify the address location the application begins at.

Load command (Main entry point) Offset| Bytes| Description  
---|---|---  
0| 4| 0x00000028 (Command type)  
4| 4| Command size (always 24 bytes)  
8| 8| Address location  
16| 8| Stack memory size  
  
If the segments/sections of the program do not have to be relocated to run, then the main entry point is the exact address location. This is only if the application segment addresses are added to an application base address of zero and the sections did not need any relocations.

The main entry point in a Mach-O loader is the program's base address plus the Address location. This is the address at which the CPU is set to begin running machine code instructions.

This replaced the old load command 0x00000005 which varied by CPU type as it stored the state that all the registers should be at before the program starts.

### Application UUID number

[[edit](</w/index.php?title=Mach-O&action=edit&section=16> "Edit section: Application UUID number")]

A load command starting with type 0x0000001B is used to specify the [universally unique identifier](<https://en.wikipedia.org/wiki/Universally_unique_identifier> "Universally unique identifier") (UUID) of the application.

Load command (UUID number) Offset| Bytes| Description  
---|---|---  
0| 4| 0x0000001B (Command type)  
4| 4| Command size (always 24 bytes)  
8| 16| 128-bit UUID  
  
The UUID contains a 128-bit unique random[_[citation needed](<https://en.wikipedia.org/wiki/Wikipedia:Citation_needed> "Wikipedia:Citation needed")_] number when the application is compiled that can be used to identify the application file on the internet or in app stores.

### Minimum OS version

[[edit](</w/index.php?title=Mach-O&action=edit&section=17> "Edit section: Minimum OS version")]

A load command starting with type 0x00000032 is used to specify the minimum OS version information.

Load command (Minimum OS version) Offset| Bytes| Description  
---|---|---  
0| 4| 0x00000032 (Command type)  
4| 4| Command size  
8| 4| Platform type  
12| 4| Minimum OS version  
16| 4| SDK version  
20| 4| Number of tools used  
  
The Platform type the binary is intended to run on are as follows:

Platform type. Value| Platform  
---|---  
0x00000001| [macOS](<https://en.wikipedia.org/wiki/MacOS> "MacOS")  
0x00000002| [iOS](<https://en.wikipedia.org/wiki/IOS> "IOS")  
0x00000003| [tvOS](<https://en.wikipedia.org/wiki/TvOS> "TvOS")  
0x00000004| [watchOS](<https://en.wikipedia.org/wiki/WatchOS> "WatchOS")  
0x00000005| [bridgeOS](<https://en.wikipedia.org/wiki/BridgeOS> "BridgeOS")  
0x00000006| [Mac Catalyst](<https://en.wikipedia.org/wiki/Mac_Catalyst> "Mac Catalyst")  
0x00000007| iOS simulator  
0x00000008| tvOS simulator  
0x00000009| watchOS simulator  
0x0000000A| DriverKit  
0x0000000B| [visionOS](<https://en.wikipedia.org/wiki/VisionOS> "VisionOS")  
0x0000000C| visionOS simulator  
  
The 32-bit version value is read as a 16-bit value and two 8-bit values. A 32-bit version value of 0x000D0200 breaks down as 0x000D which is 13 in value, then the next 8-bits is 0x02 which is 2 in value, then the last 8-bits is 0x00 which is zero in value giving a version number of 13.2.0v. The SDK version value is read the same way.

The number of tools to create the binary is a set of entries that are read as follows:

Tool type Offset| Bytes| Description  
---|---|---  
0| 4| Tool type  
4| 4| Tool version  
  
The tool type values are as follows:

Tool type value. Value| Tool type used  
---|---  
0x00000001| CLANG  
0x00000002| SWIFT  
0x00000003| LD  
  
The version number is read the same as OS version and SDK version.

With the introduction of [Mac OS X 10.6](<https://en.wikipedia.org/wiki/Mac_OS_X_10.6> "Mac OS X 10.6") platform the Mach-O file underwent a significant modification that causes binaries compiled on a computer running 10.6 or later to be (by default) executable only on computers running Mac OS X 10.6 or later. The difference stems from load commands that the [dynamic linker](<https://en.wikipedia.org/wiki/Dynamic_linker> "Dynamic linker"), in previous Mac OS X versions, does not understand. Another significant change to the Mach-O format is the change in how the Link Edit tables (found in the `__LINKEDIT` section) function. In 10.6 these new Link Edit tables are compressed by removing unused and unneeded bits of information; however, Mac OS X 10.5 and earlier cannot read this new Link Edit table format. To make backwards-compatible executables, the linker flag "-mmacosx-version-min=" can be used.

## Other implementations

[[edit](</w/index.php?title=Mach-O&action=edit&section=18> "Edit section: Other implementations")]

### Mach-O parsers and editors

[[edit](</w/index.php?title=Mach-O&action=edit&section=19> "Edit section: Mach-O parsers and editors")]

It is not uncommon for security researchers and others to work with Mach-O files from places other than a Mac computer. Programs that allow parsing or even editing the data structure of Mach-O (as a file format) are commonplace.

For the [Ruby](<https://en.wikipedia.org/wiki/Ruby_\(programming_language\)> "Ruby \(programming language\)") programming language, the ruby-macho[16] library provides an implementation of a Mach-O binary parser and editor.

### Mach-O runners

[[edit](</w/index.php?title=Mach-O&action=edit&section=20> "Edit section: Mach-O runners")]

In theory, a program in Mach-O format could be run, by code that can load Mach-O images into memory, on operating systems other than the one for which the program was built, as long as a Mach-O binary image exists that matches the CPU type in the computer being used. Most desktop and laptop computers have [x86](<https://en.wikipedia.org/wiki/X86> "X86") processors, meaning that a Mach-O with an x86 binary will be able to run the sections are loaded into memory. If the Mach-O has only [ARM](<https://en.wikipedia.org/wiki/ARM_architecture_family> "ARM architecture family") binaries, such as programs for iPhones or iPads, then it could only be run on a computer with a compatible ARM core (not necessarily an [Apple silicon](<https://en.wikipedia.org/wiki/Apple_silicon> "Apple silicon") core); otherwise, an emulation tool such as [QEMU](<https://en.wikipedia.org/wiki/QEMU> "QEMU") would have to be used you would have to change ARM instructions to equivalent x86 instructions using CPU emulation tools such as QEMU.

A practical problem with loading and directly executing a Mach-O is "undefined symbols": binaries generally do not exist in a vacuum and they call functions/methods (symbols) from Mach-O binaries (libraries) to work; a failure to find a symbol manifests in this error. Mach-O files for iPhone (iOS), macOS, watchOS, and tvOS each assume a different collection of libraries, causing incompatibility from this issue. These libraries need to either be present on the machine trying to execute the program, or be replaced by the Mach-O loader using either its own adapter functions or existing functions of the host operating systems. The library routines being called either would also have to provide the same [application binary interface](<https://en.wikipedia.org/wiki/Application_binary_interface> "Application binary interface") as the routines from the OS for which the binary was intended, or an adapter routine would have to be provided.

  * Some versions of [NetBSD](<https://en.wikipedia.org/wiki/NetBSD> "NetBSD") have had Mach-O support added as part of an implementation of binary compatibility, which allowed some Mac OS 10.3 binaries to be executed.[17][18]
  * For Linux, a Mach-O loader was written by Shinichiro Hamaji that can load 10.6 binaries.[19] As a more extensive solution based on this loader, the [Darling Project](<https://en.wikipedia.org/wiki/Darling_\(software\)> "Darling \(software\)") aims at providing a complete environment allowing macOS applications to run on Linux.



See also [Darwin operating system#Derived projects](<https://en.wikipedia.org/wiki/Darwin_operating_system#Derived_projects> "Darwin operating system"), which includes a few other efforts to achieve macOS/iOS binary compatibility. Even the efforts directly based on the same Darwin kernel required additional code to replace libraries and other components not open-sourced by Apple.

## See also

[[edit](</w/index.php?title=Mach-O&action=edit&section=21> "Edit section: See also")]

  * [Fat binary](<https://en.wikipedia.org/wiki/Fat_binary> "Fat binary")
  * [Universal binary](<https://en.wikipedia.org/wiki/Universal_binary> "Universal binary")
  * [Dynamic linker](<https://en.wikipedia.org/wiki/Dynamic_linker> "Dynamic linker")
  * [Mac transition to Intel processors](<https://en.wikipedia.org/wiki/Mac_transition_to_Intel_processors> "Mac transition to Intel processors")
  * [Mac transition to Apple silicon](<https://en.wikipedia.org/wiki/Mac_transition_to_Apple_silicon> "Mac transition to Apple silicon")
  * [Xcode](<https://en.wikipedia.org/wiki/Xcode> "Xcode")
  * [PE](<https://en.wikipedia.org/wiki/Portable_Executable> "Portable Executable")
  * [ELF](<https://en.wikipedia.org/wiki/Executable_and_Linkable_Format> "Executable and Linkable Format")
  * [Comparison of executable file formats](<https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats> "Comparison of executable file formats")



## References

[[edit](</w/index.php?title=Mach-O&action=edit&section=22> "Edit section: References")]

  1. ↑ [_Mach-O Programming Topics_](<https://www.cs.miami.edu/home/burt/learning/Csc521.091/docs/MachOTopics.pdf>) (PDF). Apple. November 28, 2006.
  2. ↑ ["OS X ABI Mach-O File Format Reference"](<https://web.archive.org/web/20140904004108/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html>). Apple Inc. February 4, 2009. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html>) on September 4, 2014.
  3. ↑ Avadis Tevanian, Jr.; Richard F. Rashid; Michael W. Young; David B. Golub; Mary R. Thompson; William Bolosky; Richard Sanzi (June 1987). ["A Unix Interface for Shared Memory and Memory Mapped Files Under Mach"](<http://citeseer.ist.psu.edu/viewdoc/summary?doi=10.1.1.52.675>). _Proceedings of the USENIX Summer Conference_. Phoenix, AZ, USA: USENIX Association. pp. 53–67.`{{[cite conference](<https://en.wikipedia.org/wiki/Template:Cite_conference> "Template:Cite conference")}}`: CS1 maint: miscellaneous url ([link](<https://en.wikipedia.org/wiki/Category:CS1_maint:_miscellaneous_url> "Category:CS1 maint: miscellaneous url"))
  4. 1 2 ["Data Types"](<https://web.archive.org/web/20140911185310/https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF>). _OS X ABI Mach-O File Format Reference_. [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.") February 4, 2009 [2003]. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF>) on September 11, 2014. Retrieved March 15, 2023.
  5. ↑ [xnu/EXTERNAL_HEADERS/mach-o/loader.h at main - apple-oss-distributions/xnu](<https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>) on [GitHub](<https://en.wikipedia.org/wiki/GitHub> "GitHub")
  6. 1 2 3 [cctools/include/mach/machine-cctools.h at main - apple-oss-distributions/cctools](<https://github.com/apple-oss-distributions/cctools/blob/main/include/mach/machine-cctools.h>) on [GitHub](<https://en.wikipedia.org/wiki/GitHub> "GitHub")
  7. ↑ [llvm-project/llvm/include/llvm/BinaryFormat/MachO.h at main - llvm-project/llvm](<https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/MachO.h>) on [GitHub](<https://en.wikipedia.org/wiki/GitHub> "GitHub")
  8. ↑ [xnu/osfmk/mach/machine.h at main - apple-oss-distributions/xnu](<https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/machine.h#L160>) on [GitHub](<https://en.wikipedia.org/wiki/GitHub> "GitHub")
  9. ↑ ["Universal Binaries and 32-bit/64-bit PowerPC Binaries"](<https://web.archive.org/web/20140904004108/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-154889>). _OS X ABI Mach-O File Format Reference_. [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.") February 4, 2009 [2003]. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-154889>) on September 4, 2014.
  10. ↑ ["Building a Universal macOS Binary"](<https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary>). _Apple Developer_.
  11. ↑ ["fat_header"](<https://web.archive.org/web/20140904004108/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/c/tag/fat_header>). _OS X ABI Mach-O File Format Reference_. [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.") February 4, 2009 [2003]. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/c/tag/fat_header>) on September 4, 2014.
  12. ↑ ["fat_arch"](<https://web.archive.org/web/20140904004108/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/c/tag/fat_arch>). _OS X ABI Mach-O File Format Reference_. [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.") February 4, 2009 [2003]. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/c/tag/fat_arch>) on September 4, 2014.
  13. ↑ ["Load Command Data Structures"](<https://web.archive.org/web/20140911185310/https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-TPXREF114>). _OS X ABI Mach-O File Format Reference_. [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.") February 4, 2009 [2003]. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-TPXREF114>) on September 11, 2014. Retrieved March 15, 2023.
  14. ↑ ["segment_command"](<https://web.archive.org/web/20140911185310/https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-segment_command>). _OS X ABI Mach-O File Format Reference_. [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.") February 4, 2009 [2003]. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-segment_command>) on September 11, 2014. Retrieved March 15, 2023.
  15. ↑ ["segment_command_64"](<https://web.archive.org/web/20140911185310/https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-CJBDHJGA>). _OS X ABI Mach-O File Format Reference_. [Apple Inc.](<https://en.wikipedia.org/wiki/Apple_Inc.> "Apple Inc.") February 4, 2009 [2003]. Archived from [the original](<https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-CJBDHJGA>) on September 11, 2014. Retrieved March 15, 2023.
  16. ↑ William Woodruff (November 15, 2021), [_A pure-Ruby library for parsing Mach-O files._](<https://github.com/Homebrew/ruby-macho>)
  17. ↑ Emmanuel Dreyfus (June 20, 2006). ["Mach and Darwin binary compatiblity [_sic_] for NetBSD/powerpc and NetBSD/i386"](<http://hcpnet.free.fr/applebsd.html>). Retrieved October 18, 2013.
  18. ↑ Emmanuel Dreyfus (September 2004), [_Mac OS X binary compatibility on NetBSD: challenges and implementation_](<http://2004.eurobsdcon.org/uploads/media/EBSD04_21.pdf>) (PDF)
  19. ↑ Shinichiro Hamaji, [_Mach-O loader for Linux - I wrote..._](<http://shinh.skr.jp/slide/ldmac/001.html>)



### Bibliography

[[edit](</w/index.php?title=Mach-O&action=edit&section=23> "Edit section: Bibliography")]

  * Levin, Jonathan (September 25, 2019). _*OS Internals, Volume 1: User Mode_ (v1.3.3.7 ed.). North Castle, NY: Technologeeks. [ISBN](<https://en.wikipedia.org/wiki/ISBN_\(identifier\)> "ISBN \(identifier\)") [978-0-9910555-6-2](<https://en.wikipedia.org/wiki/Special:BookSources/978-0-9910555-6-2> "Special:BookSources/978-0-9910555-6-2").
  * Singh, Amit (June 19, 2006). _Mac OS X Internals: A Systems Approach_. Addison-Wesley Professional. [ISBN](<https://en.wikipedia.org/wiki/ISBN_\(identifier\)> "ISBN \(identifier\)") [978-0-13-270226-3](<https://en.wikipedia.org/wiki/Special:BookSources/978-0-13-270226-3> "Special:BookSources/978-0-13-270226-3").



## External links

[[edit](</w/index.php?title=Mach-O&action=edit&section=24> "Edit section: External links")]

  * [OS X ABI Mach-O File Format Reference](<https://web.archive.org/web/20140904004108/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html>) at the [Wayback Machine](<https://en.wikipedia.org/wiki/Wayback_Machine> "Wayback Machine") (archived September 4, 2014) (Apple Inc.)
  * `[Mach-O(5)](<https://keith.github.io/xcode-man-pages/Mach-O.5.html>)` – [Darwin](<https://en.wikipedia.org/wiki/Darwin_\(operating_system\)> "Darwin \(operating system\)") and [macOS](<https://en.wikipedia.org/wiki/MacOS> "MacOS") File Formats [Manual](<https://en.wikipedia.org/wiki/Man_page> "Man page")
  * [Mach Object Files](<http://www.cilinder.be/docs/next/NeXTStep/3.3/nd/DevTools/14_MachO/MachO.htmld/index.html>) (NEXTSTEP documentation)
  * [Mach-O Dynamic Library Reference](<http://www.fileinfo.com/extension/dylib>)
  * [Mach-O linking and loading tricks](<http://blog.darlinghq.org/2018/07/mach-o-linking-and-loading-tricks.html>)
  * [MachOView](<https://sourceforge.net/projects/machoview>)
  * [JDasm](<https://github.com/Recoskie/JDasm>) (Cross-platform disassembler, for macOS, iOS, windows PE, ELF, and file format analysis tool)



  * [v](<https://en.wikipedia.org/wiki/Template:Executables> "Template:Executables")
  * [t](<https://en.wikipedia.org/wiki/Template_talk:Executables> "Template talk:Executables")
  * [e](<https://en.wikipedia.org/wiki/Special:EditPage/Template:Executables> "Special:EditPage/Template:Executables")

[Executable](<https://en.wikipedia.org/wiki/Executable> "Executable") and [object file](<https://en.wikipedia.org/wiki/Object_file> "Object file") formats  
---  
  
  * [a.out](<https://en.wikipedia.org/wiki/A.out> "A.out")
  * [AIF](<https://en.wikipedia.org/wiki/Arm_Image_Format> "Arm Image Format")
  * [COFF](<https://en.wikipedia.org/wiki/COFF> "COFF")
  * [CMD](<https://en.wikipedia.org/wiki/CMD_file_\(CP/M\)> "CMD file \(CP/M\)")
  * [COM](<https://en.wikipedia.org/wiki/COM_file> "COM file")
  * [ECOFF](<https://en.wikipedia.org/wiki/ECOFF> "ECOFF")
  * [ELF](<https://en.wikipedia.org/wiki/Executable_and_Linkable_Format> "Executable and Linkable Format")
  * [GOFF](<https://en.wikipedia.org/wiki/GOFF> "GOFF")
  * [Hunk](<https://en.wikipedia.org/wiki/Amiga_Hunk> "Amiga Hunk")
  * [Mach-O](<https://en.wikipedia.org/wiki/Mach-O>)
  * [MZ](<https://en.wikipedia.org/wiki/DOS_MZ_executable> "DOS MZ executable")
  * [NE](<https://en.wikipedia.org/wiki/New_Executable> "New Executable")
  * [OMF](<https://en.wikipedia.org/wiki/Object_Module_Format_\(Intel\)> "Object Module Format \(Intel\)")
  * [OS/360](<https://en.wikipedia.org/wiki/OS/360_Object_File_Format> "OS/360 Object File Format")
  * [PE](<https://en.wikipedia.org/wiki/Portable_Executable> "Portable Executable")
  * [PEF](<https://en.wikipedia.org/wiki/Preferred_Executable_Format> "Preferred Executable Format")
  * [X](<https://en.wikipedia.org/wiki/.X_\(Human68K\)> ".X \(Human68K\)")
  * [XCOFF](<https://en.wikipedia.org/wiki/XCOFF> "XCOFF")

  
  
  * [Comparison of formats](<https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats> "Comparison of executable file formats")
  * [.exe](<https://en.wikipedia.org/wiki/.exe> ".exe")

  
  
  * [v](<https://en.wikipedia.org/wiki/Template:MacOS> "Template:MacOS")
  * [t](<https://en.wikipedia.org/wiki/Template_talk:MacOS> "Template talk:MacOS")
  * [e](<https://en.wikipedia.org/wiki/Special:EditPage/Template:MacOS> "Special:EditPage/Template:MacOS")

[macOS](<https://en.wikipedia.org/wiki/MacOS> "MacOS")  
---  
  
  * [History](<https://en.wikipedia.org/wiki/MacOS_version_history> "MacOS version history")
  * [Architecture](<https://en.wikipedia.org/wiki/Architecture_of_macOS> "Architecture of macOS")
  * [Built-in apps](<https://en.wikipedia.org/wiki/List_of_built-in_macOS_apps> "List of built-in macOS apps")
  * [Server](<https://en.wikipedia.org/wiki/MacOS_Server> "MacOS Server")
  * [Software](<https://en.wikipedia.org/wiki/List_of_Mac_software> "List of Mac software")

  
Versions| | Mac OS X| 

  * [Server 1.0](<https://en.wikipedia.org/wiki/Mac_OS_X_Server_1.0> "Mac OS X Server 1.0")
  * [Public Beta](<https://en.wikipedia.org/wiki/Mac_OS_X_Public_Beta> "Mac OS X Public Beta")
  * [10.0 Cheetah](<https://en.wikipedia.org/wiki/Mac_OS_X_10.0> "Mac OS X 10.0")
  * [10.1 Puma](<https://en.wikipedia.org/wiki/Mac_OS_X_10.1> "Mac OS X 10.1")
  * [10.2 Jaguar](<https://en.wikipedia.org/wiki/Mac_OS_X_Jaguar> "Mac OS X Jaguar")
  * [10.3 Panther](<https://en.wikipedia.org/wiki/Mac_OS_X_Panther> "Mac OS X Panther")
  * [10.4 Tiger](<https://en.wikipedia.org/wiki/Mac_OS_X_Tiger> "Mac OS X Tiger")
  * [10.5 Leopard](<https://en.wikipedia.org/wiki/Mac_OS_X_Leopard> "Mac OS X Leopard")
  * [10.6 Snow Leopard](<https://en.wikipedia.org/wiki/Mac_OS_X_Snow_Leopard> "Mac OS X Snow Leopard")

  
---|---  
OS X| 

  * [10.7 Lion](<https://en.wikipedia.org/wiki/OS_X_Lion> "OS X Lion")
  * [10.8 Mountain Lion](<https://en.wikipedia.org/wiki/OS_X_Mountain_Lion> "OS X Mountain Lion")
  * [10.9 Mavericks](<https://en.wikipedia.org/wiki/OS_X_Mavericks> "OS X Mavericks")
  * [10.10 Yosemite](<https://en.wikipedia.org/wiki/OS_X_Yosemite> "OS X Yosemite")
  * [10.11 El Capitan](<https://en.wikipedia.org/wiki/OS_X_El_Capitan> "OS X El Capitan")

  
macOS| 

  * [10.12 Sierra](<https://en.wikipedia.org/wiki/MacOS_Sierra> "MacOS Sierra")
  * [10.13 High Sierra](<https://en.wikipedia.org/wiki/MacOS_High_Sierra> "MacOS High Sierra")
  * [10.14 Mojave](<https://en.wikipedia.org/wiki/MacOS_Mojave> "MacOS Mojave")
  * [10.15 Catalina](<https://en.wikipedia.org/wiki/MacOS_Catalina> "MacOS Catalina")
  * [11 Big Sur](<https://en.wikipedia.org/wiki/MacOS_Big_Sur> "MacOS Big Sur")
  * [12 Monterey](<https://en.wikipedia.org/wiki/MacOS_Monterey> "MacOS Monterey")
  * [13 Ventura](<https://en.wikipedia.org/wiki/MacOS_Ventura> "MacOS Ventura")
  * [14 Sonoma](<https://en.wikipedia.org/wiki/MacOS_Sonoma> "MacOS Sonoma")
  * [15 Sequoia](<https://en.wikipedia.org/wiki/MacOS_Sequoia> "MacOS Sequoia")
  * [26 Tahoe](<https://en.wikipedia.org/wiki/MacOS_Tahoe> "MacOS Tahoe")
  * [27 Golden Gate](<https://en.wikipedia.org/wiki/MacOS_Golden_Gate> "MacOS Golden Gate")

  
Predecessors| 

  * [Classic Mac OS](<https://en.wikipedia.org/wiki/Classic_Mac_OS> "Classic Mac OS")
  * [NeXTSTEP](<https://en.wikipedia.org/wiki/NeXTSTEP> "NeXTSTEP")
  * [Rhapsody](<https://en.wikipedia.org/wiki/Rhapsody_\(operating_system\)> "Rhapsody \(operating system\)")

  
  
Applications| | Core  
applications| 

  * [App Store](<https://en.wikipedia.org/wiki/Mac_App_Store> "Mac App Store")
  * [Automator](<https://en.wikipedia.org/wiki/Automator_\(macOS\)> "Automator \(macOS\)")
  * [Calculator](<https://en.wikipedia.org/wiki/Calculator_\(Apple\)> "Calculator \(Apple\)")
  * [Calendar](<https://en.wikipedia.org/wiki/Calendar_\(Apple\)> "Calendar \(Apple\)")
  * [Contacts](<https://en.wikipedia.org/wiki/Contacts_\(Apple\)> "Contacts \(Apple\)")
  * [Control Center](<https://en.wikipedia.org/wiki/Control_Center_\(Apple\)> "Control Center \(Apple\)")
  * [Dictionary](<https://en.wikipedia.org/wiki/Dictionary_\(software\)> "Dictionary \(software\)")
  * [FaceTime](<https://en.wikipedia.org/wiki/FaceTime> "FaceTime")
  * [Finder](<https://en.wikipedia.org/wiki/Finder_\(software\)> "Finder \(software\)")
  * [Game Center](<https://en.wikipedia.org/wiki/Game_Center> "Game Center")
  * [Grapher](<https://en.wikipedia.org/wiki/Grapher> "Grapher")
  * [Home](<https://en.wikipedia.org/wiki/HomeKit> "HomeKit")
  * [Mail](<https://en.wikipedia.org/wiki/Apple_Mail> "Apple Mail")
  * [Messages](<https://en.wikipedia.org/wiki/Messages_\(Apple\)> "Messages \(Apple\)")
  * [News](<https://en.wikipedia.org/wiki/Apple_News> "Apple News")
  * [Music](<https://en.wikipedia.org/wiki/Music_\(software\)> "Music \(software\)")
  * [Notes](<https://en.wikipedia.org/wiki/Notes_\(Apple\)> "Notes \(Apple\)")
  * [Notification Center](<https://en.wikipedia.org/wiki/Notification_Center> "Notification Center")
  * [Podcasts](<https://en.wikipedia.org/wiki/Apple_Podcasts> "Apple Podcasts")
  * [Photo Booth](<https://en.wikipedia.org/wiki/Photo_Booth> "Photo Booth")
  * [Photos](<https://en.wikipedia.org/wiki/Photos_\(Apple\)> "Photos \(Apple\)")
  * [Preview](<https://en.wikipedia.org/wiki/Preview_\(macOS\)> "Preview \(macOS\)")
  * [QuickTime Player](<https://en.wikipedia.org/wiki/QuickTime> "QuickTime")
  * [Reminders](<https://en.wikipedia.org/wiki/Reminders_\(Apple\)> "Reminders \(Apple\)")
  * [Safari](<https://en.wikipedia.org/wiki/Safari_\(web_browser\)> "Safari \(web browser\)")
  * [Shortcuts](<https://en.wikipedia.org/wiki/Shortcuts_\(app\)> "Shortcuts \(app\)")
  * [Siri](<https://en.wikipedia.org/wiki/Siri> "Siri")
  * [Stickies](<https://en.wikipedia.org/wiki/Stickies_\(Apple\)> "Stickies \(Apple\)")
  * [TextEdit](<https://en.wikipedia.org/wiki/TextEdit> "TextEdit")
  * [Time Machine](<https://en.wikipedia.org/wiki/Time_Machine_\(macOS\)> "Time Machine \(macOS\)")

  
---|---  
[Developer  
Tools](<https://en.wikipedia.org/wiki/Apple_Developer_Tools> "Apple Developer Tools")| | [Xcode](<https://en.wikipedia.org/wiki/Xcode> "Xcode")| 

  * [Instruments](<https://en.wikipedia.org/wiki/Instruments_\(software\)> "Instruments \(software\)")

  
---|---  
Former| 

  * [Interface Builder](<https://en.wikipedia.org/wiki/Interface_Builder> "Interface Builder")
  * [Dashcode](<https://en.wikipedia.org/wiki/Dashcode> "Dashcode")
  * [Quartz Composer](<https://en.wikipedia.org/wiki/Quartz_Composer> "Quartz Composer")

  
  
Utilities| 

  * [Boot Camp](<https://en.wikipedia.org/wiki/Boot_Camp_\(software\)> "Boot Camp \(software\)") (deprecated)
  * [ColorSync](<https://en.wikipedia.org/wiki/ColorSync> "ColorSync")
  * [Configurator](<https://en.wikipedia.org/wiki/Apple_Configurator> "Apple Configurator")
  * [Disk Utility](<https://en.wikipedia.org/wiki/Disk_Utility> "Disk Utility")
  * [Font Book](<https://en.wikipedia.org/wiki/Font_Book> "Font Book")
  * [Keychain Access](<https://en.wikipedia.org/wiki/Keychain_\(software\)> "Keychain \(software\)")
  * [Script Editor](<https://en.wikipedia.org/wiki/Script_Editor> "Script Editor")
  * [System Settings](<https://en.wikipedia.org/wiki/System_Settings> "System Settings")
  * [Terminal](<https://en.wikipedia.org/wiki/Terminal_\(macOS\)> "Terminal \(macOS\)")
  * [VoiceOver](<https://en.wikipedia.org/wiki/VoiceOver> "VoiceOver")

  
Former| 

  * [Dashboard](<https://en.wikipedia.org/wiki/Dashboard_\(macOS\)> "Dashboard \(macOS\)")
  * [Front Row](<https://en.wikipedia.org/wiki/Front_Row_\(software\)> "Front Row \(software\)")
  * [iChat](<https://en.wikipedia.org/wiki/IChat> "IChat")
  * [iPhoto](<https://en.wikipedia.org/wiki/IPhoto> "IPhoto")
  * [iSync](<https://en.wikipedia.org/wiki/ISync> "ISync")
  * [iTunes](<https://en.wikipedia.org/wiki/ITunes> "ITunes")
    * [history](<https://en.wikipedia.org/wiki/History_of_iTunes> "History of iTunes")
  * [Sherlock](<https://en.wikipedia.org/wiki/Sherlock_\(software\)> "Sherlock \(software\)")

  
  
Technologies,  
[user interface](<https://en.wikipedia.org/wiki/User_interface> "User interface")| | 

  * [AirDrop](<https://en.wikipedia.org/wiki/AirDrop> "AirDrop")
  * [AppKit](<https://en.wikipedia.org/wiki/AppKit> "AppKit")
  * [Apple File System](<https://en.wikipedia.org/wiki/Apple_File_System> "Apple File System")
  * [Apple menu](<https://en.wikipedia.org/wiki/Apple_menu> "Apple menu")
  * [Apple Push Notification service](<https://en.wikipedia.org/wiki/Apple_Push_Notification_service> "Apple Push Notification service")
  * [AppleScript](<https://en.wikipedia.org/wiki/AppleScript> "AppleScript")
  * [Aqua](<https://en.wikipedia.org/wiki/Aqua_\(user_interface\)> "Aqua \(user interface\)")
  * [Audio Units](<https://en.wikipedia.org/wiki/Audio_Units> "Audio Units")
  * [AVFoundation](<https://en.wikipedia.org/wiki/AVFoundation> "AVFoundation")
  * [Bonjour](<https://en.wikipedia.org/wiki/Bonjour_\(software\)> "Bonjour \(software\)")
  * [Bundle](<https://en.wikipedia.org/wiki/Bundle_\(macOS\)> "Bundle \(macOS\)")
  * [CloudKit](<https://en.wikipedia.org/wiki/CloudKit> "CloudKit")
  * [Cocoa](<https://en.wikipedia.org/wiki/Cocoa_\(API\)> "Cocoa \(API\)")
  * [ColorSync](<https://en.wikipedia.org/wiki/ColorSync> "ColorSync")
  * [Command key](<https://en.wikipedia.org/wiki/Command_key> "Command key")
  * [Core Animation](<https://en.wikipedia.org/wiki/Core_Animation> "Core Animation")
  * [Core Audio](<https://en.wikipedia.org/wiki/Core_Audio> "Core Audio")
  * [Core Data](<https://en.wikipedia.org/wiki/Core_Data> "Core Data")
  * [Core Foundation](<https://en.wikipedia.org/wiki/Core_Foundation> "Core Foundation")
  * [Core Image](<https://en.wikipedia.org/wiki/Core_Image> "Core Image")
  * [Core OpenGL](<https://en.wikipedia.org/wiki/Core_OpenGL> "Core OpenGL")
  * [Core Text](<https://en.wikipedia.org/wiki/Core_Text> "Core Text")
  * [Core Video](<https://en.wikipedia.org/wiki/Core_Video> "Core Video")
  * [Cover Flow](<https://en.wikipedia.org/wiki/Cover_Flow> "Cover Flow")
  * [CUPS](<https://en.wikipedia.org/wiki/CUPS> "CUPS")
  * [Darwin](<https://en.wikipedia.org/wiki/Darwin_\(operating_system\)> "Darwin \(operating system\)")
  * [Dock](<https://en.wikipedia.org/wiki/Dock_\(macOS\)> "Dock \(macOS\)")
  * [FileVault](<https://en.wikipedia.org/wiki/FileVault> "FileVault")
  * [Fonts](<https://en.wikipedia.org/wiki/List_of_typefaces_included_with_macOS> "List of typefaces included with macOS")
  * [Foundation](<https://en.wikipedia.org/wiki/Foundation_Kit> "Foundation Kit")
  * [Gatekeeper](<https://en.wikipedia.org/wiki/Gatekeeper_\(macOS\)> "Gatekeeper \(macOS\)")
  * [Grand Central Dispatch](<https://en.wikipedia.org/wiki/Grand_Central_Dispatch> "Grand Central Dispatch")
  * [icns](<https://en.wikipedia.org/wiki/Apple_Icon_Image_format> "Apple Icon Image format")
  * [iCloud](<https://en.wikipedia.org/wiki/ICloud> "ICloud")
  * [Kernel panic](<https://en.wikipedia.org/wiki/Kernel_panic#macOS> "Kernel panic")
  * [Keychain](<https://en.wikipedia.org/wiki/Keychain_\(software\)> "Keychain \(software\)")
  * [launchd](<https://en.wikipedia.org/wiki/Launchd> "Launchd")
  * [Liquid Glass](<https://en.wikipedia.org/wiki/Liquid_Glass> "Liquid Glass")
  * [Mach-O](<https://en.wikipedia.org/wiki/Mach-O>)
  * [Menu extra](<https://en.wikipedia.org/wiki/Menu_extra> "Menu extra")
  * [Metal](<https://en.wikipedia.org/wiki/Metal_\(API\)> "Metal \(API\)")
  * [Mission Control](<https://en.wikipedia.org/wiki/Mission_Control_\(macOS\)> "Mission Control \(macOS\)")
  * [Night Shift](<https://en.wikipedia.org/wiki/Night_Shift_\(software\)> "Night Shift \(software\)")
  * [OpenCL](<https://en.wikipedia.org/wiki/OpenCL> "OpenCL")
  * [Option key](<https://en.wikipedia.org/wiki/Option_key> "Option key")
  * [Preference Pane](<https://en.wikipedia.org/wiki/Preference_Pane> "Preference Pane")
  * [Property list](<https://en.wikipedia.org/wiki/Property_list> "Property list")
  * [Quartz](<https://en.wikipedia.org/wiki/Quartz_\(graphics_layer\)> "Quartz \(graphics layer\)")
  * [Quick Look](<https://en.wikipedia.org/wiki/Quick_Look> "Quick Look")
  * [Rosetta](<https://en.wikipedia.org/wiki/Rosetta_\(software\)> "Rosetta \(software\)")
  * [Smart Folders](<https://en.wikipedia.org/wiki/Virtual_folder#macOS> "Virtual folder")
  * [Speakable items](<https://en.wikipedia.org/wiki/Speakable_items> "Speakable items")
  * [Spotlight](<https://en.wikipedia.org/wiki/Spotlight_\(Apple\)> "Spotlight \(Apple\)")
  * [Stacks](<https://en.wikipedia.org/wiki/Stacks_\(Mac_OS\)> "Stacks \(Mac OS\)")
  * [System Integrity Protection](<https://en.wikipedia.org/wiki/System_Integrity_Protection> "System Integrity Protection")
  * [Uniform Type Identifier](<https://en.wikipedia.org/wiki/Uniform_Type_Identifier> "Uniform Type Identifier")
  * [Universal binary](<https://en.wikipedia.org/wiki/Universal_binary> "Universal binary")
  * [WebKit](<https://en.wikipedia.org/wiki/WebKit> "WebKit")
  * [XNU](<https://en.wikipedia.org/wiki/XNU> "XNU")
  * [XQuartz](<https://en.wikipedia.org/wiki/XQuartz> "XQuartz")

  
---  
Deprecated| 

  * [HFS+](<https://en.wikipedia.org/wiki/HFS+> "HFS+")

  
Discontinued| 

  * [ATSUI](<https://en.wikipedia.org/wiki/Apple_Type_Services_for_Unicode_Imaging> "Apple Type Services for Unicode Imaging")
  * [BootX](<https://en.wikipedia.org/wiki/BootX_\(Apple\)> "BootX \(Apple\)")
  * [Brushed metal](<https://en.wikipedia.org/wiki/Brushed_metal_\(interface\)> "Brushed metal \(interface\)")
  * [Carbon](<https://en.wikipedia.org/wiki/Carbon_\(API\)> "Carbon \(API\)")
  * [Classic Environment](<https://en.wikipedia.org/wiki/Classic_Environment> "Classic Environment")
  * [Inkwell](<https://en.wikipedia.org/wiki/Inkwell_\(Macintosh\)> "Inkwell \(Macintosh\)")
  * [QuickTime](<https://en.wikipedia.org/wiki/QuickTime> "QuickTime")
  * [Spaces](<https://en.wikipedia.org/wiki/Spaces_\(software\)> "Spaces \(software\)")
  * [Xgrid](<https://en.wikipedia.org/wiki/Xgrid> "Xgrid")

  
  
 [Category](<https://en.wikipedia.org/wiki/Category:MacOS> "Category:MacOS")  
  
Retrieved from "[https://en.wikipedia.org/w/index.php?title=Mach-O&oldid=1366410267](<https://en.wikipedia.org/w/index.php?title=Mach-O&oldid=1366410267>)"

[Categories](</wiki/Help:Category> "Help:Category"): 

  * [Executable file formats](</wiki/Category:Executable_file_formats> "Category:Executable file formats")
  * [MacOS development](</wiki/Category:MacOS_development> "Category:MacOS development")
  * [NeXT](</wiki/Category:NeXT> "Category:NeXT")
  * [Mach (kernel)](</wiki/Category:Mach_\(kernel\)> "Category:Mach \(kernel\)")



Hidden categories: 

  * [Articles with short description](</wiki/Category:Articles_with_short_description> "Category:Articles with short description")
  * [Short description is different from Wikidata](</wiki/Category:Short_description_is_different_from_Wikidata> "Category:Short description is different from Wikidata")
  * [Articles lacking in-text citations from February 2021](</wiki/Category:Articles_lacking_in-text_citations_from_February_2021> "Category:Articles lacking in-text citations from February 2021")
  * [All articles lacking in-text citations](</wiki/Category:All_articles_lacking_in-text_citations> "Category:All articles lacking in-text citations")
  * [Wikipedia articles that are excessively detailed from July 2026](</wiki/Category:Wikipedia_articles_that_are_excessively_detailed_from_July_2026> "Category:Wikipedia articles that are excessively detailed from July 2026")
  * [All articles that are excessively detailed](</wiki/Category:All_articles_that_are_excessively_detailed> "Category:All articles that are excessively detailed")
  * [Wikipedia articles with style issues from July 2026](</wiki/Category:Wikipedia_articles_with_style_issues_from_July_2026> "Category:Wikipedia articles with style issues from July 2026")
  * [All articles with style issues](</wiki/Category:All_articles_with_style_issues> "Category:All articles with style issues")
  * [Articles with multiple maintenance issues](</wiki/Category:Articles_with_multiple_maintenance_issues> "Category:Articles with multiple maintenance issues")
  * [Use mdy dates from October 2013](</wiki/Category:Use_mdy_dates_from_October_2013> "Category:Use mdy dates from October 2013")
  * [All articles with unsourced statements](</wiki/Category:All_articles_with_unsourced_statements> "Category:All articles with unsourced statements")
  * [Articles with unsourced statements from May 2013](</wiki/Category:Articles_with_unsourced_statements_from_May_2013> "Category:Articles with unsourced statements from May 2013")
  * [CS1 maint: miscellaneous url](</wiki/Category:CS1_maint:_miscellaneous_url> "Category:CS1 maint: miscellaneous url")
  * [Articles with unsourced statements from March 2023](</wiki/Category:Articles_with_unsourced_statements_from_March_2023> "Category:Articles with unsourced statements from March 2023")
  * [Webarchive template wayback links](</wiki/Category:Webarchive_template_wayback_links> "Category:Webarchive template wayback links")



  * This page was last edited on 27 July 2026, at 21:25 (UTC).
  * Page was rendered with [Parsoid](<https://www.mediawiki.org/wiki/Special:MyLanguage/Parsoid> "mw:Special:MyLanguage/Parsoid").
  * Text is available under the [Creative Commons Attribution-ShareAlike 4.0 License](</wiki/Wikipedia:Text_of_the_Creative_Commons_Attribution-ShareAlike_4.0_International_License> "Wikipedia:Text of the Creative Commons Attribution-ShareAlike 4.0 International License"); additional terms may apply. By using this site, you agree to the [Terms of Use](<https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Terms_of_Use> "foundation:Special:MyLanguage/Policy:Terms of Use") and [Privacy Policy](<https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy> "foundation:Special:MyLanguage/Policy:Privacy policy"). Wikipedia® is a registered trademark of the [Wikimedia Foundation, Inc.](<https://wikimediafoundation.org/>), a non-profit organization.


  * [Privacy policy](<https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy>)
  * [About Wikipedia](</wiki/Wikipedia:About>)
  * [Disclaimers](</wiki/Wikipedia:General_disclaimer>)
  * [Contact Wikipedia](<//en.wikipedia.org/wiki/Wikipedia:Contact_us>)
  * [Legal & safety contacts](<https://foundation.wikimedia.org/wiki/Special:MyLanguage/Legal:Wikimedia_Foundation_Legal_and_Safety_Contact_Information>)
  * [Code of Conduct](<https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Universal_Code_of_Conduct>)
  * [Developers](<https://developer.wikimedia.org>)
  * [Statistics](<https://stats.wikimedia.org/#/en.wikipedia.org>)
  * [Cookie statement](<https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Cookie_statement>)
  * [Mobile view](<//en.wikipedia.org/w/index.php?title=Mach-O&mobileaction=toggle_view_mobile>)


  * [](<https://www.wikimedia.org/>)
  * [](<https://www.mediawiki.org/>)



Search

Search

Toggle the table of contents

Mach-O

8 languages Add topic



  *[v]: View this template
  *[t]: Discuss this template
  *[e]: Edit this template
