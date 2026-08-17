# Overview of the Mach-O Executable Format — Apple Developer

> **Source:** <https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html>  
> **Fetched:** 2026-08-17  
> **License:** Content © respective upstream authors.
Reproduced here as a developer reference for the mac-ify
codebase. The Mach-O format itself is publicly documented
in `<mach-o/loader.h>` and Apple's open documentation.

---

[Documentation Archive](<https://developer.apple.com/library/archive/navigation/>) [Developer](<https://developer.apple.com/>)

Search

Search Documentation Archive

# Code Size Performance Guidelines

PDF Companion File

  * Table of Contents
  * Jump To…
  * Download Sample Code



  * [Introduction](</library/archive/documentation/Performance/Conceptual/CodeFootprint/CodeFootprint.html#//apple_ref/doc/uid/10000149-SW1>)
  * [Overview of the Mach-O Executable Format](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html#//apple_ref/doc/uid/20001860-BAJGJEJC>)
    * [The __TEXT Segment: Read Only](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html#//apple_ref/doc/uid/20001860-99893-BAJJEJIA>)
    * [The __DATA Segment: Read/Write](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html#//apple_ref/doc/uid/20001860-100029-TPXREF104>)
    * [Mach-O Performance Implications](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html#//apple_ref/doc/uid/20001860-100189-TPXREF105>)
  * [Managing Code Size](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-CJBJFIDD>)
    * [Compiler-Level Optimizations](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-102307>)
    * [Additional Optimizations](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-102413-BCIEBFGC>)
      * [Dead Strip Your Code](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-131369>)
      * [Strip Symbol Information](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-131489>)
      * [Eliminate C++ Exception Handling Overhead](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-131584>)
        * [Disabling Exceptions](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-131606>)
        * [Selectively Disabling Exceptions](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-131636>)
        * [Minimizing Exception Use](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-131737>)
      * [Avoid Excessive Function Inlining](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-131770-BAJGFFAE>)
      * [Build Frameworks as a Single Module](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/CompilerOptions.html#//apple_ref/doc/uid/20001861-104466>)
  * [Improving Locality of Reference](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-CJBJFIDD>)
    * [Profiling Code With gprof](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-106785-TPXREF102>)
      * [Generating Profiling Data](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-106854>)
      * [Generating Order Files](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-117091-BCIBJEBH>)
      * [Fixing Up Your Order Files](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-112550>)
      * [Linking with an Order File](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-109955-BCIFEIIB>)
      * [Limitations of gprof Order Files](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-110125-TPXREF149>)
    * [Profiling With the Monitor Functions](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-138832>)
    * [Organizing Code at Compile Time](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-111363>)
    * [Reordering the __text Section](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-111686-TPXREF124>)
      * [Reordering Procedures](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-102991-BCIHIDGE>)
      * [Procedure Reordering for Large Programs](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-103571-TPXREF127>)
        * [Creating a Default Order File](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-103584-BCIEFDCH>)
        * [Using pagestuff to Examine Pages on Disk](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-103710-BCIFCBDI>)
        * [Grouping Routines According to Usage](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-103785-BCIFAHAC>)
        * [Finding That One Last Hot Routine](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-109188-TPXREF128>)
    * [Reordering Other Sections](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-110250-TPXREF108>)
      * [Reordering Literal Sections](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-104418-TPXREF109>)
      * [Reordering Data Sections](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-104599-TPXREF129>)
    * [Reordering Assembly Language Code](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ImprovingLocality.html#//apple_ref/doc/uid/20001862-104673-BCIGJDHD>)
  * [Reducing Shared Memory Pages](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/SharedPages.html#//apple_ref/doc/uid/20001863-CJBJFIDD>)
    * [Declaring Data as const](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/SharedPages.html#//apple_ref/doc/uid/20001863-101955-BBCBBBIH>)
    * [Initializing Static Data](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/SharedPages.html#//apple_ref/doc/uid/20001863-102402-BBCCAEJC>)
    * [Avoiding Tentative-Definition Symbols](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/SharedPages.html#//apple_ref/doc/uid/20001863-102528-TPXREF110>)
    * [Analyzing Mach-O Executables](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/SharedPages.html#//apple_ref/doc/uid/20001863-102597-TPXREF111>)
  * [Minimizing Your Exported Symbols](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ReducingExports.html#//apple_ref/doc/uid/20001864-CJBJFIDD>)
    * [Identifying Exported Symbols](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ReducingExports.html#//apple_ref/doc/uid/20001864-103144>)
    * [Limiting Your Exported Symbols](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ReducingExports.html#//apple_ref/doc/uid/20001864-103946>)
    * [Limiting Exports Using GCC 4.0](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/ReducingExports.html#//apple_ref/doc/uid/20001864-SW1>)
  * [Revision History](</library/archive/documentation/Performance/Conceptual/CodeFootprint/RevisionHistory.html#//apple_ref/doc/uid/20001865-SW1>)
  * [Index](</library/archive/documentation/Performance/Conceptual/CodeFootprint/Index/index_of_book.html#//apple_ref/doc/uid/10000149i-Index>)

### RELATED DOCUMENT

    * [Memory Usage Performance Guidelines](</library/archive/documentation/Performance/Conceptual/ManagingMemory/ManagingMemory.html#//apple_ref/doc/uid/10000160i>)



[Next](<CompilerOptions.html>)[Previous](<../CodeFootprint.html>)

[](<../index.html>)

# Retired Document

**Important:** This document may not represent best practices for current development. Links to downloads and other resources may no longer be valid.

# Overview of the Mach-O Executable Format

Mach-O is the native executable format of binaries in OS X and is the preferred format for shipping code. An executable format determines the order in which the code and data in a binary file are read into memory. The ordering of code and data has implications for memory usage and paging activity and thus directly affects the performance of your program.

A Mach-O binary is organized into segments. Each segment contains one or more sections. Code or data of different types goes into each section. Segments always start on a page boundary, but sections are not necessarily page-aligned. The size of a segment is measured by the number of bytes in all the sections it contains and rounded up to the next virtual memory page boundary. Thus, a segment is always a multiple of 4096 bytes, or 4 kilobytes, with 4096 bytes being the minimum size.

The segments and sections of a Mach-O executable are named according to their intended use. The convention for segment names is to use all-uppercase letters preceded by double underscores (for example, `__TEXT`); the convention for section names is to use all-lowercase letters preceded by double underscores (for example, `__text`). 

There are several possible segments within a Mach-O executable, but only two of them are of interest in relation to performance: the `__TEXT` segment and the `__DATA` segment.

## The __TEXT Segment: Read Only

The `__TEXT` segment is a read-only area containing executable code and constant data. By convention, the compiler tools create every executable file with at least one read-only `__TEXT` segment. Because the segment is read-only, the kernel can map the `__TEXT` segment directly from the executable into memory just once. When the segment is mapped into memory, it can be shared among all processes interested in its contents. (This is primarily the case with frameworks and other shared libraries.) The read-only attribute also means that the pages that make up the `__TEXT` segment never have to be saved to backing store. If the kernel needs to free up physical memory, it can discard one or more `__TEXT` pages and re-read them from disk when they are needed.

Table 1 lists some of the more important sections that can appear in the `__TEXT` segment. For a complete list of segments, see _Mach-O Runtime Architecture_. 

**Table 1**   Major sections in the __TEXT segment Section | Description  
---|---  
`__text` | The compiled machine code for the executable  
`__const` | The general constant data for the executable  
`__cstring` | Literal string constants (quoted strings in source code)  
`__picsymbol_stub` | Position-independent code stub routines used by the dynamic linker (`dyld`).  
  
## The __DATA Segment: Read/Write

The `__DATA` segment contains the non-constant data for an executable. This segment is both readable and writable. Because it is writable, the `__DATA` segment of a framework or other shared library is logically copied for each process linking with the library. When memory pages are readable and writable, the kernel marks them _copy-on-write_. This technique defers copying the page until one of the processes sharing that page attempts to write to it. When that happens, the kernel creates a private copy of the page for that process. 

The `__DATA` segment has a number of sections, some of which are used only by the dynamic linker. Table 2 lists some of the more important sections that can appear in the `__DATA` segment. For a complete list of segments, see _Mach-O Runtime Architecture_.

**Table 2**   Major sections of the __DATA segment Section | Description  
---|---  
`__data` | Initialized global variables (for example `int a = 1;` or `static int a = 1;`).  
`__const` | Constant data needing relocation (for example, `char * const p = "foo";`).  
`__bss` | Uninitialized static variables (for example, `static int a;`).  
`__common` | Uninitialized external globals (for example, `int a;` outside function blocks).  
`__dyld` | A placeholder section, used by the dynamic linker.  
`__la_symbol_ptr` | “Lazy” symbol pointers. Symbol pointers for each undefined function called by the executable.  
`__nl_symbol_ptr` | “Non lazy” symbol pointers. Symbol pointers for each undefined data symbol referenced by the executable.  
  
## Mach-O Performance Implications

The composition of the `__TEXT` and `__DATA` segments of a Mach-O executable file has a direct bearing on performance. The techniques and goals for optimizing these segments are different. However, they have as a common goal: greater efficiency in the use of memory.

Most of a typical Mach-O file consists of executable code, which occupies the `__TEXT`, `__text` section. As noted in The __TEXT Segment: Read Only, the `__TEXT` segment is read-only and is mapped directly to the executable file. Thus, if the kernel needs to reclaim the physical memory occupied by some `__text` pages, it does not have to save the pages to backing store and page them in later. It only needs to free up the memory and, when the code is later referenced, read it back in from disk. Although this is cheaper than swapping—because it involves one disk access instead of two—it can still be expensive, especially if many pages have to be recreated from disk.

One way to improve this situation is through improving your code’s locality of reference through procedure reordering, as described in [Improving Locality of Reference](<ImprovingLocality.html#//apple_ref/doc/uid/20001862-CJBJFIDD>). This technique groups methods and functions together based on the order in which they are executed, how often they are called, and the frequency with which they call one another. If pages in the `__text` section group functions logically in this way, it is less likely they have to be freed and read back in multiple times. For example, if you put all of your launch-time initialization functions on one or two pages, the pages do not have to be recreated after those initializations have occurred.

Unlike the `__TEXT` segment, the `__DATA` segment can be written to and thus the pages in the `__DATA` segment are not shareable. The non-constant global variables in frameworks can have an impact on performance because each process that links with the framework gets its own copy of these variables. The main solution to this problem is to move as many of the non-constant global variables as possible to the `__TEXT`,`__const` section by declaring them `const`. [Reducing Shared Memory Pages](<SharedPages.html#//apple_ref/doc/uid/20001863-CJBJFIDD>) describes this and related techniques. This is not usually a problem for applications because the `__DATA` section in an application is not shared with other applications.

The compiler stores different types of nonconstant global data in different sections of the `__DATA` segment. These types of data are uninitialized static data and symbols consistent with the ANSI C notion of “tentative definition” that aren’t declared `extern`. Uninitialized static data is in the `__bss` section of the `__DATA` segment. Tentative-definition symbols are in the `__common` section of the `__DATA` segment. 

The ANSI C and C++ standards specify that the system must set uninitialized static variables to zero. (Other types of uninitialized data are left uninitialized.) Because uninitialized static variables and tentative-definition symbols are stored in separate sections, the system needs to treat them differently. But when variables are in different sections, they are more likely to end up on different memory pages and thus can be swapped in and out separately, making your code run slower. The solution to these problems, as described in [Reducing Shared Memory Pages](<SharedPages.html#//apple_ref/doc/uid/20001863-CJBJFIDD>), is to consolidate the non-constant global data in one section of the `__DATA` segment.

[Next](<CompilerOptions.html>)[Previous](<../CodeFootprint.html>)

  


  


* * *

Copyright © 2003, 2014 Apple Inc. All Rights Reserved. [Terms of Use](<http://www.apple.com/legal/internet-services/terms/site.html>) | [Privacy Policy](<http://www.apple.com/privacy/>) | Updated: 2014-03-10
  *[v]: View this template
  *[t]: Discuss this template
  *[e]: Edit this template
