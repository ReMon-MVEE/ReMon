# ReMon Status

## GCC issues on monitor shutdown

### \[12/08/2020\]

relevant:
 
- Ubuntu 18.04
- local gcc version 7.5.0
- local clang/clang++ version 6.0.0
- latest ReMon-LLVM build
- all branches latest as of date

Issue occurs on Release build only.

When compiling with GCC: monitor aborts when shutting down.
When compiling with clang: issues with `__asm__` blocks in 
    MVEE/Src/arch/amd64/shared_mem/instruction_intent_emulation.cpp

 
Possible solutions:

- **Don't use static linking, dynamically link instead.** i.e. replace `-static` with `-rdynamic` in 
    `target_link_libraries()` in CMakeLists.txt.
  - results: 
    - ReMon-LLVM: Does not compile, `error: unknown token in expression` in inline assembly block because of symbolic 
        names for operands.
    - clang/clang++: Does not compile, `error: unknown token in expression` in inline assembly block because of 
        symbolic names for operands.
    - gcc: Compiles and works.
    - g++: Compiles and works.
  - note: `-no-integrated-as` does not affect the result for the unknown token issue.
  
- **Remove `-flto` from `target_compile_options()`.** It seems that `-flto` in compile options interferes with 
    `-no-integrated-as` for clang/clang++ and ReMon-LLVM, and with the static linking for gcc/g++.
  - results: 
    - ReMon-LLVM: Compiles and works.
    - clang/clang++: Compiles and works.
    - gcc/g++: Compiles and works.
    - gcc/g++: Compiles and works.

- **Rewriting inlined assembly to att_syntax.** This would solve the issue of the compilation with ReMon-LLVM and 
    clang/clang++, however, the Abort issue when building with gcc/g++ might actually still be there.

----
----