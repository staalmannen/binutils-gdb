OUTPUT_FORMAT("plan9-i386")
OUTPUT_ARCH(i386)
SEARCH_DIR(/lib); SEARCH_DIR(/usr/lib); SEARCH_DIR(/386/lib/gnu); SEARCH_DIR(/usr/local/lib); SEARCH_DIR(/386/bin/gnu/i386-lucent-plan9/lib);
PROVIDE (__stack = 0);
SECTIONS
{
  . = 0x1020;
  .text :
  {
    CREATE_OBJECT_SYMBOLS
    *(.text)
    _etext = .;
    __etext = .;
  }
  . = ALIGN(0x1000);
  .data :
  {
    *(.data)
    CONSTRUCTORS
    _edata  =  .;
    __edata  =  .;
  }
  .bss :
  {
     __bss_start = .;
    *(.bss)
    *(COMMON)
    _end = . ;
    __end = . ;
  }
}
