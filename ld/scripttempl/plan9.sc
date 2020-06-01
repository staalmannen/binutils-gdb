test -z "${ALIGNMENT}" && ALIGNMENT="4"

cat <<EOF
OUTPUT_FORMAT("${OUTPUT_FORMAT}")
OUTPUT_ARCH(${ARCH})
${RELOCATING+${LIB_SEARCH_DIRS}}
${RELOCATING+PROVIDE (__stack = 0);}

SECTIONS
{
  ${RELOCATING+. = ${TEXT_START_ADDR};}
  .text :
  {
    CREATE_OBJECT_SYMBOLS
    *(.text)
    ${RELOCATING+_etext = .;}
    ${RELOCATING+__etext = .;}
  }
  ${RELOCATING+. = ${DATA_ALIGNMENT};}
  .data :
  {
    *(.data)
    ${CONSTRUCTING+CONSTRUCTORS}
    ${RELOCATING+_edata  =  .;}
    ${RELOCATING+__edata  =  .;}
  }
  .bss :
  {
    ${RELOCATING+ __bss_start = .};
    *(.bss)
    *(COMMON)
    ${RELOCATING+_end = . };
    ${RELOCATING+__end = . };
  }
}
EOF
#    ${PAD_TEXT+${RELOCATING+. = ${DATA_ALIGNMENT};}}
#    ${RELOCATING+. = ALIGN(${ALIGNMENT});}
