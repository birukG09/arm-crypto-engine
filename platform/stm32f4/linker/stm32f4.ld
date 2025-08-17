/*
 * STM32F407VGT6 Linker Script
 * ArmAsm-CryptoEngine - STM32F4 Discovery Board
 * 
 * Memory layout and section definitions for STM32F407VGT6
 * 1MB Flash, 128KB SRAM, 64KB CCM
 */

/* Entry point */
ENTRY(Reset_Handler)

/* Stack size */
_Min_Heap_Size = 0x200;      /* Required heap size (512 bytes) */
_Min_Stack_Size = 0x400;     /* Required stack size (1KB) */

/* Memory definition */
MEMORY
{
    FLASH (rx)     : ORIGIN = 0x08000000, LENGTH = 1024K
    SRAM (xrw)     : ORIGIN = 0x20000000, LENGTH = 128K
    CCM (xrw)      : ORIGIN = 0x10000000, LENGTH = 64K
}

/* Section definitions */
SECTIONS
{
    /* Interrupt vector table */
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))
        . = ALIGN(4);
    } >FLASH

    /* Program code and read-only data */
    .text :
    {
        . = ALIGN(4);
        *(.text)           /* Normal program code */
        *(.text*)          /* C++ code */
        *(.glue_7)         /* ARM-to-Thumb glue */
        *(.glue_7t)        /* Thumb-to-ARM glue */
        *(.eh_frame)       /* Exception handling */

        KEEP (*(.init))    /* Initialization code */
        KEEP (*(.fini))    /* Finalization code */

        . = ALIGN(4);
        _etext = .;        /* End of code section */
    } >FLASH

    /* Constant data */
    .rodata :
    {
        . = ALIGN(4);
        *(.rodata)         /* Read-only data */
        *(.rodata*)        /* Read-only data */
        . = ALIGN(4);
    } >FLASH

    /* ARM exception handling */
    .ARM.extab   : 
    { 
        . = ALIGN(4);
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        . = ALIGN(4);
    } >FLASH
    
    .ARM :
    {
        . = ALIGN(4);
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
        . = ALIGN(4);
    } >FLASH

    /* C++ constructors/destructors */
    .preinit_array     :
    {
        . = ALIGN(4);
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP (*(.preinit_array*))
        PROVIDE_HIDDEN (__preinit_array_end = .);
        . = ALIGN(4);
    } >FLASH

    .init_array :
    {
        . = ALIGN(4);
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP (*(SORT(.init_array.*)))
        KEEP (*(.init_array*))
        PROVIDE_HIDDEN (__init_array_end = .);
        . = ALIGN(4);
    } >FLASH

    .fini_array :
    {
        . = ALIGN(4);
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP (*(SORT(.fini_array.*)))
        KEEP (*(.fini_array*))
        PROVIDE_HIDDEN (__fini_array_end = .);
        . = ALIGN(4);
    } >FLASH

    /* Used by startup code to initialize data */
    _sidata = LOADADDR(.data);

    /* Initialized data - loaded in FLASH, copied to SRAM at startup */
    .data :
    {
        . = ALIGN(4);
        _sdata = .;        /* Start of data section */
        *(.data)           /* Initialized global variables */
        *(.data*)          /* Initialized global variables */
        *(.RamFunc)        /* Functions to be copied to RAM */

        . = ALIGN(4);
        _edata = .;        /* End of data section */
    } >SRAM AT> FLASH

    /* Uninitialized data - zero-initialized at startup */
    . = ALIGN(4);
    .bss :
    {
        _sbss = .;         /* Start of BSS section */
        __bss_start__ = _sbss;
        *(.bss)            /* Uninitialized global variables */
        *(.bss*)           /* Uninitialized global variables */
        *(COMMON)          /* Common symbols */

        . = ALIGN(4);
        _ebss = .;         /* End of BSS section */
        __bss_end__ = _ebss;
    } >SRAM

    /* User heap and stack */
    ._user_heap_stack :
    {
        . = ALIGN(8);
        PROVIDE ( end = . );
        PROVIDE ( _end = . );
        . = . + _Min_Heap_Size;
        . = . + _Min_Stack_Size;
        . = ALIGN(8);
    } >SRAM

    /* CCM (Core Coupled Memory) for crypto operations */
    .ccm (NOLOAD) :
    {
        . = ALIGN(4);
        _sccm = .;
        *(.ccm)
        *(.ccm*)
        . = ALIGN(4);
        _eccm = .;
    } >CCM

    /* Crypto keys and sensitive data in CCM */
    .crypto_keys (NOLOAD) :
    {
        . = ALIGN(16);     /* Align to 16 bytes for AES */
        _scrypto_keys = .;
        *(.crypto_keys)
        *(.crypto_sensitive)
        . = ALIGN(16);
        _ecrypto_keys = .;
    } >CCM

    /* Remove information from the standard libraries */
    /DISCARD/ :
    {
        libc.a ( * )
        libm.a ( * )
        libgcc.a ( * )
    }

    /* Symbols for memory map information */
    _flash_start = ORIGIN(FLASH);
    _flash_size = LENGTH(FLASH);
    _sram_start = ORIGIN(SRAM);
    _sram_size = LENGTH(SRAM);
    _ccm_start = ORIGIN(CCM);
    _ccm_size = LENGTH(CCM);

    /* Stack pointer initialization */
    PROVIDE(_stack = ORIGIN(SRAM) + LENGTH(SRAM));

    /* Crypto library specific symbols */
    PROVIDE(_crypto_work_area = ORIGIN(CCM));
    PROVIDE(_crypto_work_size = LENGTH(CCM) - (_ecrypto_keys - _scrypto_keys));

    .ARM.attributes 0 : { *(.ARM.attributes) }
}
