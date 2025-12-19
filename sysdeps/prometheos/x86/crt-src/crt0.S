.section .text
.global _start
_start:
    mov $main, %ebx
    call __mlibc_entry

.section .note.GNU-stack,"",%progbits