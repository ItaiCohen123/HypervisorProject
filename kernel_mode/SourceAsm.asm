


;PUBLIC AsmEnableVmxOperation
;PUBLIC AsmNop
;PUBLIC AsmReadTimeStamp
;PUBLIC AsmAdd
;PUBLIC AsmXor
;PUBLIC AsmSaveStateForVmxoff
;PUBLIC AsmVmxoffAndRestoreState
;PUBLIC GetCs
;PUBLIC GetDs
;PUBLIC GetEs
;PUBLIC GetSs
;PUBLIC GetFs
;PUBLIC GetGs
;PUBLIC GetLdtr
;PUBLIC GetTr
;PUBLIC GetGdtBase
;PUBLIC GetIdtBase
;PUBLIC GetGdtLimit
;PUBLIC GetIdtLimit
;PUBLIC GetRflags
;PUBLIC GetRsp


extern KeStallExecutionProcessor:proc


.data
    PUBLIC g_StackPointerForReturning
    PUBLIC g_BasePointerForReturning
    
g_StackPointerForReturning dq 0
g_BasePointerForReturning dq 0


.code




    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2





;------------------------------------------------------------------------
; 

AsmReadTimeStamp PROC ;PUBLIC
   
  

   RDTSC  ;Read the timestamp counter into EDX:EAX (64-bit value)
   
   ret
   
AsmReadTimeStamp ENDP



AsmAdd PROC ;PUBLIC

    xor rax, rax
    add rax, 5

    ret
    
AsmAdd ENDP


AsmXor PROC ;PUBLIC

    xor rax, rax

    ret

AsmXor ENDP



AsmNop PROC ;PUBLIC
    
   nop
   
   ret

    
AsmNop ENDP



;------------------------------------------------------------------------

AsmEnableVmxOperation PROC ;PUBLIC

    push rax               ; Save the state
    
    xor rax, rax           ; Clear the RAX
    mov rax, cr4

    or rax, 02000h          ; Set the 14th bit
    mov cr4, rax
    
    pop rax             ; Restore the state
    ret

AsmEnableVmxOperation ENDP

;------------------------------------------------------------------------


AsmSaveStateForVmxoff PROC PUBLIC
    mov g_StackPointerForReturning, rsp
    mov g_BasePointerForReturning, rbp

    RET

AsmSaveStateForVmxoff ENDP 

;------------------------------------------------------------------------

AsmVmxoffAndRestoreState PROC PUBLIC

    vmxoff 

    mov rsp, g_StackPointerForReturning
    mov rbp, g_BasePointerForReturning

    add rsp, 8 ;make rsp point to a correct return point

   

    ; return section

    mov rbx, [rsp+28h+8h]
    mov rsi, [rsp+28h+10h]
    add rsp, 40h
    pop rdi

    ret

AsmVmxoffAndRestoreState ENDP

;------------------------------------------------------------------------

GetGdtBase PROC
    
    local GDTR[10]:BYTE
    sgdt GDTR
    mov rax, QWORD PTR GDTR[2]


    ret

GetGdtBase ENDP

;------------------------------------------------------------------------

GetCs PROC
    
    mov rax, cs

    ret

GetCs ENDP

;------------------------------------------------------------------------

GetDs PROC
    
    mov rax, ds

    ret

GetDs ENDP

;------------------------------------------------------------------------

GetEs PROC
    
    mov rax, es

    ret

GetEs ENDP

GetRsp PROC

    mov rax, rsp
        
    ret
GetRsp ENDP

;------------------------------------------------------------------------

GetSs PROC
    
    mov rax, ss

    ret

GetSs ENDP

;------------------------------------------------------------------------

GetFs PROC
    
    mov rax, fs

    ret

GetFs ENDP

;------------------------------------------------------------------------

GetGs PROC
    
    mov rax, gs

    ret

GetGs ENDP


;------------------------------------------------------------------------

GetLdtr PROC
    
    sldt rax

    ret

GetLdtr ENDP

;------------------------------------------------------------------------

GetTr PROC
    
    str rax

    ret

GetTr ENDP

;------------------------------------------------------------------------

GetIdtBase PROC
    
    local IDTR[10]:BYTE

    sidt IDTR
    mov rax, QWORD PTR IDTR[2]


    ret

GetIdtBase ENDP

;------------------------------------------------------------------------

GetGdtLimit PROC
    
    local GDTR[10]:BYTE

    sgdt GDTR
    mov ax, WORD PTR GDTR[0]


    ret

GetGdtLimit ENDP


;------------------------------------------------------------------------

GetIdtLimit PROC
    
    local IDTR[10]:BYTE

    sidt IDTR
    mov ax, WORD PTR IDTR[0]


    ret

GetIdtLimit ENDP

;------------------------------------------------------------------------

GetRflags PROC
    
   pushfq
   pop rax

    ret

GetRflags ENDP


END
