.text
.extern Inject
.globl alignstack

alignstack:
    pushq %rdi                 
    movq %rsp, %rdi           
    andq $-0x10, %rsp          
    subq $0x20, %rsp          
    callq Inject              
    movq %rdi, %rsp            
    popq %rdi                  
    ret                       
