    .text
tramp0:
    addi10.sp   #-4
    smw.adm     $r0, [$sp], $p1, #0x2
    sethi       $r15, #0x16b
    ori         $r15, $r15, #0xd3e
    jral        $lp, $r15
    lmw.bim     $r0, [$sp], $p1, #0x2
    addi10.sp   #4
    ret5        $lp
