from __future__ import annotations


class Arm32Reg:
    INVALID = 0
    APSR = 1
    APSR_NZCV = 2
    CPSR = 3
    FPEXC = 4
    FPINST = 5
    FPSCR = 6
    FPSCR_NZCV = 7
    FPSID = 8
    ITSTATE = 9
    LR = 10
    PC = 11
    SP = 12
    SPSR = 13
    D0 = 14
    D1 = 15
    D2 = 16
    D3 = 17
    D4 = 18
    D5 = 19
    D6 = 20
    D7 = 21
    D8 = 22
    D9 = 23
    D10 = 24
    D11 = 25
    D12 = 26
    D13 = 27
    D14 = 28
    D15 = 29
    D16 = 30
    D17 = 31
    D18 = 32
    D19 = 33
    D20 = 34
    D21 = 35
    D22 = 36
    D23 = 37
    D24 = 38
    D25 = 39
    D26 = 40
    D27 = 41
    D28 = 42
    D29 = 43
    D30 = 44
    D31 = 45
    FPINST2 = 46
    MVFR0 = 47
    MVFR1 = 48
    MVFR2 = 49
    Q0 = 50
    Q1 = 51
    Q2 = 52
    Q3 = 53
    Q4 = 54
    Q5 = 55
    Q6 = 56
    Q7 = 57
    Q8 = 58
    Q9 = 59
    Q10 = 60
    Q11 = 61
    Q12 = 62
    Q13 = 63
    Q14 = 64
    Q15 = 65
    R0 = 66
    R1 = 67
    R2 = 68
    R3 = 69
    R4 = 70
    R5 = 71
    R6 = 72
    R7 = 73
    R8 = 74
    R9 = 75
    R10 = 76
    R11 = 77
    R12 = 78
    S0 = 79
    S1 = 80
    S2 = 81
    S3 = 82
    S4 = 83
    S5 = 84
    S6 = 85
    S7 = 86
    S8 = 87
    S9 = 88
    S10 = 89
    S11 = 90
    S12 = 91
    S13 = 92
    S14 = 93
    S15 = 94
    S16 = 95
    S17 = 96
    S18 = 97
    S19 = 98
    S20 = 99
    S21 = 100
    S22 = 101
    S23 = 102
    S24 = 103
    S25 = 104
    S26 = 105
    S27 = 106
    S28 = 107
    S29 = 108
    S30 = 109
    S31 = 110
    C1_C0_2 = 111
    C13_C0_2 = 112
    C13_C0_3 = 113
    IPSR = 114
    MSP = 115
    PSP = 116
    CONTROL = 117
    IAPSR = 118
    EAPSR = 119
    XPSR = 120
    EPSR = 121
    IEPSR = 122
    PRIMASK = 123
    BASEPRI = 124
    BASEPRI_MAX = 125
    FAULTMASK = 126
    APSR_NZCVQ = 127
    APSR_G = 128
    APSR_NZCVQG = 129
    IAPSR_NZCVQ = 130
    IAPSR_G = 131
    IAPSR_NZCVQG = 132
    EAPSR_NZCVQ = 133
    EAPSR_G = 134
    EAPSR_NZCVQG = 135
    XPSR_NZCVQ = 136
    XPSR_G = 137
    XPSR_NZCVQG = 138
    CP_REG = 139
    ENDING = 140

    R13 = 12
    R14 = 10
    R15 = 11
    SB = 75
    SL = 76
    FP = 77
    IP = 78

    R = [R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15]
    D = [
        D0,
        D1,
        D2,
        D3,
        D4,
        D5,
        D6,
        D7,
        D8,
        D9,
        D10,
        D11,
        D12,
        D13,
        D14,
        D15,
        D16,
        D17,
        D18,
        D19,
        D20,
        D21,
        D22,
        D23,
        D24,
        D25,
        D26,
        D27,
        D28,
        D29,
        D30,
        D31,
    ]
    S = [
        S0,
        S1,
        S2,
        S3,
        S4,
        S5,
        S6,
        S7,
        S8,
        S9,
        S10,
        S11,
        S12,
        S13,
        S14,
        S15,
        S16,
        S17,
        S18,
        S19,
        S20,
        S21,
        S22,
        S23,
        S24,
        S25,
        S26,
        S27,
        S28,
        S29,
        S30,
        S31,
    ]
    Q = [Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15]
    ARG_REGS = [R0, R1, R2, R3]
    RET_REG = R0
    SYSCALL_NR = R7
    SYSCALL_ARG_REGS = [R0, R1, R2, R3, R4, R5, R6]
