from idaapi import *

TYPE_R = 0
TYPE_I = 1

CODE_DEFAULT_BASE = 0x00000
STACK_DEFAULT_BASE = 0xf0000
ERRORS = -1

FL_INDIRECT = 0x000000800  # This is an indirect access (not immediate value)
FL_ABSOLUTE = 1  # absolute: &addr
class DecodingError(Exception):
    pass

class Inst:
    command = 0
    oprand1 = 0
    oprand2 = 0
    oprand3 = 0

class SubleqProcessor(processor_t):
    id = 0x8000 + 8888
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    author = "invano"
    psnames = ["slq"]
    plnames = ["Subleq"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "Subleq",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = ['sp', 'CS', 'DS']

    instruc = instrs = [
        {'name': 'subleq', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2 | CF_JUMP},
        {'name': 'mov', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'mov_deref_dst', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'mov_deref_src', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'movjmp', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2 | CF_JUMP },
        {'name': 'add', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'sub', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'inc', 'feature': CF_USE1 | CF_CHG1 },
        {'name': 'dec', 'feature': CF_USE1 | CF_CHG1 },
        {'name': 'ijmp', 'feature': CF_USE1 | CF_JUMP },
        {'name': 'clear', 'feature': CF_USE1 | CF_CHG2 },
        {'name': 'jmp', 'feature': CF_USE1 | CF_JUMP },
        {'name': 'jle', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2 | CF_JUMP},
        {'name': 'jne', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2 | CF_JUMP},
    ]

    instruc_end = len(instruc)
    curInst = Inst()
    
    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            print(idx, ins)
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.reg_first_sreg = self.reg_code_sreg = self.reg_ids["CS"]
        self.reg_last_sreg = self.reg_data_sreg = self.reg_ids["DS"]

    def _set_insn_type(self, insn, typ, dtyp):
        insn.type = typ
        insn.dtyp = dtyp

    def _set_insn_near(self, insn, dtyp, addr):
        self._set_insn_type(insn, o_near, dtyp)
        insn.addr = addr

    def _set_insn_mem(self, insn, dtyp, value):
        self._set_insn_type(insn, o_mem, dtyp)
        insn.addr = value
    
    def _set_insn_imm(self, insn, dtyp, value):
        self._set_insn_type(insn, o_imm, dtyp)
        insn.value = value

    def _read_subleq_ops(self, addr):
        a = get_full_word(addr)
        b = get_full_word(addr + 2)
        c = get_full_word(addr + 4)
        return a, b, c

    def _read_movjmp_ops(self, addr):
        a = get_full_word(addr + 6)
        b = get_full_word(addr)
        c = get_full_word(addr + 22)
        return a, b, c
    
    def _read_add_ops(self, addr):
        a = get_full_word(addr)
        b = get_full_word(addr + 8)
        return a, b
    
    def _read_inc_ops(self, addr):
        a = get_full_word(addr + 16)
        return a
    
    def _read_dec_ops(self, addr):
        a = get_full_word(addr + 10)
        return a
    
    def _read_jne_ops(self, addr):
        a = get_full_word(addr + 6)
        b = get_full_word(addr + 24)
        c = get_full_word(addr + 58)
        return a, b, c
    
    NO_LIFT = 0
    LIFT_EASY = 1
    LIFT_HARD = 2
    # DO_LIFT = LIFT_EASY
    DO_LIFT = LIFT_HARD
    
    def _subleq_is_clear(self, addr):
        a, b, c = self._read_subleq_ops(addr)
        if c == 0 and a == b:
            return True
        return False

    def _subleq_is_jmp(self, addr):
        a, b, c = self._read_subleq_ops(addr)
        if c != 0 and a == b:
            return True
        return False

    def _subleq_is_sub(self, addr):
        a, b, c = self._read_subleq_ops(addr)
        if c == 0 and a != b:
            return True
        return False
    
    def _subleq_is_jle(self, addr):
        a, b, c = self._read_subleq_ops(addr)
        if c != 0 and a != b:
            return True
        return False

    def _subleq_is_movjmp(self, addr):
        a1, b1, c1 = self._read_subleq_ops(addr)
        a2, b2, c2 = self._read_subleq_ops(addr + 6)
        a3, b3, c3 = self._read_subleq_ops(addr + 12)
        a4, b4, c4 = self._read_subleq_ops(addr + 18)
        
        if a1 == b1 and c1 == 0 and \
           b2 == 0 and c2 == 0 and \
           a3 == 0 and b1 == b3 and c3 == 0 and \
           a4 == 0 and b4 == 0:
            return True
        return False

    def _subleq_is_mov(self, addr):
        a, b, c = self._read_subleq_ops(addr)
        if c == 0 and self._subleq_is_movjmp(addr):
            return True
        return False
    
    def _subleq_is_mov_deref_dst(self, addr):
        if self._subleq_is_mov(addr) and \
           self._subleq_is_mov(addr+24) and \
           self._subleq_is_mov(addr+48) and \
           self._subleq_is_mov(addr+72):
            a1, b1, c1 = self._read_movjmp_ops(addr)
            a2, b2, c2 = self._read_movjmp_ops(addr+24)
            a3, b3, c3 = self._read_movjmp_ops(addr+48)
            a4, b4, c4 = self._read_movjmp_ops(addr+72)
            if a1 == a2 == a3 and c1 == c2 == c3 == c4 == 0 and \
               b1+1 == b2 and b1+7 == b3 and b4 == 0:
                return True
        return False
    
    def _subleq_is_mov_deref_src(self, addr):
        if self._subleq_is_mov(addr) and \
           self._subleq_is_mov(addr+24):
            a1, b1, c1 = self._read_movjmp_ops(addr)
            a2, b2, c2 = self._read_movjmp_ops(addr+24)
            if b1*2 == addr+24+6 and c1 == c2 == 0:
                return True
        return False

    def _subleq_is_add(self, addr):
        a1, b1, c1 = self._read_subleq_ops(addr)
        a2, b2, c2 = self._read_subleq_ops(addr+6)
        a3, b3, c3 = self._read_subleq_ops(addr+12)

        if b1 == 0 and c1 == 0 and \
           a2 == 0 and c2 == 0 and \
           a3 == 0 and b3 == 0 and c3 == 0:
            return True
        return False

    def _subleq_is_inc(self, addr):
        a1, b1, c1 = self._read_subleq_ops(addr)
        dw = get_full_word(addr + 6) 
        if dw != 1 or a1 != 0 or b1 != 0 or c1*2 != addr + 8:
            return False
        
        if self._subleq_is_add(addr+8):
            a2, b2 = self._read_add_ops(addr+8)
            if a2*2 == addr+6:
                return True
        return False

    def _subleq_is_dec(self, addr):
        a1, b1, c1 = self._read_subleq_ops(addr)
        dw = get_full_word(addr + 6) 
        if dw != 1 or a1 != 0 or b1 != 0 or c1*2 != addr + 8:
            return False

        a2, b2, c2 = self._read_subleq_ops(addr + 8)
        
        if a2*2 == addr + 6 and c2 == 0:
            return True
        return False

    def _subleq_is_jne(self, addr):
        if self._subleq_is_mov(addr) and \
           self._subleq_is_sub(addr+24) and \
           self._subleq_is_jle(addr+30) and \
           self._subleq_is_jmp(addr+36) and \
           self._subleq_is_clear(addr+42) and \
           self._subleq_is_jle(addr+48) and \
           self._subleq_is_jmp(addr+54) and \
           get_full_word(addr+60) == 0:
            
            a1, b1, c1 = self._read_movjmp_ops(addr)
            a2, b2, c2 = self._read_subleq_ops(addr+24)
            a3, b3, c3 = self._read_subleq_ops(addr+30)
            a4, b4, c4 = self._read_subleq_ops(addr+36)
            a5, b5, c5 = self._read_subleq_ops(addr+42)
            a6, b6, c6 = self._read_subleq_ops(addr+48)

            if b1 == b2 == a3 == b6 and \
               b3 == a5 == a6 == 0 and \
               c3*2 == addr+42:
                return True
        return False

    def subleq_ana_lift_hard(self, insn):
        if self._subleq_is_jne(insn.ea):
            insn.itype = self.inames["jne"]
            a, b, c = self._read_jne_ops(insn.ea)
            if c != 0xffff:
                self._set_insn_near(insn[2], dt_word, c*2)
            else:
                self._set_insn_imm(insn[2], dt_word, c)
            self._set_insn_mem(insn[1], dt_word, b*2)
            self._set_insn_mem(insn[0], dt_word, a*2)
            insn.size = 24 + 6*6 + 2
        elif self._subleq_is_mov_deref_dst(insn.ea):
            insn.itype = self.inames["mov_deref_dst"]
            a1, b1, c1 = self._read_movjmp_ops(insn.ea)
            a2, b2, c2 = self._read_movjmp_ops(insn.ea+72)
            self._set_insn_mem(insn[1], dt_word, a1*2)
            self._set_insn_mem(insn[0], dt_word, a2*2)
            insn.size = 2 * 3 * 4 * 4
        elif self._subleq_is_mov_deref_src(insn.ea):
            insn.itype = self.inames["mov_deref_src"]
            a1, b1, c1 = self._read_movjmp_ops(insn.ea)
            a2, b2, c2 = self._read_movjmp_ops(insn.ea+24)
            self._set_insn_mem(insn[1], dt_word, b2*2)
            self._set_insn_mem(insn[0], dt_word, a1*2)
            insn.size = 2 * 3 * 4 * 2
        elif self._subleq_is_mov(insn.ea):
            insn.itype = self.inames["mov"]
            a, b, c = self._read_movjmp_ops(insn.ea)
            self._set_insn_mem(insn[1], dt_word, b*2)
            self._set_insn_mem(insn[0], dt_word, a*2)
            insn.size = 2 * 3 * 4
        elif self._subleq_is_movjmp(insn.ea):
            insn.itype = self.inames["movjmp"]
            a, b, c = self._read_movjmp_ops(insn.ea)
            if c != 0xffff:
                self._set_insn_near(insn[2], dt_word, c*2)
            else:
                self._set_insn_imm(insn[2], dt_word, c)
            self._set_insn_mem(insn[1], dt_word, b*2)
            self._set_insn_mem(insn[0], dt_word, a*2)
            insn.size = 2 * 3 * 4
        elif self._subleq_is_inc(insn.ea):
            insn.itype = self.inames["inc"]
            a = self._read_inc_ops(insn.ea)
            self._set_insn_mem(insn[0], dt_word, a*2)
            insn.size = 2 * 3 * 4 + 2
        elif self._subleq_is_dec(insn.ea):
            insn.itype = self.inames["dec"]
            a = self._read_dec_ops(insn.ea)
            self._set_insn_mem(insn[0], dt_word, a*2)
            insn.size = 2 * 3 * 2 + 2
        elif self._subleq_is_add(insn.ea):
            insn.itype = self.inames["add"]
            a, b = self._read_add_ops(insn.ea)
            self._set_insn_mem(insn[1], dt_word, b*2)
            self._set_insn_mem(insn[0], dt_word, a*2)
            insn.size = 2 * 3 * 3
        else:
            self.subleq_ana_lift(insn)
        return insn.size

    def subleq_ana_lift(self, insn):
        a, b, c = self._read_subleq_ops(insn.ea)
       
        if c == 0:
            if a == b:
                insn.itype = self.inames["clear"]
                self._set_insn_mem(insn[0], dt_word, b * 2)
            else:
                insn.itype = self.inames["sub"]
                self._set_insn_mem(insn[1], dt_word, b * 2)
                self._set_insn_mem(insn[0], dt_word, a * 2)
        else:
            if a == b:
                insn.itype = self.inames["jmp"]
                if c != 0xffff:
                    self._set_insn_near(insn[0], dt_word, c * 2)
                else:
                    self._set_insn_imm(insn[0], dt_word, c)
            else:
                insn.itype = self.inames["jle"]
                if c != 0xffff:
                    self._set_insn_near(insn[2], dt_word, c * 2)
                else:
                    self._set_insn_imm(insn[2], dt_word, c)
                self._set_insn_mem(insn[1], dt_word, b * 2)
                self._set_insn_mem(insn[0], dt_word, a * 2)
        insn.size = 6
        return insn.size

    def subleq_ana_nolift(self, insn):
        a, b, c = self._read_subleq_ops(insn.ea)
        
        insn.itype = self.inames["subleq"]
        if c != 0xffff:
            self._set_insn_near(insn[2], dt_word, c * 2)
        else:
            self._set_insn_imm(insn[2], dt_word, c)
        self._set_insn_mem(insn[1], dt_word, b * 2)
        self._set_insn_mem(insn[0], dt_word, a * 2)
        insn.size = 6
        return insn.size

    def notify_ana(self, insn):
        if self.DO_LIFT == self.LIFT_EASY:
            return self.subleq_ana_lift(insn)
        elif self.DO_LIFT == self.LIFT_HARD:
            return self.subleq_ana_lift_hard(insn)
        else:
            return self.subleq_ana_nolift(insn)

    def _emu_operand(self,op,insn):
        if op.type == o_mem:
            # insn.create_op_data(op.addr, 0, op.dtyp)
            insn.add_dref(op.addr, 0, dr_O| XREF_USER)
        elif op.type == o_near:
            insn.add_cref(op.addr, 0, fl_JN)

    def subleq_emu_lift(self, insn):
        ft = insn.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(insn[0], insn)
        if ft & CF_USE2:
            self._emu_operand(insn[1], insn)
        if ft & CF_USE3:
            self._emu_operand(insn[2], insn)
        if ft & CF_USE4:
            self._emu_operand(insn[3], insn)
        if not ft & CF_STOP and insn.itype != self.inames["jmp"]:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        return True

    def subleq_emu_nolift(self, insn):
        ft = insn.get_canon_feature()
        a = insn[0].addr
        b = insn[1].addr
        if insn[2].type == o_mem:
            c = insn[2].addr
        else:
            c = insn[2].value

        insn.add_dref(a, 0, dr_O | XREF_USER)
        insn.add_dref(b, 0, dr_O | XREF_USER)
        if c != 0:
            if b == a:
                insn.add_cref(c, 0, fl_JN)
            else:
                insn.add_cref(c, 0, fl_JN)
                insn.add_cref(insn.ea + insn.size, 0, fl_F)
        else:
            if not ft & CF_STOP:
                insn.add_cref(insn.ea + insn.size, 0, fl_F)
        return True

    def notify_emu(self, insn):
        if self.DO_LIFT:
            return self.subleq_emu_lift(insn)
        else:
            return self.subleq_emu_nolift(insn)
    
    def notify_out_operand(self, outctx, op):
        if op.type == o_imm:
            outctx.out_value(op, OOFW_IMM)
        elif op.type in [o_near, o_mem]:
            ok = outctx.out_name_expr(op, op.addr, BADADDR)
            if not ok:
                outctx.out_tagon(COLOR_ERROR)
                outctx.out_long(op.addr, 16)
                outctx.out_tagoff(COLOR_ERROR)
        else:
            return False
        return True

    def notify_out_insn(self,outctx):
        insn=outctx.insn
        ft = insn.get_canon_feature()
        outctx.out_mnem()
        if ft & CF_USE1:
            outctx.out_one_operand(0)
        if ft & CF_USE2:
            outctx.out_char(',')
            outctx.out_char(' ')
            outctx.out_one_operand(1)
        if ft & CF_USE3:
            outctx.out_char(',')
            outctx.out_char(' ')
            outctx.out_one_operand(2)
        outctx.flush_outbuf()
        cvar.gl_comm = 1

def PROCESSOR_ENTRY():
    return SubleqProcessor()
