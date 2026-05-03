/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 *
 * LoongArch translation routines for the privileged instructions.
 */

#include "csr.h"

#ifdef CONFIG_USER_ONLY

#define GEN_FALSE_TRANS(name)   \
static bool trans_##name(DisasContext *ctx, arg_##name * a)  \
{   \
    return false;   \
}

GEN_FALSE_TRANS(csrrd)
GEN_FALSE_TRANS(csrwr)
GEN_FALSE_TRANS(csrxchg)
GEN_FALSE_TRANS(gcsrrd)
GEN_FALSE_TRANS(gcsrwr)
GEN_FALSE_TRANS(gcsrxchg)
GEN_FALSE_TRANS(iocsrrd_b)
GEN_FALSE_TRANS(iocsrrd_h)
GEN_FALSE_TRANS(iocsrrd_w)
GEN_FALSE_TRANS(iocsrrd_d)
GEN_FALSE_TRANS(iocsrwr_b)
GEN_FALSE_TRANS(iocsrwr_h)
GEN_FALSE_TRANS(iocsrwr_w)
GEN_FALSE_TRANS(iocsrwr_d)
GEN_FALSE_TRANS(tlbsrch)
GEN_FALSE_TRANS(tlbrd)
GEN_FALSE_TRANS(tlbwr)
GEN_FALSE_TRANS(tlbfill)
GEN_FALSE_TRANS(tlbclr)
GEN_FALSE_TRANS(tlbflush)
GEN_FALSE_TRANS(invtlb)
GEN_FALSE_TRANS(cacop)
GEN_FALSE_TRANS(ldpte)
GEN_FALSE_TRANS(lddir)
GEN_FALSE_TRANS(ertn)
GEN_FALSE_TRANS(dbcl)
GEN_FALSE_TRANS(idle)

#else

typedef void (*GenCSRRead)(TCGv dest, TCGv_ptr env);
typedef void (*GenCSRWrite)(TCGv dest, TCGv_ptr env, TCGv src);

static bool check_plv(DisasContext *ctx)
{
    if (ctx->plv == MMU_PLV_USER) {
        generate_exception(ctx, EXCCODE_IPE);
        return true;
    }
    return false;
}

/*
 * LVZ: Check if a privileged instruction should generate GSPR exception.
 * When in guest mode (PVM=1), privileged instructions trap to the host
 * hypervisor via GSPR exception, regardless of the guest's PLV.
 * Returns true if exception was generated (caller should stop translation).
 */
static bool check_plv_gspr(DisasContext *ctx)
{
    if (ctx->plv == MMU_PLV_USER) {
        generate_exception(ctx, EXCCODE_IPE);
        return true;
    }
    if (ctx->pvm) {
        generate_exception(ctx, EXCCODE_GSPR);
        return true;
    }
    return false;
}

/*
 * LVZ: Check if GCFG.TOP (Trap On Privilege) is set.
 * When TOP=1, ALL privileged instructions in guest mode trap via GSPR,
 * giving the hypervisor full control over guest CSR state. When TOP=0,
 * the shadow optimization allows direct guest CSR access for performance.
 * Returns true if TOP is set (full trap-and-emulate mode).
 */
static bool lvz_gcfg_top_is_set(DisasContext *ctx)
{
    if (!ctx->pvm) {
        return false;
    }
    /* GCFG.TOP is bit 13. Read from env->CSR_GCFG.
     * We can't use ctx->cpucfg_gcfg because GCFG is runtime-changeable,
     * so we use a helper to read it at translation time. */
    return (ctx->cpucfg_gcfg >> 13) & 1;
}

/*
 * LVZ inline guest CSR optimization:
 * When in PVM mode, most CSR accesses can go directly to the guest CSR
 * shadow in CPULoongArchState.guest.* without generating a GSPR trap.
 * This dramatically improves performance (similar to RISC-V H-extension
 * handling VS-mode CSRs inline).
 *
 * CSRs that MUST still trap via GSPR (need hypervisor intervention):
 * - TCFG write: hypervisor manages guest timer deadline
 * - TICLR write: clears timer interrupt in ESTAT
 * - ESTAT write: hypervisor manages interrupt state
 * - ASID write: may need TLB flush coordination
 *
 * Returns the offset into CPULoongArchState for the guest shadow CSR,
 * or -1 if the CSR should trap via GSPR.
 */
static int get_guest_csr_offset(unsigned int csr_num)
{
#define GUEST_CSR_OFF(NAME) \
    offsetof(CPULoongArchState, guest.CSR_##NAME)
#define GUEST_CSR_OFF_ARRAY(NAME, N) \
    offsetof(CPULoongArchState, guest.CSR_##NAME[N])

    switch (csr_num) {
    case LOONGARCH_CSR_CRMD:     return GUEST_CSR_OFF(CRMD);
    case LOONGARCH_CSR_PRMD:     return GUEST_CSR_OFF(PRMD);
    case LOONGARCH_CSR_EUEN:     return GUEST_CSR_OFF(EUEN);
    case LOONGARCH_CSR_ECFG:     return GUEST_CSR_OFF(ECFG);
    case LOONGARCH_CSR_ESTAT:    return GUEST_CSR_OFF(ESTAT);
    case LOONGARCH_CSR_ERA:      return GUEST_CSR_OFF(ERA);
    case LOONGARCH_CSR_BADV:     return GUEST_CSR_OFF(BADV);
    case LOONGARCH_CSR_BADI:     return GUEST_CSR_OFF(BADI);
    case LOONGARCH_CSR_EENTRY:   return GUEST_CSR_OFF(EENTRY);
    case LOONGARCH_CSR_TLBIDX:   return GUEST_CSR_OFF(TLBIDX);
    case LOONGARCH_CSR_TLBEHI:   return GUEST_CSR_OFF(TLBEHI);
    case LOONGARCH_CSR_TLBELO0:  return GUEST_CSR_OFF(TLBELO0);
    case LOONGARCH_CSR_TLBELO1:  return GUEST_CSR_OFF(TLBELO1);
    case LOONGARCH_CSR_ASID:     return GUEST_CSR_OFF(ASID);
    case LOONGARCH_CSR_PGDL:     return GUEST_CSR_OFF(PGDL);
    case LOONGARCH_CSR_PGDH:     return GUEST_CSR_OFF(PGDH);
    case LOONGARCH_CSR_PWCL:     return GUEST_CSR_OFF(PWCL);
    case LOONGARCH_CSR_PWCH:     return GUEST_CSR_OFF(PWCH);
    case LOONGARCH_CSR_STLBPS:   return GUEST_CSR_OFF(STLBPS);
    case LOONGARCH_CSR_RVACFG:   return GUEST_CSR_OFF(RVACFG);
    case LOONGARCH_CSR_CPUID:    return GUEST_CSR_OFF(CPUID);
    case LOONGARCH_CSR_PRCFG1:   return GUEST_CSR_OFF(PRCFG1);
    case LOONGARCH_CSR_PRCFG2:   return GUEST_CSR_OFF(PRCFG2);
    case LOONGARCH_CSR_PRCFG3:   return GUEST_CSR_OFF(PRCFG3);
    case LOONGARCH_CSR_SAVE(0):  return GUEST_CSR_OFF_ARRAY(SAVE, 0);
    case LOONGARCH_CSR_SAVE(1):  return GUEST_CSR_OFF_ARRAY(SAVE, 1);
    case LOONGARCH_CSR_SAVE(2):  return GUEST_CSR_OFF_ARRAY(SAVE, 2);
    case LOONGARCH_CSR_SAVE(3):  return GUEST_CSR_OFF_ARRAY(SAVE, 3);
    case LOONGARCH_CSR_SAVE(4):  return GUEST_CSR_OFF_ARRAY(SAVE, 4);
    case LOONGARCH_CSR_SAVE(5):  return GUEST_CSR_OFF_ARRAY(SAVE, 5);
    case LOONGARCH_CSR_SAVE(6):  return GUEST_CSR_OFF_ARRAY(SAVE, 6);
    case LOONGARCH_CSR_SAVE(7):  return GUEST_CSR_OFF_ARRAY(SAVE, 7);
    case LOONGARCH_CSR_SAVE(8):  return GUEST_CSR_OFF_ARRAY(SAVE, 8);
    case LOONGARCH_CSR_SAVE(9):  return GUEST_CSR_OFF_ARRAY(SAVE, 9);
    case LOONGARCH_CSR_SAVE(10): return GUEST_CSR_OFF_ARRAY(SAVE, 10);
    case LOONGARCH_CSR_SAVE(11): return GUEST_CSR_OFF_ARRAY(SAVE, 11);
    case LOONGARCH_CSR_SAVE(12): return GUEST_CSR_OFF_ARRAY(SAVE, 12);
    case LOONGARCH_CSR_SAVE(13): return GUEST_CSR_OFF_ARRAY(SAVE, 13);
    case LOONGARCH_CSR_SAVE(14): return GUEST_CSR_OFF_ARRAY(SAVE, 14);
    case LOONGARCH_CSR_SAVE(15): return GUEST_CSR_OFF_ARRAY(SAVE, 15);
    case LOONGARCH_CSR_TID:      return GUEST_CSR_OFF(TID);
    case LOONGARCH_CSR_TCFG:     return GUEST_CSR_OFF(TCFG);
    case LOONGARCH_CSR_TVAL:     return GUEST_CSR_OFF(TVAL);
    case LOONGARCH_CSR_CNTC:     return GUEST_CSR_OFF(CNTC);
    case LOONGARCH_CSR_LLBCTL:   return GUEST_CSR_OFF(LLBCTL);
    case LOONGARCH_CSR_TLBRENTRY: return GUEST_CSR_OFF(TLBRENTRY);
    case LOONGARCH_CSR_TLBRBADV: return GUEST_CSR_OFF(TLBRBADV);
    case LOONGARCH_CSR_TLBRERA:  return GUEST_CSR_OFF(TLBRERA);
    case LOONGARCH_CSR_TLBRSAVE: return GUEST_CSR_OFF(TLBRSAVE);
    case LOONGARCH_CSR_TLBRELO0: return GUEST_CSR_OFF(TLBRELO0);
    case LOONGARCH_CSR_TLBRELO1: return GUEST_CSR_OFF(TLBRELO1);
    case LOONGARCH_CSR_TLBREHI:  return GUEST_CSR_OFF(TLBREHI);
    case LOONGARCH_CSR_TLBRPRMD: return GUEST_CSR_OFF(TLBRPRMD);
    case LOONGARCH_CSR_DMW(0):   return GUEST_CSR_OFF_ARRAY(DMW, 0);
    case LOONGARCH_CSR_DMW(1):   return GUEST_CSR_OFF_ARRAY(DMW, 1);
    case LOONGARCH_CSR_DMW(2):   return GUEST_CSR_OFF_ARRAY(DMW, 2);
    case LOONGARCH_CSR_DMW(3):   return GUEST_CSR_OFF_ARRAY(DMW, 3);
    case LOONGARCH_CSR_MISC:     return GUEST_CSR_OFF(MISC);
    default:                     return -1;
    }
#undef GUEST_CSR_OFF
#undef GUEST_CSR_OFF_ARRAY
}

/*
 * CSRs that must still trap via GSPR on write in PVM mode.
 * These require hypervisor intervention for proper emulation.
 */
static bool guest_csr_write_needs_trap(unsigned int csr_num)
{
    switch (csr_num) {
    case LOONGARCH_CSR_TCFG:   /* Timer config - hypervisor manages deadline */
    case LOONGARCH_CSR_TICLR:  /* Timer interrupt clear */
    case LOONGARCH_CSR_ERA:    /* Exception Return Address - needed for ertn */
    case LOONGARCH_CSR_PRMD:   /* Previous Mode - needed for ertn */
    case LOONGARCH_CSR_EENTRY: /* Exception Entry - needed for IRQ delivery */
    case LOONGARCH_CSR_ECFG:   /* Exception Config - needed for IRQ delivery */
    case LOONGARCH_CSR_ESTAT:  /* Exception Status - needed for IRQ delivery */
    case LOONGARCH_CSR_CRMD:   /* Current Mode - needed for IRQ delivery */
        return true;
    default:
        return false;
    }
}

/*
 * CSRs that must trap via GSPR on read in PVM mode.
 * These require hypervisor intervention because the hypervisor
 * modifies the guest's view of these CSRs (e.g. ESTAT for IRQ).
 */
static bool guest_csr_read_needs_trap(unsigned int csr_num)
{
    switch (csr_num) {
    case LOONGARCH_CSR_ESTAT:  /* Exception Status - hypervisor sets IS bits */
    case LOONGARCH_CSR_ERA:    /* Exception Return Address - set by ertn */
    case LOONGARCH_CSR_CRMD:   /* Current Mode - set by ertn */
    case LOONGARCH_CSR_ECFG:   /* Exception Config - guest checks vs ESTAT */
        return true;
    default:
        return false;
    }
}

static bool set_csr_trans_func(unsigned int csr_num, GenCSRRead readfn,
                               GenCSRWrite writefn)
{
    CSRInfo *csr;

    csr = get_csr(csr_num);
    if (!csr) {
        return false;
    }

    csr->readfn = (GenCSRFunc)readfn;
    csr->writefn = (GenCSRFunc)writefn;
    return true;
}

#define SET_CSR_FUNC(NAME, read, write)                 \
        set_csr_trans_func(LOONGARCH_CSR_##NAME, read, write)

void loongarch_csr_translate_init(void)
{
    SET_CSR_FUNC(STLBPS, NULL, gen_helper_csrwr_stlbps);
    SET_CSR_FUNC(ESTAT, NULL, gen_helper_csrwr_estat);
    SET_CSR_FUNC(ASID,  NULL, gen_helper_csrwr_asid);
    SET_CSR_FUNC(PGD,   gen_helper_csrrd_pgd, NULL);
    SET_CSR_FUNC(PWCL,  NULL, gen_helper_csrwr_pwcl);
    SET_CSR_FUNC(PWCH,  NULL, gen_helper_csrwr_pwch);
    SET_CSR_FUNC(CPUID, gen_helper_csrrd_cpuid, NULL);
    SET_CSR_FUNC(TCFG,  NULL, gen_helper_csrwr_tcfg);
    SET_CSR_FUNC(TVAL,  gen_helper_csrrd_tval, NULL);
    SET_CSR_FUNC(TICLR, NULL, gen_helper_csrwr_ticlr);
    SET_CSR_FUNC(MSGIR, gen_helper_csrrd_msgir, NULL);
    SET_CSR_FUNC(GSTAT, NULL, gen_helper_csrwr_gstat);
}
#undef SET_CSR_FUNC

static bool check_csr_flags(DisasContext *ctx, const CSRInfo *csr, bool write)
{
    if ((csr->flags & CSRFL_READONLY) && write) {
        return false;
    }
    if ((csr->flags & CSRFL_IO) && translator_io_start(&ctx->base)) {
        ctx->base.is_jmp = DISAS_EXIT_UPDATE;
    } else if ((csr->flags & CSRFL_EXITTB) && write) {
        ctx->base.is_jmp = DISAS_EXIT_UPDATE;
    }
    return true;
}

static bool trans_csrrd(DisasContext *ctx, arg_csrrd *a)
{
    TCGv dest;
    const CSRInfo *csr;
    GenCSRRead readfn;

    if (ctx->plv == MMU_PLV_USER) {
        generate_exception(ctx, EXCCODE_IPE);
        return false;
    }

    /*
     * LVZ inline optimization: in PVM mode, read from guest CSR shadow
     * directly without generating a GSPR trap, unless the CSR needs
     * hypervisor intervention.
     */
    if (ctx->pvm) {
        /* GCFG.TOP=1: trap ALL CSR accesses to hypervisor */
        if (lvz_gcfg_top_is_set(ctx)) {
            generate_exception(ctx, EXCCODE_GSPR);
            return true;
        }
        /* Shadow optimization: direct access to guest CSR shadow */
        if (guest_csr_read_needs_trap(a->csr)) {
            generate_exception(ctx, EXCCODE_GSPR);
            return true;
        }
        int guest_off = get_guest_csr_offset(a->csr);
        if (guest_off >= 0) {
            dest = gpr_dst(ctx, a->rd, EXT_NONE);
            tcg_gen_ld_tl(dest, tcg_env, guest_off);
            gen_set_gpr(a->rd, dest, EXT_NONE);
            return true;
        }
        /* CSR not in guest shadow - trap to hypervisor */
        generate_exception(ctx, EXCCODE_GSPR);
        return true;
    }

    csr = get_csr(a->csr);
    if (csr == NULL) {
        /* CSR is undefined: read as 0. */
        dest = tcg_constant_tl(0);
    } else {
        check_csr_flags(ctx, csr, false);
        dest = gpr_dst(ctx, a->rd, EXT_NONE);
        readfn = (GenCSRRead)csr->readfn;
        if (readfn) {
            readfn(dest, tcg_env);
        } else {
            tcg_gen_ld_tl(dest, tcg_env, csr->offset);
        }
    }
    gen_set_gpr(a->rd, dest, EXT_NONE);
    return true;
}

static bool trans_csrwr(DisasContext *ctx, arg_csrwr *a)
{
    TCGv dest, src1;
    const CSRInfo *csr;
    GenCSRWrite writefn;

    if (ctx->plv == MMU_PLV_USER) {
        generate_exception(ctx, EXCCODE_IPE);
        return false;
    }

    /*
     * LVZ inline optimization: in PVM mode, write to guest CSR shadow
     * directly without generating a GSPR trap for most CSRs.
     */
    if (ctx->pvm) {
        /* GCFG.TOP=1: trap ALL CSR accesses to hypervisor */
        if (lvz_gcfg_top_is_set(ctx)) {
            generate_exception(ctx, EXCCODE_GSPR);
            return true;
        }
        /* Shadow optimization: direct access to guest CSR shadow */
        if (guest_csr_write_needs_trap(a->csr)) {
            generate_exception(ctx, EXCCODE_GSPR);
            return true;
        }
        int guest_off = get_guest_csr_offset(a->csr);
        if (guest_off >= 0) {
            TCGv newval = tcg_temp_new();
            TCGv oldval = tcg_temp_new();
            tcg_gen_mov_tl(newval, gpr_src(ctx, a->rd, EXT_NONE));
            tcg_gen_ld_tl(oldval, tcg_env, guest_off);
            tcg_gen_st_tl(newval, tcg_env, guest_off);
            gen_set_gpr(a->rd, oldval, EXT_NONE);
            return true;
        }
        /* CSR not in guest shadow - trap to hypervisor */
        generate_exception(ctx, EXCCODE_GSPR);
        return true;
    }

    csr = get_csr(a->csr);
    if (csr == NULL) {
        /* CSR is undefined: write ignored, read old_value as 0. */
        gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
        return true;
    }
    if (!check_csr_flags(ctx, csr, true)) {
        /* CSR is readonly: trap. */
        return false;
    }
    src1 = gpr_src(ctx, a->rd, EXT_NONE);
    writefn = (GenCSRWrite)csr->writefn;
    if (writefn) {
        dest = gpr_dst(ctx, a->rd, EXT_NONE);
        writefn(dest, tcg_env, src1);
    } else {
        dest = tcg_temp_new();
        tcg_gen_ld_tl(dest, tcg_env, csr->offset);
        tcg_gen_st_tl(src1, tcg_env, csr->offset);
    }
    gen_set_gpr(a->rd, dest, EXT_NONE);
    return true;
}

static bool trans_csrxchg(DisasContext *ctx, arg_csrxchg *a)
{
    TCGv src1, mask, oldv, newv, temp;
    const CSRInfo *csr;
    GenCSRWrite writefn;

    if (ctx->plv == MMU_PLV_USER) {
        generate_exception(ctx, EXCCODE_IPE);
        return false;
    }

    /*
     * LVZ inline optimization: in PVM mode, do masked exchange on
     * guest CSR shadow directly, unless the CSR needs hypervisor
     * intervention.
     */
    if (ctx->pvm) {
        /* GCFG.TOP=1: trap ALL CSR accesses to hypervisor */
        if (lvz_gcfg_top_is_set(ctx)) {
            generate_exception(ctx, EXCCODE_GSPR);
            return true;
        }
        /* Shadow optimization: direct access to guest CSR shadow */
        if (guest_csr_write_needs_trap(a->csr)) {
            generate_exception(ctx, EXCCODE_GSPR);
            return true;
        }
        int guest_off = get_guest_csr_offset(a->csr);
        if (guest_off >= 0) {
            src1 = gpr_src(ctx, a->rd, EXT_NONE);
            mask = gpr_src(ctx, a->rj, EXT_NONE);
            oldv = tcg_temp_new();
            newv = tcg_temp_new();
            temp = tcg_temp_new();

            tcg_gen_ld_tl(oldv, tcg_env, guest_off);
            tcg_gen_and_tl(newv, src1, mask);
            tcg_gen_andc_tl(temp, oldv, mask);
            tcg_gen_or_tl(newv, newv, temp);
            tcg_gen_st_tl(newv, tcg_env, guest_off);
            gen_set_gpr(a->rd, oldv, EXT_NONE);
            return true;
        }
        generate_exception(ctx, EXCCODE_GSPR);
        return true;
    }

    csr = get_csr(a->csr);
    if (csr == NULL) {
        /* CSR is undefined: write ignored, read old_value as 0. */
        gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
        return true;
    }

    if (!check_csr_flags(ctx, csr, true)) {
        /* CSR is readonly: trap. */
        return false;
    }

    /* So far only readonly csrs have readfn. */
    assert(csr->readfn == NULL);

    src1 = gpr_src(ctx, a->rd, EXT_NONE);
    mask = gpr_src(ctx, a->rj, EXT_NONE);
    oldv = tcg_temp_new();
    newv = tcg_temp_new();
    temp = tcg_temp_new();

    tcg_gen_ld_tl(oldv, tcg_env, csr->offset);
    tcg_gen_and_tl(newv, src1, mask);
    tcg_gen_andc_tl(temp, oldv, mask);
    tcg_gen_or_tl(newv, newv, temp);

    writefn = (GenCSRWrite)csr->writefn;
    if (writefn) {
        writefn(oldv, tcg_env, newv);
    } else {
        tcg_gen_st_tl(newv, tcg_env, csr->offset);
    }
    gen_set_gpr(a->rd, oldv, EXT_NONE);
    return true;
}

/*
 * LVZ Guest CSR instructions (GCSRRD/GCSRWR/GCSRXCHG)
 * These allow the host hypervisor to read/write guest CSR state directly.
 * Only accessible at PLV0 in host mode (PVM=0).
 */
static bool trans_gcsrrd(DisasContext *ctx, arg_gcsrrd *a)
{
    TCGv dest;

    if (check_plv(ctx)) {
        return false;
    }
    /* GCSRRD is only valid in host mode (not in PVM) */
    if (ctx->pvm) {
        generate_exception(ctx, EXCCODE_IPE);
        return false;
    }

    int guest_off = get_guest_csr_offset(a->csr);
    if (guest_off >= 0) {
        dest = gpr_dst(ctx, a->rd, EXT_NONE);
        tcg_gen_ld_tl(dest, tcg_env, guest_off);
        gen_set_gpr(a->rd, dest, EXT_NONE);
        return true;
    }
    /* Unknown guest CSR: read as 0 */
    gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
    return true;
}

static bool trans_gcsrwr(DisasContext *ctx, arg_gcsrwr *a)
{
    TCGv dest, src1;

    if (check_plv(ctx)) {
        return false;
    }
    if (ctx->pvm) {
        generate_exception(ctx, EXCCODE_IPE);
        return false;
    }

    int guest_off = get_guest_csr_offset(a->csr);
    if (guest_off >= 0) {
        src1 = gpr_src(ctx, a->rd, EXT_NONE);
        dest = gpr_dst(ctx, a->rd, EXT_NONE);
        /* Return old value, store new value */
        tcg_gen_ld_tl(dest, tcg_env, guest_off);
        tcg_gen_st_tl(src1, tcg_env, guest_off);
        gen_set_gpr(a->rd, dest, EXT_NONE);
        return true;
    }
    /* Unknown guest CSR: write ignored, return 0 */
    gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
    return true;
}

static bool trans_gcsrxchg(DisasContext *ctx, arg_gcsrxchg *a)
{
    TCGv src1, mask, oldv, newv, temp;

    if (check_plv(ctx)) {
        return false;
    }
    if (ctx->pvm) {
        generate_exception(ctx, EXCCODE_IPE);
        return false;
    }

    int guest_off = get_guest_csr_offset(a->csr);
    if (guest_off >= 0) {
        src1 = gpr_src(ctx, a->rd, EXT_NONE);
        mask = gpr_src(ctx, a->rj, EXT_NONE);
        oldv = tcg_temp_new();
        newv = tcg_temp_new();
        temp = tcg_temp_new();

        tcg_gen_ld_tl(oldv, tcg_env, guest_off);
        tcg_gen_and_tl(newv, src1, mask);
        tcg_gen_andc_tl(temp, oldv, mask);
        tcg_gen_or_tl(newv, newv, temp);
        tcg_gen_st_tl(newv, tcg_env, guest_off);
        gen_set_gpr(a->rd, oldv, EXT_NONE);
        return true;
    }
    /* Unknown guest CSR: write ignored, return 0 */
    gen_set_gpr(a->rd, tcg_constant_tl(0), EXT_NONE);
    return true;
}

static bool gen_iocsrrd(DisasContext *ctx, arg_rr *a,
                        void (*func)(TCGv, TCGv_ptr, TCGv))
{
    TCGv dest = gpr_dst(ctx, a->rd, EXT_NONE);
    TCGv src1 = gpr_src(ctx, a->rj, EXT_NONE);

    if (check_plv_gspr(ctx)) {
        return false;
    }
    func(dest, tcg_env, src1);
    return true;
}

static bool gen_iocsrwr(DisasContext *ctx, arg_rr *a,
                        void (*func)(TCGv_ptr, TCGv, TCGv))
{
    TCGv val = gpr_src(ctx, a->rd, EXT_NONE);
    TCGv addr = gpr_src(ctx, a->rj, EXT_NONE);

    if (check_plv_gspr(ctx)) {
        return false;
    }
    func(tcg_env, addr, val);
    return true;
}

TRANS(iocsrrd_b, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_b)
TRANS(iocsrrd_h, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_h)
TRANS(iocsrrd_w, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_w)
TRANS64(iocsrrd_d, IOCSR, gen_iocsrrd, gen_helper_iocsrrd_d)
TRANS(iocsrwr_b, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_b)
TRANS(iocsrwr_h, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_h)
TRANS(iocsrwr_w, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_w)
TRANS64(iocsrwr_d, IOCSR, gen_iocsrwr, gen_helper_iocsrwr_d)

static void check_mmu_idx(DisasContext *ctx)
{
    if (ctx->mem_idx != MMU_DA_IDX) {
        tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next + 4);
        ctx->base.is_jmp = DISAS_EXIT;
    }
}

static bool trans_tlbsrch(DisasContext *ctx, arg_tlbsrch *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_tlbsrch(tcg_env);
    return true;
}

static bool trans_tlbrd(DisasContext *ctx, arg_tlbrd *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_tlbrd(tcg_env);
    return true;
}

static bool trans_tlbwr(DisasContext *ctx, arg_tlbwr *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_tlbwr(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_tlbfill(DisasContext *ctx, arg_tlbfill *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_tlbfill(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_tlbclr(DisasContext *ctx, arg_tlbclr *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_tlbclr(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_tlbflush(DisasContext *ctx, arg_tlbflush *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_tlbflush(tcg_env);
    check_mmu_idx(ctx);
    return true;
}

static bool trans_invtlb(DisasContext *ctx, arg_invtlb *a)
{
    TCGv rj = gpr_src(ctx, a->rj, EXT_NONE);
    TCGv rk = gpr_src(ctx, a->rk, EXT_NONE);

    if (check_plv_gspr(ctx)) {
        return false;
    }

    switch (a->imm) {
    case 0:
    case 1:
        gen_helper_invtlb_all(tcg_env);
        break;
    case 2:
        gen_helper_invtlb_all_g(tcg_env, tcg_constant_i32(1));
        break;
    case 3:
        gen_helper_invtlb_all_g(tcg_env, tcg_constant_i32(0));
        break;
    case 4:
        gen_helper_invtlb_all_asid(tcg_env, rj);
        break;
    case 5:
        gen_helper_invtlb_page_asid(tcg_env, rj, rk);
        break;
    case 6:
        gen_helper_invtlb_page_asid_or_g(tcg_env, rj, rk);
        break;
    default:
        return false;
    }
    ctx->base.is_jmp = DISAS_STOP;
    return true;
}

static bool trans_cacop(DisasContext *ctx, arg_cacop *a)
{
    /* Treat the cacop as a nop */
    if (check_plv_gspr(ctx)) {
        return false;
    }
    return true;
}

static bool trans_ldpte(DisasContext *ctx, arg_ldpte *a)
{
    TCGv_i32 mem_idx = tcg_constant_i32(ctx->mem_idx);
    TCGv src1 = gpr_src(ctx, a->rj, EXT_NONE);

    if (!avail_LSPW(ctx)) {
        return true;
    }

    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_ldpte(tcg_env, src1, tcg_constant_tl(a->imm), mem_idx);
    return true;
}

static bool trans_lddir(DisasContext *ctx, arg_lddir *a)
{
    TCGv_i32 mem_idx = tcg_constant_i32(ctx->mem_idx);
    TCGv src = gpr_src(ctx, a->rj, EXT_NONE);
    TCGv dest = gpr_dst(ctx, a->rd, EXT_NONE);

    if (!avail_LSPW(ctx)) {
        return true;
    }

    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_lddir(dest, tcg_env, src, tcg_constant_i32(a->imm), mem_idx);
    return true;
}

static bool trans_ertn(DisasContext *ctx, arg_ertn *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }
    gen_helper_ertn(tcg_env);
    ctx->base.is_jmp = DISAS_EXIT;
    return true;
}

static bool trans_dbcl(DisasContext *ctx, arg_dbcl *a)
{
    if (check_plv(ctx)) {
        return false;
    }
    generate_exception(ctx, EXCCODE_DBP);
    return true;
}

static bool trans_idle(DisasContext *ctx, arg_idle *a)
{
    if (check_plv_gspr(ctx)) {
        return false;
    }

    tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next + 4);
    gen_helper_idle(tcg_env);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}
#endif
