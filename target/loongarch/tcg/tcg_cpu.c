/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch CPU parameters for QEMU.
 *
 * Copyright (c) 2025 Loongson Technology Corporation Limited
 */
#include "qemu/osdep.h"
#include "qemu/accel.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/plugin.h"
#include "accel/accel-cpu-target.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-ops.h"
#include "exec/translation-block.h"
#include "exec/tb-flush.h"
#include "exec/target_page.h"
#include "tcg_loongarch.h"
#include "internals.h"

struct TypeExcp {
    int32_t exccode;
    const char * const name;
};

static const struct TypeExcp excp_names[] = {
    {EXCCODE_INT, "Interrupt"},
    {EXCCODE_PIL, "Page invalid exception for load"},
    {EXCCODE_PIS, "Page invalid exception for store"},
    {EXCCODE_PIF, "Page invalid exception for fetch"},
    {EXCCODE_PME, "Page modified exception"},
    {EXCCODE_PNR, "Page Not Readable exception"},
    {EXCCODE_PNX, "Page Not Executable exception"},
    {EXCCODE_PPI, "Page Privilege error"},
    {EXCCODE_ADEF, "Address error for instruction fetch"},
    {EXCCODE_ADEM, "Address error for Memory access"},
    {EXCCODE_SYS, "Syscall"},
    {EXCCODE_BRK, "Break"},
    {EXCCODE_INE, "Instruction Non-Existent"},
    {EXCCODE_IPE, "Instruction privilege error"},
    {EXCCODE_FPD, "Floating Point Disabled"},
    {EXCCODE_FPE, "Floating Point Exception"},
    {EXCCODE_GSPR, "Guest Sensitive Privileged Resource"},
    {EXCCODE_HVC, "HyperVisor Call"},
    {EXCCODE_GCM, "Guest CSR Modified"},
    {EXCCODE_DBP, "Debug breakpoint"},
    {EXCCODE_BCE, "Bound Check Exception"},
    {EXCCODE_SXD, "128 bit vector instructions Disable exception"},
    {EXCCODE_ASXD, "256 bit vector instructions Disable exception"},
    {EXCP_HLT, "EXCP_HLT"},
};

static const char *loongarch_exception_name(int32_t exception)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(excp_names); i++) {
        if (excp_names[i].exccode == exception) {
            return excp_names[i].name;
        }
    }
    return "Unknown";
}

void G_NORETURN do_raise_exception(CPULoongArchState *env,
                                   uint32_t exception,
                                   uintptr_t pc)
{
    CPUState *cs = env_cpu(env);

    qemu_log_mask(CPU_LOG_INT, "%s: exception: %d (%s)\n",
                  __func__,
                  exception,
                  loongarch_exception_name(exception));
    cs->exception_index = exception;

    cpu_loop_exit_restore(cs, pc);
}

#ifndef CONFIG_USER_ONLY

/*
 * LVZ: VM exit - transition from guest (PVM) mode to host mode.
 * Clear PVM and the cached in_guest_mode flag.
 * Save the guest CNTC (stable counter) view so it remains consistent
 * across VM exit/entry cycles.
 */
void loongarch_lvz_vm_exit(CPULoongArchState *env)
{
    CPUState *cs = env_cpu(env);
    env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, PVM, 0);
    env->in_guest_mode = false;
    cs->tcg_cflags &= ~CF_NO_GOTO_TB;
    /* Save guest CNTC view: guest_cntc = host_cntc - offset */
    env->guest.CSR_CNTC = env->CSR_CNTC - env->guest_timer_offset;
    /*
     * No tlb_flush() here: guest and host use separate MMU indices
     * (MMU_GUEST_PLV0 vs MMU_KERNEL_IDX), so QEMU softmmu maintains
     * independent TLB entries.  Only flush on guest invtlb/GID change.
     */
}

/*
 * LVZ: VM entry - transition from host mode to guest (PVM) mode.
 * Set PVM and the cached in_guest_mode flag.
 * Flush the primary TLB (MMU index switch) and root TLB (new guest).
 * Initialise the GCNT offset so the guest sees a consistent view of
 * the stable counter.
 */
void loongarch_lvz_vm_entry(CPULoongArchState *env)
{
    CPUState *cs = env_cpu(env);
    env->CSR_GSTAT = FIELD_DP64(env->CSR_GSTAT, CSR_GSTAT, PVM, 1);
    env->in_guest_mode = true;
    env->guest_tb_count = 0;
    /*
     * Disable TB chaining in guest mode to ensure timer interrupts
     * (delivered via cpu_interrupt from iothread) are promptly processed.
     * Without this, a self-looping TB may chain via goto_tb and the
     * icount_decr exit check at TB start races with the kick.
     */
    cs->tcg_cflags |= CF_NO_GOTO_TB;
    /*
     * Flush the TB jmp cache so that any TBs previously translated
     * without CF_NO_GOTO_TB are discarded. Otherwise, cached TBs with
     * goto_tb chains would be reused, bypassing the interrupt check.
     */
    tcg_flush_jmp_cache(cs);
    /*
     * Initialize guest CRMD to DA mode (Direct Addressing) on first entry.
     * The hypervisor manages guest CRMD in software and syncs via GCSRWR,
     * but the initial boot state requires DA=1 for the first instruction
     * fetch to succeed (before any GSPR trap can sync the value).
     */
    if (env->guest.CSR_CRMD == 0) {
        env->guest.CSR_CRMD = FIELD_DP64(0, CSR_CRMD, DA, 1);
    }
    /*
     * Flush softmmu TLB only when guest is entering DA mode.
     * Host always runs in PG mode; DA-mode entries (VA=PA) would conflict.
     * When guest re-enters PG mode (most common path), host and guest share
     * the same DMW config so cached translations remain valid.
     */
    if (FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, DA)) {
        extern void tlb_flush(CPUState *cpu);
        tlb_flush(env_cpu(env));
    }
    /*
     * GCNT offset: the guest's view of CNTC starts at the current host
     * counter value minus whatever the guest has already written to
     * CSR_CNTC (stored in its shadow).  This gives the guest a
     * continuous view across VM exits/entries.
     */
    uint64_t host_cntc = env->CSR_CNTC; /* Host view of stable counter */
    uint64_t guest_cntc = env->guest.CSR_CNTC;
    env->guest_timer_offset = host_cntc - guest_cntc;
}

static void loongarch_cpu_do_interrupt(CPUState *cs)
{
    CPULoongArchState *env = cpu_env(cs);
    bool update_badinstr = 1;
    int cause = -1;
    bool tlbfill = FIELD_EX64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR);
    uint32_t vec_size = FIELD_EX64(env->CSR_ECFG, CSR_ECFG, VS);
    uint64_t last_pc = env->pc;

    if (cs->exception_index != EXCCODE_INT) {
        qemu_log_mask(CPU_LOG_INT,
                     "%s enter: pc " TARGET_FMT_lx " ERA " TARGET_FMT_lx
                     " TLBRERA " TARGET_FMT_lx " exception: %d (%s)\n",
                     __func__, env->pc, env->CSR_ERA, env->CSR_TLBRERA,
                     cs->exception_index,
                     loongarch_exception_name(cs->exception_index));
    }

    switch (cs->exception_index) {
    case EXCCODE_DBP:
        env->CSR_DBG = FIELD_DP64(env->CSR_DBG, CSR_DBG, DCL, 1);
        env->CSR_DBG = FIELD_DP64(env->CSR_DBG, CSR_DBG, ECODE, 0xC);
        goto set_DERA;
    set_DERA:
        env->CSR_DERA = env->pc;
        env->CSR_DBG = FIELD_DP64(env->CSR_DBG, CSR_DBG, DST, 1);
        set_pc(env, env->CSR_EENTRY + 0x480);
        break;
    case EXCCODE_INT:
        if (FIELD_EX64(env->CSR_DBG, CSR_DBG, DST)) {
            env->CSR_DBG = FIELD_DP64(env->CSR_DBG, CSR_DBG, DEI, 1);
            goto set_DERA;
        }
        QEMU_FALLTHROUGH;
    case EXCCODE_PIF:
    case EXCCODE_PNX:
    case EXCCODE_ADEF:
        cause = cs->exception_index;
        update_badinstr = 0;
        break;
    case EXCCODE_BCE:
        env->CSR_BADV = env->pc;
        QEMU_FALLTHROUGH;
    case EXCCODE_SYS:
    case EXCCODE_BRK:
    case EXCCODE_INE:
    case EXCCODE_IPE:
    case EXCCODE_FPD:
    case EXCCODE_FPE:
    case EXCCODE_SXD:
    case EXCCODE_ASXD:
    case EXCCODE_ADEM:
    case EXCCODE_PIL:
    case EXCCODE_PIS:
    case EXCCODE_PME:
    case EXCCODE_PNR:
    case EXCCODE_PPI:
    case EXCCODE_GSPR:
    case EXCCODE_HVC:
    case EXCCODE_GCM:
        cause = cs->exception_index;
        break;
    default:
        qemu_log("Error: exception(%d) has not been supported\n",
                 cs->exception_index);
        abort();
    }

    if (update_badinstr) {
        MemOpIdx oi = make_memop_idx(MO_LEUL, cpu_mmu_index(cs, true));

        env->CSR_BADI = cpu_ldl_code_mmu(env, env->pc, oi, 0);
    }

    /*
     * LVZ: When in guest (PVM) mode and a GSPR/HVC/timer exception occurs,
     * we do NOT clear PVM here. The exception is delivered normally to the
     * host's EENTRY, and the host hypervisor's trap entry code detects
     * PVM=1, clears it, and handles the VM exit.
     *
     * However, we do need to clear the cached in_guest_mode flag so that
     * the host hypervisor's exception handler code (which uses CSR/TLB
     * instructions) does not itself generate GSPR. The actual PVM bit
     * in CSR_GSTAT remains set for the trap handler to detect.
     */
    if (env->in_guest_mode && cause >= 0) {
        /*
         * LVZ Exception Delegation: Check if the guest can handle this
         * exception itself based on GCFG configuration.
         *
         * GCFG.TOE (bit 8): Trap On Exception - when set, synchronous
         *   exceptions (syscall, breakpoint, page faults) cause VM exit.
         *   When clear, they are delivered directly to the guest.
         * GCFG.TIT (bit 9): Trap on Timer Interrupt - when set, timer
         *   interrupts cause VM exit.
         *
         * Exceptions that ALWAYS cause VM exit (cannot be delegated):
         *   GSPR, HVC, GCM - these are virtualization-specific.
         */
        bool delegate_to_guest = false;
        uint64_t gcfg = env->CSR_GCFG;

        switch (cs->exception_index) {
        case EXCCODE_SYS:
        case EXCCODE_BRK:
        case EXCCODE_INE:
        case EXCCODE_FPD:
        case EXCCODE_FPE:
        case EXCCODE_SXD:
        case EXCCODE_ASXD:
        case EXCCODE_PIL:
        case EXCCODE_PIS:
        case EXCCODE_PIF:
        case EXCCODE_PME:
        case EXCCODE_PNR:
        case EXCCODE_PNX:
        case EXCCODE_PPI:
        case EXCCODE_IPE:
        case EXCCODE_ALE:
            /* Delegate to guest if GCFG.TOE is clear */
            if (!(gcfg & (1ULL << 8))) {
                delegate_to_guest = true;
            }
            break;
        case EXCCODE_INT: {
            /* TIT (bit 9) controls whether timer interrupt traps to host.
             * For our emulation with GCFG.TIT=1:
             *   - Timer interrupts (IS bit 11): cause VM exit (not delegated)
             *   - Other interrupts (IPI, HWI): also cause VM exit.
             *     The host hypervisor (PRTOS) handles all interrupts and
             *     injects virtual interrupts to the guest as needed.
             *
             * The guest receives interrupts only through virtual injection
             * (host sets guest ESTAT bits and re-enters guest with IE=1).
             * Direct delegation would bypass the host's interrupt management.
             */
            /* All interrupts cause VM exit — delegate_to_guest stays false */
            break;
        }
        default:
            /* GSPR, HVC, GCM always cause VM exit */
            break;
        }

        if (delegate_to_guest) {
            if (tlbfill) {
                /* TLB Refill delegation: route to guest TLBRENTRY.
                 * TORU (bit 11) controls whether refills trap to host.
                 * If TORU=0, delegate refill to guest. */
                if (!(gcfg & (1ULL << 11))) {
                    uint64_t guest_tlbrentry = env->guest.CSR_TLBRENTRY;
                    if (guest_tlbrentry) {
                        /* Save state to TLB refill CSRs */
                        env->guest.CSR_TLBRPRMD = FIELD_DP64(
                            env->guest.CSR_TLBRPRMD, CSR_TLBRPRMD, PPLV,
                            FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, PLV));
                        env->guest.CSR_TLBRPRMD = FIELD_DP64(
                            env->guest.CSR_TLBRPRMD, CSR_TLBRPRMD, PIE,
                            FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, IE));
                        env->guest.CSR_TLBRERA = FIELD_DP64(
                            env->guest.CSR_TLBRERA, CSR_TLBRERA,
                            PC, (env->pc >> 2));
                        env->guest.CSR_TLBRERA = FIELD_DP64(
                            env->guest.CSR_TLBRERA, CSR_TLBRERA, ISTLBR, 1);
                        env->guest.CSR_TLBRBADV = env->CSR_TLBRBADV;
                        if (is_la64(env)) {
                            env->guest.CSR_TLBREHI = FIELD_DP64(
                                env->guest.CSR_TLBREHI, CSR_TLBREHI_64,
                                VPPN, extract64(env->CSR_TLBRBADV, 13, 35));
                        }
                        /* Set guest CRMD: DA=1, PG=0, PLV=0, IE=0 */
                        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                            CSR_CRMD, DA, 1);
                        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                            CSR_CRMD, PG, 0);
                        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                            CSR_CRMD, PLV, 0);
                        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                            CSR_CRMD, IE, 0);

                        env->pc = guest_tlbrentry;
                        /* Clear ISTLBR in host CSR since we handled it */
                        env->CSR_TLBRERA = FIELD_DP64(env->CSR_TLBRERA,
                            CSR_TLBRERA, ISTLBR, 0);
                        cs->exception_index = -1;
                        return;
                    }
                }
                /* TORU=1 or no guest_tlbrentry: fall through to VM exit */
            } else {
                /* Normal exception/interrupt delegation: route to guest EENTRY */
                uint64_t guest_eentry = env->guest.CSR_EENTRY;
                if (guest_eentry) {
                    /* Save current guest PC and PLV/IE to guest PRMD/ERA */
                    env->guest.CSR_PRMD = FIELD_DP64(env->guest.CSR_PRMD,
                        CSR_PRMD, PPLV,
                        FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, PLV));
                    env->guest.CSR_PRMD = FIELD_DP64(env->guest.CSR_PRMD,
                        CSR_PRMD, PIE,
                        FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, IE));
                    env->guest.CSR_ERA = env->pc;

                    /* Update guest CRMD: PLV=0, IE=0 */
                    env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                        CSR_CRMD, PLV, 0);
                    env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                        CSR_CRMD, IE, 0);

                    /* Compute target PC based on exception type */
                    uint32_t gvs = FIELD_EX64(env->guest.CSR_ECFG,
                                             CSR_ECFG, VS);
                    uint32_t gvec_size = gvs ? (1 << gvs) * 4 : 0;

                    if (cs->exception_index == EXCCODE_INT) {
                        /* Interrupt: use vectored interrupt entry.
                         * Vector = EXCCODE_EXTERNAL_INT + highest_irq_bit */
                        uint32_t gpending = FIELD_EX64(env->guest.CSR_ESTAT,
                                                      CSR_ESTAT, IS);
                        gpending &= FIELD_EX64(env->guest.CSR_ECFG,
                                              CSR_ECFG, LIE);
                        if (gpending) {
                            uint32_t vector = 31 - __builtin_clz(gpending);
                            env->pc = guest_eentry +
                                (EXCCODE_EXTERNAL_INT + vector) * gvec_size;
                        } else {
                            env->pc = guest_eentry;
                        }
                    } else {
                        /* Synchronous exception */
                        env->guest.CSR_ESTAT = FIELD_DP64(env->guest.CSR_ESTAT,
                            CSR_ESTAT, ECODE,
                            EXCODE_MCODE(cs->exception_index));
                        env->guest.CSR_BADV = env->CSR_BADV;

                        /* Set TLBEHI for page-related exceptions */
                        if (EXCODE_MCODE(cs->exception_index) >= 1 &&
                            EXCODE_MCODE(cs->exception_index) <= 6) {
                            env->guest.CSR_TLBEHI = env->CSR_BADV &
                                (TARGET_PAGE_MASK << 1);
                        }

                        env->pc = guest_eentry +
                            EXCODE_MCODE(cs->exception_index) * gvec_size;
                    }

                    /* Stay in guest mode */
                    cs->exception_index = -1;
                    return;
                }
            }
        }

        /* Not delegated: VM Exit to host hypervisor */
        env->in_guest_mode = false;
        cs->tcg_cflags &= ~CF_NO_GOTO_TB;
    }

    /* Save PLV and IE */
    if (tlbfill) {
        env->CSR_TLBRPRMD = FIELD_DP64(env->CSR_TLBRPRMD, CSR_TLBRPRMD, PPLV,
                                       FIELD_EX64(env->CSR_CRMD,
                                       CSR_CRMD, PLV));
        env->CSR_TLBRPRMD = FIELD_DP64(env->CSR_TLBRPRMD, CSR_TLBRPRMD, PIE,
                                       FIELD_EX64(env->CSR_CRMD, CSR_CRMD, IE));
        /* set the DA mode */
        env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, DA, 1);
        env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, PG, 0);
        env->CSR_TLBRERA = FIELD_DP64(env->CSR_TLBRERA, CSR_TLBRERA,
                                      PC, (env->pc >> 2));
    } else {
        env->CSR_ESTAT = FIELD_DP64(env->CSR_ESTAT, CSR_ESTAT, ECODE,
                                    EXCODE_MCODE(cause));
        env->CSR_ESTAT = FIELD_DP64(env->CSR_ESTAT, CSR_ESTAT, ESUBCODE,
                                    EXCODE_SUBCODE(cause));
        env->CSR_PRMD = FIELD_DP64(env->CSR_PRMD, CSR_PRMD, PPLV,
                                   FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PLV));
        env->CSR_PRMD = FIELD_DP64(env->CSR_PRMD, CSR_PRMD, PIE,
                                   FIELD_EX64(env->CSR_CRMD, CSR_CRMD, IE));
        env->CSR_ERA = env->pc;
    }

    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, PLV, 0);
    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, IE, 0);

    if (vec_size) {
        vec_size = (1 << vec_size) * 4;
    }

    if  (cs->exception_index == EXCCODE_INT) {
        /* Interrupt */
        uint32_t vector = 0;
        uint32_t pending = FIELD_EX64(env->CSR_ESTAT, CSR_ESTAT, IS);
        pending &= FIELD_EX64(env->CSR_ECFG, CSR_ECFG, LIE);

        /* Find the highest-priority interrupt. */
        vector = 31 - clz32(pending);
        set_pc(env, env->CSR_EENTRY + \
               (EXCCODE_EXTERNAL_INT + vector) * vec_size);
        qemu_log_mask(CPU_LOG_INT,
                      "%s: PC " TARGET_FMT_lx " ERA " TARGET_FMT_lx
                      " cause %d\n" "    A " TARGET_FMT_lx " D "
                      TARGET_FMT_lx " vector = %d ExC " TARGET_FMT_lx "ExS"
                      TARGET_FMT_lx "\n",
                      __func__, env->pc, env->CSR_ERA,
                      cause, env->CSR_BADV, env->CSR_DERA, vector,
                      env->CSR_ECFG, env->CSR_ESTAT);
        qemu_plugin_vcpu_interrupt_cb(cs, last_pc);
    } else {
        if (tlbfill) {
            set_pc(env, env->CSR_TLBRENTRY);
        } else {
            set_pc(env, env->CSR_EENTRY + EXCODE_MCODE(cause) * vec_size);
        }
        qemu_log_mask(CPU_LOG_INT,
                      "%s: PC " TARGET_FMT_lx " ERA " TARGET_FMT_lx
                      " cause %d%s\n, ESTAT " TARGET_FMT_lx
                      " EXCFG " TARGET_FMT_lx " BADVA " TARGET_FMT_lx
                      "BADI " TARGET_FMT_lx " SYS_NUM " TARGET_FMT_lu
                      " cpu %d asid " TARGET_FMT_lx "\n", __func__, env->pc,
                      tlbfill ? env->CSR_TLBRERA : env->CSR_ERA,
                      cause, tlbfill ? "(refill)" : "", env->CSR_ESTAT,
                      env->CSR_ECFG,
                      tlbfill ? env->CSR_TLBRBADV : env->CSR_BADV,
                      env->CSR_BADI, env->gpr[11], cs->cpu_index,
                      env->CSR_ASID);
        qemu_plugin_vcpu_exception_cb(cs, last_pc);
    }
    cs->exception_index = -1;
}

static void loongarch_cpu_do_transaction_failed(CPUState *cs, hwaddr physaddr,
                                                vaddr addr, unsigned size,
                                                MMUAccessType access_type,
                                                int mmu_idx, MemTxAttrs attrs,
                                                MemTxResult response,
                                                uintptr_t retaddr)
{
    CPULoongArchState *env = cpu_env(cs);

    env->CSR_BADV = addr;
    if (access_type == MMU_INST_FETCH) {
        do_raise_exception(env, EXCCODE_ADEF, retaddr);
    } else {
        do_raise_exception(env, EXCCODE_ADEM, retaddr);
    }
}

static inline bool cpu_loongarch_hw_interrupts_enabled(CPULoongArchState *env)
{
    uint64_t crmd;

    crmd = env->in_guest_mode ? env->guest.CSR_CRMD : env->CSR_CRMD;

    return FIELD_EX64(crmd, CSR_CRMD, IE) &&
           !FIELD_EX64(env->CSR_DBG, CSR_DBG, DST);
}

static bool loongarch_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        CPULoongArchState *env = cpu_env(cs);

        if (env->in_guest_mode) {
            /* IPI: always VM exit to PRTOS. Timer: handled by helper
             * at TB start (direct delivery or fallback VM exit). */
            uint32_t host_pending = FIELD_EX64(env->CSR_ESTAT, CSR_ESTAT, IS);
            uint32_t host_enabled = FIELD_EX64(env->CSR_ECFG, CSR_ECFG, LIE);
            if ((host_pending & host_enabled) & BIT(IRQ_IPI)) {
                cs->exception_index = EXCCODE_INT;
                loongarch_cpu_do_interrupt(cs);
                return true;
            }
            return false;
        }

        if (cpu_loongarch_hw_interrupts_enabled(env) &&
            cpu_loongarch_hw_interrupts_pending(env)) {
            /* Raise it */
            cs->exception_index = EXCCODE_INT;
            loongarch_cpu_do_interrupt(cs);
            return true;
        }
    }
    return false;
}

static vaddr loongarch_pointer_wrap(CPUState *cs, int mmu_idx,
                                    vaddr result, vaddr base)
{
    return is_va32(cpu_env(cs)) ? (uint32_t)result : result;
}
#endif

static TCGTBCPUState loongarch_get_tb_cpu_state(CPUState *cs)
{
    CPULoongArchState *env = cpu_env(cs);
    uint32_t flags;
    uint64_t crmd, euen;

    if (env->in_guest_mode) {
        crmd = env->guest.CSR_CRMD;
        euen = env->guest.CSR_EUEN;
    } else {
        crmd = env->CSR_CRMD;
        euen = env->CSR_EUEN;
    }

    flags = crmd & (R_CSR_CRMD_PLV_MASK | R_CSR_CRMD_PG_MASK);
    flags |= FIELD_EX64(euen, CSR_EUEN, FPE) * HW_FLAGS_EUEN_FPE;
    flags |= FIELD_EX64(euen, CSR_EUEN, SXE) * HW_FLAGS_EUEN_SXE;
    flags |= FIELD_EX64(euen, CSR_EUEN, ASXE) * HW_FLAGS_EUEN_ASXE;
    flags |= is_va32(env) * HW_FLAGS_VA32;
    flags |= env->in_guest_mode * HW_FLAGS_PVM;

    return (TCGTBCPUState){ .pc = env->pc, .flags = flags };
}

static void loongarch_cpu_synchronize_from_tb(CPUState *cs,
                                              const TranslationBlock *tb)
{
    tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));
    set_pc(cpu_env(cs), tb->pc);
}

static void loongarch_restore_state_to_opc(CPUState *cs,
                                           const TranslationBlock *tb,
                                           const uint64_t *data)
{
    set_pc(cpu_env(cs), data[0]);
}

static int loongarch_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    CPULoongArchState *env = cpu_env(cs);

    if (FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PG)) {
        return FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PLV);
    }
    return MMU_DA_IDX;
}

const TCGCPUOps loongarch_tcg_ops = {
    .guest_default_memory_order = 0,
    .mttcg_supported = true,

    .initialize = loongarch_translate_init,
    .translate_code = loongarch_translate_code,
    .get_tb_cpu_state = loongarch_get_tb_cpu_state,
    .synchronize_from_tb = loongarch_cpu_synchronize_from_tb,
    .restore_state_to_opc = loongarch_restore_state_to_opc,
    .mmu_index = loongarch_cpu_mmu_index,

#ifndef CONFIG_USER_ONLY
    .tlb_fill = loongarch_cpu_tlb_fill,
    .pointer_wrap = loongarch_pointer_wrap,
    .cpu_exec_interrupt = loongarch_cpu_exec_interrupt,
    .cpu_exec_halt = loongarch_cpu_has_work,
    .cpu_exec_reset = cpu_reset,
    .do_interrupt = loongarch_cpu_do_interrupt,
    .do_transaction_failed = loongarch_cpu_do_transaction_failed,
#endif
};
