/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch emulation helpers for QEMU.
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "cpu.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"
#include "internals.h"
#include "qemu/crc32c.h"
#include <zlib.h> /* for crc32 */
#include "cpu-csr.h"
#include "exec/cputlb.h"

#define CONSTANT_TIMER_ENABLE 0x1UL
#define TIMER_PERIOD 10

/* Exceptions helpers */
void helper_raise_exception(CPULoongArchState *env, uint32_t exception)
{
    do_raise_exception(env, exception, GETPC());
}

target_ulong helper_bitrev_w(target_ulong rj)
{
    return (int32_t)revbit32(rj);
}

target_ulong helper_bitrev_d(target_ulong rj)
{
    return revbit64(rj);
}

target_ulong helper_bitswap(target_ulong v)
{
    v = ((v >> 1) & (target_ulong)0x5555555555555555ULL) |
        ((v & (target_ulong)0x5555555555555555ULL) << 1);
    v = ((v >> 2) & (target_ulong)0x3333333333333333ULL) |
        ((v & (target_ulong)0x3333333333333333ULL) << 2);
    v = ((v >> 4) & (target_ulong)0x0F0F0F0F0F0F0F0FULL) |
        ((v & (target_ulong)0x0F0F0F0F0F0F0F0FULL) << 4);
    return v;
}

/* loongarch assert op */
void helper_asrtle_d(CPULoongArchState *env, target_ulong rj, target_ulong rk)
{
    if (rj > rk) {
        env->CSR_BADV = rj;
        do_raise_exception(env, EXCCODE_BCE, GETPC());
    }
}

void helper_asrtgt_d(CPULoongArchState *env, target_ulong rj, target_ulong rk)
{
    if (rj <= rk) {
        env->CSR_BADV = rj;
        do_raise_exception(env, EXCCODE_BCE, GETPC());
    }
}

target_ulong helper_crc32(target_ulong val, target_ulong m, uint64_t sz)
{
    uint8_t buf[8];
    target_ulong mask = ((sz * 8) == 64) ? -1ULL : ((1ULL << (sz * 8)) - 1);

    m &= mask;
    stq_le_p(buf, m);
    return (int32_t) (crc32(val ^ 0xffffffff, buf, sz) ^ 0xffffffff);
}

target_ulong helper_crc32c(target_ulong val, target_ulong m, uint64_t sz)
{
    uint8_t buf[8];
    target_ulong mask = ((sz * 8) == 64) ? -1ULL : ((1ULL << (sz * 8)) - 1);
    m &= mask;
    stq_le_p(buf, m);
    return (int32_t) (crc32c(val, buf, sz) ^ 0xffffffff);
}

target_ulong helper_cpucfg(CPULoongArchState *env, target_ulong rj)
{
    return rj >= ARRAY_SIZE(env->cpucfg) ? 0 : env->cpucfg[rj];
}

uint64_t helper_rdtime_d(CPULoongArchState *env)
{
#ifdef CONFIG_USER_ONLY
    return cpu_get_host_ticks();
#else
    uint64_t plv;
    LoongArchCPU *cpu = env_archcpu(env);

    plv = FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PLV);
    if (extract64(env->CSR_MISC, R_CSR_MISC_DRDTL_SHIFT + plv, 1)) {
        do_raise_exception(env, EXCCODE_IPE, GETPC());
    }

    return cpu_loongarch_get_constant_timer_counter(cpu);
#endif
}

#ifndef CONFIG_USER_ONLY
void helper_ertn(CPULoongArchState *env)
{
    uint64_t csr_pplv, csr_pie;

    /*
     * LVZ: When in guest (PVM) mode, use guest shadow CSRs for the
     * ERTN so the guest returns to its own saved PC/PLV rather than
     * the host's stale values.  Entering guest mode (host -> guest)
     * still uses the host CSRs because in_guest_mode is false until
     * loongarch_lvz_vm_entry() sets it below.
     */
    if (env->in_guest_mode) {
        uint8_t old_da = FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, DA);
        if (FIELD_EX64(env->guest.CSR_TLBRERA, CSR_TLBRERA, ISTLBR)) {
            csr_pplv = FIELD_EX64(env->guest.CSR_TLBRPRMD, CSR_TLBRPRMD, PPLV);
            csr_pie = FIELD_EX64(env->guest.CSR_TLBRPRMD, CSR_TLBRPRMD, PIE);
            /* Clear ISTLBR bit before using as return PC (bit 0 is flag) */
            env->guest.CSR_TLBRERA = FIELD_DP64(env->guest.CSR_TLBRERA,
                                                CSR_TLBRERA, ISTLBR, 0);
            set_pc(env, env->guest.CSR_TLBRERA);
            /* Transition from DA mode back to PG mode */
            env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                                             CSR_CRMD, DA, 0);
            env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD,
                                             CSR_CRMD, PG, 1);
        } else {
            csr_pplv = FIELD_EX64(env->guest.CSR_PRMD, CSR_PRMD, PPLV);
            csr_pie = FIELD_EX64(env->guest.CSR_PRMD, CSR_PRMD, PIE);
            set_pc(env, env->guest.CSR_ERA);
        }
        /* Use guest CRMD for PLV/IE update */
        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD, CSR_CRMD,
                                         PLV, csr_pplv);
        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD, CSR_CRMD,
                                         IE, csr_pie);
        /* Flush TLB on DA/PG mode transitions (DA→PG or PG→DA) */
        uint8_t new_da = FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, DA);
        if (old_da != new_da) {
            tlb_flush(env_cpu(env));
        }
        env->lladdr = 1;
        return;
    }

    if (FIELD_EX64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR)) {
        csr_pplv = FIELD_EX64(env->CSR_TLBRPRMD, CSR_TLBRPRMD, PPLV);
        csr_pie = FIELD_EX64(env->CSR_TLBRPRMD, CSR_TLBRPRMD, PIE);

        env->CSR_TLBRERA = FIELD_DP64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR, 0);
        env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, DA, 0);
        env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, PG, 1);
        set_pc(env, env->CSR_TLBRERA);
        qemu_log_mask(CPU_LOG_INT, "%s: TLBRERA " TARGET_FMT_lx "\n",
                      __func__, env->CSR_TLBRERA);
    } else {
        csr_pplv = FIELD_EX64(env->CSR_PRMD, CSR_PRMD, PPLV);
        csr_pie = FIELD_EX64(env->CSR_PRMD, CSR_PRMD, PIE);

        set_pc(env, env->CSR_ERA);
        qemu_log_mask(CPU_LOG_INT, "%s: ERA " TARGET_FMT_lx "\n",
                      __func__, env->CSR_ERA);
    }
    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, PLV, csr_pplv);
    env->CSR_CRMD = FIELD_DP64(env->CSR_CRMD, CSR_CRMD, IE, csr_pie);

    env->lladdr = 1;

    /*
     * LVZ: If GSTAT.PVM=1 and we're not currently in guest mode,
     * the host hypervisor is returning to guest. Enter guest mode.
     * The hypervisor manages guest CSR state in software, so we just
     * need to track the PVM mode flag.
     */
    if (!env->in_guest_mode && FIELD_EX64(env->CSR_GSTAT, CSR_GSTAT, PVM)) {
        loongarch_lvz_vm_entry(env);
    }
}

void helper_idle(CPULoongArchState *env)
{
    CPUState *cs = env_cpu(env);

    cs->halted = 1;
    do_raise_exception(env, EXCP_HLT, 0);
}

/* Synchronous interrupt/timer check for guest-mode vCPUs at TB start. */
void helper_check_timer_irq(CPULoongArchState *env)
{
    CPUState *cs = env_cpu(env);

    /* IPI: always deliver immediately (VM exit for PRTOS to handle) */
    if (qatomic_read(&cs->interrupt_request) & CPU_INTERRUPT_HARD) {
        uint64_t host_pending = FIELD_EX64(env->CSR_ESTAT, CSR_ESTAT, IS);
        uint64_t host_enabled = FIELD_EX64(env->CSR_ECFG, CSR_ECFG, LIE);
        if ((host_pending & host_enabled) & BIT(IRQ_IPI)) {
            cs->exception_index = EXCCODE_INT;
            cpu_loop_exit(cs);
        }
    }

    /* Guest timer: deliver directly to guest like RISC-V hvip.
     * Fire when timer armed AND (callback fired OR deadline passed).
     * Callback handles idle wakeup, deadline handles active CPUs
     * (callbacks don't fire between TBs in single-thread TCG). */
    {
        int fire = 0;
        if (!(env->CSR_GCFG & (1ULL << 9)) && env->guest_timer_deadline) {
            if (env->CSR_ESTAT & (1ULL << IRQ_TIMER)) {
                fire = 1;
            } else {
                int64_t now_t = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT) / 10;
                if (now_t >= (int64_t)env->guest_timer_deadline) fire = 1;
            }
        }
        if (fire &&
            FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, IE) &&
            !(env->guest.CSR_ESTAT & (1ULL << 11)) &&
            (env->guest.CSR_EENTRY >= 0x9000000000000000ULL) &&
            (FIELD_EX64(env->guest.CSR_ECFG, CSR_ECFG, LIE) &
             (1ULL << IRQ_TIMER))) {
        /* Save guest state (hardware exception entry emulation) */
        env->guest.CSR_PRMD = FIELD_DP64(env->guest.CSR_PRMD, CSR_PRMD, PPLV,
            FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, PLV));
        env->guest.CSR_PRMD = FIELD_DP64(env->guest.CSR_PRMD, CSR_PRMD, PIE,
            FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, IE));
        env->guest.CSR_ERA = env->pc;
        env->guest.CSR_ESTAT |= (1ULL << 11); /* Set TI */
        env->guest.CSR_ESTAT = FIELD_DP64(env->guest.CSR_ESTAT, CSR_ESTAT, ECODE, 0);
        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD, CSR_CRMD, IE, 0);
        env->guest.CSR_CRMD = FIELD_DP64(env->guest.CSR_CRMD, CSR_CRMD, PLV, 0);

        /* Compute vectored interrupt entry point */
        uint32_t gvs = FIELD_EX64(env->guest.CSR_ECFG, CSR_ECFG, VS);
        uint64_t vec_size = gvs ? ((1ULL << gvs) * 4) : 0;
        if (vec_size) {
            env->pc = env->guest.CSR_EENTRY + (64 + 11) * vec_size; /* TI = bit 11 */
        } else {
            env->pc = env->guest.CSR_EENTRY;
        }

        /* Clear host ESTAT.TI and STOP the host timer to prevent
         * re-delivery before the guest writes TICLR. The guest's inline
         * TICLR helper (helper_gcsrwr_ticlr) will re-arm the timer. */
        env->CSR_ESTAT = deposit64(env->CSR_ESTAT, IRQ_TIMER, 1, 0);
        if (!FIELD_EX64(env->CSR_ESTAT, CSR_ESTAT, IS)) {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
        }
        env->guest_timer_deadline = 0; /* TICLR in handler will re-arm */
        cpu_loop_exit(cs);
        }
    }

    /* Fallback: if conditions not met for direct delivery, trigger VM exit
     * so PRTOS can handle it (e.g., during early boot before EENTRY set). */
    if ((env->CSR_ESTAT & (1ULL << IRQ_TIMER)) &&
        (FIELD_EX64(env->CSR_ECFG, CSR_ECFG, LIE) & (1ULL << IRQ_TIMER))) {
        cs->exception_index = EXCCODE_INT;
        cpu_loop_exit(cs);
    }
}
#endif
