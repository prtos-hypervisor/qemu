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
#define CONSTANT_TIMER_TICK_MASK 0xfffffffffffcUL
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

/*
 * Synchronous interrupt/timer check for guest-mode vCPUs.
 * Called at TB start when in PVM (guest) mode.
 *
 * Handles two cases:
 * 1) interrupt_request already set by iothread → deliver immediately.
 * 2) Timer expired but iothread hasn't delivered yet (MTTCG race) →
 *    set interrupt directly. Don't re-arm; the iothread callback will
 *    handle that when it fires (the expired deadline triggers it
 *    on the next main loop iteration).
 */
void helper_check_timer_irq(CPULoongArchState *env)
{
    CPUState *cs = env_cpu(env);
    LoongArchCPU *cpu = LOONGARCH_CPU(cs);

    /* Fast path: interrupt already pending — only deliver if guest IE=1 */
    if (qatomic_read(&cs->interrupt_request) & CPU_INTERRUPT_HARD) {
        if (FIELD_EX64(env->guest.CSR_CRMD, CSR_CRMD, IE)) {
            cs->exception_index = EXCCODE_INT;
            cpu_loop_exit(cs);
        }
        /* IE=0: hold the interrupt pending until guest enables interrupts */
    }

    /* Check timer expiry directly — only for secondary vCPUs.
     * CPU0's timer delivery via the iothread works reliably; applying
     * this check to CPU0 interferes with its normal timer management. */
    if (cs->cpu_index != 0 && (env->CSR_TCFG & CONSTANT_TIMER_ENABLE)) {
        int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        int64_t expire = timer_expire_time_ns(&cpu->timer);
        if (expire != -1 && now >= expire) {
            env->CSR_ESTAT = deposit64(env->CSR_ESTAT, IRQ_TIMER, 1, 1);
            qatomic_or(&cs->interrupt_request, CPU_INTERRUPT_HARD);

            /* Re-arm periodic timer */
            if (FIELD_EX64(env->CSR_TCFG, CSR_TCFG, PERIODIC)) {
                int64_t next = now + (env->CSR_TCFG & CONSTANT_TIMER_TICK_MASK)
                               * TIMER_PERIOD;
                timer_mod(&cpu->timer, next);
            } else {
                env->CSR_TCFG = FIELD_DP64(env->CSR_TCFG, CSR_TCFG, EN, 0);
                timer_del(&cpu->timer);
            }

            cs->exception_index = EXCCODE_INT;
            cpu_loop_exit(cs);
        }
    }
}
#endif
