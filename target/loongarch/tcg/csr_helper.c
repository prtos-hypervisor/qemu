/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch emulation helpers for CSRs
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internals.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "exec/cputlb.h"
#include "accel/tcg/cpu-ldst.h"
#include "hw/core/irq.h"
#include "cpu-csr.h"
#include "cpu-mmu.h"

target_ulong helper_csrwr_stlbps(CPULoongArchState *env, target_ulong val)
{
    int64_t old_v = env->CSR_STLBPS;

    /*
     * The real hardware only supports the min tlb_ps is 12
     * tlb_ps=0 may cause undefined-behavior.
     */
    uint8_t tlb_ps = FIELD_EX64(val, CSR_STLBPS, PS);
    if (!check_ps(env, tlb_ps)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "Attempted set ps %d\n", tlb_ps);
    } else {
        /* Only update PS field, reserved bit keeps zero */
        val = FIELD_DP64(val, CSR_STLBPS, RESERVE, 0);
        env->CSR_STLBPS = val;
    }

    return old_v;
}

target_ulong helper_csrrd_pgd(CPULoongArchState *env)
{
    int64_t v;

    if (env->CSR_TLBRERA & 0x1) {
        v = env->CSR_TLBRBADV;
    } else {
        v = env->CSR_BADV;
    }

    if ((v >> 63) & 0x1) {
        v = env->CSR_PGDH;
    } else {
        v = env->CSR_PGDL;
    }

    return v;
}

target_ulong helper_csrrd_cpuid(CPULoongArchState *env)
{
    LoongArchCPU *lac = env_archcpu(env);

    env->CSR_CPUID = CPU(lac)->cpu_index;

    return env->CSR_CPUID;
}

target_ulong helper_csrrd_tval(CPULoongArchState *env)
{
    LoongArchCPU *cpu = env_archcpu(env);

    return cpu_loongarch_get_constant_timer_ticks(cpu);
}

target_ulong helper_csrrd_msgir(CPULoongArchState *env)
{
    int irq, new;

    irq = find_first_bit((unsigned long *)env->CSR_MSGIS, 256);
    if (irq < 256) {
        clear_bit(irq, (unsigned long *)env->CSR_MSGIS);
        new = find_first_bit((unsigned long *)env->CSR_MSGIS, 256);
        if (new < 256) {
            return irq;
        }

        env->CSR_ESTAT = FIELD_DP64(env->CSR_ESTAT, CSR_ESTAT, MSGINT, 0);
    } else {
        /* bit 31 set 1 for no invalid irq */
        irq = BIT(31);
    }

    return irq;
}

target_ulong helper_csrwr_estat(CPULoongArchState *env, target_ulong val)
{
    int64_t old_v = env->CSR_ESTAT;

    /* Only IS[1:0] can be written */
    env->CSR_ESTAT = deposit64(env->CSR_ESTAT, 0, 2, val);

    return old_v;
}

target_ulong helper_csrwr_asid(CPULoongArchState *env, target_ulong val)
{
    int64_t old_v = env->CSR_ASID;

    /* Only ASID filed of CSR_ASID can be written */
    env->CSR_ASID = deposit64(env->CSR_ASID, 0, 10, val);
    if (old_v != env->CSR_ASID) {
        tlb_flush(env_cpu(env));
    }
    return old_v;
}

target_ulong helper_csrwr_tcfg(CPULoongArchState *env, target_ulong val)
{
    LoongArchCPU *cpu = env_archcpu(env);
    int64_t old_v = env->CSR_TCFG;

    cpu_loongarch_store_constant_timer_config(cpu, val);

    /* Store absolute deadline in TICKS for helper_check_timer_irq.
     * TCFG[63:2] is the interval count value. Counter = ns/10. */
    if (val & 0x1UL) {
        int64_t now_ticks = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT) / 10;
        int64_t interval_ticks = (val & 0xfffffffffffcUL);
        if (interval_ticks > 0) {
            env->guest_timer_offset = now_ticks + interval_ticks;
        }
    }

    return old_v;
}

target_ulong helper_csrwr_ticlr(CPULoongArchState *env, target_ulong val)
{
    LoongArchCPU *cpu = env_archcpu(env);
    int64_t old_v = 0;

    if (val & 0x1) {
        bql_lock();
        loongarch_cpu_set_irq(cpu, IRQ_TIMER, 0);
        bql_unlock();
    }
    return old_v;
}

target_ulong helper_csrwr_pwcl(CPULoongArchState *env, target_ulong val)
{
    uint8_t shift, ptbase;
    int64_t old_v = env->CSR_PWCL;

    /*
     * The real hardware only supports 64bit PTE width now, 128bit or others
     * treated as illegal.
     */
    shift = FIELD_EX64(val, CSR_PWCL, PTEWIDTH);
    ptbase = FIELD_EX64(val, CSR_PWCL, PTBASE);
    if (shift) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "Attempted set pte width with %d bit\n", 64 << shift);
        val = FIELD_DP64(val, CSR_PWCL, PTEWIDTH, 0);
    }
    if (!check_ps(env, ptbase)) {
         qemu_log_mask(LOG_GUEST_ERROR,
                      "Attempted set ptbase 2^%d\n", ptbase);
    }
    env->CSR_PWCL = val;
    return old_v;
}

target_ulong helper_csrwr_pwch(CPULoongArchState *env, target_ulong val)
{
    uint8_t has_ptw;
    int64_t old_v = env->CSR_PWCH;

    val = FIELD_DP64(val, CSR_PWCH, RESERVE, 0);
    has_ptw = FIELD_EX32(env->cpucfg[2], CPUCFG2, HPTW);
    if (!has_ptw) {
        val = FIELD_DP64(val, CSR_PWCH, HPTW_EN, 0);
    }

    env->CSR_PWCH = val;
    return old_v;
 }

target_ulong helper_csrwr_gstat(CPULoongArchState *env, target_ulong val)
{
    int64_t old_v = env->CSR_GSTAT;

    env->CSR_GSTAT = val;
    /*
     * Do NOT update in_guest_mode here. The PVM bit is set by the
     * hypervisor before ERTN, but we only want to enter guest mode
     * at the ERTN boundary (in helper_ertn). Otherwise, host code
     * between csrwr(GSTAT) and ertn would incorrectly generate GSPR.
     */

    return old_v;
}

target_ulong helper_csrwr_gintc(CPULoongArchState *env, target_ulong val)
{
    int64_t old_v = env->CSR_GINTC;
    uint64_t estat_is = 0;
    const uint64_t guest_irq_mask = ((1ULL << 13) - 1) & ~((1ULL << 5) - 1);

    env->CSR_GINTC = val;
    env->guest_gintc = val;

    /*
     * When the hypervisor sets VIP (Virtual Interrupt Pending) bits,
     * inject the corresponding interrupts into the guest's view of
     * ESTAT so they are delivered on the next guest interrupt window.
     *
     * GINTC.VIP bits are ORed into ESTAT.IS (Interrupt Status).
     * The hypervisor is responsible for clearing them after delivery.
     */
    uint64_t vip = FIELD_EX64(val, CSR_GINTC, VIP);

    /*
     * Keep the guest shadow ESTAT interrupt-status view aligned with the
     * current VIP bitmap. We must clear the bits we previously virtualized
     * when the hypervisor drops a VIP source, otherwise QEMU will continue
     * to think the guest has a pending interrupt after TICLR/IPI clear.
     */
    if (vip & (1 << 0)) { estat_is |= (1ULL << 12); } /* IPI */
    if (vip & (1 << 1)) { estat_is |= (1ULL << 11); } /* TI */
    if (vip & (1 << 2)) { estat_is |= (1ULL << 10); } /* HW0 */
    if (vip & (1 << 3)) { estat_is |= (1ULL << 9);  } /* HW1 */
    if (vip & (1 << 4)) { estat_is |= (1ULL << 8);  } /* HW2 */
    if (vip & (1 << 5)) { estat_is |= (1ULL << 7);  } /* HW3 */
    if (vip & (1 << 6)) { estat_is |= (1ULL << 6);  } /* HW4 */
    if (vip & (1 << 7)) { estat_is |= (1ULL << 5);  } /* HW5 */

    env->guest.CSR_ESTAT &= ~guest_irq_mask;
    env->guest.CSR_ESTAT |= estat_is;

    /*
     * Like RISC-V hvip: when VIP bits are set and guest interrupts are
     * enabled (guest CRMD.IE=1 && pending & enabled), immediately exit
     * the current TB so exec_interrupt delivers the guest interrupt on
     * the very next instruction. This eliminates the 50ms+ latency of
     * waiting for the next TB boundary.
     */

    return old_v;
}

target_ulong helper_gcsrwr_ticlr(CPULoongArchState *env, target_ulong val)
{
    uint64_t old_v = 0;

    if (val & 0x1) {
        uint64_t vip = FIELD_EX64(env->guest_gintc, CSR_GINTC, VIP);
        vip &= ~(1ULL << 1);
        helper_csrwr_gintc(env, FIELD_DP64(env->guest_gintc, CSR_GINTC, VIP, vip));

        /* Re-arm: update guest_timer_offset to next deadline.
         * The helper_check_timer_irq will use this for next delivery.
         * Also re-enable CSR_TCFG so the helper knows timer is active. */
        if (env->guest.CSR_TCFG & 0x1UL) {
            int64_t now_ticks = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT) / 10;
            int64_t interval = (env->guest.CSR_TCFG & 0xfffffffffffcUL);
            env->CSR_TCFG = env->guest.CSR_TCFG;
            env->guest_timer_offset = now_ticks + interval;
        }
    }

    return old_v;
}

target_ulong helper_gcsrwr_crmd(CPULoongArchState *env, target_ulong val)
{
    uint64_t old_v = env->guest.CSR_CRMD;
    uint8_t old_da = FIELD_EX64(old_v, CSR_CRMD, DA);

    env->guest.CSR_CRMD = val;

    if (old_da != FIELD_EX64(val, CSR_CRMD, DA)) {
        tlb_flush(env_cpu(env));
    }

    return old_v;
}
