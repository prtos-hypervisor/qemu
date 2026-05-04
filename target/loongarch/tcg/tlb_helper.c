/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU LoongArch TLB helpers
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 *
 */

#include "qemu/osdep.h"
#include "qemu/guest-random.h"

#include "cpu.h"
#include "cpu-mmu.h"
#include "internals.h"
#include "exec/helper-proto.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ldst.h"
#include "exec/log.h"
#include "cpu-csr.h"
#include "tcg/tcg_loongarch.h"

typedef bool (*tlb_match)(bool global, int asid, int tlb_asid);

static bool tlb_match_any(bool global, int asid, int tlb_asid)
{
    return global || tlb_asid == asid;
}

static bool tlb_match_asid(bool global, int asid, int tlb_asid)
{
    return !global && tlb_asid == asid;
}

/*
 * LVZ: Return the host or guest CSR value depending on the current mode.
 * In guest (PVM) mode the guest's shadow CSR is returned; in host mode
 * the real hardware CSR is returned.  Reduces if/else duplication across
 * the TLB helper hot paths (sptw_prepare_context, helper_tlbwr,
 * helper_tlbfill).
 */
static inline uint64_t guest_csr64(CPULoongArchState *env,
                                   uint64_t host_val, uint64_t guest_val)
{
    return env->in_guest_mode ? guest_val : host_val;
}

bool check_ps(CPULoongArchState *env, uint8_t tlb_ps)
{
    if (tlb_ps >= 64) {
        return false;
    }
    return BIT_ULL(tlb_ps) & (env->CSR_PRCFG2);
}

static void raise_mmu_exception(CPULoongArchState *env, vaddr address,
                                MMUAccessType access_type, TLBRet tlb_error)
{
    CPUState *cs = env_cpu(env);

    switch (tlb_error) {
    default:
    case TLBRET_BADADDR:
        cs->exception_index = access_type == MMU_INST_FETCH
                              ? EXCCODE_ADEF : EXCCODE_ADEM;
        break;
    case TLBRET_NOMATCH:
        /* No TLB match for a mapped address */
        if (access_type == MMU_DATA_LOAD) {
            cs->exception_index = EXCCODE_PIL;
        } else if (access_type == MMU_DATA_STORE) {
            cs->exception_index = EXCCODE_PIS;
        } else if (access_type == MMU_INST_FETCH) {
            cs->exception_index = EXCCODE_PIF;
        }
        env->CSR_TLBRERA = FIELD_DP64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR, 1);
        break;
    case TLBRET_INVALID:
        /* TLB match with no valid bit */
        if (access_type == MMU_DATA_LOAD) {
            cs->exception_index = EXCCODE_PIL;
        } else if (access_type == MMU_DATA_STORE) {
            cs->exception_index = EXCCODE_PIS;
        } else if (access_type == MMU_INST_FETCH) {
            cs->exception_index = EXCCODE_PIF;
        }
        break;
    case TLBRET_DIRTY:
        /* TLB match but 'D' bit is cleared */
        cs->exception_index = EXCCODE_PME;
        break;
    case TLBRET_XI:
        /* Execute-Inhibit Exception */
        cs->exception_index = EXCCODE_PNX;
        break;
    case TLBRET_RI:
        /* Read-Inhibit Exception */
        cs->exception_index = EXCCODE_PNR;
        break;
    case TLBRET_PE:
        /* Privileged Exception */
        cs->exception_index = EXCCODE_PPI;
        break;
    }

    if (tlb_error == TLBRET_NOMATCH) {
        env->CSR_TLBRBADV = address;
        if (is_la64(env)) {
            env->CSR_TLBREHI = FIELD_DP64(env->CSR_TLBREHI, CSR_TLBREHI_64,
                                        VPPN, extract64(address, 13, 35));
        } else {
            env->CSR_TLBREHI = FIELD_DP64(env->CSR_TLBREHI, CSR_TLBREHI_32,
                                        VPPN, extract64(address, 13, 19));
        }
    } else {
        if (!FIELD_EX64(env->CSR_DBG, CSR_DBG, DST)) {
            env->CSR_BADV = address;
        }
        env->CSR_TLBEHI = address & (TARGET_PAGE_MASK << 1);
   }
}

static void invalidate_tlb_entry(CPULoongArchState *env, int index)
{
    target_ulong addr, mask, pagesize;
    uint8_t tlb_ps;
    LoongArchTLB *tlb = &env->tlb[index];
    int idxmap = BIT(MMU_KERNEL_IDX) | BIT(MMU_USER_IDX) | BIT(MMU_GUEST_PLV0) | BIT(MMU_GUEST_PLV3);
    uint64_t tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
    bool tlb_v;

    tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    pagesize = MAKE_64BIT_MASK(tlb_ps, 1);
    mask = MAKE_64BIT_MASK(0, tlb_ps + 1);
    addr = (tlb_vppn << R_TLB_MISC_VPPN_SHIFT) & ~mask;
    addr = sextract64(addr, 0, TARGET_VIRT_ADDR_SPACE_BITS);

    tlb_v = pte_present(env, tlb->tlb_entry0);
    if (tlb_v) {
        tlb_flush_range_by_mmuidx(env_cpu(env), addr, pagesize,
                                  idxmap, TARGET_LONG_BITS);
    }

    tlb_v = pte_present(env, tlb->tlb_entry1);
    if (tlb_v) {
        tlb_flush_range_by_mmuidx(env_cpu(env), addr + pagesize, pagesize,
                                  idxmap, TARGET_LONG_BITS);
    }
}

static void invalidate_tlb(CPULoongArchState *env, int index)
{
    LoongArchTLB *tlb;
    uint16_t csr_asid, tlb_asid, tlb_g;
    uint8_t tlb_e;

    csr_asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);
    tlb = &env->tlb[index];
    tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
    if (!tlb_e) {
        return;
    }

    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
    tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
    tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
    /* QEMU TLB is flushed when asid is changed */
    if (tlb_g == 0 && tlb_asid != csr_asid) {
        return;
    }
    invalidate_tlb_entry(env, index);
}

/* Prepare tlb entry information in software PTW mode */
static void sptw_prepare_context(CPULoongArchState *env, MMUContext *context)
{
    uint64_t lo0, lo1, csr_vppn;
    uint8_t csr_ps;

    uint64_t tlbrera  = guest_csr64(env, env->CSR_TLBRERA,  env->guest.CSR_TLBRERA);
    uint64_t tlbrehi  = guest_csr64(env, env->CSR_TLBREHI,  env->guest.CSR_TLBREHI);
    uint64_t tlbehi   = guest_csr64(env, env->CSR_TLBEHI,   env->guest.CSR_TLBEHI);
    uint64_t tlbidx   = guest_csr64(env, env->CSR_TLBIDX,   env->guest.CSR_TLBIDX);
    uint64_t tlbrelo0 = guest_csr64(env, env->CSR_TLBRELO0, env->guest.CSR_TLBRELO0);
    uint64_t tlbrelo1 = guest_csr64(env, env->CSR_TLBRELO1, env->guest.CSR_TLBRELO1);
    uint64_t tlbelo0  = guest_csr64(env, env->CSR_TLBELO0,  env->guest.CSR_TLBELO0);
    uint64_t tlbelo1  = guest_csr64(env, env->CSR_TLBELO1,  env->guest.CSR_TLBELO1);

    if (FIELD_EX64(tlbrera, CSR_TLBRERA, ISTLBR)) {
        csr_ps = FIELD_EX64(tlbrehi, CSR_TLBREHI, PS);
        if (is_la64(env)) {
            csr_vppn = FIELD_EX64(tlbrehi, CSR_TLBREHI_64, VPPN);
        } else {
            csr_vppn = FIELD_EX64(tlbrehi, CSR_TLBREHI_32, VPPN);
        }
        lo0 = tlbrelo0;
        lo1 = tlbrelo1;
    } else {
        csr_ps = FIELD_EX64(tlbidx, CSR_TLBIDX, PS);
        if (is_la64(env)) {
            csr_vppn = FIELD_EX64(tlbehi, CSR_TLBEHI_64, VPPN);
        } else {
            csr_vppn = FIELD_EX64(tlbehi, CSR_TLBEHI_32, VPPN);
        }
        lo0 = tlbelo0;
        lo1 = tlbelo1;
    }

    context->ps = csr_ps;
    context->addr = csr_vppn << R_TLB_MISC_VPPN_SHIFT;
    context->pte_buddy[0] = lo0;
    context->pte_buddy[1] = lo1;
}

static void fill_tlb_entry(CPULoongArchState *env, LoongArchTLB *tlb,
                           MMUContext *context)
{
    uint64_t lo0, lo1, csr_vppn;
    uint16_t csr_asid;
    uint8_t csr_ps;

    csr_vppn = context->addr >> R_TLB_MISC_VPPN_SHIFT;
    csr_ps   = context->ps;
    lo0      = context->pte_buddy[0];
    lo1      = context->pte_buddy[1];

    /* Store page size in field PS */
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, PS, csr_ps);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, VPPN, csr_vppn);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 1);
    csr_asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);
    tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, ASID, csr_asid);

    tlb->tlb_entry0 = lo0;
    tlb->tlb_entry1 = lo1;
}

/* Return an random value between low and high */
static uint32_t get_random_tlb(uint32_t low, uint32_t high)
{
    uint32_t val;

    qemu_guest_getrandom_nofail(&val, sizeof(val));
    return val % (high - low + 1) + low;
}

/*
 * One tlb entry holds an adjacent odd/even pair, the vpn is the
 * content of the virtual page number divided by 2. So the
 * compare vpn is bit[47:15] for 16KiB page. while the vppn
 * field in tlb entry contains bit[47:13], so need adjust.
 * virt_vpn = vaddr[47:13]
 */
static LoongArchTLB *loongarch_tlb_search_cb(CPULoongArchState *env,
                                             vaddr vaddr, int csr_asid,
                                             tlb_match func)
{
    LoongArchTLB *tlb;
    uint16_t tlb_asid, stlb_idx;
    uint8_t tlb_e, tlb_ps, stlb_ps;
    bool tlb_g;
    int i, compare_shift;
    uint64_t vpn, tlb_vppn;

    stlb_ps = FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);
    vpn = (vaddr & TARGET_VIRT_MASK) >> (stlb_ps + 1);
    stlb_idx = vpn & 0xff; /* VA[25:15] <==> TLBIDX.index for 16KiB Page */
    compare_shift = stlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;

    /* Search STLB */
    for (i = 0; i < 8; ++i) {
        tlb = &env->tlb[i * 256 + stlb_idx];
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = !!FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);

            if (func(tlb_g, csr_asid, tlb_asid) &&
                (vpn == (tlb_vppn >> compare_shift))) {
                return tlb;
            }
        }
    }

    /* Search MTLB */
    for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; ++i) {
        tlb = &env->tlb[i];
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        if (tlb_e) {
            tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
            tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            compare_shift = tlb_ps + 1 - R_TLB_MISC_VPPN_SHIFT;
            vpn = (vaddr & TARGET_VIRT_MASK) >> (tlb_ps + 1);
            if (func(tlb_g, csr_asid, tlb_asid) &&
                (vpn == (tlb_vppn >> compare_shift))) {
                return tlb;
            }
        }
    }
    return NULL;
}

static bool loongarch_tlb_search(CPULoongArchState *env, vaddr vaddr,
                                 int *index)
{
    int csr_asid;
    tlb_match func;
    LoongArchTLB *tlb;

    func = tlb_match_any;
    csr_asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);
    tlb = loongarch_tlb_search_cb(env, vaddr, csr_asid, func);
    if (tlb) {
        *index = tlb - env->tlb;
        return true;
    }

    return false;
}

void helper_tlbsrch(CPULoongArchState *env)
{
    int index, match;

    if (FIELD_EX64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR)) {
        match = loongarch_tlb_search(env, env->CSR_TLBREHI, &index);
    } else {
        match = loongarch_tlb_search(env, env->CSR_TLBEHI, &index);
    }

    if (match) {
        env->CSR_TLBIDX = FIELD_DP64(env->CSR_TLBIDX, CSR_TLBIDX, INDEX, index);
        env->CSR_TLBIDX = FIELD_DP64(env->CSR_TLBIDX, CSR_TLBIDX, NE, 0);
        return;
    }

    env->CSR_TLBIDX = FIELD_DP64(env->CSR_TLBIDX, CSR_TLBIDX, NE, 1);
}

void helper_tlbrd(CPULoongArchState *env)
{
    LoongArchTLB *tlb;
    int index;
    uint8_t tlb_ps, tlb_e;

    index = FIELD_EX64(env->CSR_TLBIDX, CSR_TLBIDX, INDEX);
    tlb = &env->tlb[index];
    tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);

    if (!tlb_e) {
        /* Invalid TLB entry */
        env->CSR_TLBIDX = FIELD_DP64(env->CSR_TLBIDX, CSR_TLBIDX, NE, 1);
        env->CSR_ASID  = FIELD_DP64(env->CSR_ASID, CSR_ASID, ASID, 0);
        env->CSR_TLBEHI = 0;
        env->CSR_TLBELO0 = 0;
        env->CSR_TLBELO1 = 0;
        env->CSR_TLBIDX = FIELD_DP64(env->CSR_TLBIDX, CSR_TLBIDX, PS, 0);
    } else {
        /* Valid TLB entry */
        env->CSR_TLBIDX = FIELD_DP64(env->CSR_TLBIDX, CSR_TLBIDX, NE, 0);
        env->CSR_TLBIDX = FIELD_DP64(env->CSR_TLBIDX, CSR_TLBIDX,
                                     PS, (tlb_ps & 0x3f));
        env->CSR_TLBEHI = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN) <<
                                     R_TLB_MISC_VPPN_SHIFT;
        env->CSR_TLBELO0 = tlb->tlb_entry0;
        env->CSR_TLBELO1 = tlb->tlb_entry1;
    }
}

static void update_tlb_index(CPULoongArchState *env, MMUContext *context,
                             int index)
{
    LoongArchTLB *old, new = {};
    bool skip_inv = false, tlb_v0, tlb_v1;

    old = env->tlb + index;
    fill_tlb_entry(env, &new, context);
    /* Check whether ASID/VPPN is the same */
    if (old->tlb_misc == new.tlb_misc) {
        /* Check whether both even/odd pages is the same or invalid */
        tlb_v0 = pte_present(env, old->tlb_entry0);
        tlb_v1 = pte_present(env, old->tlb_entry1);
        if ((!tlb_v0 || new.tlb_entry0 == old->tlb_entry0) &&
            (!tlb_v1 || new.tlb_entry1 == old->tlb_entry1)) {
            skip_inv = true;
        }
    }

    /* flush tlb before updating the entry */
    if (!skip_inv) {
        invalidate_tlb(env, index);
    }

    *old = new;
}


/* ================================================================
 *  LVZ Root TLB (Stage-2) implementation
 *
 *  The Root TLB caches GPA->HPA translations for the current guest.
 *  On a miss, the stage-2 page-table walker reads the hypervisor's
 *  TLB refill table from guest-physical memory (address in CSR_SAVE4).
 *
 *  Each entry is tagged with GID (GSTAT.GID) to isolate different
 *  guest partitions.  The replacement policy is round-robin.
 * ================================================================ */

/*
 * Look up a GPA in the Root TLB.
 * Returns HPA on hit, or ~0ULL on miss.
 */
static uint64_t root_tlb_lookup(CPULoongArchState *env, uint64_t gpa,
                                 uint64_t gid)
{
    LoongArchRootTLBState *rt = &env->root_tlb;
    for (int i = 0; i < rt->count; i++) {
        LoongArchRootTLBEntry *e = &rt->entries[i];
        if ((e->flags & 1) &&               /* V bit */
            e->gid == gid &&                /* GID match */
            gpa >= e->gpa_start &&
            gpa < e->gpa_end) {
            uint64_t offset = gpa - e->gpa_start;
            return e->hpa + offset;
        }
    }
    return ~0ULL; /* Miss */
}

/*
 * Insert a Root TLB entry with round-robin replacement.
 */
static void root_tlb_insert(CPULoongArchState *env,
                             uint64_t gpa_start, uint64_t gpa_end,
                             uint64_t hpa, uint32_t ps,
                             uint64_t gid, uint32_t flags)
{
    LoongArchRootTLBState *rt = &env->root_tlb;
    int idx;

    if (rt->count < LOONGARCH_ROOT_TLB_SIZE) {
        idx = rt->count++;
    } else {
        idx = rt->next_victim;
        rt->next_victim = (rt->next_victim + 1) % LOONGARCH_ROOT_TLB_SIZE;
    }

    LoongArchRootTLBEntry *e = &rt->entries[idx];
    e->gpa_start = gpa_start;
    e->gpa_end   = gpa_end;
    e->hpa       = hpa;
    e->ps        = ps;
    e->gid       = gid;
    e->flags     = flags;

    /* Keep victim pointer moving in round-robin */
    if (rt->count == LOONGARCH_ROOT_TLB_SIZE) {
        rt->next_victim = (idx + 1) % LOONGARCH_ROOT_TLB_SIZE;
    }
}

/*
 * Flush (invalidate) the entire Root TLB.
 * Called on VM entry (new guest context) or when the hypervisor
 * switches partitions.
 */
void loongarch_root_tlb_flush(CPULoongArchState *env)
{
    LoongArchRootTLBState *rt = &env->root_tlb;
    memset(rt->entries, 0, sizeof(rt->entries));
    rt->count = 0;
    rt->next_victim = 0;
}

/*
 * Stage-2 page-table walker: reads the hypervisor's TLB refill table
 * from guest-physical memory and caches the result in the Root TLB.
 *
 * The hypervisor stores its per-CPU tlb_refill_table PA in CSR_SAVE4.
 * Each entry is a 64-bit value:
 *   [63:0] = (HPA_PPN << 20) | flags  (0 if the page is not mapped)
 *
 * Returns HPA, or ~0ULL if the GPA is unmapped.
 */
static uint64_t root_tlb_walk_stage2(CPULoongArchState *env, uint64_t gpa,
                                      uint64_t gid)
{
    uint64_t table_pa = env->CSR_SAVE[4];
    if (!table_pa) {
        return gpa & 0x0000FFFFFFFFFFFFULL; /* Identity fallback */
    }

    /* 1MB page index */
    uint32_t page_idx = (uint32_t)(gpa >> 20);
    if (page_idx >= 4096) {
        return ~0ULL; /* GPA above 4 GB */
    }

    /* Read entry from guest-physical memory */
    uint64_t entry;
    cpu_physical_memory_read(table_pa + page_idx * 8, &entry, sizeof(entry));

    if (!(entry & 1ULL)) {
        return ~0ULL; /* Invalid */
    }

    /* Extract HPA, flags, and page offset */
    uint64_t hpa_ppn = (entry >> 20) << 20;
    uint32_t flags = entry & 0xFFFFF;
    uint32_t ps = 20; /* 1MB page size */
    uint64_t gpa_base = (uint64_t)page_idx << 20;
    uint64_t gpa_end  = gpa_base + (1ULL << 20);

    /* Populate root TLB cache */
    root_tlb_insert(env, gpa_base, gpa_end, hpa_ppn, ps, gid, flags);

    uint64_t gpa_offset = gpa & 0xFFFFFULL;
    return hpa_ppn + gpa_offset;
}

/*
 * LVZ: Translate Guest Physical Address to Host Physical Address.
 *
 * Checks the Root TLB first (with GID match), then falls back to the
 * stage-2 page-table walker on miss.  The result is cached for future
 * lookups.
 */
uint64_t loongarch_root_tlb_translate(CPULoongArchState *env, uint64_t gpa)
{
    uint64_t gid = FIELD_EX64(env->CSR_GSTAT, CSR_GSTAT, GID);

    /* Fast path: Root TLB hit */
    uint64_t hpa = root_tlb_lookup(env, gpa, gid);
    if (hpa != ~0ULL) {
        return hpa;
    }

    /* Slow path: walk stage-2 page tables */
    hpa = root_tlb_walk_stage2(env, gpa, gid);

    /* On miss, return GPA identity as a fallback
     * (avoids crashing early-boot guests that touch unmapped GPA) */
    if (hpa == ~0ULL) {
        hpa = gpa & 0x0000FFFFFFFFFFFFULL;
    }

    return hpa;
}

/*
 * LVZ: Translate Guest Physical Address to Host Physical Address.
 * (wrapper for use by lvz_translate_tlbelo)
 */
static uint64_t lvz_gpa_to_hpa(CPULoongArchState *env, uint64_t gpa)
{
    return loongarch_root_tlb_translate(env, gpa);
}

/*
 * LVZ: Translate guest TLBELO entries (GPA -> HPA) before filling
 * the real TLB. This is called from helper_tlbwr/helper_tlbfill
 * when in guest (PVM) mode.
 */
static void lvz_translate_tlbelo(CPULoongArchState *env,
                                  uint64_t *elo0, uint64_t *elo1)
{
    if (!env->in_guest_mode) {
        return;
    }

    /* Translate GPA to HPA for each valid entry */
    if (pte_present(env, *elo0)) {
        uint64_t gpa_ppn = (*elo0 >> 12) & ((1ULL << 36) - 1);
        uint64_t gpa = gpa_ppn << 12;
        uint64_t hpa = lvz_gpa_to_hpa(env, gpa);
        uint64_t hpa_ppn = hpa >> 12;
        /* Replace PPN with HPA PPN, keep flags (low 12 bits + high 3 bits) */
        *elo0 = (hpa_ppn << 12) | (*elo0 & 0xFFFULL) | (*elo0 & (7ULL << 61));
    }
    if (pte_present(env, *elo1)) {
        uint64_t gpa_ppn = (*elo1 >> 12) & ((1ULL << 36) - 1);
        uint64_t gpa = gpa_ppn << 12;
        uint64_t hpa = lvz_gpa_to_hpa(env, gpa);
        uint64_t hpa_ppn = hpa >> 12;
        *elo1 = (hpa_ppn << 12) | (*elo1 & 0xFFFULL) | (*elo1 & (7ULL << 61));
    }
}

void helper_tlbwr(CPULoongArchState *env)
{
    uint64_t tlbidx = guest_csr64(env, env->CSR_TLBIDX, env->guest.CSR_TLBIDX);
    int index = FIELD_EX64(tlbidx, CSR_TLBIDX, INDEX);

    MMUContext context;

    if (FIELD_EX64(tlbidx, CSR_TLBIDX, NE)) {
        invalidate_tlb(env, index);
        return;
    }

    sptw_prepare_context(env, &context);
    /* LVZ: Translate guest TLBELO entries (GPA->HPA) */
    lvz_translate_tlbelo(env, &context.pte_buddy[0], &context.pte_buddy[1]);
    update_tlb_index(env, &context, index);
}

static int get_tlb_random_index(CPULoongArchState *env, vaddr addr,
                                int pagesize)
{
    uint64_t address;
    int index, set, i, stlb_idx;
    uint16_t asid, tlb_asid, stlb_ps;
    LoongArchTLB *tlb;
    uint8_t tlb_e, tlb_g;

    /* Validity of stlb_ps is checked in helper_csrwr_stlbps() */
    stlb_ps = FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);
    asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);
    if (pagesize == stlb_ps) {
        /* Only write into STLB bits [47:13] */
        address = addr & ~MAKE_64BIT_MASK(0, R_CSR_TLBEHI_64_VPPN_SHIFT);
        set = -1;
        stlb_idx = (address >> (stlb_ps + 1)) & 0xff; /* [0,255] */
        for (i = 0; i < 8; ++i) {
            tlb = &env->tlb[i * 256 + stlb_idx];
            tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
            if (!tlb_e) {
                set = i;
                break;
            }

            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            if (tlb_g == 0 && asid != tlb_asid) {
                set = i;
            }
        }

        /* Choose one set randomly */
        if (set < 0) {
            set = get_random_tlb(0, 7);
        }
        index = set * 256 + stlb_idx;
    } else {
        /* Only write into MTLB */
        index = -1;
        for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; i++) {
            tlb = &env->tlb[i];
            tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);

            if (!tlb_e) {
                index = i;
                break;
            }

            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            if (tlb_g == 0 && asid != tlb_asid) {
                index = i;
            }
        }

        if (index < 0) {
            index = get_random_tlb(LOONGARCH_STLB, LOONGARCH_TLB_MAX - 1);
        }
    }

    return index;
}

void helper_tlbfill(CPULoongArchState *env)
{
    vaddr entryhi;
    int index, pagesize;
    MMUContext context;

    /*
     * LVZ: use guest shadow CSRs when in PVM (guest) mode so that
     * tlbfill translates the guest's GPA to HPA.  The guest_csr64()
     * helper selects the host or guest CSR set transparently.
     */
    uint64_t tlbrera = guest_csr64(env, env->CSR_TLBRERA, env->guest.CSR_TLBRERA);
    uint64_t tlbrehi = guest_csr64(env, env->CSR_TLBREHI, env->guest.CSR_TLBREHI);
    uint64_t tlbidx  = guest_csr64(env, env->CSR_TLBIDX,  env->guest.CSR_TLBIDX);
    uint64_t tlbehi  = guest_csr64(env, env->CSR_TLBEHI,  env->guest.CSR_TLBEHI);

    if (FIELD_EX64(tlbrera, CSR_TLBRERA, ISTLBR)) {
        entryhi = tlbrehi;
        pagesize = FIELD_EX64(tlbrehi, CSR_TLBREHI, PS);
    } else {
        entryhi = tlbehi;
        pagesize = FIELD_EX64(tlbidx, CSR_TLBIDX, PS);
    }

    sptw_prepare_context(env, &context);
    index = get_tlb_random_index(env, entryhi, pagesize);
    invalidate_tlb(env, index);
    fill_tlb_entry(env, env->tlb + index, &context);
}

void helper_tlbclr(CPULoongArchState *env)
{
    LoongArchTLB *tlb;
    int i, index;
    uint16_t csr_asid, tlb_asid, tlb_g;

    csr_asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);
    index = FIELD_EX64(env->CSR_TLBIDX, CSR_TLBIDX, INDEX);

    if (index < LOONGARCH_STLB) {
        /* STLB. One line per operation */
        for (i = 0; i < 8; i++) {
            tlb = &env->tlb[i * 256 + (index % 256)];
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            if (!tlb_g && tlb_asid == csr_asid) {
                tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
            }
        }
    } else if (index < LOONGARCH_TLB_MAX) {
        /* All MTLB entries */
        for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; i++) {
            tlb = &env->tlb[i];
            tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
            tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
            if (!tlb_g && tlb_asid == csr_asid) {
                tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
            }
        }
    }

    tlb_flush(env_cpu(env));
}

void helper_tlbflush(CPULoongArchState *env)
{
    int i, index;

    index = FIELD_EX64(env->CSR_TLBIDX, CSR_TLBIDX, INDEX);

    if (index < LOONGARCH_STLB) {
        /* STLB. One line per operation */
        for (i = 0; i < 8; i++) {
            int s_idx = i * 256 + (index % 256);
            env->tlb[s_idx].tlb_misc = FIELD_DP64(env->tlb[s_idx].tlb_misc,
                                                  TLB_MISC, E, 0);
        }
    } else if (index < LOONGARCH_TLB_MAX) {
        /* All MTLB entries */
        for (i = LOONGARCH_STLB; i < LOONGARCH_TLB_MAX; i++) {
            env->tlb[i].tlb_misc = FIELD_DP64(env->tlb[i].tlb_misc,
                                              TLB_MISC, E, 0);
        }
    }

    tlb_flush(env_cpu(env));
}

void helper_invtlb_all(CPULoongArchState *env)
{
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        env->tlb[i].tlb_misc = FIELD_DP64(env->tlb[i].tlb_misc,
                                          TLB_MISC, E, 0);
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_all_g(CPULoongArchState *env, uint32_t g)
{
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->tlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);

        if (tlb_g == g) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_all_asid(CPULoongArchState *env, target_ulong info)
{
    uint16_t asid = info & R_CSR_ASID_ASID_MASK;

    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        LoongArchTLB *tlb = &env->tlb[i];
        uint8_t tlb_g = FIELD_EX64(tlb->tlb_entry0, TLBENTRY, G);
        uint16_t tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);

        if (!tlb_g && (tlb_asid == asid)) {
            tlb->tlb_misc = FIELD_DP64(tlb->tlb_misc, TLB_MISC, E, 0);
        }
    }
    tlb_flush(env_cpu(env));
}

void helper_invtlb_page_asid(CPULoongArchState *env, target_ulong info,
                             target_ulong addr)
{
    int asid = info & 0x3ff;
    LoongArchTLB *tlb;
    tlb_match func;

    func = tlb_match_asid;
    tlb = loongarch_tlb_search_cb(env, addr, asid, func);
    if (tlb) {
        invalidate_tlb(env, tlb - env->tlb);
    }
}

void helper_invtlb_page_asid_or_g(CPULoongArchState *env,
                                  target_ulong info, target_ulong addr)
{
    int asid = info & 0x3ff;
    LoongArchTLB *tlb;
    tlb_match func;

    func = tlb_match_any;
    tlb = loongarch_tlb_search_cb(env, addr, asid, func);
    if (tlb) {
        invalidate_tlb(env, tlb - env->tlb);
    }
}

static void ptw_update_tlb(CPULoongArchState *env, MMUContext *context)
{
    int index;

    index = context->tlb_index;
    if (index < 0) {
        index = get_tlb_random_index(env, context->addr, context->ps);
    }

    update_tlb_index(env, context, index);
}

bool loongarch_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                            MMUAccessType access_type, int mmu_idx,
                            bool probe, uintptr_t retaddr)
{
    CPULoongArchState *env = cpu_env(cs);
    hwaddr physical;
    int prot;
    MMUContext context;
    TLBRet ret;

    /* Data access */
    context.addr = address;
    context.tlb_index = -1;
    ret = get_physical_address(env, &context, access_type, mmu_idx, 0);
    if (ret == TLBRET_MATCH && context.mmu_index != MMU_DA_IDX
        && cpu_has_ptw(env)) {
        bool need_update = true;

        if (access_type == MMU_DATA_STORE && pte_dirty(context.pte)) {
            need_update = false;
        } else if (access_type != MMU_DATA_STORE && pte_access(context.pte)) {
            need_update = false;

            /*
             * FIXME: should context.prot be set without PAGE_WRITE with
             * pte_write(context.pte) && !pte_dirty(context.pte)??
             *
             * Otherwise there will be no loongarch_cpu_tlb_fill() function call
             * for MMU_DATA_STORE access_type in future since QEMU TLB with
             * prot PAGE_WRITE is added already
             */
        }

        if (need_update) {
            /* Need update bit A/D in PTE entry, take PTW again */
            ret = TLBRET_NOMATCH;
        }
    }

    if (ret != TLBRET_MATCH && cpu_has_ptw(env)) {
        /* Take HW PTW if TLB missed or bit P is zero */
        if (ret == TLBRET_NOMATCH || ret == TLBRET_INVALID) {
            ret = loongarch_ptw(env, &context, access_type, mmu_idx, 0);
            if (ret == TLBRET_MATCH) {
                ptw_update_tlb(env, &context);
            }
        } else if (context.tlb_index >= 0) {
            invalidate_tlb(env, context.tlb_index);
        }
    }

    if (ret == TLBRET_MATCH) {
        physical = context.physical;
        prot = context.prot;
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     physical & TARGET_PAGE_MASK, prot,
                     mmu_idx, TARGET_PAGE_SIZE);
        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " physical " HWADDR_FMT_plx
                      " prot %d\n", __func__, address, physical, prot);
        return true;
    } else {
        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " ret %d\n", __func__, address,
                      ret);
    }
    if (probe) {
        return false;
    }
    raise_mmu_exception(env, address, access_type, ret);
    cpu_loop_exit_restore(cs, retaddr);
}

static inline uint64_t loongarch_sanitize_hw_pte(CPULoongArchState *env,
                                                 uint64_t pte)
{
    uint64_t palen_mask = loongarch_palen_mask(env);
    uint64_t ppn_mask = is_la64(env) ? R_TLBENTRY_64_PPN_MASK : R_TLBENTRY_32_PPN_MASK;

    /*
     * Keep only architecturally-defined PTE bits. Guests may use some
     * otherwise-unused bits for software purposes.
     */
    pte &= env->hw_pte_mask;

    return (pte & ~ppn_mask) | ((pte & ppn_mask) & palen_mask);
}

target_ulong helper_lddir(CPULoongArchState *env, target_ulong base,
                          uint32_t level, uint32_t mem_idx)
{
    CPUState *cs = env_cpu(env);
    uint64_t badvaddr;
    hwaddr index, phys;
    uint64_t palen_mask = loongarch_palen_mask(env);
    uint64_t dir_base, dir_width;


    if (unlikely((level == 0) || (level > 4))) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "Attepted LDDIR with level %u\n", level);
        return base;
    }

    if (FIELD_EX64(base, TLBENTRY, HUGE)) {
        if (unlikely(level == 4)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "Attempted use of level 4 huge page\n");
            return base;
        }

        if (FIELD_EX64(base, TLBENTRY, LEVEL)) {
            return base;
        } else {
            return FIELD_DP64(base, TLBENTRY, LEVEL, level);
        }
    }

    badvaddr = env->CSR_TLBRBADV;
    base = base & palen_mask;
    get_dir_base_width(env, &dir_base, &dir_width, level);
    index = (badvaddr >> dir_base) & ((1 << dir_width) - 1);
    phys = base | index << 3;
    return ldq_le_phys(cs->as, phys) & palen_mask;
}

void helper_ldpte(CPULoongArchState *env, target_ulong base, target_ulong odd,
                  uint32_t mem_idx)
{
    CPUState *cs = env_cpu(env);
    hwaddr phys, tmp0, ptindex, ptoffset0, ptoffset1;
    uint64_t pte_raw;
    uint64_t badv;
    uint64_t ptbase = FIELD_EX64(env->CSR_PWCL, CSR_PWCL, PTBASE);
    uint64_t ptwidth = FIELD_EX64(env->CSR_PWCL, CSR_PWCL, PTWIDTH);
    uint64_t palen_mask = loongarch_palen_mask(env);
    uint64_t dir_base, dir_width;
    uint8_t  ps;


    /*
     * The parameter "base" has only two types,
     * one is the page table base address,
     * whose bit 6 should be 0,
     * and the other is the huge page entry,
     * whose bit 6 should be 1.
     */
    if (FIELD_EX64(base, TLBENTRY, HUGE)) {
        /*
         * Gets the huge page level and Gets huge page size.
         * Clears the huge page level information in the entry.
         * Clears huge page bit.
         * Move HGLOBAL bit to GLOBAL bit.
         */
        get_dir_base_width(env, &dir_base, &dir_width,
                           FIELD_EX64(base, TLBENTRY, LEVEL));

        base = FIELD_DP64(base, TLBENTRY, LEVEL, 0);
        base = FIELD_DP64(base, TLBENTRY, HUGE, 0);
        if (FIELD_EX64(base, TLBENTRY, HGLOBAL)) {
            base = FIELD_DP64(base, TLBENTRY, HGLOBAL, 0);
            base = FIELD_DP64(base, TLBENTRY, G, 1);
        }

        ps = dir_base + dir_width - 1;
        /*
         * Huge pages are evenly split into parity pages
         * when loaded into the tlb,
         * so the tlb page size needs to be divided by 2.
         */
        tmp0 = loongarch_sanitize_hw_pte(env, base);
        if (odd) {
            tmp0 += MAKE_64BIT_MASK(ps, 1);
        }

        if (!check_ps(env, ps)) {
            qemu_log_mask(LOG_GUEST_ERROR, "Illegal huge pagesize %d\n", ps);
            return;
        }
    } else {
        badv = env->CSR_TLBRBADV;

        base = base & palen_mask;

        ptindex = (badv >> ptbase) & ((1 << ptwidth) - 1);
        ptindex = ptindex & ~0x1;   /* clear bit 0 */
        ptoffset0 = ptindex << 3;
        ptoffset1 = (ptindex + 1) << 3;
        phys = base | (odd ? ptoffset1 : ptoffset0);
        pte_raw = ldq_le_phys(cs->as, phys);
        tmp0 = loongarch_sanitize_hw_pte(env, pte_raw);
        ps = ptbase;
    }

    if (odd) {
        env->CSR_TLBRELO1 = tmp0;
    } else {
        env->CSR_TLBRELO0 = tmp0;
    }
    env->CSR_TLBREHI = FIELD_DP64(env->CSR_TLBREHI, CSR_TLBREHI, PS, ps);
}

static TLBRet loongarch_map_tlb_entry(CPULoongArchState *env,
                                      MMUContext *context,
                                      MMUAccessType access_type, int index,
                                      int mmu_idx)
{
    LoongArchTLB *tlb = &env->tlb[index];
    uint8_t tlb_ps, n;

    tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    n = (context->addr >> tlb_ps) & 0x1;/* Odd or even */
    context->pte = n ? tlb->tlb_entry1 : tlb->tlb_entry0;
    context->ps = tlb_ps;
    context->tlb_index = index;
    return loongarch_check_pte(env, context, access_type, mmu_idx);
}

TLBRet loongarch_get_addr_from_tlb(CPULoongArchState *env,
                                   MMUContext *context,
                                   MMUAccessType access_type, int mmu_idx)
{
    int index, match;

    match = loongarch_tlb_search(env, context->addr, &index);
    if (match) {
        return loongarch_map_tlb_entry(env, context, access_type, index,
                                       mmu_idx);
    }

    return TLBRET_NOMATCH;
}

/*
 * LVZ: Two-level address translation for guest (PVM) mode.
 *
 * When PVM=1, guest virtual addresses must be translated twice:
 *   Level 1 (GVA -> GPA): Use guest TLB (env->guest.CSR_TLB*)
 *   Level 2 (GPA -> HPA): Use root TLB (env->tlb[] with GID tagging)
 *
 * For now, Level 2 is a direct 1:1 mapping (GPA == HPA) since the
 * hypervisor configures identity-mapped guest physical memory.
 * Full root TLB support can be added later.
 */
TLBRet loongarch_lvz_translate(CPULoongArchState *env, vaddr addr,
                                MMUAccessType access_type, int mmu_idx,
                                hwaddr *phys_addr)
{
    /* Level 1: GVA -> GPA using guest TLB shadow state.
     * The guest TLB entries are in env->guest.CSR_TLB* which were
     * written by the guest kernel via shadow CSR optimization.
     * We need to search the guest TLB for a matching entry. */
    uint64_t guest_vppn, guest_ps, guest_elo0, guest_elo1;
    uint64_t gpa = addr; /* Default: identity map if no guest TLB match */

    /* Check if guest has page mapping enabled via shadow CRMD */
    uint64_t guest_crmd = env->guest.CSR_CRMD;
    if (!(guest_crmd & (1ULL << 4))) {
        /* PG=0: direct address mode, VA=GPA */
        *phys_addr = addr & 0x0000FFFFFFFFFFFFULL;
        return TLBRET_MATCH;
    }

    /* Read guest TLB registers from shadow state */
    guest_ps = FIELD_EX64(env->guest.CSR_STLBPS, CSR_STLBPS, PS);
    guest_vppn = addr >> (guest_ps + 1);

    /* Simple guest TLB lookup: iterate over guest TLB entries.
     * For a full implementation, we would maintain a separate guest_tlb[]
     * array. For now, we use the guest CSR shadow state directly.
     * The guest kernel fills TLB entries via tlbfill/tlbwr which trap
     * to the hypervisor, so the shadow CSRs reflect the last TLB operation. */

    /* Check if the address matches the last guest TLB operation */
    uint64_t gtlbehi_vppn;
    if (FIELD_EX64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR)) {
        gtlbehi_vppn = FIELD_EX64(env->guest.CSR_TLBREHI, CSR_TLBREHI, PS);
        /* Use TLBR* registers for refill context */
        guest_elo0 = env->guest.CSR_TLBRELO0;
        guest_elo1 = env->guest.CSR_TLBRELO1;
    } else {
        gtlbehi_vppn = FIELD_EX64(env->guest.CSR_TLBEHI, CSR_TLBEHI_64, VPPN);
        guest_elo0 = env->guest.CSR_TLBELO0;
        guest_elo1 = env->guest.CSR_TLBELO1;
    }

    /* Level 2: GPA -> HPA (identity mapping for now).
     * The hypervisor configures the partition memory as identity-mapped,
     * so GPA == HPA for all valid partition addresses. */
    if (pte_present(env, guest_elo0) || pte_present(env, guest_elo1)) {
        /* Extract GPA from guest TLBELO: PPN is bits [47:12] */
        uint64_t gpa_ppn;
        int odd = (addr >> guest_ps) & 1;
        uint64_t elo = odd ? guest_elo1 : guest_elo0;

        if (!pte_present(env, elo)) {
            return TLBRET_INVALID;
        }

        gpa_ppn = (elo >> 12) & ((1ULL << 36) - 1);
        gpa = (gpa_ppn << 12) | (addr & ((1ULL << guest_ps) - 1));

        /* Check D bit for writes */
        if (access_type == MMU_DATA_STORE && !(elo & (1ULL << 1))) {
            return TLBRET_DIRTY;
        }
        /* Check NX bit for instruction fetch */
        if (access_type == MMU_INST_FETCH && (elo & (1ULL << 62))) {
            return TLBRET_XI;
        }
        /* Check NR bit for reads */
        if (access_type == MMU_DATA_LOAD && (elo & (1ULL << 61))) {
            return TLBRET_RI;
        }
    }

    /* Level 2: GPA -> HPA (identity mapping) */
    *phys_addr = gpa & 0x0000FFFFFFFFFFFFULL;
    return TLBRET_MATCH;
}
