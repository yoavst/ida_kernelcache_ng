# IDA 9.5 integration plan

## Goal

Keep the plugin's coverage of KEXT classes, but merge with IDA 9.5's kernel types
instead of overwriting them. Add the `ida_kcu` bridge, use `kalloc_type` data for
field layout, and align names/vtable EAs with IDA.

Measured facts this plan is based on:

- IDA 9.5 types only the 157 `com.apple.kernel` classes. KEXT classes get a flat
  `kalloc_type` struct: no base class, no `X_vtbl`, no `X::gMetaClass`.
- `load_kexts()` + `auto_wait()` does not change that in idalib.
- IDA applies `X_vtbl` at the first slot (`ipsw` `VtableAddr`), not at
  `first_slot - 16`.
- `get_vftable_ordinal()` / `get_vftable_ea()` return 0 in this environment.
  Do not use them to check the EA; use `idc.get_type(ea)`.

## Steps

1. Add `ida_helpers/kcu.py`.
   - Wrap `ida_kcu.get_kcu_svc()`: KEXTs, info, regions, kalloc views.
   - Return `None` on IDA < 9.5 or non-KC input.
   - Proof: `kalloc_views("AppleA7IOP")` returns one fixed view, size 392.

2. Align names and vtable EAs with IDA.
   - `X::gMetaClass`, `X::vtable`, `X::MetaClass::vtable`.
   - Use `VtableInfo.start_ea` for the symbol and for `set_vftable_ea`.
   - Never rename an IDA-provided name.
   - Proof: on a copy DB, `X::gMetaClass` == `ida_name.get_name_ea(...)`; the
     `X_vtbl` data type sits at `idc.get_type(VtableAddr)`.

3. Replace `CreateTypes` overwrite logic with merge.
   - Existing real C++ type (cppobj + base): keep it untouched.
   - Existing flat `kalloc` struct: replace by `struct __cppobj X : Super` with
     own fields after `super.class_size`.
   - Existing `X_vtbl`: keep it untouched.
   - Field kind from `kalloc` `sig`: `ptr_XX` vs `data_XX`; fall back to
     `field_XX`.
   - Proof: `AppleA7IOP` size 392, base `IOService`, own fields start at 0x88;
     `OSArray` still `: OSCollection` and `OSArray_vtbl` still has 38 members.

4. Remove dead code.
   - `build_struct.py`, `data_flow.py`, `kplist.py`.
   - Prelink `Kext`/`kexts`/`prelink_info`/`segments_matching`.
   - Duplicate metaclass/vtable mangled naming.
   - Proof: `python -m compileall`, no imports of removed modules.

5. Native KEXT harvest fallback (when `ipsw` is absent).
   - Reuse the pre-ipsw callsite decoding and `::getMetaClass` vtable lookup.
   - Only runs when `ipsw kernel cpp` fails.
   - Proof: run on a copy with `IPSW=/nonexistent`; expect `AppleA7IOP` in the
     class map.

## Verification

- Headless: `IDADIR` 9.5, fresh DB from a `/tmp` copy, run
  `KernelCache().process()`.
- Assert class count, base links, vtable EAs, no changes to `OSArray*`.
- GUI: user tests the same code on the open DB.

## Status (branch `feature/ida95-merge`)

- Steps 1-4 done. Verified with idalib 9.5.261026 on a filtered DB
  (kernel + `AppleA7IOP` + `AppleA7IOP-ASCWrap-v4`):
  - `AppleA7IOP` rebuilt as `struct __cppobj AppleA7IOP : AppleIOP`, 392 bytes,
    fields `ptr_f0`... from the kalloc granule signature.
  - `AppleA7IOP::gMetaClass`, `AppleA7IOP::vtable`,
    `AppleA7IOP::MetaClass::vtable` named at the ipsw EAs.
  - `AppleA7IOP_vtbl` created and applied at the first slot
    (`idc.get_type(0xfffffff007cc4df0) == "AppleA7IOP_vtbl"`).
  - Kernel types untouched: `OSArray : OSCollection`, `OSArray_vtbl` 38 members.
  - 5 class types rebuilt, 151 kept; 4 vtable types created, 154 kept.
- Step 5 done. Native fallback found 161 classes and 156 vtables on the same DB,
  including the KEXT classes. It logs 29 wrong function boundaries, because the
  decompiler is weaker than ipsw; use ipsw when it is installed.
- Parser note: IDA 9.5 rejects `__hidden` in a struct member declaration. The
  vtable member parameter is named `self` instead.
