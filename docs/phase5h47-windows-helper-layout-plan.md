# Phase 5h.47: Windows helper trusted layout contract

This phase defines a pure layout contract for LocalService helper artifacts that
deliberately supersedes Phase 5a LocalAppData/home roots for the distinct-writer
boundary.

`buildWindowsHelperLayoutPlan` accepts only a branded Phase 5h.8 boundary plan
and `{ layout_mode: 'disposable' | 'persistent' }`. Both modes require
ProgramData-class trusted roots, service-SID (or trusted admin/SYSTEM) ownership,
caller non-writability, and no reparse points. Disposable mode requires cleanup;
persistent mode requires uninstall/absence proof. The plan never emits concrete
paths, commands, SIDs as inputs, or vault references and always reports mutation
unauthorized.
