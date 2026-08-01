#ifndef BW_AGENT_MACOS_ELEVATION_IDENTITY_H
#define BW_AGENT_MACOS_ELEVATION_IDENTITY_H

#include <stdbool.h>

bool bw_stable_direct_sudo_parent(void);
bool bw_stable_sudo_or_provisioner_parent(void);

#if defined(BW_ELEVATION_IDENTITY_TESTING)
bool bw_elevation_chain_fixture(bool direct_sudo, bool parent_provisioner,
    bool grandparent_sudo);
#endif

#endif
