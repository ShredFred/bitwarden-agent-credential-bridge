#ifndef BW_AGENT_MACOS_DSCL_DIRECTORY_ADAPTER_H
#define BW_AGENT_MACOS_DSCL_DIRECTORY_ADAPTER_H

#include "macos-account-ownership.h"
#include "macos-fixed-command-runner.h"

typedef struct {
  bw_fixed_command_runner run;
} bw_dscl_directory_adapter;

bool bw_init_dscl_directory_ops(
    bw_dscl_directory_adapter *adapter,
    bw_fixed_command_runner runner,
    bw_directory_ops *ops);

#endif
