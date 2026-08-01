#include "macos-launchctl-mach-presence.h"
#include "macos-fixed-system-probes.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define NAME "de.frederikstadler.bitwarden-agent-credential-bridge.helper"

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  static const char present[] = "endpoints = {\n\t\"" NAME "\" = {\n\t}\n}\n";
  static const char prefix[] = "name = x" NAME "\n";
  static const char suffix[] = "name = " NAME "x\n";
  static const char path[] = "program = /Library/PrivilegedHelperTools/" NAME "\n";
  static const char absent[] = "system/com.apple.example = {\n}\n";
  bool parser_exact = bw_test_snapshot_contains_name(present, sizeof(present) - 1, NAME) &&
      !bw_test_snapshot_contains_name(prefix, sizeof(prefix) - 1, NAME) &&
      !bw_test_snapshot_contains_name(suffix, sizeof(suffix) - 1, NAME) &&
      !bw_test_snapshot_contains_name(path, sizeof(path) - 1, NAME) &&
      !bw_test_snapshot_contains_name(absent, sizeof(absent) - 1, NAME);
  bw_launchctl_presence_context context;
  bw_init_launchctl_presence_context(&context);
  bool live_fixed_name_absent = bw_probe_fixed_system_mach_name(&context, NAME) == BW_LAUNCHD_ABSENT;
  bw_fixed_system_probes probes;
  bw_init_fixed_system_probes(&probes);
  bool bundle_absent = bw_fixed_system_presence_probe(&probes, NAME) == BW_LAUNCHD_ABSENT &&
      !bw_fixed_system_denial_probe(&probes, NULL, 0);
  bool all = parser_exact && live_fixed_name_absent && bundle_absent;
  (void)printf(
      "{\"schema_version\":1,\"parser_exact\":%s,\"live_fixed_name_absent\":%s,"
      "\"bundle_absent\":%s,\"activation_attempted\":false}\n",
      parser_exact ? "true" : "false", live_fixed_name_absent ? "true" : "false",
      bundle_absent ? "true" : "false");
  return all ? 0 : 1;
}
