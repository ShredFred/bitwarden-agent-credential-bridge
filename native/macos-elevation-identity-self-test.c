#include "macos-elevation-identity.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  bool direct = bw_elevation_chain_fixture(true, false, false);
  bool mediated = bw_elevation_chain_fixture(false, true, true);
  bool arbitrary_parent_rejected = !bw_elevation_chain_fixture(false, false, true);
  bool missing_sudo_rejected = !bw_elevation_chain_fixture(false, true, false);
  bool all = direct && mediated && arbitrary_parent_rejected && missing_sudo_rejected;
  (void)printf(
      "{\"schema_version\":1,\"direct_sudo\":%s,\"mediated\":%s,"
      "\"arbitrary_parent_rejected\":%s,\"missing_sudo_rejected\":%s}\n",
      direct ? "true" : "false", mediated ? "true" : "false",
      arbitrary_parent_rejected ? "true" : "false",
      missing_sudo_rejected ? "true" : "false");
  return all ? 0 : 1;
}
