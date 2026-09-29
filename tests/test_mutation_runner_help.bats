#!/usr/bin/env bats
# tests/mutation/run.sh prints its leading comment block as --help. The range
# must end at the first blank source line, not at a bare `#` inside the block.

load helpers.bash

@test "mutation runner --help prints the whole usage block and no code" {
    run bash "$(_vpssec_repo_root)/tests/mutation/run.sh" --help
    [ "$status" -eq 0 ]
    [ "${lines[0]}" = "Mutation testing harness for vpssec." ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" == *"run-in-container.sh"* ]]
    [[ "$output" != *"set -uo pipefail"* ]]
}
