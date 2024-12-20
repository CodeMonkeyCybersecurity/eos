#!/bin/bash
# test.sh
echo "This is a test script to see if these bash scripts are handling the different directories okay or if theyre getting lost"
PROJECT_ROOT=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
echo ""
echo "Test.sh has defined this as PROJECT_ROOT: $PROJECT_ROOT"
echo ""
source "$PROJECT_ROOT/variables.conf" || { echo "Failed to source variables.conf"; exit 1; }
source "$START" || { echo "Failed to source start.sh"; exit 1; }
echo "The project start file is: $START"
echo "Keep humans in the loop"
source "$STOP" || { echo "Failed to source stop.sh"; exit 1; }
echo "The project start file is: $STOP"