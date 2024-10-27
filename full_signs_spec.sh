#!/bin/bash

# Function to prompt the user for the version of Dilithium
get_dilithium_version() {
  while true; do
    read -p "Which version of Dilithium do you want to target (2/3/5)? " ALG
    case $ALG in
      2)
        NBSIGNS=1250000
        break
        ;;
      3)
        NBSIGNS=3500000
        break
        ;;
      5)
        NBSIGNS=4000000
        break
        ;;
      *)
        echo "Error: Invalid version. Please enter 2, 3, or 5."
        ;;
    esac
  done
}

# Get the Dilithium version
get_dilithium_version

# Set NBKEYS to 1
NBKEYS=1

# Execution of the intermediate functions needed for the attack
## Navigate to the directory where the Makefile is located
cd Additional_files/C_functions

## First generate 1 key for the chosen security level
make PQCgenKAT_sign_Modified$ALG
echo '>>> Generating KATS ' | tr -d '\n'
./PQCgenKAT_sign_Modified$ALG $NBKEYS
echo -e '\u2705'

## Then generate the corresponding number of (simulated) faulted signatures
make Gen_Signs_KeyKAT$ALG
echo '>>> Generating faulted signs ' | tr -d '\n'
./Gen_Signs_KeyKAT$ALG $NBSIGNS
echo -e '\u2705'

## Finally filter the ones that give inequalities on $\mathbf{s}_2$
make Filter_Signs_Proposition3$ALG
echo '>>> Filtering faulted signs ' | tr -d '\n'
./Filter_Signs_Proposition3$ALG $NBSIGNS
echo -e '\u2705'