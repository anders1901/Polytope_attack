#!/bin/bash

# Function to prompt the user for the security level of Dilithium
get_dilithium_security_level() {
  while true; do
    read -p "Which security level of Dilithium do you want to target (2/3/5)? " ALG
    case $ALG in
      2)
        # NBSIGNS=1250000
        NBSIGNS=100000
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
        echo "Error: Invalid security level. Please enter 2, 3, or 5."
        ;;
    esac
  done
}

# Get the Dilithium security level
get_dilithium_security_level

# Set NBKEYS to 1
NBKEYS=1

# Execution of the intermediate functions needed for the attack
## Navigate to the directory where the Makefile is located
cd Additional_files/C_functions

## First generate 1 key for the chosen security level
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
  make PQCgenKAT_sign_Modified$ALG > NUL
else
  make PQCgenKAT_sign_Modified$ALG > /dev/null
fi
echo '>>> Generating KATS ' | tr -d '\n'
./PQCgenKAT_sign_Modified$ALG $NBKEYS
echo -e '\n\u2705'

## Then generate the corresponding number of (simulated) faulted signatures
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
  make Gen_Signs_KeyKAT$ALG > NUL
else
  make Gen_Signs_KeyKAT$ALG > /dev/null
fi
echo '>>> Generating faulted signs ' 
./Gen_Signs_KeyKAT$ALG $NBSIGNS
echo ' '
echo -e '\u2705'

## Finally filter the ones that give inequalities on $\mathbf{s}_2$
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
  make Filter_Signs_Proposition3$ALG > NUL
else
  make Filter_Signs_Proposition3$ALG > /dev/null
fi
echo '>>> Filtering faulted signs ' 
./Filter_Signs_Proposition3$ALG $NBSIGNS
echo ' '
echo -e '\u2705'