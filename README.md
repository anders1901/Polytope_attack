# Finding a Polytope: A Practical Fault Attack against Dilithium

This repository contains the artifact related to the corresponding article.

> ⚠️ This artifact is only tested for Linux distributions.

-----
## Prerequisites

The following is required:

* Python >= 3.9
* Pipenv
* lpsolve5.5
* Dilithium (commit 3e9b9f1)

### Installation Steps
1. Check Python version:  
```bash
python --version # on some systems try python3 --version
```
If not installed or outdated, you can install it with:
```bash
sudo apt-get install python3-full
```

2. Check Pip version:  
```bash
pip --version
```
If not installed, use:
```bash
apt install python3-pip
```

3. Check Pipenv version:  
```bash
pipenv --version
```
If not installed, run:
```bash
pip install --user pipenv --break-system-packages  
```  

4. The library lpsolve for Python is used for faster LP solver and ILP solver but the installation can be tedious. Alternatively you can skip this installation and perform the resolution part with scipy.  

   1. Install lpsolve with the provided package. This will create a shared library file in ```lp_solve_5.5/lpsolve55/bin/platform/liblpsolve55.so```, where `/platform/` depeends on your platform:
```bash
cd lp_solve_5.5/lpsolve55
sh ccc
```
   2.  Export the complete path to the shared library file to the environment variable:
 ```bash
export LD_LIBRARY_PATH=/start/of/path/lp_solve_5.5/lpsolve55/bin/platform/liblpsolve55.so
```  
   3.  Install lpsolve extension into site-packages.
```bash
python setup.py install
python setup.py bdist
```

5. For some of the test, the Dilithium reference implementation requires OpenSSL. Install it (if needed) with:
```bash
sudo apt-get install openssl libssl-de
```
------
## Recommended Execution Order
### C part (faulted signature generation and detection of useful ones)
In the following: 
   - `$ALG` refers to the Dilithium security level (2, 3, or 5) 
   - `$NB_KEYS` corresponds to the number of keys from the KAT file to produce 
   - `$NB_SIGNS` the number of faulted signatures to do for each key tested.  

For an end-to-end generation of faulted signatures and filtration of interesting ones on the specification of Dilithium, in `Polytope_Attack/` use the script 
```bash
./full_signs_spec.sh
```
Then, with the set of signatures in `Polytope_Attack/Additionnal_files/Signs_filtered/`, you can directly skip to the Python part.

Alternatively, you can do the steps independently. It is recommend to be in `Polytope_Attack/Additionnal_files/C_functions/`.  

1. Generate the KAT files using the script `PQCgenKAT_sign_Modified.c`:
```bash
make PQCgenKAT_sign_Modified$ALG
./PQCgenKAT_sign_Modified$ALG $NB_KEYS
```

2. Generate the faulted signatures associated with each key:
- For the specification of Dilithium using the script `Gen_Signs_KeyKAT.c`
```bash
make Gen_Signs_KeyKAT$ALG
./Gen_Signs_KeyKAT$ALG $NB_SIGNS
```

- For the implementation of Dilithium using the script `Gen_SignsRef_KeyKAT.c`
```bash
make Gen_SignsRef_KeyKAT$ALG
./Gen_SignsRef_KeyKAT$ALG $NB_SIGNS
```

3. Filter for the signature providing information on $\mathbf{s}_2$:
- For signatures produced using the specification of Dilithium using the script `Filter_Signs_Proposition3.c`:
```bash
make Filter_Signs_Proposition3$ALG
./Filter_Signs_Proposition3$ALG $NB_SIGNS
```

- For signatures produced using the implementation of Dilithium using the script `Filter_Signs_Proposition5.c`:
```bash
make Filter_Signs_Proposition5$ALG
./Filter_Signs_Proposition5$ALG $NB_SIGNS
```

4. To verify Assumption 2 from the paper use the script `Verify_Assumption2.c` (not necessary for the attack):
```bash
make Verify_Assumption2$ALG
./Verify_Assumption2$ALG $NB_SIGNS
```

### Python part (for LP generation and solving based on interesting signatures)
Make sure you have the file `Polytope_Attack/Additionnal_files/Signs_filtered/Dilithium$ALG/$NB_SIGNSSignsKAT_keyKEY_TARGET_filtered.rsp` before continuing.  

1. Install Virtual Environment Dependencies
```bash 
pipenv install
```

2. Activate the Virtual Environment 
```bash 
pipenv shell
```

4. Launch Jupyter Notebook 
```bash 
jupyter notebook
```

5. Analyze the set of useful signatures and generate the resulting LP problems for each polynomial of the vector $\textbf{s}_2$ with:  
`Polytope_Attack/Additionnal_files/Notebooks/Formulate_LP_instance.ipynb`: 


6. Solve the LP instances created with the previous notebook and verify the results using:  
`Polytope_Attack/Additionnal_files/Notebooks/Solve_ILP_instance.ipynb`
------
## Files
| Name                   | Description                                              |
| :---                   | :---                                                     |
| `Additional_files`     | Additional material used for the attack                  |
| `dilithium-master`     | Reference implementation of Dilithium from   [GitHub](https://github.com/pq-crystals/dilithium/tree/3e9b9f1412f6c7435dbeb4e10692ea58f181ee51)               |
| `lp_solve_5.5`         | Library used to solve LP systems                     |
| `full_signs_spec.sh`   | Bash script to automate generation of useful faulted signatures    |

------
## License

This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

[![CC BY 4.0](https://i.creativecommons.org/l/by/4.0/88x31.png)](http://creativecommons.org/licenses/by/4.0/)

See [LICENSE.txt](./LICENSE.txt).

This artifact uses the Dilithium reference implementation from [GitHub](https://github.com/pq-crystals/dilithium), under the Apache 2.0 License, as a submodule.

