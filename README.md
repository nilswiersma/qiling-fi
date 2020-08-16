# qiling-fi

Using qiling to build simple scripts simulating fault injection models. 
Some FI extensions in `QilingFi.py`.
Script template with `TODO`s in `qiling_template.py`.

Tested in Ubuntu 18.04 and WSL Ubuntu 18.04

# Set up qiling and other packages

https://docs.qiling.io/en/latest/install/

```
python3 -m venv venv
. venv\bin\activate
python -m pip install qiling --pre
python -m pip install tqdm
```


# Compile ifelse.c, generate inline disassembly

Set up arm compiler:
```
apt install gcc-8-arm-linux-gnueabi
```

Compile and dump:
```
cd ifelse
arm-linux-gnueabi-gcc-8 -static -g ifelse.c -o ifelse
arm-linux-gnueabi-objdump -S ifelse > ifelse.objdump
```

`ifelse.objdump` can be used to very conveniently find addresses etc.

# Run ifelse with different fault models

Some example fault models in `fault_models.py`.
Testing them on the `ifelse` binary:

```
python3 ifelse.py singlebit
python3 ifelse.py nop
python3 ifelse.py random
```

Pause with CTRL-C.

## Some details
`ql.patch` to patch the binary with the faulty instruction.

`ql.hook_code(asm_trace)` to use capstone to decompile portions of the binary, useful for tracing

While executing counters and progress are printed using tqdm:
```
FREE_BEER: 1 | NO_BEER: 106 | EXCEPTION: 40:  26%|█████████▍                          | 174/661 [00:28<01:19,  6.12it/s]
```

Stuff is logged to sqlite3 database:
![database.png](database.png)

# SQL queries and results with random bytes

FREE BEER counts with random bytes at the compare instruction:
```
SELECT data,count(id),1.0*count(id)/(sum(count(*)) over()) AS frac FROM log_1596811491505 GROUP BY data
```
|  Output                  | Count |  Frac                 |
|--------------------------|-------|-----------------------|
|                          | 8763  | 0.605137766728817     |
|\x01                      | 1     | 6.90560044195843e-05  |
|FREE BEER                 | 187   | 0.0129134728264623    |
|FREE BEER\x0a             | 180   | 0.0124300807955252    |
|\x4c\xcf\xf3\x7f          | 1     | 6.90560044195843e-05  |
|NO BEER                   | 3433  | 0.237069263172433     |
|NO BEER\x0a               | 1786  | 0.123334023893378     |
|NO BEER\x0aFREE BEER\x0a  | 130   | 0.00897728057454596   |

Exception counts:
```
SELECT exception,count(id),1.0*count(id)/(sum(count(*)) over()) AS frac FROM log_1596811491505 GROUP BY exception
```
|  Exception                                          |  Count |  Frac                 |
|-----------------------------------------------------|--------|-----------------------|
| 	                                                  |  11261 | 0.657730272764441     |
| Invalid instruction (UC_ERR_INSN_INVALID)           |  1821  | 0.106360609777466     |
| Invalid memory read (UC_ERR_READ_UNMAPPED)          |  2723  | 0.159044448338298     |
| Invalid memory write (UC_ERR_WRITE_UNMAPPED)        |  1034  | 0.0603936685941242    |
| Write to write-protected memory (UC_ERR_WRITE_PROT) |  281   | 0.0164125927223877    |
| _hook_intr_cb : catched == False                    |  1     | 5.84078032825185e-05  |


# Annotated objdump

Script to parse sqlite db and add notes to the objdump (set the right TABLE_NAME manually):
```
python annotate_objdump.py
```

Example outputs added to repo, see also screenshot below:
![free_beer_flip.png](free_beer_flip.png)


# 1000 randomized ifelse with and without snapshots

Without:

```
100%|███████████████████████████████████████████████████████████████████████████████| 1000/1000 [02:26<00:00,  6.84it/s]
```

With:
```
100%|███████████████████████████████████████████████████████████████████████████████| 1000/1000 [00:33<00:00, 29.45it/s]
```

With snapshots and tqdm thread_map:
```
100%|███████████████████████████████████████████████████████████████████████████████| 1000/1000 [00:40<00:00, 24.74it/s]
```

With snapshots and tqdm process_map:
```
100%|███████████████████████████████████████████████████████████████████████████████| 1000/1000 [00:19<00:00, 51.93it/s]
```