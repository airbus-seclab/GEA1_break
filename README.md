# GEA1_break

This tool is an implementation of the attack against the GEA-1 described
in [Cryptanalysis of the GPRS Encryption Algorithms GEA-1 and GEA-2](https://eprint.iacr.org/2021/819.pdf).
This algorithm is one of the GPRS native algorithm and does not provide
the expected level of security, being easily breakable using a single
computer.

## Table of content

1. [Compiling](#compiling)
2. [Usage](#usage)
3. [Howto](#howto)
4. [Performance](#performance)
5. [Optimization](#optimizing)
6. [Authors & contributions](#authors)

## Compiling

First install the `libm4ri` development package on your favorite Linux 
distribution and then type:

```bash
make
```

## Usage

```
$ ./gea1_break --help
Usage: gea1_break [OPTION...] 

Implementation of the attack described in https://eprint.iacr.org/2021/819.pdf
to recover GEA-1 keys.

  -a, --all                  prevent an early exit in stage #2
  -b, --bench                Run the benchmarks mode
  -c, --core=nr_cores        The number of cores to use (default is maximum
                             available)
  -d, --dir=dir              The directoring storing the results of the
                             precomputation
  -f, --flag=dir_flag {0,1}  The direction flag
  -i, --iv=iv (hex)          The IV
  -k, --keystream=keystream (hex)
                             The keystream
  -l, --length=keystream length (bits)
                             The keystream length (must be >= 48 && <= 64)
  -p, --precomputation       Run the precomputation sage (stage #1)
  -r, --reverse              Return the key based on the IV and dir_flag (stage
                             #3)
  -s, --state=recovered_state (hex)
                             The S recovered in stage #2
  -t, --tests                Run in test mode
  -v, --verbose              Increase the verbosity level (default: 0)
  -x, --bruteforce           Run the key recovery stage (stage #2)
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to roderick.asselineau@{__no_spam__}airbus.com.
$
```

## Howto

You can (and you should) test all the internal algorithms using the (default)
`-t` command:
```
$ ./gea1_break -t
[+] Satety tests
        -> OK [0.01s]
```

If an `assert()` is triggered then it is probably the sign that you found
a bug and that you won't be able to run correctly the program (for now).

To recover the secret key used to generate some known keystream, you need
to generate a set of tables first using `-p`:
```
$ ./gea1_break -p --dir mytables
```

This precomputes tables within the `./mytables/` directory. This operation
only needs to be done _once_ and should only take a couple of minutes on
a _recent_ computer. Please notice that there is a set of tables for each 
of the two backends. Selecting the backend is done at the compilation time
by assigning `OPTIM_LOOKUP` either to `OPTIM_LKUP_CUCKOO` (default) or to
`OPTIM_LKUP_BSEARCH` (much slower in general).

The second step is to recover the internal state `S` for a given bitstream
using the `-x` option. `gea1_break` comes in two flavors: the `single` mode
and the `batch` mode, depending on the compilation flag `OPTIM_BATCH` (0 or 1).

In the `single` mode, `gea1_break` is optimized to break a unique key. However
it is possible that you may actually need to recover two (or even more)
keys in which case using the `batch` mode would definitely be better for
you since the computation is _mutualized_.

### Single mode
 
```
$ make clean && make EXT="-DOPTIM_BATCH=0"
[...]
$ ./gea1_break -V
GEA1_break v0.3 - cuckoo/single/high
$ ./gea1_break -x --dir ./mytables --keystream 14b36a6fb803c7bb -l 64
[...]
[+] State found in 24663.00s [411.05m]!
 UB = 38740ac2
 V = ac
 T = da2e48
 S = 243c504a2733bce6
[...]
```

### Batch mode

```
$ make clean && make EXT="-DOPTIM_BATCH=1"
[...]
$ ./gea1_break -V
GEA1_break v0.3 - cuckoo/batch/high
$ ./gea1_break -x --dir ./mytables --batch 14b36a6fb803c7bb:64,88a63c9dad536a11:64
[+] Batch mode! Attempting to crack:
        -> [b00] 14b36a6fb803c7bb (64) [mask:ffffffffffffffff]
        -> [b01] 88a63c9dad536a11 (64) [mask:ffffffffffffffff]
[...]
[+] State found for b01 in 24210.00s [403.50m]!
 S = 713ed89153b804f0
[...]
[+] State found for b00 in 42702.00s [711.70m]!
 S = 243c504a2733bce6
[...]
```

### Recovering `K`

Once `S` is recovered, `K` can be computed by providing the `IV` (as an
`uint32_t`) and the direction flag `f` (0 or 1):

```
$ ./gea1_break -r --iv 88d64f69 --state 713ed89153b804f0 -f 1
K = 78b1bfcfe3ca4b65
```

`K` is returned as an `uint64_t` integer as well. In that regard, please
understand that `uint{32,64}_t` types are used as convenient storage areas.
`K`'s _ith_ bit should be retrieved using the classic `(K >> i)&1`. The
same logic applies to `IV` and `S`.

### A few observations

In the last mode, the key recovery process accelerates each time a key is
recovered and asymptotically converges toward the speed of the `single`
mode.

In [Cryptanalysis of the GPRS Encryption Algorithms GEA-1 and GEA-2](https://eprint.iacr.org/2021/819.pdf),
the authors recover each secret key using 65 bits of keystream. According 
to our practical observations though, 64 bits of keystream is enough. As
a result it is convenient to store the keystream as an `uint64_t` with a
maximum size of 64 bits (by definition). This is comfortable for a number
of reasons including saving memory and speeding up computations.

The default behavior of the program is to stop the computation whenever
a key candidate has been found for each specified keystream. However there
are two exceptions:

* If one of the keystreams is smaller than 64 bits (for example 61 bits 
  long using the `-l` option of the `single` mode) then by definition multiple
  candidates per keystream pop up and the program cannot tell which ones
  are the false positives. For this reason `gea1_break` computes all the
  candidates and only stops when the computation is over.
* If the `--all` option is set then the early exit is disabled no matter
  the size of the keystream.

## Performance

It is difficult to measure accurately the performance difference between
the original paper and this implementation since the hardware is not the
same at all and some design choices are obviously different. However you
may be able to roughly estimate the running time on your computer based
on the tests that we made.

All the following tests were performed on an old DELL server with the
following characteristics:

* 2x Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz
* cache size: 20480 KB
* 8x physical cores / CPU, 16x virtual cores / CPU (HT)
* 64 GB of RAM

Note: The code is _not_ currently designed to run on a cluster. This may
change in the future should the need occur.

### Generating the tables

Generating the `cuckoo` tables:
```
$ make clean && make EXT="-DOPTIM_LOOKUP=OPTIM_LKUP_CUCKOO" -j`nproc`
$ time ./gea1_break -p --dir ./tables_cuckoo
```

Or generating the `bsearch` tables (not recommended):
```
$ make clean && make EXT="-DOPTIM_LOOKUP=OPTIM_LKUP_BSEARCH" -j`nproc`
$ time ./gea1_break -p --dir ./tables_bsearch
```

If compiled with `-DOPTIM_MEM=OPTIM_MEM_HIGH` which is the default option:

| Backend name    | Generation Time  | RAM Required  | Space required (*) |
| --------------- | ---------------- | ------------- | ------------------ |
| Cuckoo          | ~5m30            | <20 GB        | 41 GB              |
| Bsearch         | ~4m40            | <20 GB        | 33 GB              |


(*): This requires to remove the `unsorted_` files within the precomputation
directory.


### Cracking a key (cuckoo/single)

Searching through the whole key space takes us between 12h and 13h as 
demonstrated below:

```
$ time ./gea1_break -v -x --dir ./table24_cuck04 --keystream 14b36a6fb803c7bb -l 64 --all
[+] Preparing V, B, TAC basis
        -> OK [0.32 ms]
[+] Preparing MA, MB, MC
        -> OK [0.36 ms]
[+] Preparing the v elements for all the cores
        -> OK [0.37 ms]
[+] Loading hash tables [0,127] from ./table24_cuck04/
        -> OK [31s]
[+] Generating RegA+RegC keystreams (2^32) [Full]
        -> using 32 cores
        -> All LP have terminated
        -> OK [24953s]
[+] Unloading hash tables from ./table24_cuck04/
        -> OK [3s]
[+] Loading hash tables [128,255] from ./table24_cuck04/
        -> OK [54s]
[+] Generating RegA+RegC keystreams (2^32) [Full]
        -> using 32 cores
[+] State found in 26229.00s [437.15m]!
        UB = 38740ac2
        V = ac
        T = da2e48
        S = 243c504a2733bce6
        -> All LP have terminated
        -> OK [21554s]
[+] Unloading hash tables from ./table24_cuck04/
        -> OK [1s]

real    776m36.133s
user    23213m50.278s
sys     286m23.211s
```

One can observe that during this run our first round completed within 6h
when the second one took a 1 hour penalty (while doing the same amount of
computation) which may be because of other jobs running on the server. 
With such results we can expect to recover a single key in half that time
on average thus with ~6.5h of computation.

```
$ (time stdbuf -oL ./gea1_break -v -x --dir ./table24_cuck04 --keystream 14b36a6fb803c7bb -l 64 2>&1) 2>&1 | tee single_14b36a6fb803c7bb.txt
[+] Preparing V, B, TAC basis
        -> OK [0.29 ms]
[+] Preparing MA, MB, MC
        -> OK [0.35 ms]
[+] Preparing the v elements for all the cores
        -> OK [0.37 ms]
[+] Loading hash tables [0,127] from ./table24_cuck04/
        -> OK [17s]
[+] Generating RegA+RegC keystreams (2^32) [Full]
        -> using 32 cores
        -> All LP have terminated
        -> OK [22232s]
[+] Unloading hash tables from ./table24_cuck04/
        -> OK [2s]
[+] Loading hash tables [128,255] from ./table24_cuck04/
        -> OK [31s]
[+] Generating RegA+RegC keystreams (2^32) [Full]
        -> using 32 cores
[+] State found in 23435.00s [390.58m]!
        UB = 38740ac2
        V = ac
        T = da2e48
        S = 243c504a2733bce6
        -> All LP have terminated
        -> OK [1154s]
[+] Unloading hash tables from ./table24_cuck04/
        -> OK [1s]

real    390m36.541s
user    11898m11.818s
sys     123m3.758s
```

The RAM requirement to complete this stage is ~23 GB (`OPTIM_MEM_HIGH`)
and ~12 GB (`OPTIM_MEM_LOW`).


### Cracking multiple keys (cuckoo/batch)

The running time is tied to the number of keys. Attempting to break five
testvectors from [this file](https://github.com/Dude100/MediaTek-HelioX10-Baseband/blob/591772a0d659ef0f7bba1953d18f8fe7c18b11de/(FDD)MT6795.MOLY.LR9.W1423.MD.LWTG.MP.V24/driver/cipher/include/gcu_ut.h)
gives us:

```
$ time ./gea1_break -v -x --dir ./table24_cuck04/ --batch 8ac31421ab98a11f:64,14b36a6fb803c7bb:64,88a63c9dad536a11:64,c725804289b920d2:64,8ac45e0f6419395a:64,3ff638812ee23296:64
[+] Batch mode! Attempting to crack:
	-> [b00] 8ac31421ab98a11f (64) [mask:ffffffffffffffff]
	-> [b01] 14b36a6fb803c7bb (64) [mask:ffffffffffffffff]
	-> [b02] 88a63c9dad536a11 (64) [mask:ffffffffffffffff]
	-> [b03] c725804289b920d2 (64) [mask:ffffffffffffffff]
	-> [b04] 8ac45e0f6419395a (64) [mask:ffffffffffffffff]
	-> [b05] 3ff638812ee23296 (64) [mask:ffffffffffffffff]
[+] Preparing V, B, TAC basis
	-> OK [1.68 ms]
[+] Preparing MA, MB, MC
	-> OK [1.72 ms]
[+] Preparing the v elements for all the cores
	-> OK [1.72 ms]
[+] Loading hash tables [0,127] from ./table24_cuck04//
	-> OK [29s]
[+] Generating RegA+RegC keystreams (2^32) [Full]
	-> using 32 cores
[+] State found for b02 in 24210.00s [403.50m]!
	UB = 94e9e91c
	V = d
	T = becfe1
	S = 713ed89153b804f0
[+] State found for b03 in 37807.00s [630.12m]!
	UB = 67685e4e
	V = 6c
	T = 2fac34
	S = 43c43be610d42616
	-> All LP have terminated
	-> OK [40507s]
[+] Unloading hash tables from ./table24_cuck04//
	-> OK [0s]
[+] Loading hash tables [128,255] from ./table24_cuck04//
	-> OK [42s]
[+] Generating RegA+RegC keystreams (2^32) [Full]
	-> using 32 cores
[+] State found for b01 in 42702.00s [711.70m]!
	UB = 38740ac2
	V = ac
	T = da2e48
	S = 243c504a2733bce6
[+] State found for b05 in 57419.00s [956.98m]!
	UB = a437ea66
	V = c5
	T = 250c10
	S = 51dc282bfb0479f3
	-> All LP have terminated
	-> OK [28720s]
[+] Unloading hash tables from ./table24_cuck04//
	-> OK [1s]

real 1154m59.552s
user 34861m59.565s
sys  361m49.503s
```

One can observe that the state corresponding to the first testvector
(which is in fact quite _special_) and is not recovered and neither is
the 4th candidate forcing the program to continue until the very end.

Practically speaking in 956.98m (~16h) we recovered 4 different states thus
four different keys so the benefit of this mode is obvious. The RAM 
requirement during this stage is also ~23 GB (`OPTIM_MEM_HIGH`) and ~12 GB
(`OPTIM_MEM_LOW`).


## Optimization


You may want to play with a couple of flags within `exploit.h`:

| Optimization name      | Default value     | Description                                                                              |
| ---------------------- | ----------------- | ---------------------------------------------------------------------------------------- |
| OPTIM_BATCH            | 0                 | If enabled, compiles a special version of the program able to handle multiple keystreams.|
| OPTIM_LIN_ALG          | 1                 | Use a linear algebra trick to skip expensive matrix operations                           |
| OPTIM_LOOKUP           | OPTIM_LKUP_CUCKOO | Select the hash table backend, the slowest being `OPTIM_LKUP_BSEARCH`                    |
| OPTIM_MEM              | OPTIM_MEM_HIGH    | Select the memory requirements policy. `OPTIM_MEM_HIGH` expects 64 GB of RAM.            |
| OPTIM_SCHED            | 1                 | Change the scheduling policy to the most interesting depending on the current task       |
| OPTIM_SKIP_COLLISIONS  | 1                 | Skip handling collisions within the hash table (some keys may not be broken as a result).|

Generally speaking unless you know what you do, we recommend to keep the
default flag values for the best performances.

Note: `OPTIM_SKIP_COLLISIONS` is the default behavior and handling collisions
thus 100% of the keys is currently not implemented.

## FAQ


#### Q: What will be the next features?

Handling the collisions is likely to appear within a couple of days.

A major modification of the cli in order to integrate `bitmasks` and arbitrary
long keystreams. While we have not tested it, it seems likely that, in 
some cases, you may have difficulties to extract 64 consecutive bits of 
keystream. As a result it makes sense to provide a mask and to extend the
bitstream size since otherwise this would increase the number of false 
positives. This is meant to be addressed in the short term as well.

A full memory version with extended precomputed tables is an option and
likely to be one of our priorities (when we get time though).

Modifying the program to allow it to run on a (heterogeneous) cluster is
another option.

None of these options takes time to implement but testing does.

#### Q: Will there be a `gea2_break`?

Perhaps! If enough people sign the petition ;>

#### Q: Can you give me a trick to estimate the average/worst running time on my machine?

Edit `exploit.h` and set `NR_BITS_UB` to `24` then recompile the binary.
Note the `demo` tag appearing the version:

```
$ ./gea1_break -V
GEA1_break v0.3 - cuckoo/batch/high/demo
```

Now run:
```
$ time ./gea1_break -v -x --dir ./tables25_round_cuckoo4 --keystream d93922ae6ccba015 -l 64 --all
[+] Preparing V, B, TAC basis
 -> OK [0.24 ms]
[+] Preparing MA, MB, MC
 -> OK [0.28 ms]
[+] Preparing the v elements for all the cores
 -> OK [0.29 ms]
[+] Loading hash tables [0,127] from ./tables25_round_cuckoo4/
 -> OK [17s]
[+] Generating RegA+RegC keystreams (2^24) to crack 0xd93922ae6ccba015 [Demo]
 -> using 32 cores
[+] State found in 17.00s [0.28m]!
 UB = e
 V = 5d
 T = 15
 S = 3807cf4fdb121506
 -> All LP have terminated
 -> OK [106s]
[+] Unloading hash tables from ./tables25_round_cuckoo4/
 -> OK [2s]
[+] Loading hash tables [128,255] from ./tables25_round_cuckoo4/
 -> OK [45s]
[+] Generating RegA+RegC keystreams (2^24) to crack 0xd93922ae6ccba015 [Demo]
 -> using 32 cores
 -> All LP have terminated
 -> OK [92s]
[+] Unloading hash tables from ./tables25_round_cuckoo4/
 -> OK [1s]

real 4m23.091s
user 89m31.224s
sys  5m24.429s
```

So basically, what does that tell us? Loading the memory takes a couple 
of seconds. Since it is only done twice and is independent from the complexity
of the attack it is negligible.

On the other hand the keystream generation took respectively 106s and 92s
to perform each 2^23 (similar) operations.

Therefore:
* The full run should take less than 15.08h in the worst case. In fact
since the measure is polluted by the creation/destruction of children
process, 13.08h is a much better approximation and generally speaking you
may consider the lowest measure, unless you intend to have your cores
parasites with other loads.
* On average a key should break within half that time thus 6.5h.

#### Q: The memory requirements are way above what I have currently, is there any hope?

Well yes, you could recompile with `-DOPTIM_MEM=OPTIM_MEM_LOW` which was
meant for configurations with 16 GB of RAM.

#### Q: Using all the cores is too much load on my laptop, how I can use a subset of the available cores?

Use the `-c` option to specify the maximum amount of cores that you want
to use. Running the program without that option is obviously equivalent
to ``-c`nproc` ``.


## Authors & contributions


Roderick ASSELINEAU (main author), Erik-Oliver BLASS (cuckoo backend)

The authors would like to thank:
* Gaëtan LEURENT for gently taking the time to answer to our questions;
* Luc ROUDE and Alexandre GAZET for helping with tests and suggestions;
* Guillaume SYLVAND for sharing a bit of his HP computing knowledge;
* The Airbus' VCE/VCX teams (#rollercoaster).

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.
