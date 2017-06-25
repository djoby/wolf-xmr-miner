# XMR Wolf Miner - xmrwm

```
NOTE: Wolf's XMR Miner is no longer maintained - please use https://github.com/genesismining/sgminer-gm.git
```

## Requirement 

```
gcc 5 or newer
```

## Dependencies

```
libjansson-dev
```

## Building and running

```
make clean && make
./miner xmr.conf
```

## Sample Conf

```
olag@barmv8-01:~$ cat xmrwm/xmr.conf
{
  "threads": 3,
  "pools":
  [
    {
      "url": "stratum+tcp://xmr-eu1.nanopool.org:14444",
      "user": "<xmr address>.xmrwm-01",
      "pass": "x"
    },
    {
      "url": "stratum+tcp://xmr-eu2.nanopool.org:14444",
      "user": "<xmr address>.xmrwm-01",
      "pass": "x"
    }
  ]
}
olag@barmv8-01:~$ 
```

