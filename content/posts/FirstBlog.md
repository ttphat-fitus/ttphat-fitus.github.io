---
title: "ssmal Writeup"
date: 2026-02-24
draft: false
math: true
summary: "When they leak the high bits of p+q, the rest is just a distributed search — rent the cloud and flex."
tags: ["CTF", "RSA", "Cryptography"]
showToc: true
TocOpen: true
---

# ssmal

> When they leak the high bits of p+q, the rest is just a distributed search — rent the cloud and flex.

---

## Challenge Description
`chall.py`
```python
from Crypto.Util.number import getPrime, isPrime

p = getPrime(256)
q = getPrime(256) 
N = p*q

e = 65537

flag = b'BPCTF{redact}' 
c = pow(int.from_bytes(flag, 'big'), e, N)
gift = (p+q)>>40
print(f'N = {N}\nc = {c}\ngift = {gift}')


"""
N = 5758124415184468271370250630048687746812715972269092676700260830924771547226161680827118153372606993872590019171624226415454063566537634596851695999313069
c = 4258014490469377191207443169980969026536758269486705363402307773455639773007422079769567310663689852817179059312032143236005345809847891632360620594960862
gift = 139200565274113272217771369795858181556454302427519574149545982701
"""

```

The program leaks `N = p*q`, the ciphertext `c`, and `gift = (p+q) >> 40` — an approximation of `s = p+q` with the lower 40 bits removed. Recovering `p` and `q` (and thus `d`) reduces to finding the unknown 40 lower bits of `s`. Once `p,q` are recovered, decrypt `c` to obtain the flag.

---

## Code Review

This is a classic **partial-sum leak** RSA problem:

* If `s = p + q` were known exactly, `p` and `q` are roots of `x^2 - s x + N = 0`.
* With `gift = s >> 40`, we have `s = (gift << 40) + k` for unknown `k` in `[0, 2^40)`.
* For each candidate `k` compute `D = s^2 - 4N`. If `D` is a perfect square then `p = (s + sqrt(D)) // 2` and `q = (s - sqrt(D)) // 2`. Verify `p*q == N`.
* So the problem is an **exhaustive search over 2^40 candidates**, with plenty of ways to prune and parallelize.

This leakage is fatal but straightforward: leaking the high bits of `p+q` turns factorization into a bounded brute-force search rather than requiring subexponential factoring.

---

## Solution

1. Compute `s0 = gift << 40`.
2. For `k` in `0 .. 2^40 - 1` (parallelize!):

   * `s = s0 + k`
   * `D = s*s - 4*N`
   * If `D < 0` continue. Let `r = isqrt(D)`. If `r*r == D` then candidate found.
   * Compute `p = (s + r) // 2`, `q = (s - r) // 2`. Verify `p*q == N`.
3. Compute `d = inverse(e, (p-1)*(q-1))` and `m = pow(c, d, N)`; convert `m` to bytes to get the flag.

---

## ssmal Slayer

`solve.sage`

```python
import sys
from Crypto.Util.number import long_to_bytes
from sage.all import Integer

if len(sys.argv) != 3:
    print("Usage: sage solve.sage <start_k> <end_k>")
    sys.exit(1)

start_k = Integer(sys.argv[1])
end_k = Integer(sys.argv[2])

N = Integer("5758124415184468271370250630048687746812715972269092676700260830924771547226161680827118153372606993872590019171624226415454063566537634596851695999313069")
c = Integer("4258014415184468271370250630048687746812715972269092676700260830924771547226161680827118153372606993872590019171624226415454063566537634596851695999313069")
gift = Integer("139200565274113272217771369795858181556454302427519574149545982701")
e = 65537

print(f"Finding k from {start_k} to {end_k-1}...")

s_approx = gift << 40
Dk = (s_approx + start_k)**2 - 4*N
add_term = 2*(s_approx + start_k) + 1

for k in range(start_k, end_k):
    if Dk.is_square():
        p_minus_q = Dk.isqrt()
        s = s_approx + k
        p = (s - p_minus_q) // 2
        q = (s + p_minus_q) // 2
        
        if p * q == N:
            print(f"Found solution at k = {k}")
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, N)
            
            m_int = int(m)
            flag_bytes = long_to_bytes(m_int)
            flag_string = flag_bytes.decode()
            print(f" {flag_string}")
    Dk += add_term
    add_term += 2
```

---

## Now it's time for money to talk🐧

When the math is done, the last stage is pure engineering muscle — buying compute time and showing off your hardware.

So the simple job is to go to Google Cloud Platform (GCP) and rent the most powerful and expensive compute instances they have.
Hmm, the C4 chip series with 288 vCPUs, 144 cores, and 576 GB of memory seems good. Besides, to drain my money, I’ll add some NVIDIA H100 80GB GPUs to my instance to test something funny later 🐧.

With those electricity-grid destroyers, my goal is to run many parallel workers, each searching a small shard of the `2^40` space. Each worker runs the optimized code above (with small-prime prefilters and gmpy2/C for speed) and returns immediately when it finds the correct `k`.
![htop](/images/htop.png)

So now watch the CPUs burn through cycles to brute-force `2^40` values.

After just over 2 hours, the master node printed:
![found](/images/found.png)
The flag was harvested. Sometimes, throwing money at math really *does* work.

Then decode the found value to get the flag.

---

## FLAG

```
BPCTF{l4w_priv4ate_key_attack_easy_right?}
```
---

## Takeaway

* Leaking high bits of `p+q` reduces factorization to a bounded brute-force problem.
* Engineering and parallelism win: small-prime prefilters + GMP + massive parallelism make 2^40 feasible.

