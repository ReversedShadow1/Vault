# PQC Toolchain Setup (liboqs / liboqs-python)

`liboqs-python` is a thin wrapper — it needs the actual `liboqs` C library
built and on the loader path. This is a one-time setup step, documented here
so it's reproducible on another machine (or by whoever grades/reviews this).

## What we built

A **minimal** liboqs build containing only the two algorithms this project
uses — `ML-KEM-768` and `ML-DSA-65` — rather than the full algorithm zoo.
This cuts build time down substantially and matches the "only what's
specified" principle from the plan (§4 tech stack).

## Prerequisites

```bash
sudo apt-get install -y cmake ninja-build build-essential libssl-dev
pip install liboqs-python --break-system-packages
```

## Build steps

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build

cmake -GNinja \
  -DCMAKE_INSTALL_PREFIX=/root/_oqs \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_DIST_BUILD=OFF \
  ..

ninja
ninja install
```

`OQS_MINIMAL_BUILD` is the key flag — without it, liboqs builds every NIST
PQC candidate and finalist, which is unnecessary here and much slower.

## Running anything that imports `oqs`

The shared library isn't on the default loader path, so set:

```bash
export LD_LIBRARY_PATH=/root/_oqs/lib:$LD_LIBRARY_PATH
```

Add this to your shell profile or a project `.env` for convenience. The
Week 3 sync module and its tests will need this set too — worth wrapping
in a small `scripts/run_with_pqc_env.sh` once the sync server exists, so
nobody has to remember it by hand.

## Verifying the install

```bash
python3 -c "
import oqs
print(oqs.get_enabled_kem_mechanisms())
print(oqs.get_enabled_sig_mechanisms())
"
```
Expected output: `('ML-KEM-768',)` and `('ML-DSA-65', 'ML-DSA-65-extmu')`
(the `-extmu` variant is a message-pre-hashing mode included automatically;
we use plain `ML-DSA-65`).

## Sanity-check scripts

- `sync/pqc_test_kem.py` — ML-KEM-768 keygen/encapsulate/decapsulate
- `sync/pqc_test_sig.py` — ML-DSA-65 sign/verify, including tamper and
  wrong-key rejection checks

Both are standalone (per spec Week 2 deliverable) — not wired into the
vault or sync protocol yet. That integration is Week 3.
