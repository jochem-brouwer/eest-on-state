Running EEST tests on top of any state
=====
This tool allows to build payloads on top of any state and run EEST tests. Following this procedure will:

1. Launch a Geth node with an OverlayFS mount to prevent editing the original state/snapshot.
2. Setup a MITM proxy to capture all the payloads/FCUs created by this tool or EEST to replay later.
3. Setup the network by funding a test account and setting the gas limit to the desired value (60M)
4. Run EEST test(s). This will invoke the block builder of the EL client.
5. Replay the payloads. This will not run block builder logic, but directly the execution path.

Once a test payload has been made, it can be reran against a client at any time. By setting the state to the original state it will import and execute the blocks like on a live network (as instructed by the CL).

Preparation
========

Ensure the datadir of your client is in `./snapshot`. If docker tooling is provided, the script will create an OverlayFS for you to prevent this tooling to edit any data of the original snapshot. If no tooling is provided it is recommended to use OverlayFS to prevent updates to the base snapshot. If no script is provided or you wish to use custom tooling, ensure that the engine API port is 8551, the jwt is read from `./jwt/jwt.hex` and the JSON RPC API port is 8545.

For a fresh start, ensure `docker stop geth-bench` (or `besu-bench`) and to wipe the past changes to the state `rm -rf overlay-*` folders.

Commands
========

```
# Ensure MITM is running to capture payloads
mitmdump --mode reverse:http://127.0.0.1:8551 -p 8550 -s save_payloads.py
```

In another terminal:
```
python3 start_geth.py # Start Geth with the OverlayFS mount
# Or python3 start_besu.py for Besu
python3 start_test.py # Fund test account and set gas limit to desired value
```

From the EEST repository (from this remote/branch: https://github.com/jochem-brouwer/execution-spec-tests/tree/xen-state-tests):

```
uv run execute remote --engine-endpoint http://localhost:8550 --engine-jwt-secret-file /PATH/TO/THE/REPOSITORY/jwt/jwt.hex --rpc-endpoint http://localhost:8545 --rpc-seed-key 0x45A915E4D060149EB4365960E6A7A45F334393093061116B197E3240065FF2D8 --fork Prague -m benchmark ./tests/benchmark/mainnet/test_state_xen.py --get-payload-wait-time 11 -k xen_approve_set
```

This runs the EEST test (here: `test_xen_approve_set_only`) against the engine API. Your node will build the payload and EEST will ensure the client sets that payload as head block.

To replay payloads (and to thus run the execution paths non-block builders use): `python3 send_payloads_and_fcu.py --requests-file captures_engine_requests_[TIME].ndjson`.

Notes
=====

Notes to EEST command: `--get-payload-wait-time 11` ensures EEST does not interrupt the payload building especially for the slow blocks. This number can be tweaked to allow for faster payload generation, but if EEST throws then the payload build time is too short (will resolve this issue in EEST).

`--engine-endpoint` should point to the MITM in order to save the payloads.

`--chain-id <NUMBER>` should be added for any non-mainnet chain.

This test `xen_approve_set` is a short test which will spam-approve the XEN contract. It will thus approve() as much as approvals which are possible, to non-existing slots.

Once the test is done, the `captures_engine_requests_[TIME].ndjson` file has captured the payloads which are necessary to re-run the payloads. It is now ok to wipe the state, so `docker kill geth-bench` and then `rm -rf overlay-*; umount overlay-mount; rm -r overlay-mount` to wipe the state. Now start geth `python start_geth.py`.

To rerun the just-created payloads, `python3 send_payloads_and_fcu.py --requests-file captures_engine_requests_[TIME].ndjson`.

Setup/Troubleshooting
=====

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To setup Geth, ensure the state directory is in snapshot, such that it looks like this:

```
./snapshot
├── blobpool
├── chaindata
├── nodes
└── triedb
```

