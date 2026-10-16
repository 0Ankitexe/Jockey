# JOCKY: project and demonstration guide (through Version 5)

## The idea in one minute

**Digital forensics** means examining a computer's information to learn what happened. JOCKY is a university project with **two working parts**:

1. **JOCKY language unit:** write an investigation as a `.jky` program. The compiler checks it, and a sample runner gives a result from prepared data.
2. **Linux collector unit:** run a separate program *inside a Debian VM*. It reads selected, permitted facts from that VM and writes a JSON report.

The parts **do not connect yet**. A `.jky` program does not start the live collector in Version 5. The browser dashboard only shows whether the controller is running; it does not display reports. Say this clearly during the demonstration.

**Why build it?** An investigation needs clear requests, understandable results and limits on what can be read. The language checks requests before running them. The collector demonstrates bounded, read-only collection from a real Linux machine. The long-term aim is to join these parts.

| Project stage | What was added |
| --- | --- |
| V0 | Shared result formats, basic controller and status dashboard. |
| V1 | Read `.jky` writing and report syntax errors. |
| V2 | Check names, types, targets and function calls. |
| V3 | Make a checked JSON plan (**IR**) and run programs with sample data (**fixtures**). |
| V5 | Separate native Linux collector, real Debian VM tests and a generic-Linux compiler route. |

Version 4 was an earlier Windows plan. The planned V6 integration is where `.jky` source would call native Linux packages. A version printed by a component is not necessarily the project's stage number.

## What runs where

```text
Your normal computer: .jky -> jockyc checks -> sample fixture -> sample result
Debian VM:            approved scope -> jocky-collect-linux -> real VM report
Browser (optional):    dashboard -> controller health/version only
```

The **host** is your real Fedora computer. The **guest** is Debian inside the VM. Use a VM so the demonstration reads a separate machine with known, controlled contents. The original text-only Debian VM was used for saved V5 evidence. A new desktop VM is easier to show with a mouse and keyboard; it is a new demonstration, not the same acceptance test.

## Unit 1: write and run a `.jky` program with sample data

Run these commands on your **normal computer**, in the folder with `Cargo.toml`:

```bash
cd /home/zer0/main/projects/jockey
bash scripts/setup.sh --demo
mkdir -p target/demo
cp examples/triage.jky target/demo/investigate.jky
```

`cd` enters the project. `setup.sh --demo` checks tools and builds the two command-line programs; it may download Rust packages on first use. `mkdir` makes a place for demo output. `cp` makes a writable copy of the example program. To write it yourself, run `nano target/demo/investigate.jky`, paste the program below, save with `Ctrl+O`, `Enter`, and exit with `Ctrl+X`.

```jocky
module triage
target windows | ubuntu

fn investigate(target: endpoint) -> forensic_result {
    let system = forensic.system.profile(target)
    let processes = forensic.process.list(target)
    let connections = forensic.network.connections(target)
    let indicators = forensic.indicator.correlate(system, processes, connections)
    return forensic_result(system, indicators)
}

run investigate on selected_endpoints
```

Read it aloud: `module` names the program. `target` says which **sample platforms** this old example accepts; `ubuntu` is a fixture label, not a claim of live Ubuntu testing. `fn` defines a function. The input `target: endpoint` means “a computer.” `let` stores an answer. The four `forensic.*` calls ask for a system profile, process list, network connections and comparison with supplied indicators. `return` combines the system and indicator answers. `run` selects this function for the chosen sample endpoint. The types after `:` and `->` say what kind of input and result are expected.

Now run one command at a time:

```bash
target/debug/jockyc parse target/demo/investigate.jky
target/debug/jockyc check target/demo/investigate.jky
target/debug/jockyc build-ir target/demo/investigate.jky --output target/demo/investigate.ir.json
target/debug/jockyc verify-ir target/demo/investigate.ir.json
target/debug/jockyc run-fixture target/demo/investigate.jky --fixture examples/fixtures/triage/ubuntu > target/demo/sample-result.json
python3 -m json.tool target/demo/sample-result.json | head -40
```

| Command | What it does | What success means |
| --- | --- | --- |
| `parse` | Checks punctuation and grammar. | Prints `parsed: ...`; the program is written in valid JOCKY syntax. |
| `check` | Checks names, types and allowed calls. | Usually prints nothing; exit code `0` means those checks passed. |
| `build-ir` | Writes a JSON **intermediate representation (IR)**: a checked plan. | `target/demo/investigate.ir.json` exists. It is data, not a Linux executable. |
| `verify-ir` | Checks that saved plan's format and rules. | Usually prints nothing and exits `0`. |
| `run-fixture` | Compiles the source again, supplies prepared answers, writes result JSON. | `sample-result.json` exists. It is a **sample** result, not VM evidence. |
| `json.tool ... | head` | Makes the first lines of JSON readable. | You can inspect the answer. `head` only shortens what is displayed. |

To check the exact outcome without reading a large JSON file:

```bash
python3 - <<'PY'
import json
r = json.load(open('target/demo/sample-result.json'))
print('Mode:', r['mode'])
print('Status:', r['outcome']['status'])
print('Computer:', r['outcome']['value']['value']['system']['hostname'])
print('Indicators:', r['outcome']['value']['value']['indicators'])
PY
```

Expect `Mode: fixture`, `Status: success`, and `Computer: fixture-ubuntu`. `success` means the sample program ran correctly. It does **not** mean the VM was examined. The indicator shown is an authored example match, not malware detection. If `check` reports an error, read its line/column and fix that line. You can show the checker catches mistakes with `target/debug/jockyc check language/tests/fixtures/semantic/invalid/non-bool-condition.jky`; this command is **expected to fail** because a condition has the wrong type.

### What is inside the sample data?

Open [fixture.json](../examples/fixtures/triage/ubuntu/fixture.json) and [expected-result.json](../examples/fixtures/triage/ubuntu/expected-result.json). These are ordinary JSON text files written for a repeatable test.

| Field or call | Plain meaning |
| --- | --- |
| `schema_version` | Which rules the JSON follows. |
| `fixture_id`, `endpoint_id`, `record_id` | Unique labels that link the sample computer and its records. They are not real VM IDs. |
| `observed_at` | Fixed example time, so repeated runs get the same answer. |
| `forensic.system.profile` | Prepared answer: Ubuntu label `fixture-ubuntu`, release `synthetic`. |
| `forensic.process.list` | One invented process: PID `1200`, name `fixture-demo`, path `/fixture/demo`. |
| `forensic.network.connections` | One invented TCP connection tied to that process. The two IPs are example addresses, and port `443` is the remote port. |
| `forensic.indicator.correlate.expected` | Inputs that the sample runner expects from the earlier three calls. This checks that values are passed through correctly. |
| `forensic.indicator.correlate.outcome` | One deliberately authored `fixture_match` pointing to the process and connection record IDs. Its message explicitly says it is not live detection. |
| `expected-result.json` | The final answer we expect: the sample system plus that authored indicator. |

A **provider** is a prepared answer for one named function. The sample runner looks up these providers instead of reading `/proc`, logs or network state. Thus the demo proves the language path works; it does not claim to find a real incident.

## Unit 2: show real Debian collector results

For an immediate, reliable presentation, show the **saved** report from the original Debian VM campaign on your normal computer:

```bash
target/debug/jocky-collect-linux verify-report "$PWD/project-records/evidence/version-5/debian/lab-small-00.json"
python3 - <<'PY'
import json
r = json.load(open('project-records/evidence/version-5/debian/lab-small-00.json'))
print('Kind:', r['report_kind'])
print('Status:', r['summary']['status'])
print('Records:', len(r['records']))
print('Errors:', r['summary']['errors'])
PY
```

`verify-report` checks saved JSON format and internal integrity; it should print `ReportValid`. It does not recollect or independently prove where bytes came from. The second command counts the saved records. Expect `Kind: live_lab`, `Status: partial`, and about 300 records. `partial` means some extra VM facts were unreadable to the ordinary user; allowed facts were still recorded. The [Debian evidence notes](../project-records/evidence/version-5/debian/README.md) give the known test facts and 11 measured runs.

For **fresh** collection on a new desktop VM, follow the next section. Its short command path is a **system-only smoke test**. If you want a demonstration comparable to the original Version 5 campaign, use the full LAB-SMALL procedure after that; the system-only result is not a substitute.

## Make a Debian VM with a real desktop

The existing `jocky-v5-debian-13-7` VM has a **text login**. Its VNC console is graphical as a window, but Debian inside has no desktop. GNOME Boxes can show “Unsupported display” for that VNC console. Use **Virtual Machine Manager** (`virt-manager`), and create a **separate** desktop VM. Keep the original evidence VM intact.

1. On Fedora, run `virt-manager --connect qemu:///session`. Choose the **QEMU/KVM user session** connection, not `qemu:///system`.
2. Choose **File → New Virtual Machine → Local install media**. Select `/home/zer0/Downloads/debian-13.7.0-amd64-netinst.iso`. If that path is gone, download the current Debian amd64 installer from Debian.
3. Give the new VM a distinct name, for example `jocky-presentation-debian`; use about **2 CPUs, 4 GiB RAM and 30 GiB disk**. Allow a network connection during installation because the net installer downloads packages.
4. Start **Graphical install**. Create your own Debian user and password. On **Software selection**, keep **Debian desktop environment** and a desktop choice such as GNOME, plus **standard system utilities**. Finish installation and reboot.
5. Double-click the new VM in virt-manager, open **Console**, click inside it and log in. Mouse and keyboard now work in the Debian desktop. Open its Terminal application.

The official [Debian installer guide](https://www.debian.org/releases/trixie/amd64/ch06s03.en.html) explains that selecting “Desktop environment” installs the graphical desktop. If the installer does not offer a network mirror, use Debian's DVD image or connect the VM to a working virtual network. A desktop login screen is the visual check that installation succeeded.

## Quick system-only check inside your new desktop VM

Do the next commands in **Debian's Terminal**, not Fedora's. Use only a VM you own and intend to examine. This simple demo requests only the system profile; it does not request files, logs, processes or indicators. The generated IDs are labels for this one demo run, and the request expires after two hours. Review the four generated JSON files before running `collect`.

1. While the new VM has internet, install build tools, then get your **current** repository into the VM. Push your local guide/helper changes first if you want the clone to include them:

```bash
sudo apt update
sudo apt install -y build-essential curl git pkg-config ca-certificates python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
git clone https://github.com/0Ankitexe/Jockey.git
cd Jockey
bash scripts/setup.sh --demo
```

`apt` installs tools, `rustup` installs Rust/Cargo, `git clone` copies the repository, and `setup.sh` builds the collector **inside Debian**. See the [official Rust installer](https://rust-lang.org/tools/install/) if its prompt changes. `target/debug/jocky-collect-linux` is the collector binary. If your GitHub repository does not yet contain the helper below, copy the current project into the VM first or push it before cloning.

2. On **Fedora**, run `virsh -c qemu:///session domuuid jocky-presentation-debian` and copy the UUID it prints. This is the identifier of the new VM. You may also try `cat /sys/class/dmi/id/product_uuid` in Debian, but ordinary users cannot read it on some systems. Shut down the VM, disconnect its virtual network in virt-manager's **Show virtual hardware details → NIC** (or remove that NIC), then start it again. This makes the collection demo an isolated guest. Reopen Terminal and `cd ~/Jockey`.

3. Prepare a **new**, private, system-only request and check it. Change the directory suffix if you repeat the demo; the helper refuses to reuse an old request.

```bash
python3 scripts/prepare_debian_demo_collection.py --vm-name jocky-presentation-debian --vm-uuid YOUR-VM-UUID --output-dir "$HOME/jocky-demo-inputs-1"
ls -l "$HOME/jocky-demo-inputs-1"
cat "$HOME/jocky-demo-inputs-1/endpoint-designation.json"
mkdir -m 700 "$HOME/jocky-demo-reports"
BIN="$PWD/target/debug/jocky-collect-linux"
INPUT="$HOME/jocky-demo-inputs-1"
"$BIN" validate-inputs --designation "$INPUT/endpoint-designation.json" --authorisation "$INPUT/authorisation.json" --policy "$INPUT/policy.json" --request "$INPUT/request.json"
```

Replace `YOUR-VM-UUID` with the UUID printed on Fedora. The helper makes four `0600` files in a new `0700` directory. **Designation** names this VM and its libvirt UUID; **authorisation** records the case/operator IDs, allowed system data and time window; **policy** lists the allowed kernel-profile source; **request** asks to run the system collector. `validate-inputs` checks them without reading VM evidence. It should return `InputsValid`. A failed validation means stop and read its error; do not substitute the expired test fixtures.

4. Start the actual VM read, then check and inspect the **new** report:

```bash
"$BIN" collect --allow-live-lab --designation "$INPUT/endpoint-designation.json" --authorisation "$INPUT/authorisation.json" --policy "$INPUT/policy.json" --request "$INPUT/request.json" --output "$HOME/jocky-demo-reports/system-1.json"
"$BIN" verify-report "$HOME/jocky-demo-reports/system-1.json"
python3 - <<'PY'
import json
from pathlib import Path
r = json.loads((Path.home() / 'jocky-demo-reports/system-1.json').read_text())
print('Report kind:', r['report_kind'])
print('Status:', r['summary']['status'])
print('Record count:', len(r['records']))
print('Record categories:', sorted({item.get('category', '?') for item in r['records']}))
PY
```

`--allow-live-lab` is the explicit choice to read the VM. `--output` names a **new** report file; it will not overwrite one. `verify-report` should print `ReportValid`. A `complete` result means all requested system data was collected; `partial` means the report names something it could not read; `failed` means inspect the error and do not claim success. In the report, `records[0].payload.hostname.value` and `distribution_id.value` are the collected computer name and distribution. Compare them with `hostnamectl` and `cat /etc/os-release` in the **same VM**. This is a useful live sanity check, not the full 11-run acceptance campaign. If `collect` fails or publishes no file, keep the terminal output and inspect the typed error; do not present the saved report as if it were this fresh run.

## Full VM demonstration: repeat the original style

The original Debian run used the [LAB-SMALL harness](../tests/lab/linux/lab_campaign.py), not the system-only helper. This is the path to use if you want a fresh demonstration with measured results. The harness temporarily creates **five harmless processes, five local connection pairs, twenty sample files and ten journal markers** in the approved VM. It supplies **1,000 exact comparison values**, asks the native collector to read the chosen sources, and checks the report against those known facts. It runs once after a cold boot and ten more times on the same boot. Each report is real VM data; the planted facts give an independent answer to compare against.

The new desktop VM needs its **own** inventory and current approval/configuration files. The old VM's IDs, disk hash, machine ID, binary hash, journal path, approval window and output paths cannot be reused. The full run requires:

1. Build the collector **in the Debian guest** with `cargo build --release --locked -p jocky-native-linux --features journal`. Install `libsystemd-dev` before this build. Install Python **3.12** and the harness test dependencies too; Debian 13's default Python may be 3.13, but the controller package requires 3.12.
2. Set a deliberate demo hostname ending in `.invalid`, provide a readable user journal, and prepare separate private scratch and output directories. These are setup facts, not malware.
3. Shut down the VM and disconnect its NIC. On Fedora, record its libvirt UUID, disk path and disk SHA-256. Inside Debian, record `/etc/machine-id`. Create a new `inventory.json` linking these facts. Run the host's `tests.lab.linux.host_preflight` **while the VM is shut off**; it rejects the wrong VM or a VM with a NIC.
4. Create fresh, linked designation, authorisation, policy, request and `lab-scenario.json` files for this VM and a current time window. Include the collector's **actual SHA-256**. The authorised sources must cover system, processes, connections, files, events and indicators. The journal path must be the readable journal file in this new VM.
5. Boot the VM and run `tests.lab.linux.run_scenario --profile lab-small-v1 --allow-live-lab` with those files and the new release collector. The harness runs collection and verifies all 11 reports. The full argument list and exact file rules are in the [collector procedure](reference/linux-collectors.md#t178-debian-lab-small-replay).
6. Show `samples.jsonl`, `lab-small-00.json` through `lab-small-10.json`, and the harness summary. Explain **known fact matched**, **partial permission denial**, time, memory and report size. A passing new run is evidence for **your new VM**; it does not change the pinned V5 acceptance verdict.

**Do not feed the four files from `prepare_debian_demo_collection.py` into LAB-SMALL.** They deliberately grant only the system profile. The full run needs its own wider, explicitly reviewed request and the host/guest preflight described above.

## Optional dashboard

On your normal computer, `bash scripts/setup.sh --full` prepares its dependencies. Then open two terminals in the project folder:

```bash
(cd controller && .venv/bin/python -m uvicorn jocky_controller.main:app --host 127.0.0.1 --port 8000)
```

```bash
(cd dashboard && npm run dev -- --host localhost --port 5173 --strictPort)
```

Open `http://localhost:5173`. **Dashboard Ready** means the webpage loaded. **Controller Online** means its health/version requests succeeded. **Unavailable** means the webpage cannot reach the controller. The displayed service/version describe the controller only. This page does not show `.jky` results, VM reports or a start-collection button.

## Where the project information lives

| Place | What to find there |
| --- | --- |
| `language/`, `ir/`, `examples/` | Language compiler, checked plan, example source and sample answers. |
| `native/linux/`, `forensic-lib/`, `shared/` | Real Linux collector, collection rules and shared JSON formats. |
| `controller/`, `dashboard/` | Basic service and browser status page. |
| `tests/`, `fixtures/`, `ci/` | Automated checks and repeatable test inputs. |
| [docs/README.md](README.md) | Menu of **how the project works**: architecture, language, diagnostics, result fields, Linux collector and supported scope. |
| [docs/current-state.md](current-state.md) | Short answer to “what works today?” |
| [project-records/README.md](../project-records/README.md) | Menu of **what was decided or tested**, including version results and saved evidence. |
| [Version 5 verification](../project-records/version-5-verification.md) | Formal summary of V5 completion and limits. |
| [Version 5 evidence index](../project-records/evidence/version-5/index.md) | Links to the actual test measurements and Debian reports. |

`docs/` teaches **how**. `project-records/` preserves **what happened and why**. The [Version 3 checkpoint](../project-records/version-3-phases-4-5-checkpoint.md) is an earlier stage; [Version 3 verification](../project-records/version-3-verification.md) is its final result; [Version 5 verification](../project-records/version-5-verification.md) covers a later version. They overlap in background, but are not duplicate files. For individual file meanings, use the two folder menus above.

## Small vocabulary for viva answers

| Term | Simple explanation |
| --- | --- |
| Compiler / parser / type check | Tool that checks a program / part that reads grammar / check that values are the right kind. |
| IR | Intermediate representation: a checked JSON plan made from source code. |
| Fixture / provider | Prepared sample data / one prepared answer for a named function. |
| Collector / endpoint | Program that reads chosen facts / computer being examined. |
| Case / operator / scope | Investigation ID / person responsible / exact data allowed for one run. |
| JSON / schema | Readable structured data / rules for its shape. |
| Indicator / match | Value to compare, such as an IP or hash / equality with that value, not proof of malware. |
| Hash | Fingerprint of file bytes; it identifies a byte sequence, not whether it is safe. |
| VM / host / guest | Virtual computer / real computer running it / operating system inside it. |
| Read-only / partial | Collector does not intentionally edit evidence / some requested facts could not be read. |
| Dashboard / controller / API | Browser page / service behind it / way programs ask that service for information. |
| CI | Automatic build and test checks when code is pushed. |
