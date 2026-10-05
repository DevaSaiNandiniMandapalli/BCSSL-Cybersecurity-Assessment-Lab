# Exercise 02 — Nmap Local Service Discovery

## Objective

Use a tightly scoped TCP connect scan with service version detection to prove that only the authorized port 3001 is in play, and learn to read the `-oX` XML output as machine-readable evidence.

## Authorized Target

```
http://localhost:3001
```

Discovery in this exercise is restricted to loopback port 3001. No other host or port may be scanned.

## Prerequisites

- Exercise 01 completed and its preflight evidence saved to `evidence/lab-cli/ex01-validate-target.txt`.
- Nmap is installed and on your PATH. Run `nmap --version` and note the version in your notes.
- OWASP Juice Shop is still running on `http://localhost:3001`.
- You have created the folder `evidence/nmap/`.

## Tool Used

`nmap` — network mapper, invoked through the lab CLI so the port list and host stay pinned to the authorized target.

Under the hood the lab runs:

```
nmap -sT -sV -Pn -p 3001 --reason -oX <out>.xml localhost
```

## Exact Command

```bash
python -m bcssl run nmap
```

## Expected Observation

The lab CLI builds and runs the scan shown above. You should see a progress log followed by a results block. For a live Juice Shop this typically reports `3001/tcp open`, identifies the service as `http`, and prints a banner in the Node.js / Express style.

Because the port list is fixed to 3001 and the host is the loopback name `localhost`, no other port or host is ever contacted. If the service is down you will instead see `3001/tcp closed` or `filtered`, which is itself a reportable observation. Do not expect a specific number of open ports, and never edit the XML to make it look better.

## Student Task

1. Run the exact command above from the lab project root.
2. From the console output, write down the state of `3001/tcp`, the service name reported, and the banner or version string that `-sV` detected.
3. Locate the XML file the lab wrote under `reports/raw/` and open it in a text editor. Find the `<port>` element and note the state, the `<service name=...>` attribute, and any `<extra>` info.
4. Copy the XML output unmodified to `evidence/nmap/ex02-nmap-scan.xml`.
5. Note in your own words why `-sT` was chosen over `-sS`, and why `-Pn` is present.

## Evidence Requirement

- File `evidence/nmap/ex02-nmap-scan.xml` containing the unmodified nmap XML output.
- A pasted fragment of the `<port>` element from that XML in your notes, showing state and service.
- The nmap version string you recorded, and a one-line justification of the `-sT` and `-Pn` flags.
- This filename must be referenced in the evidence index of your final report (Exercise 12).

## Questions

**q1. What state did 3001/tcp report, which service was identified, and what banner evidence supports that identification?**

> Quote the port state, the service name attribute, and the banner or extra info from the XML. If version detection returned nothing conclusive, say so; an honest "service confirmed open, version not fingerprinted" is a better finding than an invented banner.

**q2. Why does this scan use -sT (TCP connect) with -Pn instead of a SYN scan with host discovery?**

> Explain that `-sT` needs no raw socket or elevated privileges, so it works on a normal Windows workstation, and that `-Pn` tells nmap to treat the host as up instead of spending time on ICMP/ARP discovery that a loopback target does not need. Mention that on loopback, host discovery adds risk of skipping the target for no benefit.

**q3. How would your findings change if the state for 3001/tcp had been closed or filtered instead of open?**

> Walk through the reasoning: no service means no HTTP layer, so the headers, path and vulnerability exercises would have nothing to talk to. Describe what you would check next on your own machine (is the container running, is it bound to a different port) without ever pointing a scan at another host.

## Safety Note

This scan is hard-scoped to a single authorized endpoint: `localhost` on port 3001 only. Never edit the command to widen the port range, drop `-p 3001`, substitute an IP address, or aim it at any public site, network, or machine you do not own. Port scanning other people's systems without written authorization is illegal in most jurisdictions. Stick to connect scans on the loopback target; no exploitation, credential testing, or denial-of-service behaviour is involved or permitted here.

## Completion Checklist

- [ ] **c1** — I ran `python -m bcssl run nmap` from the lab project root and captured the console output.
- [ ] **c2** — I opened the `-oX` XML report under `reports/raw/` and located the `<port>` element with its state and service details.
- [ ] **c3** — I copied the unmodified XML to `evidence/nmap/ex02-nmap-scan.xml` and quoted the port state and service in my notes.
- [ ] **c4** — I wrote my own explanation of the `-sT` and `-Pn` choices and answered q1, q2 and q3 in writing; I know that running the scan alone does not complete this exercise.

> Progress in this lab is never auto-completed by running a tool. An exercise is done only when you have saved the evidence, answered the questions, and ticked the checklist.