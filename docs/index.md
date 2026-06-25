---
layout: home

hero:
  name: "Horus"
  text: "Security automation for small teams."
  tagline: Discover your attack surface, scan for vulnerabilities, correlate findings against live threat intelligence, and surface only what needs your attention.
  actions:
    - theme: brand
      text: Get started
      link: /overview
    - theme: alt
      text: View on GitHub
      link: https://github.com/HorusAgentsSec/horus
    - theme: alt
      text: Live demo
      link: https://app.horusagents.com/login?demo=1

features:
  - icon: 🔍
    title: Attack surface discovery
    details: Subdomain enumeration via CT logs and DNS brute-force, network CIDR sweeps, automatic asset inventory.
  - icon: 🛡️
    title: Vulnerability scanning
    details: Nmap port/service detection, Nuclei template engine, ZAP DAST web scanning — all feeding a unified findings pipeline.
  - icon: 🧠
    title: AI agent pipeline
    details: 8-stage pipeline with Red/Blue adversarial debate on ambiguous findings. Verdicts stored and reused across scans.
  - icon: 📡
    title: Threat intelligence
    details: NVD CVE/CVSS/EPSS, CISA KEV, HIBP breach data, IntelX credentials, abuse.ch feeds, ransomware.live — correlated per asset.
  - icon: 🚨
    title: Incident management
    details: Case management with linked findings, append-only notes, and status tracking from triage to resolution.
  - icon: 🦀
    title: Iris daemon
    details: Lightweight Rust daemon that monitors your servers via journald and auditd, reporting events back with AI triage.
---
