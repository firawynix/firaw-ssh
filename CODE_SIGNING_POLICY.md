# Code-signing policy

Only the public MIT-licensed Firaw SSH client built from this repository is
eligible for the project's public trusted signature.

The signing boundary includes the Tauri desktop client and the documented
local bridge. It excludes user profiles, credentials, private keys, backup
files, private deployment configuration, websites, backend services, and any
unpublished Firawynix infrastructure.

GitHub Actions checks out the triggering commit, installs locked dependencies,
runs the frontend build and Rust tests, builds the NSIS installer, and records
artifact hashes. No signing key is stored in GitHub or this repository. The
project is applying to SignPath Foundation for public code signing.
