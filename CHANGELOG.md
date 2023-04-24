# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.1] - 2023-04-24
### Fixed
- Fixed a backward compatibility issue with agents that use a persistent mount

## [2.3.0] - 2023-04-24
### Fixed
- No requirement for a persistent mount entry in /etc/fstab
- Agent exits gracefully if the mount is inaccessible or expected files do not exist

## [2.2.0] - 2023-03-13
### Added
- Handling for terminal resize requests

## [2.1.0] - 2021-08-09
### Added
- `VERIFY_SSL` config option

## [2.0.9] - 2021-07-07
### Fixed
- Avoid issues with cumulusnetworks.com redirects

## [2.0.8] - 2021-04-28
### Fixed
- Monitored task updates are too slow
- Task monitor doesn't always send \n

## [2.0.7] - 2021-01-26
### Added
CAIR-165: Node instruction post_cmd should accept string as well as list

## [2.0.6] - 2020-11-23
### Fixed
CAIR-154: Race condition may cause node instructions to run multiple times

## [2.0.5] - 2020-11-17
### Added
Added timeout for REST call to get instructions

## [2.0.4] - 2020-10-09
### Added
CLAIR-683: Write agent logs to dedicated log file
### Fixed
CLAIR-721: AIR agent gets stuck before syncing clock on netq-ts

## [2.0.3] - 2020-09-11
### Fixed
Race condition between air-agent, chrony, and kernel's 11 minute mode

## [2.0.2] - 2020-09-03
### Fixed
Clock is not synced when auto-update is applied
Agent stuck in instruction fetch loop
Always sync clock when identity changes

## [2.0.1] - 2020-08-28
### Fixed
CLAIR-684: Agent stuck in update loop when no instructions are given

## [2.0.0] - 2020-08-20
### Added
Auto-updates

## [1.4.2] - 2020-08-19
### Added
CLAIR-656: Return demo activity in job status
### Fixed
CLAIR-659: Clock sync instruction fails for CL4

## [1.4.1] - 2020-06-17
### Fixed
Only read one line at a time from signal channel

## [1.4.0] - 2020-06-09
### Added
Signal channel for host-to-guest communication

## [1.3.2] - 2020-06-04
### Fixed
CLAIR-530: Agent doesn't always retry failed instructions

## [1.3.1] - 2020-04-14
### Fixed
#3: Agent should retry fetching instructions on failure

## [1.3.0] - 2020-04-07
### Added
File executor

## [1.2.2] - 2020-04-07
### Fixed
Removed errant debug line

## [1.2.1] - 2020-04-01
### Fixed
#2: Need better VM wake up detection

## [1.0.1] - 2020-02-13
### Fixed
CLAIR-324: Suppress agent logs when /mnt/air does not exist

## [1.0.0] - 2020-02-05
### Added
Initial functionality
