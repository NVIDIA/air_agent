# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
