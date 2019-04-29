# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).



## WIP
#### Fixed
- Tailored nmap switches


## [2.4] - 2019-03-13
#### Fixed
- Improved documentation related to building from source


## [2.3] - 2019-02-05
#### Added
- Support to automatically configure settings by loading a configuration file
#### Fixed
- Nmap output file names when running concurrently on all targets


## [2.2] - 2019-02-04
#### Fixed
- Changing output folder (`set output_folder <PATH>`) now also changes the location of the database


## [2.1] - 2018-11-14
#### Fixed
- Cross-compilation for linux 32bit
#### Removed
- Cross-compilation for darwin 64bit (failing with `CGO_ENABLED=1`)


## [2.0] - 2018-09-02
#### Added
- Complete refactoring of the core, new syntax, new commands
- Multi-step processing: detached processes for unstable environments, state saved in SQLite
- Port scan: new TCP and UDP PROD scans
- Improved enumeration
- Dry-runs for enumeration
- EyeWitness integration (for HTTP, RDP, VNC)
- Improved documentation
#### Removed
- Historical Tracking


## [1.5] - 2018-07-10
#### Added
- DNS enumeration
- SMB enumeration
- SNMP enumeration
- Windows Domain enumeration
- Dynamic nmap switches
- Dynamic wordlists


## [1.3] - 2018-06-28
#### Fixed
- Historical diff


## [1.2] - 2018-06-28
#### Added
- Refactored project structure (docker build)
- Historical diff
- Supporting SQLite DB


## [1.1] - 2018-05-22
#### Fixed
- Command Parser runtime error
 
 
## [1.0] - 2018-05-18
#### Added
- First Public Release
