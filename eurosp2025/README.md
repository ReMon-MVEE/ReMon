# README

**NOTE:** We are continually testing these benchmarks and fixing issues. If, at any point, you run into issues somewhere our best advice is to start from a clean clone again in a few days.

## Basic Setup

`eurosp2025/bootstrap.sh` Will take care of building the correctly patched kernel and installing it as a deb package.
After this, it will ask you to reboot your system to this correct kernel.
To this end, edit `/etc/default/grub`:
- Comment out `GRUB_HIDDEN_TIMEOUT=0` by prepending a `#`
- Uncomment `# GRUB_TIMEOUT_STYLE=hidden` and change it to menu
- Change `GRUB_TIMEOUT=0` to some value x greater than 0 to give you x amount of seconds before it automatically logs you in
Once in the correct kernel, re-run the script to continue with the setup, the kernel build and install will now be skipped.
Now, the script will execute ReMon's `bootstrap.sh` to set up its dependencies, before downloading and setting up the benchmarks.

**NOTE**: the benchmark script also installs the kernel module, but after a new reboot it will again be unloaded.
If FORTDIVIDE does not work the first time after rebooting your system, first make sure the kernel module is loaded.

```bash
cd /wherevever/you/put/the/main/repo/
cd eurosp2025/
./bootstrap.sh
# This will download, compile, and install the kernel as a debian package, requiring a password a few times.
# Since youn are not booted into the correct kernel, it will ask you to reboot to the correct kernel.
sudo reboot

# Just run bootstrap again
cd /wherevever/you/put/the/main/repo/
cd eurosp2025/
./bootstrap.sh
```

## Running Benchmarks

We recommend running the benchmarks through `eurosp2025/benchmarking.sh`, as it takes care of all the configuration, though it does rebuild the benchmarks each time.
For the server benchmarks we use [wrk](https://github.com/wg/wrk), which you will have to make available as a command on the benchmarking client.
The script outputs to `./paper-outputs` in the current working directory, with `./paper-outputs/latest/` always containing the latest results.
Additionally, it will call `eurosp2025/process.py` on the latest results to generate the graphs and calculate other results.

For our server benchmarks we run a separate machine as a benchmarking client and connect it with a dedicated gigabit link to the benchmarking host.
For this reason, the benchmarks are run through ssh, though they can also still be run with client and host being the same machine.
`eurosp2025/bootstrap.sh` already sets up `~/.ssh/config` with a configuration for fortdivide-benchmark as localhost.
More configuration on running from a dedicated client later.

This script process the options in the order they are given and first requires some setup options to define the specific configurations.
- `--merge-skip-shorter-pmd-kernel`: the default kernel module configuration that should be run, as described in the paper.
- `--merge-skip-pmd-kernel`: a kernel module configuration that emulates resetting the COW mappings at each entrance.
- `--no-allocator`: removes the heap from the Monomorphic Partition, to not influence the microbenchmarks.
- `--libc-allocator`: configures ReMon-glibc to map its heap in the Monomorphic partition.
- `--pmvee-allocator`: configures the monitor to LD_PRELOAD our own custom allocator to map the heap in the Monomorphic Partition.

Several options are provided by the script.
- `--paper` runs all the benchmarks seen in the paper, no additional setup options are needed.
- `--switcheroo` runs the microbenchmarks concerning the overhead of the entrance and exit system calls as well as toggling MVX.
- `--mapping-count` runs the microbenchmark on the partial fork and the state migration.
- `--nginx` runs the two main nginx configurations (native, ReMon, ReMon+IP-MON, FORTDIVIDE, and FORTDIVIDE+IP-MON), both entering at `ngx_http_process_request_line`, with one early exiting at `http_handler`.
- `--lighhtpd` runs the two main lighttd configurations (native, ReMon, ReMon+IP-MON, FORTDIVIDE, and FORTDIVIDE+IP-MON), one hooking `connection_handle_read_state` and the other `http_request_headers_process`.
- `--nginx-diffed` evaluates nginx with its exit on `http_handler` when part of the state migration is determined with a precompiled list of symbols that require migration.
- `--nginx-scan` extends `--nginx-diffed` by removing the manual handling for heap objects and replacing it with pointer scanning over the Monomorphic Partition.
- `--nginx-progress` runs a base evaluation for nginx with exit on `http_handler` as well as `--nginx-diffed` and `--nginx-scan`.

Apart from `--paper` each option requires at least one kernel and on allocator config option, some for functionality, but mostly as this organizes the results in the correct sub folders.
The table below lists the possible options for each benchmark, (v) if they are in the paper and are thus executed by `--paper`.

|                  | --merge-skip-shorter-pmd-kernel | --merge-skip-pmd-kernel |   | --no-allocator | --libc-allocator | --pmvee-allocator |
| ---------------: | :-----------------------------: | :---------------------: | - | :------------: | :--------------: | :---------------: |
| --paper          | -                               | -                       |   | -              | -                | -                 |
| --switcheroo     | v (v)                           | v                       |   | v (v)          |                  |                   |
| --mapping-count  | v (v)                           | v (v)                   |   | v (v)          |                  |                   |
| --nginx          | v (v)                           | v                       |   |                | v (v)            | v (v)             |
| --lighhtpd       | v (v)                           | v                       |   |                | v (v)            | v (v)             |
| --nginx-diffed   | v (v)                           | v                       |   |                | v                | v (v)             |
| --nginx-scan     | v (v)                           | v                       |   |                | v                | v (v)             |
| --nginx-progress | v (v)                           | v                       |   |                | v                | v (v)             |

### Examples

```bash
# Run the benchmarks from the paper.
# This requires a password a few times to switch out the kernel module.
./benchmarking.sh --paper

# Run basic nginx benchmarks only.
# --*-kernel options will always require a password input, as they switch out the kernel module.
./benchmarking.sh --merge-skip-shorter-pmd-kernel --pmvee-allocator --nginx

# Run both microbenchmarks, once with each kernel option.
./benchmarking.sh --merge-skip-shorter-pmd-kernel --no-allocator --switcheroo --mapping-count --merge-skip-pmd-kernel --switcheroo --mapping-count

# Run basic server benchmarks with two different allocator configurations.
# --*-kernel options will always require a password input, as they switch out the kernel module.
./benchmarking.sh --merge-skip-shorter-pmd-kernel --pmvee-allocator --nginx --lighttpd --libc-allocator --nginx --lighttpd
```

### Running From a Dedicated Benchmarking Client

If you run `eurosp2025/benchmarking.sh` from a separate client, you will have to set up the fortdivide-benchmark ssh config, in which case it is also best to enable ssh login through public key, otherwise you would have to enter a password every time the client accesses the host.
fortdivide-benchmark should then best be set up so that the ssh connection does not go over the same gigabit link, to limit noise on measurements.
Then, AFTER bootstrapping, you can copy `eurosp2025/benchmarking.sh` to the benchmarking client and run it from there.
On this dedicated machine, you will have to edit `benchmarking.sh` and replace localhost in `__server_ip="localhost:8080"` with the ip of the benchmarking host over the dedicated link.

### Interpreting Output

`eurosp2025/process.py` outputs the graphs in pdf as well as a comprehensive file with results, `fortdivide-results.md`, in the current working directory.
The results will always be outputted in `eurosp2025/`, regardless of whether the benchmarking client was the same local machine or a connected machine.
The latest results are also always copied to `eurosp2025/latest/`, so they can be reprocessed by running `eurosp2025/process.py eurosp2025/latest/`.

## Running FORTDIVIDE

FORTDIVIDE requires some additional info to run.
We pass this information to the monitor through its configuration file, `MVEE.ini`.
`eurosp2025/bootstrap.sh` takes care of patching `MVEE.ini`, both for the Release and Debug configurations, so there is no need to set it up manually.
- variants->sets->specs->Variant-B defines aliases for follower paths to load different binaries in the followers, for executables that contain the call gates or migration handlers.
- monitor->pmvee_mappings defines a list of translations from leader to follower offset for specific files, which also includes offsets for migration handlers.
- monitor->pmvee_migrations defines the list of offsets that will be migrated.

The files for the aliases are built by the different build scripts, pmvee_mappings and pmvee_migrations are symlinked files.
The symlinks are set by the Makefiles for the microbenchmarks and the `--mappings` options for the server benchmarks.
Thus, every time you want to run a specific benchmark, it is best to re-run these to set up the correct symlinks.

## Building Benchmarks

### Microbenchmarks

### nginx

Options for `nginx-1.23.3-build.sh` are generally divided into three classes: build configuration, building the binaries, and setting up the FORTDIVIDE configuration.

#### Configuration
**`--ngx-full`** configures the nginx build for hooking `ngx_http_process_request_line` to enter MVX when called and exiting when returned.

**`--ngx-split`** configures the nginx build for hooking `ngx_http_process_request_line` to enter MVX when called and `ngx_http_handler` to exit when called.

#### Building
**`--base`** configures and builds a native nginx. **NOTE: this resets any configuration done by `--nginx-full` or `--nginx-split`, always perform it last.**
**`--pmvee-stubs`** builds the library containing the hooks for nginx. This option is dependent on what configuration option (`--nginx-full` or `--nginx-split`) was specified before.
**`--pmvee`** builds the actual nginx binary after the hooking has been built, which we link against for simplicity. This option is dependent on what configuration option (`--nginx-full` or `--nginx-split`) was specified before and requires `--pmvee-stubs` to be specified before it.
**`--pmvee-single`** builds the nginx binary and hooking library with only manual state migration for pointers on the heap. This option is dependent on what configuration option (`--nginx-full` or `--nginx-split`) was specified before.
**`--pmvee-single-scanning`** builds the nginx binary and hooking library with no manual state migration left. This option is dependent on what configuration option (`--nginx-full` or `--nginx-split`) was specified before and requires FORTDIVIDE to be configured to perform heap scanning.

#### FORTDIVIDE Setup
**`--mappings`** constructs the file the will be loaded by the monitor through its `pmvee_mappings` configuration parameter.
**`--mappings-single`** constructs the file the will be loaded by the monitor through its `pmvee_mappings` and `pmvee_migrations` configuration parameters.
**`--mappings-single-scanning`** constructs the file the will be loaded by the monitor through its `pmvee_mappings` and `pmvee_migrations` configuration parameters.

### lighttpd

Options for `lighttpd-1.4.60-build.sh` are generally divided into three classes: build configuration, building the binaries, and setting up the FORTDIVIDE configuration.

#### Configuration

**`--default`** configures the lighttpd build for hooking `connection_handle_read_state` to enter MVX and exit on its return.
**`--faster`** configures the lighttpd build for hooking `http_request_headers_process` to enter MVX and exit on its return.

#### Building

**`--base`** configures and builds the native lighttpd binary. **NOTE: this resets any configuration done by `--default` or `--faster`, always perform it last.**
**`--pmvee`** builds the actual lighttpd binary. Requires `--default` or `--faster` to have been specified before.

#### FORTDIVIDE Setup

**`--mappings`** constructs the file the will be loaded by the monitor through its `pmvee_mappings` configuration parameter.
