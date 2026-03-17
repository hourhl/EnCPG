# Overview

This project contains three plugin:TraceExtension, AutoDetect, AutoDetect4NoTrace

# Compile & Build

## Requirements

- Java
- SBT (Scala Build Tool)
- curl (for downloading Joern)
  
## Architecture

This plugin follows the Joern plugin architecture pattern:

```
EnCPG/
├── schema/                 # Schema extension definition
│   └── src/main/scala/
│       └── CpgExtCodegen.scala
├── domain-classes/         # Generated domain classes
├── schema-extender/        # Installs extended schema in Joern
├── src/main/scala/         # Extension implementations
│   └── io/joern/
│       ├── traceextension/
│       │   └── TraceExtension.scala  # Trace data overlay
│       ├── autodetect/
│       |   └── AutoDetect.scala      # Vulnerability detection
|       └── autodetect4notrace/
|           └── AutoDetect4NoTrace.scala # Vulnerability detection without trace
├── build.sbt              # Main build configuration
├── joern-version          # Joern version to use
├── cpg-version            # CPG version to use
├── install.sh             # Installation script
└──README.md               # This file
```
## Installation
1. Navigate to the plugin directory:
   ```bash
   git clone git@github.com:hourhl/EnCPG.git
   cd EnCPG
   ```

2. Run the installation script:
   ```bash
   ./install.sh
   # recommended to select 1 for installation
   ```

This will:
- Download and install Joern (if not already present)
- Build the plugin with schema extension
- Install extended domain classes into Joern
- Package and install the plugin

## Development

If you want to update src, you need to rebuild the plugin and install in joern.

### Building

```bash
cd EnCPG
sbt compile
```

### Testing

```bash
sbt test
```

### Creating Distribution

```bash
sbt createDistribution
```

This creates `plugin.zip` that can be installed in Joern:

```bash
./joern --add-plugin /path/to/plugin.zip
```

## Upgrading

To upgrade to a newer Joern/CPG version:

1. Update `joern-version` and `cpg-version` files
2. Run `./install.sh` again


# Usage
## Plugin: Trace Extension 

A Joern plugin that augments Code Property Graphs (CPGs) with dynamic execution trace information.

Extends the CPG schema with:

- **TRACE_CALL** edge type: Represents actual function calls observed in execution traces (METHOD → METHOD)
  
- **BeenTraced** property: Boolean flag attached to METHOD nodes
  - Indicates if the method has been observed in dynamic execution trace

### 1. Start Joern with the Plugin

```bash
cd ./joern-inst/joern-cli
./joern
```

### 2. Import a CPG

```scala
# if you have cpg
joern> importCpg("/path/to/your/cpg.bin")

# if you only have source code
joern> importCode(inputPath="/path/to/src_dir/", projectName="xxx")
# you will find the cpg in ./workspace/xxx
```

### 3. Configure Trace Paths

The plugin accepts two separate trace files:

#### 3.1 BeenTraced File

Contains a list of function names to mark with the `BeenTraced` property:

```scala
joern> opts.traceextension.pathToBeenTracedFile = "/path/to/beentraced.json"
```

Format:
```json
[
  "gzclose",
  "_start",
  "__libc_csu_init",
  "main",
  ".strrchr"
]
```

#### 3.2 TRACE_CALL File

Contains call relationships in "caller -> callee" format for creating `TRACE_CALL` edges:

```scala
joern> opts.traceextension.pathToTraceCallFile = "/path/to/tracecall.json"
```

Format:
```json
[
  "zcalloc -> .malloc",
  "zcfree -> .free",
  "func_10780 -> sub_10A0"
]
```

**Note:** TRACE_CALL edges are only added when both caller and callee methods exist in the CPG.

You can specify both files or just one, depending on your needs.

### 4. Run the TraceExtension

```scala
joern> run.traceextension
```

The plugin will output performance metrics including:
- Time spent adding BeenTraced properties (if BeenTraced file provided)
- Time spent adding TRACE_CALL edges (if TRACE_CALL file provided)
- Total execution time

This will add `BeenTraced` properties and `TRACE_CALL` edges to the CPG.


## Plugin: AutoDetect 

Automatically detects vulnerability patterns in traced methods:

- Analyzes methods marked with `BeenTraced = true`
- Reports vulnerable code 

### Run the AutoDetect Plugin

```scala
# after you run the TraceExtension plugin
joern> opts.autodetect.outputPath = "/path/to/VulReport.txt"
joern> run.autodetect
```
This will analyze all traced methods and report any detected vulnerabilities.

  
## Plugin: AutoDetect4NoTrace 

Automatically detects vulnerability patterns in all methods:

- Analyzes methods
- Reports vulnerable code 

### Run the AutoDetect4NoTrace Plugin

```scala
joern> opts.autodetect4notrace.outputPath = "/path/to/VulReport.txt"
joern> run.autodetect4notrace
```
This will analyze all methods and report any detected vulnerabilities.



## Query the Enhanced CPG

```scala
// Find all methods that have been traced
joern> cpg.method.has("BeenTraced").name.l

// Find trace calls from a method
joern> cpg.method.name("gzclose").out("TRACE_CALL").cast[Method].name.l

// Find what called a method in the trace
joern> cpg.method.name(".malloc").in("TRACE_CALL").cast[Method].name.l

```

# References

- [Joern Plugin Documentation](https://docs.joern.io/extensions/)
- [Sample Plugin](https://github.com/joernio/sample-plugin)
- [CPG Schema](https://cpg.joern.io/)

## License
See the main repository LICENSE file.

