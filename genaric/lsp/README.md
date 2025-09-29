# Build & Run

```shell
docker build alecmaly/sa-tool .
docker run alecmaly/sa-tool
```

# TODO

- find out which LSP takes a while to start up and override `init-timeout` param to `(30 | x)`

# Commands for each language
- python
    - `--force-callHierarchy`

- rust
    - `--disable-outgoing-calls`
    
- java
    - `--disable-selectionRange`


# Extension file location (servers may be there from downloaded extensions)

```shell

```

# Language Servers

- Java: https://github.com/eclipse-jdtls/eclipse.jdt.ls?tab=readme-ov-file#installation


# Decompile

## Binary

- [ghidra](https://github.com/NationalSecurityAgency/ghidra)
**decompile**
- https://github.com/albertan017/LLM4Decompile
- https://github.com/clearbluejar/ghidrecomp
- https://github.com/h4sh5/ghidra-headless-decompile


```shell
# https://github.com/clearbluejar/ghidrecomp
mkdir -p ghidrecomps
wget https://github.com/stephenbradshaw/vulnserver/raw/refs/heads/master/vulnserver.exe -O ./ghidrecomps/vulnserver.exe
docker run --rm -it -v $(pwd)/ghidrecomps:/ghidrecomps ghcr.io/clearbluejar/ghidrecomp:latest /ghidrecomps/vulnserver.exe
```

## APK

```shell
git clone https://github.com/skylot/jadx.git
cd jadx
./gradlew dist
```

