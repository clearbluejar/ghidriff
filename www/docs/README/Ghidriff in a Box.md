---
sidebar_position: 6
---

## Ghidriff in a Box 

Don't want to install Ghidra and Java on your host? Try "Ghidriff in a box". It supports multiple-platforms (x64 and arm64).

<p align='center'>
<img src="https://github.com/clearbluejar/ghidriff/assets/3752074/688756fc-038c-471a-8e49-e56a1c06e77c" height="300">
</p>

### Docker

`docker pull ghcr.io/clearbluejar/ghidriff:latest`


This is a docker container with the latest [PyPi version of Ghidriff](https://pypi.org/project/ghidriff/) installed. You can check the latest container [here](https://github.com/clearbluejar/ghidriff/pkgs/container/ghidriff).


#### For Docker command-line diffing

You will need to map the binaries you want to compare into the container. See below for an example.
```bash
mkdir -p ghidriffs
wget https://msdl.microsoft.com/download/symbols/clfs.sys/9848245C6f000/clfs.sys -O ghidriffs/clfs.sys.x64.10.0.22621.2506
wget https://msdl.microsoft.com/download/symbols/clfs.sys/D929C6E56f000/clfs.sys -O ghidriffs/clfs.sys.x64.10.0.22621.2715
docker run -it --rm -v $(pwd)/ghidriffs:/ghidriffs ghcr.io/clearbluejar/ghidriff:latest  ghidriffs/clfs.sys.x64.10.0.22621.2506 ghidriffs/clfs.sys.x64.10.0.22621.2715
```

The result will produce the following. 

```bash
tree ghidriffs
ghidriffs
├── clfs.sys.x64.10.0.22621.2506
├── clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.ghidriff.md
├── clfs.sys.x64.10.0.22621.2715
├── ghidra_projects
│   └── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715
│       ├── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.gpr
│       ├── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.lock
│       └── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.rep
├── ghidriff.log
├── json
│   └── clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.ghidriff.json
└── symbols
    ├── 000admin
    ├── clfs.pdb
    │   ├── 6EAE8987F981603FEFA0E55DE0CE2C521
    │   │   └── clfs.pdb
    │   └── E3D1FEA241ECEC3DC6DB2B278A22A6A31
    │       └── clfs.pdb
    └── pingme.txt

```

### Devcontainer - For Ghidriff development

Use the [.devcontainer](https://github.com/clearbluejar/ghidriff/.devcontainer) in this repo. If you don't know how, follow the detailed instructions here: [ghidra-python-vscode-devcontainer-skeleton quick setup](https://github.com/clearbluejar/ghidra-python-vscode-devcontainer-skeleton#quick-start-setup---dev-container--best-option).


