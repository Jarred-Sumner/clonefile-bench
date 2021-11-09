# What's the fastest way to copy 1 GB of node_modules?

You'll need a copy of Zig that doesn't error on unused variables

```bash
cd huge
yarn install
cd ../
make build
```

```bash
./run clonefile
```

```bash
./run link
```

```bash
./run copyfile
```

## Numbers:

```
info: finished clonefileat() 3046553750ns (returned: 0)
info: finished fcopyfile():  21995592666ns
info: finished os.linkat():  30305318125ns
```

> Darwin macbook.local 21.1.0 Darwin Kernel Version 21.1.0: Wed Oct 13 17:33:01 PDT 2021; arm64
