# soa

[Specs](./docs/specs.md)

## Building and Running

### Clone Repository with submodules

```bash
git clone git@github.com:lioia/soa --recurse-submodules
```

### Build and insert modules

```bash
make
sudo make mount
```

### Remove modules

```bash
sudo make umount
```

## Editor Setup

To generate `compile_commands.json`, [bear](https://github.com/rizsotto/Bear)
is required:

```
bear -- make
```
