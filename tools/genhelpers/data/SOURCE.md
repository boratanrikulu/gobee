# Vendored: `bpf_helper_defs.h`

Source of truth for the BPF helper Go stubs in `bpf/helpers_generated.go`.

## Provenance

| Field | Value |
|---|---|
| Upstream | [libbpf](https://github.com/libbpf/libbpf) |
| Tag | `v1.5.0` |
| Path | `src/bpf_helper_defs.h` |
| Direct URL | https://raw.githubusercontent.com/libbpf/libbpf/v1.5.0/src/bpf_helper_defs.h |
| SHA256 | `8a83bc11ab46009920d3ac0167b051d1d5d973da4bbdc24938bc498d5f29c1f0` |
| Helper count (sanity check) | 211 |

## Bumping to a newer libbpf release

```bash
NEW_TAG=v1.6.0   # change to the desired libbpf release tag
curl -sLo tools/genhelpers/data/bpf_helper_defs.h \
    "https://raw.githubusercontent.com/libbpf/libbpf/${NEW_TAG}/src/bpf_helper_defs.h"

shasum -a 256 tools/genhelpers/data/bpf_helper_defs.h
# Update the SHA256 row above. Update the Tag row.

# Regenerate the Go stubs
go run ./tools/genhelpers > bpf/helpers_generated.go
gofmt -w bpf/helpers_generated.go

# Run the test suite — golden-file diffs will tell you what changed
go test ./...
```

## License

libbpf is dual-licensed `LGPL-2.1 OR BSD-2-Clause`. We pick the **BSD-2-Clause** option for both this vendored header and the generated `bpf/helpers_generated.go`. That keeps gobee's MIT story clean: the bulk of the codebase stays MIT, and the one derivative file carries libbpf's BSD-2-Clause notice in its file header (required by clause 1 of BSD-2-Clause when redistributing source).

If libbpf ever switches to a license incompatible with MIT, we re-evaluate before bumping.

## Notes

- This file is auto-generated upstream from kernel sources by libbpf's `bpf_doc.py`. We don't edit it by hand. If you need to tweak the parser's behaviour, change the generator (`tools/genhelpers/main.go`) instead.
- We treat the snapshot as a build-time input, not as a runtime dependency.
