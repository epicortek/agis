# Building the AgIS Internet-Draft

The AgIS Internet-Draft source is maintained in Markdown:

```text
docs/ietf/draft-ayoub-agis-agent-identity-system-00.md
```

The preferred build path is the GitHub Actions workflow:

```text
.github/workflows/ietf-draft-build.yml
```

The workflow generates:

```text
docs/ietf/generated/draft-ayoub-agis-agent-identity-system-00.xml
docs/ietf/generated/draft-ayoub-agis-agent-identity-system-00.txt
```

and uploads them as workflow artifacts.

Local builds require:

* Ruby
* kramdown-rfc
* Python 3
* xml2rfc

The local environment used during initial drafting did not include these tools, so GitHub Actions is used as the reproducible build environment.
