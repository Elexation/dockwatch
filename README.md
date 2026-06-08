# DockWatch

Self-hosted Docker image update monitor. A single static Go binary that watches running
containers, compares each image against its registry, and shows current vs. available
versions in a web dashboard. Sends one notification per new release and never updates
anything. It is a read-only observer.

## License

[AGPL-3.0](LICENSE)
