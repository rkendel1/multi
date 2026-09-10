export class MemoryTransport { constructor() { this.kind="memory"; } async send() { return { status:"sent", transport:"memory" }; } }
export class LocalTransport { constructor() { this.kind="local"; } async send() { return { status:"sent", transport:"local" }; } }
