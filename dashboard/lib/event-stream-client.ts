/**
 * The browser's EventSource gives up on a response it did not like.
 *
 * A `503` from the events route — the dashboard not ready yet, the database
 * still starting — makes the source fail the connection *permanently*: the
 * browser does not retry it, so the live view stays dark until somebody
 * reloads the page by hand. A dropped connection is different: the browser
 * retries that one by itself, and a second retry on our side would race it.
 *
 * So the source is wrapped: the case the browser abandons is the case we
 * take over.
 */

/** `EventSource.CLOSED` — the source will not reconnect on its own. */
export const EVENT_SOURCE_CLOSED = 2;
/** `EventSource.CONNECTING` — the browser is already retrying. */
export const EVENT_SOURCE_CONNECTING = 0;

/** How long to wait before replacing a source the browser gave up on. */
export const RECREATE_AFTER_MS = 2_000;

/** The part of `EventSource` this wrapper uses. */
export interface EventSourceLike {
  onopen: ((event: unknown) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onmessage: ((event: { data: string }) => void) | null;
  readonly readyState: number;
  close(): void;
}

export interface EventStreamClientOptions {
  /** The stream to subscribe to. */
  url: string;
  /** How a source is created. Overridden in tests. */
  createSource?: (url: string) => EventSourceLike;
  /** How long to wait before replacing a source the browser gave up on. */
  retryDelayMs?: number;
  onOpen?: () => void;
  onError?: () => void;
  onMessage?: (data: string) => void;
}

export class EventStreamClient {
  private source?: EventSourceLike;
  private retry?: ReturnType<typeof setTimeout>;
  private stopped = false;

  constructor(private readonly options: EventStreamClientOptions) {}

  start() {
    if (this.stopped || this.source) return;
    const source = this.options.createSource
      ? this.options.createSource(this.options.url)
      : (new EventSource(this.options.url) as unknown as EventSourceLike);
    this.source = source;

    source.onopen = () => this.options.onOpen?.();
    source.onmessage = (event) => this.options.onMessage?.(event.data);
    source.onerror = () => {
      this.options.onError?.();
      if (this.source !== source) return;
      // `CONNECTING` means the browser is already retrying this source;
      // replacing it here would race the browser's own retry.
      if (source.readyState !== EVENT_SOURCE_CLOSED) return;
      this.source = undefined;
      source.close();
      this.scheduleRecreate();
    };
  }

  stop() {
    this.stopped = true;
    if (this.retry) {
      clearTimeout(this.retry);
      this.retry = undefined;
    }
    this.source?.close();
    this.source = undefined;
  }

  private scheduleRecreate() {
    if (this.stopped) return;
    if (this.retry) clearTimeout(this.retry);
    this.retry = setTimeout(() => {
      this.retry = undefined;
      this.start();
    }, this.options.retryDelayMs ?? RECREATE_AFTER_MS);
  }
}
