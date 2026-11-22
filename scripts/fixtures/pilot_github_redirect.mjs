// Node preload for the disposable native pilot smoke test.
const originalFetch = globalThis.fetch;
const fixtureRepository = "https://api.github.com/repos/pilot-fixture/dedicated/issues/";

globalThis.fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input);
  if (url.hostname !== "api.github.com") return originalFetch(input, init);
  if (!url.href.startsWith(fixtureRepository)) throw new Error("Unexpected repository in local pilot verification");
  const fixture = new URL(process.env.MONOLITH_PILOT_FIXTURE_URL);
  if (fixture.protocol !== "http:" || fixture.hostname !== "127.0.0.1") {
    throw new Error("Local pilot fixture must use loopback");
  }
  return originalFetch(new URL(url.href.slice(fixtureRepository.length), fixture), init);
};
