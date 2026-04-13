#!/usr/bin/env node

const fs = require("fs");
const crypto = require("crypto");
const { performance } = require("perf_hooks");
const { TextEncoder } = require("util");

function atobCompat(value) {
  return Buffer.from(String(value || ""), "base64").toString("binary");
}

function btoaCompat(value) {
  return Buffer.from(String(value || ""), "binary").toString("base64");
}

globalThis.atob = globalThis.atob || atobCompat;
globalThis.btoa = globalThis.btoa || btoaCompat;
globalThis.TextEncoder = globalThis.TextEncoder || TextEncoder;

const payload = JSON.parse(fs.readFileSync(0, "utf8"));
const webcrypto = crypto.webcrypto || crypto;
const windowObject = globalThis;

function createElement() {
  return {
    style: {},
    appendChild() {},
    setAttribute() {},
    getAttribute() { return null; },
    addEventListener() {},
  };
}

const documentObject = {
  scripts: [
    { src: payload.sdk_url || "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js" },
    { src: "https://auth.openai.com/c/runtime/_app.js" },
  ],
  cookie: payload.device_id ? `oai-did=${encodeURIComponent(payload.device_id)}` : "",
  body: { appendChild() {} },
  documentElement: {
    getAttribute(name) {
      return name === "data-build" ? "c/runtime/_" : null;
    },
  },
  createElement,
  addEventListener() {},
  getElementsByTagName() {
    return [{ appendChild() {} }];
  },
};

windowObject.window = windowObject;
windowObject.self = windowObject;
windowObject.top = windowObject;
windowObject.globalThis = windowObject;
windowObject.crypto = windowObject.crypto || webcrypto;
windowObject.performance = performance;
windowObject.TextEncoder = TextEncoder;
windowObject.requestIdleCallback =
  windowObject.requestIdleCallback ||
  ((callback) => setTimeout(() => callback({ timeRemaining: () => 1, didTimeout: false }), 0));
windowObject.navigator = {
  userAgent: payload.user_agent || "Mozilla/5.0",
  language: payload.language || "en-US",
  languages: Array.isArray(payload.languages) && payload.languages.length ? payload.languages : ["en-US", "en"],
  hardwareConcurrency: Number(payload.hardware_concurrency || 8),
  platform: payload.platform || "Win32",
  vendor: payload.vendor || "Google Inc.",
  deviceMemory: Number(payload.device_memory || 8),
};
windowObject.screen = {
  width: Number(payload.screen_width || 1920),
  height: Number(payload.screen_height || 1080),
};
windowObject.document = documentObject;
windowObject.location = new URL(payload.page_url || "https://auth.openai.com/about-you");

if (globalThis.Intl && globalThis.Intl.DateTimeFormat) {
  const rawResolvedOptions = globalThis.Intl.DateTimeFormat.prototype.resolvedOptions;
  globalThis.Intl.DateTimeFormat.prototype.resolvedOptions = function (...args) {
    const result = rawResolvedOptions.apply(this, args);
    return {
      ...result,
      timeZone: payload.timezone_id || result.timeZone,
    };
  };
}

function xorText(text, key) {
  const normalizedKey = String(key ?? "");
  if (!normalizedKey) {
    return text;
  }
  let output = "";
  for (let index = 0; index < text.length; index += 1) {
    output += String.fromCharCode(
      text.charCodeAt(index) ^ normalizedKey.charCodeAt(index % normalizedKey.length),
    );
  }
  return output;
}

function createVm({ timeoutMs, timeoutMode }) {
  const state = new Map();
  let counter = 0;
  let chain = Promise.resolve();
  const queueKey = 9;
  const storeKey = 16;

  function enqueue(task) {
    const next = chain.then(task, task);
    chain = next.then(() => {}, () => {});
    return next;
  }

  async function runQueue() {
    while (Array.isArray(state.get(queueKey)) && state.get(queueKey).length > 0) {
      const instruction = state.get(queueKey).shift();
      const [opcode, ...args] = instruction;
      const handler = state.get(opcode);
      if (typeof handler !== "function") {
        throw new Error(`unknown vm opcode: ${String(opcode)}`);
      }
      const result = handler(...args);
      if (result && typeof result.then === "function") {
        await result;
      }
      counter += 1;
    }
  }

  function resetState() {
    state.clear();
    state.set(queueKey, []);
    state.set(0, (encoded) => enqueue(() => run(encoded)));
    state.set(1, (target, source) => {
      state.set(target, xorText(String(state.get(target) ?? ""), String(state.get(source) ?? "")));
    });
    state.set(2, (target, value) => state.set(target, value));
    state.set(5, (target, source) => {
      const current = state.get(target);
      if (Array.isArray(current)) {
        current.push(state.get(source));
        return;
      }
      state.set(target, current + state.get(source));
    });
    state.set(27, (target, source) => {
      const current = state.get(target);
      if (Array.isArray(current)) {
        current.splice(current.indexOf(state.get(source)), 1);
        return;
      }
      state.set(target, current - state.get(source));
    });
    state.set(29, (target, left, right) => state.set(target, state.get(left) < state.get(right)));
    state.set(33, (target, left, right) => {
      state.set(target, Number(state.get(left)) * Number(state.get(right)));
    });
    state.set(35, (target, left, right) => {
      const divisor = Number(state.get(right));
      state.set(target, divisor === 0 ? 0 : Number(state.get(left)) / divisor);
    });
    state.set(6, (target, objectKey, propertyKey) => {
      state.set(target, state.get(objectKey)?.[state.get(propertyKey)]);
    });
    state.set(7, (fnKey, ...argKeys) => state.get(fnKey)(...argKeys.map((key) => state.get(key))));
    state.set(17, (target, fnKey, ...argKeys) => {
      try {
        const value = state.get(fnKey)(...argKeys.map((key) => state.get(key)));
        if (value && typeof value.then === "function") {
          return value
            .then((resolved) => {
              state.set(target, resolved);
            })
            .catch((error) => {
              state.set(target, String(error));
            });
        }
        state.set(target, value);
      } catch (error) {
        state.set(target, String(error));
      }
      return undefined;
    });
    state.set(13, (target, fnKey, ...rawArgs) => {
      try {
        state.get(fnKey)(...rawArgs);
      } catch (error) {
        state.set(target, String(error));
      }
    });
    state.set(8, (target, source) => state.set(target, state.get(source)));
    state.set(10, windowObject);
    state.set(11, (target, patternKey) => {
      const pattern = state.get(patternKey);
      const match = (
        Array.from(documentObject.scripts || [])
          .map((item) => item?.src?.match(pattern))
          .filter((item) => item?.length)[0] ?? []
      )[0] ?? null;
      state.set(target, match);
    });
    state.set(12, (target) => state.set(target, state));
    state.set(14, (target, source) => state.set(target, JSON.parse(String(state.get(source) ?? ""))));
    state.set(15, (target, source) => state.set(target, JSON.stringify(state.get(source))));
    state.set(16, (target) => state.set(target, atob(String(state.get(target) ?? ""))));
    state.set(19, (target) => state.set(target, btoa(String(state.get(target) ?? ""))));
    state.set(20, (left, right, fnKey, ...rawArgs) => {
      if (state.get(left) === state.get(right)) {
        return state.get(fnKey)(...rawArgs);
      }
      return null;
    });
    state.set(21, (left, right, threshold, fnKey, ...rawArgs) => {
      if (Math.abs(state.get(left) - state.get(right)) > state.get(threshold)) {
        return state.get(fnKey)(...rawArgs);
      }
      return null;
    });
    state.set(23, (guardKey, fnKey, ...rawArgs) => {
      if (state.get(guardKey) !== undefined) {
        return state.get(fnKey)(...rawArgs);
      }
      return null;
    });
    state.set(24, (target, objectKey, propertyKey) => {
      state.set(target, state.get(objectKey)[state.get(propertyKey)].bind(state.get(objectKey)));
    });
    state.set(34, (target, source) => {
      try {
        return Promise.resolve(state.get(source)).then((value) => {
          state.set(target, value);
        });
      } catch {
        return undefined;
      }
    });
    state.set(22, (target, nestedQueue) => {
      const previousQueue = [...(state.get(queueKey) || [])];
      state.set(queueKey, [...nestedQueue]);
      return runQueue()
        .then((value) => {
          state.set(target, String(value));
        })
        .finally(() => {
          state.set(queueKey, previousQueue);
        });
    });
    state.set(25, () => {});
    state.set(26, () => {});
    state.set(28, () => {});
  }

  async function run(encoded, key) {
    return enqueue(
      () =>
        new Promise((resolve, reject) => {
          if (key !== undefined) {
            resetState();
            counter = 0;
            state.set(storeKey, key);
          }

          let finished = false;
          const finishResolve = (value) => {
            if (finished) {
              return;
            }
            finished = true;
            clearTimeout(timer);
            resolve(value);
          };
          const finishReject = (value) => {
            if (finished) {
              return;
            }
            finished = true;
            clearTimeout(timer);
            reject(value);
          };

          const timer = setTimeout(() => {
            if (timeoutMode === "error") {
              finishReject(new Error("session_observer_vm_timeout"));
              return;
            }
            finishResolve(String(counter));
          }, timeoutMs);

          state.set(3, (value) => {
            finishResolve(btoa(String(value)));
          });
          state.set(4, (value) => {
            finishReject(btoa(String(value)));
          });
          state.set(30, (target, resultKey, bindKeysOrQueue, maybeQueue) => {
            const hasBindings = Array.isArray(maybeQueue);
            const bindKeys = hasBindings ? bindKeysOrQueue : [];
            const queue = (hasBindings ? maybeQueue : bindKeysOrQueue) || [];
            state.set(target, (...args) => {
              if (finished) {
                return undefined;
              }
              const previousQueue = [...(state.get(queueKey) || [])];
              if (hasBindings) {
                for (let index = 0; index < bindKeys.length; index += 1) {
                  state.set(bindKeys[index], args[index]);
                }
              }
              state.set(queueKey, [...queue]);
              return runQueue()
                .then(() => state.get(resultKey))
                .catch((error) => String(error))
                .finally(() => {
                  state.set(queueKey, previousQueue);
                });
            });
          });

          try {
            const decodedQueue = JSON.parse(xorText(atob(encoded), String(state.get(storeKey) ?? "")));
            state.set(queueKey, decodedQueue);
            runQueue()
              .then((value) => {
                finishResolve(btoa(`${counter}: ${value}`));
              })
              .catch((error) => {
                finishResolve(btoa(`${counter}: ${String(error)}`));
              });
          } catch (error) {
            finishResolve(btoa(`${counter}: ${String(error)}`));
          }
        }),
    );
  }

  return { run };
}

async function main() {
  const challenge = payload.challenge || {};
  const proof = String(payload.proof || "");
  const turnstileVm = createVm({ timeoutMs: 500, timeoutMode: "counter" });
  const sessionObserverVm = createVm({ timeoutMs: 60000, timeoutMode: "error" });

  let turnstileToken = null;
  if (challenge?.turnstile?.required && typeof challenge.turnstile.dx === "string") {
    turnstileToken = await turnstileVm.run(challenge.turnstile.dx, proof);
  }

  let sessionObserverToken = null;
  if (
    challenge?.so?.required &&
    typeof challenge.so.collector_dx === "string" &&
    typeof challenge.so.snapshot_dx === "string"
  ) {
    try {
      await sessionObserverVm.run(challenge.so.collector_dx, proof);
      sessionObserverToken = await sessionObserverVm.run(challenge.so.snapshot_dx);
    } catch {
      sessionObserverToken = null;
    }
  }

  process.stdout.write(
    JSON.stringify(
      {
        t: turnstileToken,
        so: sessionObserverToken,
      },
      null,
      0,
    ),
  );
}

main().catch((error) => {
  process.stderr.write(String(error && error.stack ? error.stack : error));
  process.exit(1);
});
