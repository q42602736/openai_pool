from __future__ import annotations

import json
import os
import platform as py_platform
import random
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FingerprintProfile:
    curl_impersonate: str
    chrome_major: int
    chrome_full_version: str
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    sec_ch_ua_arch: str
    sec_ch_ua_bitness: str
    sec_ch_ua_full_version: str
    sec_ch_ua_full_version_list: str
    sec_ch_ua_platform_version: str
    accept_language: str
    locale: str
    language: str
    languages: tuple[str, ...]
    timezone_id: str
    viewport_width: int
    viewport_height: int
    screen_width: int
    screen_height: int
    hardware_concurrency: int
    device_memory: int
    platform: str
    vendor: str
    device_pixel_ratio: float
    max_touch_points: int
    brands: tuple[tuple[str, str], ...]
    full_version_list: tuple[tuple[str, str], ...]
    canvas_noise_rgba: tuple[int, int, int, int]
    canvas_noise_stride: int
    webgl_vendor: str
    webgl_renderer: str
    audio_noise: float
    audio_noise_stride: int
    connection_downlink: float
    connection_effective_type: str
    connection_rtt: int
    connection_save_data: bool
    connection_type: str
    media_devices: tuple[tuple[str, str, str, str], ...]
    battery_charging: bool
    battery_level: float
    battery_charging_time: int
    battery_discharging_time: int
    storage_quota: int
    storage_usage: int
    storage_persisted: bool
    heap_size_limit: int
    total_js_heap_size: int
    used_js_heap_size: int
    primary_pointer_type: str
    any_pointer_type: str
    hover_enabled: bool
    any_hover_enabled: bool
    screen_orientation_type: str
    screen_orientation_angle: int

    @property
    def languages_header(self) -> str:
        return ",".join(self.languages)

    @property
    def ch_platform(self) -> str:
        return _strip_quotes(self.sec_ch_ua_platform)

    @property
    def ch_arch(self) -> str:
        return _strip_quotes(self.sec_ch_ua_arch)

    @property
    def ch_bitness(self) -> str:
        return _strip_quotes(self.sec_ch_ua_bitness)

    @property
    def ch_platform_version(self) -> str:
        return _strip_quotes(self.sec_ch_ua_platform_version)

    def to_cdp_user_agent_metadata(self) -> dict[str, Any]:
        return {
            "brands": [{"brand": brand, "version": version} for brand, version in self.brands],
            "fullVersionList": [
                {"brand": brand, "version": version} for brand, version in self.full_version_list
            ],
            "fullVersion": self.chrome_full_version,
            "platform": self.ch_platform,
            "platformVersion": self.ch_platform_version,
            "architecture": self.ch_arch,
            "bitness": self.ch_bitness,
            "model": "",
            "mobile": False,
            "wow64": False,
        }

    def to_init_script(self) -> str:
        plugins = [
            {
                "name": "PDF Viewer",
                "filename": "internal-pdf-viewer",
                "description": "Portable Document Format",
                "mimeTypes": [
                    {
                        "type": "application/pdf",
                        "suffixes": "pdf",
                        "description": "Portable Document Format",
                    }
                ],
            },
            {
                "name": "Chrome PDF Viewer",
                "filename": "internal-pdf-viewer",
                "description": "Portable Document Format",
                "mimeTypes": [
                    {
                        "type": "application/x-google-chrome-pdf",
                        "suffixes": "pdf",
                        "description": "Portable Document Format",
                    }
                ],
            },
        ]
        payload = {
            "userAgent": self.user_agent,
            "appVersion": self.user_agent.replace("Mozilla/", "", 1),
            "language": self.language,
            "languages": list(self.languages),
            "platform": self.platform,
            "vendor": self.vendor,
            "hardwareConcurrency": self.hardware_concurrency,
            "deviceMemory": self.device_memory,
            "devicePixelRatio": self.device_pixel_ratio,
            "maxTouchPoints": self.max_touch_points,
            "screenWidth": self.screen_width,
            "screenHeight": self.screen_height,
            "availWidth": self.screen_width,
            "availHeight": max(720, self.screen_height - 40),
            "colorDepth": 24,
            "pixelDepth": 24,
            "outerWidth": self.screen_width,
            "outerHeight": self.screen_height,
            "innerWidth": self.viewport_width,
            "innerHeight": self.viewport_height,
            "timezoneId": self.timezone_id,
            "brands": [{"brand": brand, "version": version} for brand, version in self.brands],
            "fullVersionList": [
                {"brand": brand, "version": version} for brand, version in self.full_version_list
            ],
            "uaPlatform": self.ch_platform,
            "architecture": self.ch_arch,
            "bitness": self.ch_bitness,
            "platformVersion": self.ch_platform_version,
            "chromeFullVersion": self.chrome_full_version,
            "pdfViewerEnabled": True,
            "plugins": plugins,
            "webdriver": None,
            "canvasNoise": {
                "rgba": list(self.canvas_noise_rgba),
                "stride": self.canvas_noise_stride,
            },
            "webgl": {
                "vendor": self.webgl_vendor,
                "renderer": self.webgl_renderer,
            },
            "audio": {
                "delta": self.audio_noise,
                "stride": self.audio_noise_stride,
            },
            "connection": {
                "downlink": self.connection_downlink,
                "effectiveType": self.connection_effective_type,
                "rtt": self.connection_rtt,
                "saveData": self.connection_save_data,
                "type": self.connection_type,
            },
            "mediaDevices": [
                {
                    "kind": kind,
                    "deviceId": device_id,
                    "groupId": group_id,
                    "label": label,
                }
                for kind, device_id, group_id, label in self.media_devices
            ],
            "battery": {
                "charging": self.battery_charging,
                "level": self.battery_level,
                "chargingTime": self.battery_charging_time,
                "dischargingTime": self.battery_discharging_time,
            },
            "storage": {
                "quota": self.storage_quota,
                "usage": self.storage_usage,
                "persisted": self.storage_persisted,
            },
            "heap": {
                "jsHeapSizeLimit": self.heap_size_limit,
                "totalJSHeapSize": self.total_js_heap_size,
                "usedJSHeapSize": self.used_js_heap_size,
            },
            "pointer": {
                "primary": self.primary_pointer_type,
                "any": self.any_pointer_type,
                "hover": self.hover_enabled,
                "anyHover": self.any_hover_enabled,
            },
            "orientation": {
                "type": self.screen_orientation_type,
                "angle": self.screen_orientation_angle,
            },
        }
        payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return (
            """
(() => {
  const profile = __OPO_FINGERPRINT_PAYLOAD__;
  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const makeArrayLike = (items, keyName, extraMethods = {}) => {
    const list = items.slice();
    for (const [key, value] of Object.entries(extraMethods)) {
      try {
        Object.defineProperty(list, key, {
          value,
          configurable: true,
        });
      } catch (_error) {}
    }
    try {
      Object.defineProperty(list, "item", {
        value: (index) => list[index] || null,
        configurable: true,
      });
    } catch (_error) {}
    try {
      Object.defineProperty(list, "namedItem", {
        value: (name) => list.find((entry) => entry && entry[keyName] === name) || null,
        configurable: true,
      });
    } catch (_error) {}
    items.forEach((entry, index) => {
      try {
        list[index] = entry;
      } catch (_error) {}
      const entryKey = entry && entry[keyName];
      if (entryKey) {
        try {
          Object.defineProperty(list, entryKey, {
            value: entry,
            configurable: true,
          });
        } catch (_error) {}
      }
    });
    return list;
  };
  const define = (obj, key, value) => {
    try {
      Object.defineProperty(obj, key, {
        get: () => (value === null ? undefined : value),
        configurable: true,
      });
    } catch (_error) {}
  };
  const setValue = (obj, key, value) => {
    try {
      Object.defineProperty(obj, key, {
        value,
        configurable: true,
      });
    } catch (_error) {}
  };

  define(navigator, "webdriver", profile.webdriver);
  define(navigator, "userAgent", profile.userAgent);
  define(navigator, "appVersion", profile.appVersion);
  define(navigator, "language", profile.language);
  define(navigator, "languages", profile.languages);
  define(navigator, "platform", profile.platform);
  define(navigator, "vendor", profile.vendor);
  define(navigator, "hardwareConcurrency", profile.hardwareConcurrency);
  define(navigator, "deviceMemory", profile.deviceMemory);
  define(navigator, "maxTouchPoints", profile.maxTouchPoints);
  define(navigator, "pdfViewerEnabled", profile.pdfViewerEnabled);
  define(navigator, "onLine", true);
  define(navigator, "cookieEnabled", true);
  define(navigator, "appCodeName", "Mozilla");
  define(navigator, "appName", "Netscape");
  define(navigator, "product", "Gecko");
  define(navigator, "productSub", "20030107");
  define(navigator, "vendorSub", "");
  define(window, "devicePixelRatio", profile.devicePixelRatio);

  try {
    if (!window.chrome) {
      setValue(window, "chrome", {});
    }
    if (window.chrome && !window.chrome.app) {
      setValue(window.chrome, "app", {
        InstallState: {
          DISABLED: "disabled",
          INSTALLED: "installed",
          NOT_INSTALLED: "not_installed",
        },
        RunningState: {
          CANNOT_RUN: "cannot_run",
          READY_TO_RUN: "ready_to_run",
          RUNNING: "running",
        },
        isInstalled: false,
      });
    }
    if (window.chrome && !window.chrome.runtime) {
      setValue(window.chrome, "runtime", {});
    }
    if (window.chrome && !window.chrome.csi) {
      setValue(window.chrome, "csi", () => {
        const start = Number(window.performance?.timing?.navigationStart || Date.now() - 1200);
        const now = Date.now();
        return {
          onloadT: now,
          startE: start,
          pageT: Math.max(1, now - start),
          tran: 15,
        };
      });
    }
    if (window.chrome && !window.chrome.loadTimes) {
      setValue(window.chrome, "loadTimes", () => {
        const start = Number(window.performance?.timing?.navigationStart || Date.now() - 1200) / 1000;
        return {
          requestTime: start,
          startLoadTime: start,
          commitLoadTime: start + 0.08,
          finishDocumentLoadTime: start + 0.32,
          finishLoadTime: start + 0.61,
          firstPaintTime: start + 0.44,
          firstPaintAfterLoadTime: 0,
          navigationType: "Other",
          wasFetchedViaSpdy: true,
          wasNpnNegotiated: true,
          npnNegotiatedProtocol: "h2",
          wasAlternateProtocolAvailable: false,
          connectionInfo: "h2",
        };
      });
    }
  } catch (_error) {}

  const pluginObjects = profile.plugins.map((plugin) => {
    const mimeTypes = (plugin.mimeTypes || []).map((mimeType) => ({
      type: mimeType.type,
      suffixes: mimeType.suffixes,
      description: mimeType.description,
    }));
    const pluginObject = makeArrayLike(mimeTypes, "type");
    define(pluginObject, "name", plugin.name);
    define(pluginObject, "filename", plugin.filename);
    define(pluginObject, "description", plugin.description);
    mimeTypes.forEach((mimeType) => define(mimeType, "enabledPlugin", pluginObject));
    return pluginObject;
  });
  const mimeTypeObjects = pluginObjects.flatMap((plugin) => Array.from(plugin));
  const pluginArray = makeArrayLike(pluginObjects, "name", {
    refresh: () => undefined,
  });
  const mimeTypeArray = makeArrayLike(mimeTypeObjects, "type");
  define(navigator, "plugins", pluginArray);
  define(navigator, "mimeTypes", mimeTypeArray);

  define(navigator, "userAgentData", {
    brands: profile.brands,
    mobile: false,
    platform: profile.uaPlatform,
    getHighEntropyValues: async (hints = []) => {
      const values = {
        architecture: profile.architecture,
        bitness: profile.bitness,
        brands: profile.brands,
        fullVersionList: profile.fullVersionList,
        mobile: false,
        model: "",
        platform: profile.uaPlatform,
        platformVersion: profile.platformVersion,
        uaFullVersion: profile.chromeFullVersion,
        wow64: false,
      };
      const result = {
        brands: profile.brands,
        mobile: false,
        platform: profile.uaPlatform,
      };
      for (const hint of hints || []) {
        if (hint in values) {
          result[hint] = values[hint];
        }
      }
      return result;
    },
    toJSON: () => ({
      brands: profile.brands,
      mobile: false,
      platform: profile.uaPlatform,
    }),
  });

  if (navigator.permissions && navigator.permissions.query) {
    const rawQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = (parameters) => {
      const name = parameters && parameters.name;
      if (name === "notifications") {
        return Promise.resolve({
          state: Notification.permission || "default",
          onchange: null,
        });
      }
      if (["camera", "microphone", "clipboard-read", "clipboard-write"].includes(String(name || ""))) {
        return Promise.resolve({
          state: "prompt",
          onchange: null,
        });
      }
      return rawQuery(parameters);
    };
  }

  const connectionTarget = typeof EventTarget !== "undefined" ? new EventTarget() : {};
  if (typeof connectionTarget.addEventListener !== "function") {
    setValue(connectionTarget, "addEventListener", () => undefined);
    setValue(connectionTarget, "removeEventListener", () => undefined);
    setValue(connectionTarget, "dispatchEvent", () => true);
  }
  define(connectionTarget, "downlink", profile.connection.downlink);
  define(connectionTarget, "effectiveType", profile.connection.effectiveType);
  define(connectionTarget, "rtt", profile.connection.rtt);
  define(connectionTarget, "saveData", profile.connection.saveData);
  define(connectionTarget, "type", profile.connection.type);
  setValue(connectionTarget, "toJSON", () => ({
    downlink: profile.connection.downlink,
    effectiveType: profile.connection.effectiveType,
    rtt: profile.connection.rtt,
    saveData: profile.connection.saveData,
    type: profile.connection.type,
  }));
  define(navigator, "connection", connectionTarget);

  const resolveInfinite = (value) => (Number(value) < 0 ? Infinity : Number(value || 0));
  const batteryTarget = typeof EventTarget !== "undefined" ? new EventTarget() : {};
  if (typeof batteryTarget.addEventListener !== "function") {
    setValue(batteryTarget, "addEventListener", () => undefined);
    setValue(batteryTarget, "removeEventListener", () => undefined);
    setValue(batteryTarget, "dispatchEvent", () => true);
  }
  define(batteryTarget, "charging", !!profile.battery.charging);
  define(batteryTarget, "level", Number(profile.battery.level || 1));
  define(batteryTarget, "chargingTime", resolveInfinite(profile.battery.chargingTime));
  define(batteryTarget, "dischargingTime", resolveInfinite(profile.battery.dischargingTime));
  setValue(batteryTarget, "toJSON", () => ({
    charging: !!profile.battery.charging,
    level: Number(profile.battery.level || 1),
    chargingTime: resolveInfinite(profile.battery.chargingTime),
    dischargingTime: resolveInfinite(profile.battery.dischargingTime),
  }));
  define(navigator, "getBattery", () => Promise.resolve(batteryTarget));

  const createMediaDeviceInfo = (entry) => {
    const payload = {
      deviceId: entry.deviceId,
      kind: entry.kind,
      label: entry.label || "",
      groupId: entry.groupId || "",
    };
    return {
      ...payload,
      toJSON: () => ({ ...payload }),
    };
  };
  const mediaDeviceInfos = (profile.mediaDevices || []).map(createMediaDeviceInfo);
  const rawMediaDevices = navigator.mediaDevices || (typeof EventTarget !== "undefined" ? new EventTarget() : {});
  if (typeof rawMediaDevices.addEventListener !== "function") {
    setValue(rawMediaDevices, "addEventListener", () => undefined);
    setValue(rawMediaDevices, "removeEventListener", () => undefined);
    setValue(rawMediaDevices, "dispatchEvent", () => true);
  }
  setValue(rawMediaDevices, "ondevicechange", null);
  setValue(rawMediaDevices, "enumerateDevices", async () => mediaDeviceInfos.map(createMediaDeviceInfo));
  setValue(rawMediaDevices, "getSupportedConstraints", () => ({
    aspectRatio: true,
    autoGainControl: true,
    channelCount: true,
    deviceId: true,
    echoCancellation: true,
    facingMode: true,
    frameRate: true,
    groupId: true,
    height: true,
    latency: true,
    noiseSuppression: true,
    resizeMode: true,
    sampleRate: true,
    sampleSize: true,
    width: true,
  }));
  if (typeof rawMediaDevices.getDisplayMedia !== "function") {
    setValue(rawMediaDevices, "getDisplayMedia", () =>
      Promise.reject(new DOMException("Requested device not found", "NotFoundError")));
  }
  if (typeof rawMediaDevices.getUserMedia !== "function") {
    setValue(rawMediaDevices, "getUserMedia", () =>
      Promise.reject(new DOMException("Permission denied", "NotAllowedError")));
  }
  define(navigator, "mediaDevices", rawMediaDevices);

  const storageTarget = navigator.storage || {};
  const buildUsageDetails = () => {
    const usage = Number(profile.storage.usage || 0);
    const caches = Math.floor(usage * 0.28);
    const indexedDB = Math.floor(usage * 0.52);
    const serviceWorkerRegistrations = Math.max(0, usage - caches - indexedDB);
    return {
      caches,
      indexedDB,
      serviceWorkerRegistrations,
    };
  };
  setValue(storageTarget, "estimate", async () => ({
    quota: Number(profile.storage.quota || 0),
    usage: Number(profile.storage.usage || 0),
    usageDetails: buildUsageDetails(),
  }));
  setValue(storageTarget, "persisted", async () => !!profile.storage.persisted);
  setValue(storageTarget, "persist", async () => !!profile.storage.persisted);
  define(navigator, "storage", storageTarget);

  if (window.performance) {
    define(window.performance, "memory", {
      jsHeapSizeLimit: Number(profile.heap.jsHeapSizeLimit || 0),
      totalJSHeapSize: Number(profile.heap.totalJSHeapSize || 0),
      usedJSHeapSize: Number(profile.heap.usedJSHeapSize || 0),
    });
  }

  const rawMatchMedia = typeof window.matchMedia === "function" ? window.matchMedia.bind(window) : null;
  const evaluatePointerMediaQuery = (queryText) => {
    const text = String(queryText || "").toLowerCase();
    const checks = [];
    const addCheck = (pattern, expected) => {
      const match = pattern.exec(text);
      if (match) {
        checks.push(String(match[1]).trim() === expected);
      }
    };
    addCheck(/\(\s*pointer\s*:\s*(fine|coarse|none)\s*\)/, profile.pointer.primary);
    addCheck(/\(\s*any-pointer\s*:\s*(fine|coarse|none)\s*\)/, profile.pointer.any);
    addCheck(/\(\s*hover\s*:\s*(hover|none)\s*\)/, profile.pointer.hover ? "hover" : "none");
    addCheck(/\(\s*any-hover\s*:\s*(hover|none)\s*\)/, profile.pointer.anyHover ? "hover" : "none");
    if (!checks.length) {
      return null;
    }
    return checks.every(Boolean);
  };
  if (rawMatchMedia) {
    window.matchMedia = (query) => {
      const result = rawMatchMedia(query);
      const forced = evaluatePointerMediaQuery(query);
      if (forced === null) {
        return result;
      }
      try {
        Object.defineProperty(result, "matches", {
          get: () => forced,
          configurable: true,
        });
      } catch (_error) {}
      return result;
    };
  }

  const touchedCanvas = new WeakSet();
  const applyCanvasNoise = (canvas) => {
    if (!canvas || touchedCanvas.has(canvas)) {
      return;
    }
    try {
      const width = Number(canvas.width || 0);
      const height = Number(canvas.height || 0);
      if (!width || !height) {
        return;
      }
      const ctx = canvas.getContext("2d");
      if (!ctx || typeof ctx.getImageData !== "function" || typeof ctx.putImageData !== "function") {
        return;
      }
      const sampleWidth = Math.min(width, 64);
      const sampleHeight = Math.min(height, 64);
      const imageData = ctx.getImageData(0, 0, sampleWidth, sampleHeight);
      const data = imageData.data || [];
      const stride = Math.max(1, Number(profile.canvasNoise.stride || 1)) * 4;
      const rgba = Array.isArray(profile.canvasNoise.rgba) ? profile.canvasNoise.rgba : [0, 0, 0, 0];
      for (let index = 0; index < data.length; index += stride) {
        data[index] = clamp(data[index] + Number(rgba[0] || 0), 0, 255);
        data[index + 1] = clamp(data[index + 1] + Number(rgba[1] || 0), 0, 255);
        data[index + 2] = clamp(data[index + 2] + Number(rgba[2] || 0), 0, 255);
        data[index + 3] = clamp(data[index + 3] + Number(rgba[3] || 0), 0, 255);
      }
      ctx.putImageData(imageData, 0, 0);
      touchedCanvas.add(canvas);
    } catch (_error) {}
  };

  if (window.HTMLCanvasElement && HTMLCanvasElement.prototype) {
    const rawToDataURL = HTMLCanvasElement.prototype.toDataURL;
    if (typeof rawToDataURL === "function") {
      HTMLCanvasElement.prototype.toDataURL = function (...args) {
        applyCanvasNoise(this);
        return rawToDataURL.apply(this, args);
      };
    }
    const rawToBlob = HTMLCanvasElement.prototype.toBlob;
    if (typeof rawToBlob === "function") {
      HTMLCanvasElement.prototype.toBlob = function (...args) {
        applyCanvasNoise(this);
        return rawToBlob.apply(this, args);
      };
    }
  }

  if (window.OffscreenCanvas && OffscreenCanvas.prototype) {
    const rawConvertToBlob = OffscreenCanvas.prototype.convertToBlob;
    if (typeof rawConvertToBlob === "function") {
      OffscreenCanvas.prototype.convertToBlob = function (...args) {
        applyCanvasNoise(this);
        return rawConvertToBlob.apply(this, args);
      };
    }
  }

  const WEBGL_DEBUG_RENDERER_INFO = "WEBGL_debug_renderer_info";
  const UNMASKED_VENDOR_WEBGL = 37445;
  const UNMASKED_RENDERER_WEBGL = 37446;
  const installWebGLPatch = (Ctor) => {
    if (!Ctor || !Ctor.prototype) {
      return;
    }
    const proto = Ctor.prototype;
    const rawGetParameter = proto.getParameter;
    if (typeof rawGetParameter === "function") {
      proto.getParameter = function (parameter) {
        if (parameter === UNMASKED_VENDOR_WEBGL) {
          return profile.webgl.vendor;
        }
        if (parameter === UNMASKED_RENDERER_WEBGL) {
          return profile.webgl.renderer;
        }
        return rawGetParameter.apply(this, arguments);
      };
    }
    const rawGetExtension = proto.getExtension;
    if (typeof rawGetExtension === "function") {
      proto.getExtension = function (name) {
        if (String(name || "").toLowerCase() === WEBGL_DEBUG_RENDERER_INFO.toLowerCase()) {
          return {
            UNMASKED_VENDOR_WEBGL,
            UNMASKED_RENDERER_WEBGL,
          };
        }
        return rawGetExtension.apply(this, arguments);
      };
    }
    const rawGetSupportedExtensions = proto.getSupportedExtensions;
    if (typeof rawGetSupportedExtensions === "function") {
      proto.getSupportedExtensions = function (...args) {
        const result = rawGetSupportedExtensions.apply(this, args) || [];
        return result.includes(WEBGL_DEBUG_RENDERER_INFO)
          ? result
          : result.concat(WEBGL_DEBUG_RENDERER_INFO);
      };
    }
  };
  installWebGLPatch(window.WebGLRenderingContext);
  installWebGLPatch(window.WebGL2RenderingContext);

  const touchedAudioBuffers = new WeakSet();
  const applyAudioNoise = (values, scale = 1, persist = false) => {
    if (!values || typeof values.length !== "number") {
      return values;
    }
    if (persist && touchedAudioBuffers.has(values)) {
      return values;
    }
    const stride = Math.max(1, Number(profile.audio.stride || 1));
    const delta = Number(profile.audio.delta || 0) * scale;
    for (let index = 0; index < values.length; index += stride) {
      const currentValue = Number(values[index] || 0);
      values[index] = clamp(currentValue + delta, -1, 1);
    }
    if (persist) {
      touchedAudioBuffers.add(values);
    }
    return values;
  };

  if (window.AudioBuffer && AudioBuffer.prototype) {
    const rawGetChannelData = AudioBuffer.prototype.getChannelData;
    if (typeof rawGetChannelData === "function") {
      AudioBuffer.prototype.getChannelData = function (...args) {
        const channelData = rawGetChannelData.apply(this, args);
        return applyAudioNoise(channelData, 1, true);
      };
    }
    const rawCopyFromChannel = AudioBuffer.prototype.copyFromChannel;
    if (typeof rawCopyFromChannel === "function") {
      AudioBuffer.prototype.copyFromChannel = function (...args) {
        const result = rawCopyFromChannel.apply(this, args);
        const destination = args && args[0];
        applyAudioNoise(destination, 1, false);
        return result;
      };
    }
  }

  if (window.AnalyserNode && AnalyserNode.prototype) {
    const rawGetFloatFrequencyData = AnalyserNode.prototype.getFloatFrequencyData;
    if (typeof rawGetFloatFrequencyData === "function") {
      AnalyserNode.prototype.getFloatFrequencyData = function (...args) {
        const result = rawGetFloatFrequencyData.apply(this, args);
        const destination = args && args[0];
        applyAudioNoise(destination, 12, false);
        return result;
      };
    }
    const rawGetFloatTimeDomainData = AnalyserNode.prototype.getFloatTimeDomainData;
    if (typeof rawGetFloatTimeDomainData === "function") {
      AnalyserNode.prototype.getFloatTimeDomainData = function (...args) {
        const result = rawGetFloatTimeDomainData.apply(this, args);
        const destination = args && args[0];
        applyAudioNoise(destination, 1, false);
        return result;
      };
    }
  }

  const installAudioSampleRatePatch = (Ctor) => {
    if (!Ctor || !Ctor.prototype) {
      return;
    }
    try {
      Object.defineProperty(Ctor.prototype, "sampleRate", {
        get() {
          return 48000;
        },
        configurable: true,
      });
    } catch (_error) {}
  };
  installAudioSampleRatePatch(window.BaseAudioContext);
  installAudioSampleRatePatch(window.AudioContext);
  installAudioSampleRatePatch(window.webkitAudioContext);
  installAudioSampleRatePatch(window.OfflineAudioContext);

  if (window.screen) {
    const orientationTarget = window.screen.orientation || (typeof EventTarget !== "undefined" ? new EventTarget() : {});
    if (typeof orientationTarget.addEventListener !== "function") {
      setValue(orientationTarget, "addEventListener", () => undefined);
      setValue(orientationTarget, "removeEventListener", () => undefined);
      setValue(orientationTarget, "dispatchEvent", () => true);
    }
    define(orientationTarget, "type", profile.orientation.type);
    define(orientationTarget, "angle", Number(profile.orientation.angle || 0));
    setValue(orientationTarget, "onchange", null);
    define(window.screen, "orientation", orientationTarget);
  }

  const LOCAL_IP_PATTERN = /\b(?:127\.0\.0\.1|0\.0\.0\.0|::1|192\.168(?:\.\d{1,3}){2}|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b/ig;
  const sanitizeCandidateText = (candidateText) => {
    const text = String(candidateText || "");
    if (!text) {
      return text;
    }
    if (/\btyp\s+host\b/i.test(text)) {
      return "";
    }
    return text.replace(LOCAL_IP_PATTERN, "0.0.0.0");
  };
  const sanitizeSdp = (sdpText) => {
    return String(sdpText || "")
      .split(/\r?\n/)
      .filter((line) => {
        if (!/^a=candidate:/i.test(line)) {
          return true;
        }
        const candidateText = sanitizeCandidateText(line.replace(/^a=/i, ""));
        return Boolean(candidateText);
      })
      .map((line) => {
        if (/^(a=candidate:|candidate:)/i.test(line)) {
          const prefix = line.startsWith("a=") ? "a=" : "";
          const body = line.replace(/^a=/i, "");
          const sanitized = sanitizeCandidateText(body);
          return sanitized ? `${prefix}${sanitized}` : "";
        }
        return line.replace(LOCAL_IP_PATTERN, "0.0.0.0");
      })
      .filter(Boolean)
      .join("\r\n");
  };
  const wrapRtcDescription = (description) => {
    if (!description || !description.sdp) {
      return description;
    }
    const payload = {
      type: description.type || "",
      sdp: sanitizeSdp(description.sdp),
    };
    if (typeof RTCSessionDescription === "function") {
      try {
        return new RTCSessionDescription(payload);
      } catch (_error) {}
    }
    return {
      ...payload,
      toJSON: () => ({ ...payload }),
    };
  };
  const wrapIceCandidate = (candidate) => {
    if (!candidate) {
      return candidate;
    }
    const sanitizedText = sanitizeCandidateText(candidate.candidate || "");
    if (!sanitizedText) {
      return null;
    }
    const payload = {
      candidate: sanitizedText,
      sdpMid: candidate.sdpMid ?? null,
      sdpMLineIndex: candidate.sdpMLineIndex ?? null,
      usernameFragment: candidate.usernameFragment ?? null,
    };
    if (typeof RTCIceCandidate === "function") {
      try {
        return new RTCIceCandidate(payload);
      } catch (_error) {}
    }
    return {
      ...payload,
      toJSON: () => ({ ...payload }),
    };
  };
  const wrapIceEvent = (event) => {
    if (!event || !("candidate" in event)) {
      return event;
    }
    const sanitizedCandidate = wrapIceCandidate(event.candidate);
    if (sanitizedCandidate === event.candidate) {
      return event;
    }
    const proxyEvent = Object.create(event);
    try {
      Object.defineProperty(proxyEvent, "candidate", {
        value: sanitizedCandidate,
        configurable: true,
      });
    } catch (_error) {}
    return proxyEvent;
  };
  const installRtcPatch = (Ctor) => {
    if (!Ctor || !Ctor.prototype) {
      return;
    }
    const proto = Ctor.prototype;
    const listenerMap = new WeakMap();
    const rawCreateOffer = proto.createOffer;
    if (typeof rawCreateOffer === "function") {
      proto.createOffer = async function (...args) {
        const result = await rawCreateOffer.apply(this, args);
        return wrapRtcDescription(result);
      };
    }
    const rawCreateAnswer = proto.createAnswer;
    if (typeof rawCreateAnswer === "function") {
      proto.createAnswer = async function (...args) {
        const result = await rawCreateAnswer.apply(this, args);
        return wrapRtcDescription(result);
      };
    }
    const rawSetLocalDescription = proto.setLocalDescription;
    if (typeof rawSetLocalDescription === "function") {
      proto.setLocalDescription = function (description, ...args) {
        return rawSetLocalDescription.call(this, wrapRtcDescription(description), ...args);
      };
    }
    const wrapDescriptionGetter = (propertyName) => {
      const descriptor = Object.getOwnPropertyDescriptor(proto, propertyName);
      if (descriptor && typeof descriptor.get === "function") {
        try {
          Object.defineProperty(proto, propertyName, {
            get() {
              return wrapRtcDescription(descriptor.get.call(this));
            },
            configurable: true,
          });
        } catch (_error) {}
      }
    };
    wrapDescriptionGetter("localDescription");
    wrapDescriptionGetter("currentLocalDescription");
    wrapDescriptionGetter("pendingLocalDescription");

    const rawAddEventListener = proto.addEventListener;
    const rawRemoveEventListener = proto.removeEventListener;
    if (typeof rawAddEventListener === "function") {
      proto.addEventListener = function (type, listener, options) {
        if (type === "icecandidate" && typeof listener === "function") {
          let wrapped = listenerMap.get(listener);
          if (!wrapped) {
            wrapped = function (event) {
              return listener.call(this, wrapIceEvent(event));
            };
            listenerMap.set(listener, wrapped);
          }
          return rawAddEventListener.call(this, type, wrapped, options);
        }
        return rawAddEventListener.call(this, type, listener, options);
      };
    }
    if (typeof rawRemoveEventListener === "function") {
      proto.removeEventListener = function (type, listener, options) {
        if (type === "icecandidate" && typeof listener === "function" && listenerMap.has(listener)) {
          return rawRemoveEventListener.call(this, type, listenerMap.get(listener), options);
        }
        return rawRemoveEventListener.call(this, type, listener, options);
      };
    }
    const onIceDescriptor = Object.getOwnPropertyDescriptor(proto, "onicecandidate");
    if (onIceDescriptor && typeof onIceDescriptor.set === "function" && typeof onIceDescriptor.get === "function") {
      try {
        Object.defineProperty(proto, "onicecandidate", {
          get() {
            return onIceDescriptor.get.call(this);
          },
          set(listener) {
            if (typeof listener !== "function") {
              return onIceDescriptor.set.call(this, listener);
            }
            return onIceDescriptor.set.call(this, function (event) {
              return listener.call(this, wrapIceEvent(event));
            });
          },
          configurable: true,
        });
      } catch (_error) {}
    }
  };
  installRtcPatch(window.RTCPeerConnection);
  installRtcPatch(window.webkitRTCPeerConnection);

  if (window.screen) {
    define(window.screen, "width", profile.screenWidth);
    define(window.screen, "height", profile.screenHeight);
    define(window.screen, "availWidth", profile.availWidth);
    define(window.screen, "availHeight", profile.availHeight);
    define(window.screen, "availLeft", 0);
    define(window.screen, "availTop", 0);
    define(window.screen, "colorDepth", profile.colorDepth);
    define(window.screen, "pixelDepth", profile.pixelDepth);
    define(window.screen, "isExtended", false);
  }

  define(window, "outerWidth", profile.outerWidth);
  define(window, "outerHeight", profile.outerHeight);
  define(window, "innerWidth", profile.innerWidth);
  define(window, "innerHeight", profile.innerHeight);
  if (window.visualViewport) {
    define(window.visualViewport, "width", profile.innerWidth);
    define(window.visualViewport, "height", profile.innerHeight);
    define(window.visualViewport, "scale", 1);
    define(window.visualViewport, "offsetLeft", 0);
    define(window.visualViewport, "offsetTop", 0);
    define(window.visualViewport, "pageLeft", 0);
    define(window.visualViewport, "pageTop", 0);
  }

  const rawResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
  Intl.DateTimeFormat.prototype.resolvedOptions = function (...args) {
    const result = rawResolvedOptions.apply(this, args);
    try {
      result.timeZone = profile.timezoneId;
    } catch (_error) {}
    return result;
  };
})();
"""
            .replace("__OPO_FINGERPRINT_PAYLOAD__", payload_json)
            .strip()
        )


_CHROME_VERSION_PROFILES = [
    {
        "curl_impersonate": "chrome131",
        "major": 131,
        "build": 6778,
        "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "curl_impersonate": "chrome133a",
        "major": 133,
        "build": 6943,
        "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "curl_impersonate": "chrome136",
        "major": 136,
        "build": 7103,
        "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
    {
        "curl_impersonate": "chrome142",
        "major": 142,
        "build": 7540,
        "patch_range": (30, 150),
        "sec_ch_ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    },
]

_LANGUAGE_PROFILES = [
    {
        "locale": "en-US",
        "language": "en-US",
        "languages": ("en-US", "en"),
        "accept_language": "en-US,en;q=0.9",
    },
    {
        "locale": "en-US",
        "language": "en-US",
        "languages": ("en-US", "en"),
        "accept_language": "en-US,en;q=0.9,zh-CN;q=0.7",
    },
    {
        "locale": "en-CA",
        "language": "en-CA",
        "languages": ("en-CA", "en-US", "en"),
        "accept_language": "en-CA,en-US;q=0.9,en;q=0.8",
    },
    {
        "locale": "en-GB",
        "language": "en-GB",
        "languages": ("en-GB", "en-US", "en"),
        "accept_language": "en-GB,en-US;q=0.9,en;q=0.8",
    },
]

_TIMEZONE_POOL = [
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Phoenix",
]

_VIEWPORT_POOL = [
    (1366, 768),
    (1440, 900),
    (1536, 864),
    (1600, 900),
    (1728, 1117),
    (1920, 1080),
]

_HARDWARE_CONCURRENCY_POOL = [4, 8, 12, 16]
_DEVICE_MEMORY_POOL = [4, 8, 16]
_NOT_A_BRAND_CANDIDATES = ("24", "8", "99")
_CONNECTION_PROFILES = (
    {
        "downlink": 8.2,
        "effective_type": "4g",
        "rtt": 40,
        "save_data": False,
        "type": "wifi",
    },
    {
        "downlink": 12.6,
        "effective_type": "4g",
        "rtt": 55,
        "save_data": False,
        "type": "wifi",
    },
    {
        "downlink": 18.4,
        "effective_type": "4g",
        "rtt": 28,
        "save_data": False,
        "type": "ethernet",
    },
    {
        "downlink": 24.2,
        "effective_type": "4g",
        "rtt": 22,
        "save_data": False,
        "type": "wifi",
    },
)
_WEBGL_RENDERER_POOL = {
    ("darwin", "arm"): (
        (
            "Google Inc. (Apple)",
            "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)",
        ),
        (
            "Google Inc. (Apple)",
            "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
        ),
        (
            "Google Inc. (Apple)",
            "ANGLE (Apple, ANGLE Metal Renderer: Apple M3, Unspecified Version)",
        ),
    ),
    ("darwin", "x86"): (
        (
            "Google Inc. (Apple)",
            "ANGLE (Apple, ANGLE Metal Renderer: AMD Radeon Pro 5300M, Unspecified Version)",
        ),
        (
            "Google Inc. (Apple)",
            "ANGLE (Apple, ANGLE Metal Renderer: Intel(R) Iris Plus Graphics 655, Unspecified Version)",
        ),
        (
            "Google Inc. (Apple)",
            "ANGLE (Apple, ANGLE Metal Renderer: AMD Radeon Pro 5500M, Unspecified Version)",
        ),
    ),
    ("windows", "arm"): (
        (
            "Google Inc. (Qualcomm)",
            "ANGLE (Qualcomm, Adreno 690 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
        (
            "Google Inc. (Qualcomm)",
            "ANGLE (Qualcomm, Adreno 730 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
    ),
    ("windows", "x86"): (
        (
            "Google Inc. (Intel)",
            "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
        (
            "Google Inc. (Intel)",
            "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
        (
            "Google Inc. (NVIDIA)",
            "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
    ),
    ("linux", "arm"): (
        (
            "Google Inc. (Mesa)",
            "ANGLE (Mesa, Mesa/Panfrost, OpenGL 4.6)",
        ),
        (
            "Google Inc. (Mesa)",
            "ANGLE (Mesa, Mali-G610, OpenGL 4.6)",
        ),
    ),
    ("linux", "x86"): (
        (
            "Google Inc. (Mesa)",
            "ANGLE (Mesa, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)",
        ),
        (
            "Google Inc. (Mesa)",
            "ANGLE (Mesa, AMD Radeon RX 6600 XT (radeonsi, navi23, LLVM 17.0.6), OpenGL 4.6)",
        ),
        (
            "Google Inc. (Mesa)",
            "ANGLE (Mesa, NVIDIA GeForce RTX 3060/PCIe/SSE2, OpenGL 4.6)",
        ),
    ),
}
_BATTERY_PROFILE_POOL = (
    {
        "charging": True,
        "level": 1.0,
        "charging_time": 0,
        "discharging_time": -1,
    },
    {
        "charging": True,
        "level": 0.97,
        "charging_time": 900,
        "discharging_time": -1,
    },
    {
        "charging": False,
        "level": 0.82,
        "charging_time": -1,
        "discharging_time": 19200,
    },
    {
        "charging": False,
        "level": 0.68,
        "charging_time": -1,
        "discharging_time": 12600,
    },
)


def _strip_quotes(value: str) -> str:
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def _format_ch_brand_list(items: tuple[tuple[str, str], ...]) -> str:
    return ", ".join(f'"{brand}";v="{version}"' for brand, version in items)


def _normalize_version_text(raw: str, *, segments: int = 4, fallback: str = "") -> str:
    parts = [segment for segment in str(raw or "").strip().split(".") if segment]
    normalized: list[str] = []
    for item in parts[:segments]:
        digits = "".join(ch for ch in item if ch.isdigit())
        normalized.append(digits or "0")
    while len(normalized) < segments:
        normalized.append("0")
    result = ".".join(normalized[:segments]).strip(".")
    return result or fallback


def _build_brand_metadata(chrome_major: int, chrome_full_version: str) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...], str, str]:
    not_brand_version = random.choice(_NOT_A_BRAND_CANDIDATES)
    brands = (
        ("Google Chrome", str(chrome_major)),
        ("Chromium", str(chrome_major)),
        ("Not.A/Brand", not_brand_version),
    )
    full_version_list = (
        ("Google Chrome", chrome_full_version),
        ("Chromium", chrome_full_version),
        ("Not.A/Brand", f"{not_brand_version}.0.0.0"),
    )
    return brands, full_version_list, _format_ch_brand_list(brands), _format_ch_brand_list(full_version_list)


def _runtime_platform_signature() -> tuple[str, str]:
    machine = str(py_platform.machine() or "").strip().lower()
    arch = "arm" if "arm" in machine or "aarch64" in machine else "x86"
    if sys.platform == "darwin":
        return "darwin", arch
    if sys.platform.startswith("win"):
        return "windows", arch
    return "linux", arch


def _build_canvas_noise(rng: random.Random) -> tuple[tuple[int, int, int, int], int]:
    choices = (-2, -1, 0, 1, 2)
    red = green = blue = 0
    while red == 0 and green == 0 and blue == 0:
        red = rng.choice(choices)
        green = rng.choice(choices)
        blue = rng.choice(choices)
    return (red, green, blue, 0), rng.randint(8, 24)


def _build_audio_noise(rng: random.Random) -> tuple[float, int]:
    magnitude = rng.choice((0.0000013, 0.0000017, 0.0000021, 0.0000025))
    sign = rng.choice((-1.0, 1.0))
    return float(f"{sign * magnitude:.7f}"), rng.randint(32, 96)


def _random_token(rng: random.Random, length: int = 32) -> str:
    alphabet = "0123456789abcdef"
    return "".join(rng.choice(alphabet) for _ in range(max(8, length)))


def _choose_connection_profile(rng: random.Random) -> dict[str, Any]:
    return dict(rng.choice(_CONNECTION_PROFILES))


def _choose_webgl_identity(rng: random.Random) -> tuple[str, str]:
    platform_signature = _runtime_platform_signature()
    candidates = _WEBGL_RENDERER_POOL.get(platform_signature) or _WEBGL_RENDERER_POOL[("linux", "x86")]
    vendor, renderer = rng.choice(candidates)
    return str(vendor), str(renderer)


def _build_media_devices(rng: random.Random) -> tuple[tuple[str, str, str, str], ...]:
    audio_group = _random_token(rng, 24)
    video_group = _random_token(rng, 24)
    return (
        ("audioinput", "default", audio_group, ""),
        ("audioinput", _random_token(rng, 32), audio_group, ""),
        ("audiooutput", "default", audio_group, ""),
        ("audiooutput", "communications", audio_group, ""),
        ("videoinput", _random_token(rng, 32), video_group, ""),
    )


def _build_battery_profile(rng: random.Random) -> dict[str, Any]:
    return dict(rng.choice(_BATTERY_PROFILE_POOL))


def _build_storage_profile(device_memory: int, rng: random.Random) -> dict[str, Any]:
    quota_by_memory = {
        4: (10 * 1024**3, 12 * 1024**3),
        8: (16 * 1024**3, 20 * 1024**3),
        16: (24 * 1024**3, 32 * 1024**3),
    }
    quota = rng.choice(quota_by_memory.get(int(device_memory), (12 * 1024**3, 16 * 1024**3)))
    usage = rng.randint(140 * 1024**2, 620 * 1024**2)
    return {
        "quota": int(quota),
        "usage": int(min(usage, int(quota * 0.12))),
        "persisted": False,
    }


def _build_heap_profile(rng: random.Random) -> dict[str, Any]:
    used = rng.randint(42 * 1024**2, 118 * 1024**2)
    total = used + rng.randint(22 * 1024**2, 74 * 1024**2)
    return {
        "limit": 4294705152,
        "total": total,
        "used": min(used, total),
    }


def _build_pointer_profile(max_touch_points: int) -> dict[str, Any]:
    if int(max_touch_points) > 0:
        return {
            "primary": "coarse",
            "any": "coarse",
            "hover": False,
            "any_hover": False,
        }
    return {
        "primary": "fine",
        "any": "fine",
        "hover": True,
        "any_hover": True,
    }


def _build_orientation_profile(viewport_width: int, viewport_height: int) -> dict[str, Any]:
    if int(viewport_width) >= int(viewport_height):
        return {
            "type": "landscape-primary",
            "angle": 0,
        }
    return {
        "type": "portrait-primary",
        "angle": 0,
    }


def _candidate_browser_executable_paths(configured_path: str = "") -> list[str]:
    candidates: list[str] = []
    configured = str(configured_path or "").strip()
    if configured:
        candidates.append(configured)
    if sys.platform == "darwin":
        candidates.extend(
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]
        )
    elif sys.platform.startswith("win"):
        candidates.extend(
            [
                str(os.environ.get("PROGRAMFILES", "")) + "\\Google\\Chrome\\Application\\chrome.exe",
                str(os.environ.get("PROGRAMFILES(X86)", "")) + "\\Google\\Chrome\\Application\\chrome.exe",
            ]
        )
    else:
        for binary_name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
            resolved = shutil.which(binary_name)
            if resolved:
                candidates.append(resolved)
    seen: set[str] = set()
    result: list[str] = []
    for item in candidates:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _detect_local_browser_version(configured_path: str = "") -> str:
    version_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    for executable_path in _candidate_browser_executable_paths(configured_path):
        try:
            completed = subprocess.run(
                [executable_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            continue
        version_text = " ".join(
            item.strip() for item in (completed.stdout, completed.stderr) if str(item or "").strip()
        )
        match = version_pattern.search(version_text)
        if match:
            return match.group(1)
    return ""


def _nearest_impersonate_profile(chrome_major: int) -> dict[str, Any]:
    return min(_CHROME_VERSION_PROFILES, key=lambda item: abs(int(item["major"]) - int(chrome_major)))


def _runtime_platform_defaults() -> dict[str, Any]:
    platform_family, arch = _runtime_platform_signature()
    if platform_family == "darwin":
        mac_version = _normalize_version_text(py_platform.mac_ver()[0], fallback="15.0.0")
        return {
            "user_agent_platform_token": "Macintosh; Intel Mac OS X 10_15_7",
            "navigator_platform": "MacIntel",
            "sec_ch_ua_platform": '"macOS"',
            "sec_ch_ua_arch": f'"{arch}"',
            "sec_ch_ua_bitness": '"64"',
            "sec_ch_ua_platform_version": f'"{mac_version}"',
            "device_pixel_ratio": 2.0,
            "max_touch_points": 0,
        }
    if platform_family == "windows":
        release = _normalize_version_text(py_platform.release(), segments=1, fallback="10")
        return {
            "user_agent_platform_token": "Windows NT 10.0; Win64; x64",
            "navigator_platform": "Win32",
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_arch": f'"{arch}"',
            "sec_ch_ua_bitness": '"64"',
            "sec_ch_ua_platform_version": f'"{release}.0.0"',
            "device_pixel_ratio": random.choice((1.0, 1.25, 1.5)),
            "max_touch_points": 0,
        }
    return {
        "user_agent_platform_token": "X11; Linux x86_64",
        "navigator_platform": "Linux x86_64",
        "sec_ch_ua_platform": '"Linux"',
        "sec_ch_ua_arch": f'"{arch}"',
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_platform_version": '"6.0.0"',
        "device_pixel_ratio": 1.0,
        "max_touch_points": 0,
    }


def _build_profile(
    *,
    chrome_full_version: str,
    locale: str,
    language: str,
    languages: tuple[str, ...],
    accept_language: str,
    timezone_id: str,
    viewport_width: int,
    viewport_height: int,
    hardware_concurrency: int,
    device_memory: int,
) -> FingerprintProfile:
    version_text = _normalize_version_text(chrome_full_version, fallback="145.0.0.0")
    chrome_major = int(version_text.split(".", 1)[0])
    impersonate_profile = _nearest_impersonate_profile(chrome_major)
    platform_defaults = _runtime_platform_defaults()
    session_rng = random.Random(random.getrandbits(64))
    brands, full_version_list, sec_ch_ua, sec_ch_ua_full_version_list = _build_brand_metadata(
        chrome_major,
        version_text,
    )
    canvas_noise_rgba, canvas_noise_stride = _build_canvas_noise(session_rng)
    webgl_vendor, webgl_renderer = _choose_webgl_identity(session_rng)
    audio_noise, audio_noise_stride = _build_audio_noise(session_rng)
    connection_profile = _choose_connection_profile(session_rng)
    media_devices = _build_media_devices(session_rng)
    battery_profile = _build_battery_profile(session_rng)
    storage_profile = _build_storage_profile(device_memory, session_rng)
    heap_profile = _build_heap_profile(session_rng)
    pointer_profile = _build_pointer_profile(int(platform_defaults["max_touch_points"]))
    orientation_profile = _build_orientation_profile(viewport_width, viewport_height)
    return FingerprintProfile(
        curl_impersonate=str(impersonate_profile["curl_impersonate"]),
        chrome_major=chrome_major,
        chrome_full_version=version_text,
        user_agent=(
            f"Mozilla/5.0 ({platform_defaults['user_agent_platform_token']}) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{version_text} Safari/537.36"
        ),
        sec_ch_ua=sec_ch_ua,
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform=str(platform_defaults["sec_ch_ua_platform"]),
        sec_ch_ua_arch=str(platform_defaults["sec_ch_ua_arch"]),
        sec_ch_ua_bitness=str(platform_defaults["sec_ch_ua_bitness"]),
        sec_ch_ua_full_version=f'"{version_text}"',
        sec_ch_ua_full_version_list=sec_ch_ua_full_version_list,
        sec_ch_ua_platform_version=str(platform_defaults["sec_ch_ua_platform_version"]),
        accept_language=accept_language,
        locale=locale,
        language=language,
        languages=languages,
        timezone_id=timezone_id,
        viewport_width=viewport_width,
        viewport_height=viewport_height,
        screen_width=viewport_width,
        screen_height=viewport_height,
        hardware_concurrency=hardware_concurrency,
        device_memory=device_memory,
        platform=str(platform_defaults["navigator_platform"]),
        vendor="Google Inc.",
        device_pixel_ratio=float(platform_defaults["device_pixel_ratio"]),
        max_touch_points=int(platform_defaults["max_touch_points"]),
        brands=brands,
        full_version_list=full_version_list,
        canvas_noise_rgba=canvas_noise_rgba,
        canvas_noise_stride=canvas_noise_stride,
        webgl_vendor=webgl_vendor,
        webgl_renderer=webgl_renderer,
        audio_noise=audio_noise,
        audio_noise_stride=audio_noise_stride,
        connection_downlink=float(connection_profile["downlink"]),
        connection_effective_type=str(connection_profile["effective_type"]),
        connection_rtt=int(connection_profile["rtt"]),
        connection_save_data=bool(connection_profile["save_data"]),
        connection_type=str(connection_profile["type"]),
        media_devices=media_devices,
        battery_charging=bool(battery_profile["charging"]),
        battery_level=float(battery_profile["level"]),
        battery_charging_time=int(battery_profile["charging_time"]),
        battery_discharging_time=int(battery_profile["discharging_time"]),
        storage_quota=int(storage_profile["quota"]),
        storage_usage=int(storage_profile["usage"]),
        storage_persisted=bool(storage_profile["persisted"]),
        heap_size_limit=int(heap_profile["limit"]),
        total_js_heap_size=int(heap_profile["total"]),
        used_js_heap_size=int(heap_profile["used"]),
        primary_pointer_type=str(pointer_profile["primary"]),
        any_pointer_type=str(pointer_profile["any"]),
        hover_enabled=bool(pointer_profile["hover"]),
        any_hover_enabled=bool(pointer_profile["any_hover"]),
        screen_orientation_type=str(orientation_profile["type"]),
        screen_orientation_angle=int(orientation_profile["angle"]),
    )


def build_default_fingerprint_profile() -> FingerprintProfile:
    detected_version = _detect_local_browser_version("") or "145.0.0.0"
    return _build_profile(
        chrome_full_version=detected_version,
        locale="en-US",
        language="en-US",
        languages=("en-US", "en"),
        accept_language="en-US,en;q=0.9",
        timezone_id="America/New_York",
        viewport_width=1440,
        viewport_height=900,
        hardware_concurrency=8,
        device_memory=8,
    )


def generate_fingerprint_profile(
    *,
    locale_override: str = "",
    timezone_override: str = "",
    browser_executable_path: str = "",
) -> FingerprintProfile:
    language_profile = random.choice(_LANGUAGE_PROFILES)
    viewport_width, viewport_height = random.choice(_VIEWPORT_POOL)
    detected_version = _detect_local_browser_version(browser_executable_path)
    if not detected_version:
        version_profile = random.choice(_CHROME_VERSION_PROFILES)
        patch = random.randint(*version_profile["patch_range"])
        detected_version = f'{version_profile["major"]}.0.{version_profile["build"]}.{patch}'
    locale = str(locale_override or "").strip() or str(language_profile["locale"])
    if locale_override:
        language = locale
        languages = (locale, "en-US", "en") if locale != "en-US" else ("en-US", "en")
        accept_language = f"{locale},en-US;q=0.9,en;q=0.8" if locale != "en-US" else "en-US,en;q=0.9"
    else:
        language = str(language_profile["language"])
        languages = tuple(language_profile["languages"])
        accept_language = str(language_profile["accept_language"])
    timezone_id = str(timezone_override or "").strip() or random.choice(_TIMEZONE_POOL)
    return _build_profile(
        chrome_full_version=detected_version,
        locale=locale,
        language=language,
        languages=languages,
        accept_language=accept_language,
        timezone_id=timezone_id,
        viewport_width=viewport_width,
        viewport_height=viewport_height,
        hardware_concurrency=random.choice(_HARDWARE_CONCURRENCY_POOL),
        device_memory=random.choice(_DEVICE_MEMORY_POOL),
    )


def build_sec_ch_headers(profile: FingerprintProfile) -> dict[str, str]:
    return {
        "sec-ch-ua": profile.sec_ch_ua,
        "sec-ch-ua-mobile": profile.sec_ch_ua_mobile,
        "sec-ch-ua-platform": profile.sec_ch_ua_platform,
        "sec-ch-ua-arch": profile.sec_ch_ua_arch,
        "sec-ch-ua-bitness": profile.sec_ch_ua_bitness,
        "sec-ch-ua-full-version": profile.sec_ch_ua_full_version,
        "sec-ch-ua-full-version-list": profile.sec_ch_ua_full_version_list,
        "sec-ch-ua-platform-version": profile.sec_ch_ua_platform_version,
    }


def describe_fingerprint(profile: FingerprintProfile) -> str:
    return (
        f"ua=Chrome/{profile.chrome_full_version}, "
        f"platform={profile.ch_platform}/{profile.ch_arch}, "
        f"locale={profile.locale}, timezone={profile.timezone_id}, "
        f"viewport={profile.viewport_width}x{profile.viewport_height}, "
        f"dpr={profile.device_pixel_ratio}, touch={profile.max_touch_points}, "
        f"cpu={profile.hardware_concurrency}, mem={profile.device_memory}GB, "
        f"net={profile.connection_type}/{profile.connection_effective_type}, "
        f"impersonate={profile.curl_impersonate}"
    )
