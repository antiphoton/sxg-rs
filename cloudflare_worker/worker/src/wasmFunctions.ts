/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This variable is added by the runtime of Cloudflare worker. It contains the
// binary data of the wasm file.
declare var wasm: any;

// `wrangler` uses `wasm-pack build --target no-modules` [^1] to build wasm.
// When the target is `no-modules`, `wasm-bindgen` declares a global variable
// to initialize wasm [^2].
// The default name of this global variable is `wasm_bindgen` [^3].
// The example is here [^4].
// [^1] https://github.com/cloudflare/wrangler/blob/37caf3cb08db3e84fee4c503e1a08f849371c4b8/src/build/mod.rs#L48
// [^2] https://github.com/rustwasm/wasm-bindgen/blob/dc9141e7ccd143e67a282cfa73717bb165049169/crates/cli/src/bin/wasm-bindgen.rs#L27
// [^3] https://github.com/rustwasm/wasm-bindgen/blob/dc9141e7ccd143e67a282cfa73717bb165049169/crates/cli-support/src/lib.rs#L208
// [^4] https://rustwasm.github.io/docs/wasm-bindgen/examples/without-a-bundler.html#using-the-older---target-no-modules
declare var wasm_bindgen: any;

