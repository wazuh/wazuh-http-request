# Description
The objective of this project is to maintain a library that has the responsibility of providing efficient file downloading and information retrieval to multiple remote information providers.

The main requirement is that its use be simple and abstract to what is strictly necessary to obtain said information.

It allows the download and invocation and calls to REST apis through the methods of GET, POST, PUT and DELETE.


# Building
This project use [CMake](https://cmake.org)
```bash
mkdir build && cd build
cmake .. -GNinja
ninja
```
Please see the CMake documentation and CMakeLists.txt for more advanced usage.


## Configuration parameters

Every request receives a `ConfigurationParameters` (`include/IURLRequest.hpp`) describing *how* it is performed.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `timeout` | `long` | `0` | Maximum time in milliseconds the request may take. `0` means no limit. |
| `handlerType` | `CurlHandlerTypeEnum` | `SINGLE` | Type of the cURL handler (`SINGLE` or `MULTI`). |
| `shouldRun` | `std::atomic<bool>` | `true` | Flag that interrupts the handler when `handlerType` is `MULTI`. |
| `userAgent` | `std::string` | empty | User agent used in the request. |
| `maxResponseSize` | `size_t` | `0` | Maximum size in bytes of the response body kept in memory, counted after content decoding. `0` means no limit. Not applied to `outputFile`. |
| `acceptEncoding` | `std::optional<std::string>` | `""` | Content encodings negotiated with the server (the `Accept-Encoding` request header). See below. |

### Accept-Encoding

`acceptEncoding` is passed to libcurl as `CURLOPT_ACCEPT_ENCODING` and has three modes:

- `""` (default): advertise every encoding the linked libcurl can decode and decode the response transparently.
- `std::nullopt`: send no `Accept-Encoding` header and do not decode; a received `Content-Encoding` is left as is.
- any other string: sent verbatim (for example `"gzip"` or `"identity"`).

The advertised list in the default mode depends on the curl the library is linked against (`curl_version_info()`): `deflate, gzip`, plus `br` or `zstd` when that curl was built with them.

The test tool exposes the field as `--accept-encoding none|all|<value>`; when the flag is absent the default applies:

```bash
./urlrequest_testtool -u https://httpbin.org/gzip -t get --accept-encoding none
./urlrequest_testtool -u https://httpbin.org/gzip -t get --accept-encoding all
./urlrequest_testtool -u https://httpbin.org/headers -t get --accept-encoding gzip
```


## Contribution Requirements

### CPP Migration tools

1. **Coding Style** This project follow the Wazuh C++ Coding Style [Wazuh C++ style guide](https://github.com/wazuh/wazuh/wiki/Coding-style-guide-%28C-plus-plus%29)

2. **Tests** All changes must be accompanied by a new (or changed) tests. Unit, component and benchmarking.

3. **Fuzzing** It is quite interesting and important to fuzz the interfaces of the designed components.

4. **Diagrams** All changes must be accompanied by a new (or changed) architectural diagrams.

### Documentation

Apart from the markdown that we can find in the readme of the project subfolders, the code has doxygen headers, which generate technical documentation that gives some context of what the call tree is like, and what parameters and returns they have.

```bash
root@wazuh-dev:~/repos/wazuh-http-request# doxygen doxygen.cfg
```

After executing this command, open the index.html file that is generated in the `doc/html` folder, to view this technical and implementation documentation.


## License

Dual-licensed under `GPL-2.0-only OR AGPL-3.0-or-later`: the GPLv2 components of the Wazuh manager and agent use it under GPLv2, and the Wazuh engine (AGPLv3) under AGPLv3. See [COPYING](COPYING).
