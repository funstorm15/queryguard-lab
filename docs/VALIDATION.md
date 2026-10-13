# Release validation — 0.2.0

Validated on Python 3.14.7 during project preparation.

| Check | Result |
| --- | --- |
| Source-tree regression suite | 54 tests passed |
| Wheel build | Successful using locally installed setuptools |
| Installation in an isolated virtual environment | Successful, with no runtime dependencies |
| Regression suite against the installed package from outside the source tree | 54 tests passed |
| Installed `queryguard scan` command | Successful; JSON and HTML reports generated |
| Vulnerable simulator flow | Three baseline passes; six observed violations |
| Protected simulator flow | Four expected-result passes; five rejected plans; no observed violations |
| Both tenant contexts | Covered by the regression suite |
| Ollama adapter | Mocked request/response, error, response-size and redirect tests passed |
| Live Ollama generation | Not run; no local model was available |
| Browser visual inspection of HTML | Not completed; the browser tool's URL policy blocked local-file access |
| GitHub Actions matrix | Configured for Python 3.11–3.14; not run remotely during preparation |
| Interactive browser UI | Visually inspected; comparison and all nine cases executed using browser controls |
| Local HTTP integration | Assets, request validation, origin/token restrictions and execution tested |
| Packaged browser assets | All three assets served successfully by the installed package during HTTP tests |
| JavaScript syntax | Syntax check passed |

The example standalone reports contain simulator results and label them accordingly. Their local-file visual preview remains unverified. The separate HTTP-served interactive UI was visually inspected. Live model behavior and remote CI execution remain unverified.
