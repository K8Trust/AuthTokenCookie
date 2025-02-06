# Auth Token Cookie Plugin for Traefik

A Traefik middleware plugin that authenticates requests using an internal authentication service and sets a secure cookie containing the access token.

## Middleware Plugins

Once loaded, these plugins behave like statically compiled middlewares. Their instantiation and behavior are driven by the dynamic configuration.

## Static Configuration

In the examples below, we add the authtokencookie plugin in the Traefik Static Configuration:

### File (YAML)

```yaml
# Static configuration
pilot:
  token: "xxxx"

experimental:
  plugins:
    authtokencookie:
      moduleName: "github.com/k8trust/authtokencookie"
      version: "v1.0.0"
```

### CLI

```bash
--entryPoints.web.address=:80 \
--experimental.plugins.authtokencookie.modulename=github.com/k8trust/authtokencookie \
--experimental.plugins.authtokencookie.version=v1.0.0
```

## Dynamic Configuration

Some plugins will need to be configured by adding a dynamic configuration. For the authtokencookie plugin, for example:

### File (YAML)

```yaml
# Dynamic configuration
http:
  middlewares:
    auth-token:
      plugin:
        authtokencookie:
          conf: "http://internal-auth.example.local/auth"
          timeout: "30s"
```

## Plugin Configuration Options

| Option   | Type     | Default | Description                                    |
|----------|----------|---------|------------------------------------------------|
| conf     | String   | ""      | Full URL of the authentication service         |
| timeout  | Duration | "30s"   | Timeout for authentication service requests    |

## Required Headers

The plugin expects the following headers in incoming requests:

- `x-api-key`: API key for authentication
- `x-account`: Tenant identifier

## Usage Example

```yaml
# traefik.yml
http:
  routers:
    my-router:
      rule: "Host(`example.com`)"
      middlewares:
        - auth-token
      service: my-service
```

## Local Mode

Traefik also offers a local mode that can be used for:

- Using private plugins that are not hosted on GitHub
- Testing the plugins during their development

To use a plugin in local mode, the Traefik static configuration must define the module name (as is usual for Go packages) and a path to a Go workspace, which can be the local GOPATH or any directory.

The plugins must be placed in `./plugins-local` directory, which should be in the working directory of the process running the Traefik binary. The source code of the plugin should be organized as follows:

```plaintext
./plugins-local/
    └── src
        └── github.com
            └── k8trust
                └── authtokencookie
                    ├── plugin.go
                    ├── plugin_test.go
                    ├── go.mod
                    ├── go.sum
                    ├── LICENSE
                    ├── Makefile
                    ├── readme.md
                    └── vendor/
```

### CLI

```bash
--entryPoints.web.address=:80 \
--experimental.localPlugins.authtokencookie.modulename=github.com/k8trust/authtokencookie
```

## Development

### Building

```bash
make build
```

### Testing

```bash
make test
```

### Linting

```bash
make lint
```

### Docker Build

```bash
docker build -t authtokencookie .
```

## Security Considerations

- The plugin sets cookies with both `HttpOnly` and `Secure` flags
- Authentication is performed over internal network only
- API keys and tokens are handled securely

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for discussion.

### Contributors

- [Yousef Shamshoum](https://github.com/yousef-shamshoum)
- [Shay](https://github.com/shay)