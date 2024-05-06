## Environment variables

Code dealing with the environment variables resides in [here](internal/config/specs.go) where each attribute has an annotation which is the lowercase of the environment variable name.

At the moment the application is sourcing the following from the environment:

* `OTEL_GRPC_ENDPOINT` - needed if we want to use the otel grpc exporter for traces
* `OTEL_HTTP_ENDPOINT` - needed if we want to use the otel http exporter for traces (if grpc is specified this gets unused)
* `TRACING_ENABLED` - switch for tracing, defaults to enabled (`true`)
* `LOG_LEVEL` - log level, defaults to `error`
* `LOG_FILE` - log file which the log rotator will write into, *make sure application user has permissions to write*,  defaults to `log.txt`
* `PORT` - http server port, defaults to `8000`
* `KRATOS_PUBLIC_URL` - address of kratos apis
* `HYDRA_ADMIN_URL` - address of hydra admin apis

