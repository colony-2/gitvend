// Package jobdbprovider issues lease-bound Gitvend credentials for JobDB jobs.
// Load creates a fixed provider from an issuer configuration file. WatchConfig
// creates a provider that atomically reloads validated configuration and signing
// keys when they change; callers must close it when finished.
//
// Both providers implement jobdb.SecretProvider and support concurrent requests.
// The jobdb-gitvend-secret-provider command exposes WatchConfig through JobDB's
// subprocess plugin SDK. See docs/jobdb-secret-provider.md for configuration.
package jobdbprovider
